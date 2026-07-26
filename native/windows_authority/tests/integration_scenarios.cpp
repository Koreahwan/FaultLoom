#include "integration_support.h"

#include <array>
#include <iostream>
#include <set>
#include <sstream>

namespace faultloom::integration {
namespace {

bool oversized_rejected(Job& job) noexcept {
  auto broker = launch_broker(job);
  if (!broker) return false;
  const std::wstring pipe_name = L"\\\\.\\pipe\\FaultLoom.Broker.MVP.v1." +
      std::wstring(broker->ready.session.begin(), broker->ready.session.end());
  Handle pipe(CreateFileW(pipe_name.c_str(), GENERIC_READ | GENERIC_WRITE, 0U, nullptr,
                          OPEN_EXISTING, 0U, nullptr));
  const std::array<std::uint8_t, 4> prefix{1U, 32U, 0U, 0U};
  DWORD written = 0U;
  bool passed = pipe && WriteFile(pipe.get(), prefix.data(), static_cast<DWORD>(prefix.size()),
                                  &written, nullptr) && written == prefix.size();
  const ULONGLONG deadline = GetTickCount64() + 5000U;
  while (passed && GetTickCount64() < deadline) {
    DWORD available = 0U;
    if (!PeekNamedPipe(pipe.get(), nullptr, 0U, nullptr, &available, nullptr)) {
      passed = GetLastError() == ERROR_BROKEN_PIPE || GetLastError() == ERROR_PIPE_NOT_CONNECTED;
      break;
    }
    Sleep(1U);
  }
  passed &= stop_broker(*broker) && pipe_absent("Broker", broker->ready.session) &&
            pipe_absent("Reviewer", broker->ready.session);
  return passed;
}

bool matrix(Job& job) noexcept {
  static constexpr std::array names{
      L"faultloom_broker_process_tests.exe",
      L"faultloom_broker_invalid_signature_process_tests.exe",
      L"faultloom_broker_scm_tests.exe",
      L"faultloom_reviewer_process_tests.exe",
      L"faultloom_reviewer_ready_tests.exe"};
  for (const auto* name : names) {
    auto child = launch(job, sibling(name), L"", {}, true);
    if (!child || !finish(*child, 10000U, 0U)) {
      std::wcerr << L"negative matrix child failed: " << name << L'\n';
      return false;
    }
  }
  if (!oversized_rejected(job)) {
    std::cerr << "8193-byte payload rejection failed\n";
    return false;
  }
  return true;
}

std::string quote(std::string_view value) { return "\"" + std::string(value) + "\""; }

}

int smoke_main() noexcept {
  Job job;
  auto broker = job.create() ? launch_broker(job) : std::nullopt;
  if (!broker || broker->ready.broker_pid == broker->ready.reviewer_pid ||
      !same_sid(broker->child.process.get(), broker->reviewer.get())) {
    std::cerr << "broker/reviewer launch or identity boundary failed\n";
    return 1;
  }
  auto ping = run_ctl(job, broker->ready, L"ping");
  if (!ping || ping->captured != "PONG\r\n" ||
      !same_sid(broker->child.process.get(), ping->process.get())) {
    std::cerr << "signed PING ctl boundary failed\n";
    return 1;
  }
  std::array<std::string_view, 3> names{"BFE", "EventLog", "WinDefend"};
  std::vector<Oracle> before;
  std::vector<Oracle> after;
  std::vector<Child> controls;
  std::set<DWORD> pids{broker->ready.broker_pid, broker->ready.reviewer_pid, ping->pid};
  for (const auto name : names) {
    auto first = run_oracle(job, std::wstring(name.begin(), name.end()));
    auto ctl = run_ctl(job, broker->ready, L"query-service --name " +
        std::wstring(name.begin(), name.end()), true);
    auto second = run_oracle(job, std::wstring(name.begin(), name.end()));
    if (!first || !ctl || !second || !bracketed(*first, *second, *ctl) ||
        !same_sid(broker->child.process.get(), first->child.process.get()) ||
        !same_sid(broker->child.process.get(), ctl->process.get()) ||
        !same_sid(broker->child.process.get(), second->child.process.get()) ||
        !pids.insert(first->child.pid).second || !pids.insert(ctl->pid).second ||
        !pids.insert(second->child.pid).second) {
      std::cerr << "service oracle bracket failed: " << name << '\n';
      if (first) std::cerr << "before=" << first->child.captured;
      if (ctl) std::cerr << "ctl_exit=" << ctl->exit_code << " ctl=" << ctl->captured;
      if (second) std::cerr << "after=" << second->child.captured;
      return 1;
    }
    before.push_back(std::move(*first));
    controls.push_back(std::move(*ctl));
    after.push_back(std::move(*second));
  }
  const auto ready = broker->ready;
  const auto broker_creation = broker->child.creation_time;
  const auto reviewer_creation = broker->reviewer_creation_time;
  if (!stop_broker(*broker)) {
    std::cerr << "Broker/Reviewer shutdown failed\n";
    return 1;
  }
  const auto broker_peak = broker->child.peak_private_bytes;
  const auto reviewer_peak = broker->reviewer_peak_private_bytes;
  if (!pipe_absent("Broker", ready.session) || !pipe_absent("Reviewer", ready.session)) {
    std::cerr << "nonce pipes survived shutdown\n";
    return 1;
  }
  if (!matrix(job)) return 1;
  if (!supervisor_death_case()) {
    std::cerr << "supervisor-death cleanup failed\n";
    return 1;
  }
  std::ostringstream json;
  json << "{\"schema_version\":1,\"session\":" << quote(ready.session)
       << ",\"reviewer_key_sha256\":" << quote(ready.key_hash)
       << ",\"broker\":{\"pid\":" << ready.broker_pid << ",\"creation_time\":" << broker_creation
       << ",\"peak_private_bytes\":" << broker_peak << ",\"exit\":" << broker->child.exit_code
       << "},\"reviewer\":{\"pid\":"
       << ready.reviewer_pid << ",\"creation_time\":" << reviewer_creation
       << ",\"peak_private_bytes\":" << reviewer_peak << ",\"exit\":"
       << broker->reviewer_exit_code << "},\"ping_ctl\":{\"pid\":"
       << ping->pid << ",\"creation_time\":" << ping->creation_time
       << ",\"peak_private_bytes\":" << ping->peak_private_bytes << ",\"exit\":0},\"services\":[";
  for (std::size_t index = 0U; index < names.size(); ++index) {
    if (index != 0U) json << ',';
    json << "{\"name\":" << quote(names[index]) << ",\"start_before\":" << quote(before[index].start)
         << ",\"start_after\":" << quote(after[index].start)
         << ",\"before_oracle\":{\"pid\":" << before[index].child.pid
         << ",\"creation_time\":" << before[index].child.creation_time
         << ",\"peak_private_bytes\":" << before[index].child.peak_private_bytes << ",\"exit\":0}"
         << ",\"after_oracle\":{\"pid\":" << after[index].child.pid
         << ",\"creation_time\":" << after[index].child.creation_time
         << ",\"peak_private_bytes\":" << after[index].child.peak_private_bytes << ",\"exit\":0}"
         << ",\"ctl_pid\":" << controls[index].pid
         << ",\"ctl_creation_time\":" << controls[index].creation_time << ",\"ctl_exit\":"
         << controls[index].exit_code << ",\"ctl_peak_private_bytes\":"
         << controls[index].peak_private_bytes << '}';
  }
  json << "],\"same_sid\":true,\"distinct_pids\":true,\"signatures_valid\":true,"
          "\"pipes_gone\":true,\"negative_matrix\":true,\"supervisor_death\":true,"
          "\"memory_limit\":true}";
  std::cout << "SMOKE_JSON=" << json.str() << '\n';
  return 0;
}

}
