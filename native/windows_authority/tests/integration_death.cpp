#include "integration_support.h"

#include <array>
#include <charconv>
#include <iostream>
#include <sstream>

namespace faultloom::integration {
namespace {

struct Attributes {
  std::vector<std::uint8_t> storage;
  PPROC_THREAD_ATTRIBUTE_LIST list = nullptr;
  ~Attributes() { if (list != nullptr) DeleteProcThreadAttributeList(list); }
};

bool write_report(HANDLE report, const Broker& broker, DWORD oracle_pid) noexcept {
  const std::string line = std::to_string(broker.ready.broker_pid) + " " +
      std::to_string(broker.ready.reviewer_pid) + " " + std::to_string(oracle_pid) + " " +
      broker.ready.session + "\n";
  DWORD written = 0U;
  return WriteFile(report, line.data(), static_cast<DWORD>(line.size()), &written, nullptr) &&
         written == line.size();
}

bool process_time(HANDLE process) noexcept {
  FILETIME creation{}, exit{}, kernel{}, user{};
  return GetProcessTimes(process, &creation, &exit, &kernel, &user) &&
      (creation.dwLowDateTime != 0U || creation.dwHighDateTime != 0U);
}

std::optional<DWORD> pid(std::string_view value) noexcept {
  DWORD output = 0U;
  const auto result = std::from_chars(value.data(), value.data() + value.size(), output);
  return result.ec == std::errc{} && result.ptr == value.data() + value.size() && output != 0U
      ? std::optional<DWORD>(output) : std::nullopt;
}

DWORD remaining(ULONGLONG deadline) noexcept {
  const ULONGLONG now = GetTickCount64();
  return now >= deadline ? 0U : static_cast<DWORD>(deadline - now);
}

}

int death_supervisor_main(std::uintptr_t report_handle) noexcept {
  const HANDLE report = reinterpret_cast<HANDLE>(report_handle);
  Job job;
  auto broker = job.create() ? launch_broker(job) : std::nullopt;
  auto oracle = broker ? launch(job, sibling(L"faultloom_integration_tests.exe"),
                                L" --oracle-stall") : std::nullopt;
  if (!broker || !oracle) {
    const std::string error = "ERROR broker=" + std::to_string(broker.has_value()) +
        " oracle=" + std::to_string(oracle.has_value()) + " win32=" +
        std::to_string(GetLastError()) + "\n";
    DWORD written = 0U;
    WriteFile(report, error.data(), static_cast<DWORD>(error.size()), &written, nullptr);
    return 1;
  }
  if (!write_report(report, *broker, oracle->pid)) return 1;
  Sleep(30000U);
  return 1;
}

bool death_cleanup_within(ULONGLONG action_tick, ULONGLONG supervisor_tick,
                          ULONGLONG cleanup_tick) noexcept {
  return supervisor_tick >= action_tick && cleanup_tick >= supervisor_tick &&
      cleanup_tick - action_tick <= 10000U;
}

bool supervisor_death_case() noexcept {
  SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
  HANDLE read_raw = nullptr;
  HANDLE write_raw = nullptr;
  if (!CreatePipe(&read_raw, &write_raw, &security, 0U)) {
    std::cerr << "death CreatePipe failed error=" << GetLastError() << '\n';
    return false;
  }
  Handle read(read_raw);
  Handle write(write_raw);
  if (!SetHandleInformation(read.get(), HANDLE_FLAG_INHERIT, 0U)) {
    std::cerr << "death handle reduction failed error=" << GetLastError() << '\n';
    return false;
  }
  Attributes attributes;
  SIZE_T size = 0U;
  InitializeProcThreadAttributeList(nullptr, 1U, 0U, &size);
  attributes.storage.resize(size);
  attributes.list = reinterpret_cast<PPROC_THREAD_ATTRIBUTE_LIST>(attributes.storage.data());
  if (!InitializeProcThreadAttributeList(attributes.list, 1U, 0U, &size)) {
    std::cerr << "death attributes init failed error=" << GetLastError() << '\n';
    return false;
  }
  const std::array handles{write.get()};
  if (!UpdateProcThreadAttribute(attributes.list, 0U, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                 const_cast<HANDLE*>(handles.data()), sizeof(handles),
                                 nullptr, nullptr)) {
    std::cerr << "death handle list failed error=" << GetLastError() << '\n';
    return false;
  }
  const auto application = sibling(L"faultloom_integration_tests.exe");
  std::wstring command = L"\"" + application + L"\" --death-supervisor " +
      std::to_wstring(reinterpret_cast<std::uintptr_t>(write.get()));
  STARTUPINFOEXW startup{};
  startup.StartupInfo.cb = sizeof(startup);
  startup.lpAttributeList = attributes.list;
  PROCESS_INFORMATION raw{};
  if (!CreateProcessW(application.c_str(), command.data(), nullptr, nullptr, TRUE,
                      CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
                      nullptr, nullptr, &startup.StartupInfo, &raw)) {
    std::cerr << "death supervisor CreateProcess failed error=" << GetLastError() << '\n';
    return false;
  }
  Child supervisor{Handle(raw.hProcess), Handle(raw.hThread), {}, raw.dwProcessId};
  if (ResumeThread(supervisor.thread.get()) == static_cast<DWORD>(-1)) {
    std::cerr << "death supervisor resume failed error=" << GetLastError() << '\n';
    return false;
  }
  write.reset();
  const ULONGLONG deadline = GetTickCount64() + 10000U;
  std::array<char, 256> buffer{};
  DWORD used = 0U;
  while (GetTickCount64() < deadline) {
    DWORD available = 0U;
    if (!PeekNamedPipe(read.get(), nullptr, 0U, nullptr, &available, nullptr)) {
      std::cerr << "death report peek failed error=" << GetLastError() << '\n';
      return false;
    }
    if (available != 0U) {
      if (available >= buffer.size() ||
          !ReadFile(read.get(), buffer.data(), available, &used, nullptr)) {
        std::cerr << "death report read failed error=" << GetLastError() << '\n';
        return false;
      }
      break;
    }
    if (WaitForSingleObject(supervisor.process.get(), 0U) == WAIT_OBJECT_0) {
      DWORD code = STILL_ACTIVE;
      GetExitCodeProcess(supervisor.process.get(), &code);
      std::cerr << "death supervisor exited before report code=" << code << '\n';
      return false;
    }
    Sleep(1U);
  }
  if (used == 0U) {
    std::cerr << "death report timed out\n";
    return false;
  }
  std::istringstream report(std::string(buffer.data(), used));
  std::string broker_text;
  std::string reviewer_text;
  std::string oracle_text;
  std::string session;
  report >> broker_text >> reviewer_text >> oracle_text >> session;
  const auto broker_pid = pid(broker_text);
  const auto reviewer_pid = pid(reviewer_text);
  const auto oracle_pid = pid(oracle_text);
  if (!broker_pid || !reviewer_pid || !oracle_pid || session.size() != 32U) {
    std::cerr << "death report parse failed: " << std::string(buffer.data(), used) << '\n';
    return false;
  }
  constexpr DWORD process_access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE;
  Handle broker(OpenProcess(process_access, FALSE, *broker_pid));
  Handle reviewer(OpenProcess(process_access, FALSE, *reviewer_pid));
  Handle oracle(OpenProcess(process_access, FALSE, *oracle_pid));
  if (!broker || !reviewer || !oracle || !process_time(broker.get()) ||
      !process_time(reviewer.get()) || !process_time(oracle.get())) {
    std::cerr << "death member retention failed error=" << GetLastError() << '\n';
    return false;
  }
  const ULONGLONG action_tick = GetTickCount64();
  const ULONGLONG death_deadline = action_tick + 10000U;
  if (!TerminateProcess(supervisor.process.get(), ERROR_OPERATION_ABORTED) ||
      WaitForSingleObject(supervisor.process.get(), remaining(death_deadline)) != WAIT_OBJECT_0) {
    std::cerr << "death supervisor termination failed error=" << GetLastError() << '\n';
    return false;
  }
  const ULONGLONG supervisor_tick = GetTickCount64();
  while (GetTickCount64() <= death_deadline) {
    if (WaitForSingleObject(broker.get(), 0U) == WAIT_OBJECT_0 &&
        WaitForSingleObject(reviewer.get(), 0U) == WAIT_OBJECT_0 &&
        WaitForSingleObject(oracle.get(), 0U) == WAIT_OBJECT_0 &&
        pipe_absent_until("Broker", session, death_deadline) &&
        pipe_absent_until("Reviewer", session, death_deadline)) {
      const ULONGLONG cleanup_tick = GetTickCount64();
      std::uint64_t supervisor_peak = 0U;
      std::uint64_t broker_peak = 0U;
      std::uint64_t reviewer_peak = 0U;
      std::uint64_t oracle_peak = 0U;
      return death_cleanup_within(action_tick, supervisor_tick, cleanup_tick) &&
          peak_private(supervisor.process.get(), supervisor_peak) &&
          peak_private(broker.get(), broker_peak) && peak_private(reviewer.get(), reviewer_peak) &&
          peak_private(oracle.get(), oracle_peak);
    }
    Sleep(10U);
  }
  std::cerr << "death timeout broker=" << WaitForSingleObject(broker.get(), 0U)
            << " reviewer=" << WaitForSingleObject(reviewer.get(), 0U)
            << " oracle=" << WaitForSingleObject(oracle.get(), 0U)
            << " deadline_elapsed=" << (GetTickCount64() - action_tick) << '\n';
  return false;
}

}
