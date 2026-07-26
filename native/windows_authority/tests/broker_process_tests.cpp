#include "reviewer_process_fixture.h"
#include "faultloom/protocol.h"

#include <windows.h>

#include <algorithm>
#include <array>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>

namespace {

using faultloom::test::TestHandle;

std::wstring sibling(std::wstring_view name) {
  std::array<wchar_t, 32768> path{};
  const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
  std::wstring result(path.data(), length);
  result.resize(result.find_last_of(L"\\/") + 1U);
  result += name;
  return result;
}

struct BrokerProcess {
  TestHandle process;
  TestHandle shutdown;
  std::string ready;
};

bool read_bounded(HANDLE pipe, HANDLE process, std::string& output, DWORD timeout) {
  const ULONGLONG deadline = GetTickCount64() + timeout;
  std::array<char, 512> buffer{};
  while (GetTickCount64() < deadline) {
    DWORD available = 0U;
    if (!PeekNamedPipe(pipe, nullptr, 0U, nullptr, &available, nullptr)) return false;
    if (available != 0U) {
      DWORD received = 0U;
      if (!ReadFile(pipe, buffer.data(), static_cast<DWORD>(buffer.size()), &received, nullptr)) return false;
      output.assign(buffer.data(), received);
      return true;
    }
    if (WaitForSingleObject(process, 0U) == WAIT_OBJECT_0) return false;
    Sleep(1U);
  }
  return false;
}

std::optional<BrokerProcess> launch_broker(
    std::wstring_view executable = L"faultloom_broker.exe") {
  const auto failed = [](const char* stage) -> std::optional<BrokerProcess> {
    std::cerr << "broker launch failed at " << stage << ", error=" << GetLastError() << '\n';
    return std::nullopt;
  };
  HANDLE raw_read = nullptr;
  HANDLE raw_write = nullptr;
  if (!CreatePipe(&raw_read, &raw_write, nullptr, 0U)) return failed("CreatePipe");
  TestHandle ready_read(raw_read);
  TestHandle ready_write(raw_write);
  HANDLE raw_ready_child = nullptr;
  if (!DuplicateHandle(GetCurrentProcess(), ready_write.get(), GetCurrentProcess(),
                       &raw_ready_child, FILE_WRITE_DATA | SYNCHRONIZE, TRUE, 0U)) return failed("ready duplicate");
  TestHandle ready_child(raw_ready_child);
  ready_write.reset();
  TestHandle shutdown(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  HANDLE raw_shutdown_child = nullptr;
  if (!shutdown || !DuplicateHandle(GetCurrentProcess(), shutdown.get(), GetCurrentProcess(),
                                    &raw_shutdown_child, SYNCHRONIZE, TRUE, 0U)) return failed("shutdown duplicate");
  TestHandle shutdown_child(raw_shutdown_child);
  SIZE_T bytes = 0U;
  InitializeProcThreadAttributeList(nullptr, 1U, 0U, &bytes);
  std::vector<std::uint8_t> storage(bytes);
  auto* attributes = reinterpret_cast<PPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
  if (!InitializeProcThreadAttributeList(attributes, 1U, 0U, &bytes)) return failed("attribute init");
  const std::array inherited{ready_child.get(), shutdown_child.get()};
  const bool updated = UpdateProcThreadAttribute(
      attributes, 0U, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
      const_cast<HANDLE*>(inherited.data()), sizeof(inherited), nullptr, nullptr) != FALSE;
  const auto application = sibling(executable);
  std::wstring command = L"\"" + application + L"\" --ready-handle " +
                         std::to_wstring(reinterpret_cast<std::uintptr_t>(ready_child.get())) +
                         L" --shutdown-event-handle " +
                         std::to_wstring(reinterpret_cast<std::uintptr_t>(shutdown_child.get()));
  STARTUPINFOEXW startup{};
  startup.StartupInfo.cb = sizeof(startup);
  startup.lpAttributeList = attributes;
  PROCESS_INFORMATION raw{};
  const bool created = updated && CreateProcessW(
      application.c_str(), command.data(), nullptr, nullptr, TRUE, EXTENDED_STARTUPINFO_PRESENT,
      nullptr, nullptr, &startup.StartupInfo, &raw) != FALSE;
  DeleteProcThreadAttributeList(attributes);
  if (!created) {
    std::cerr << "broker CreateProcess failed, updated=" << updated
              << " error=" << GetLastError() << '\n';
    return std::nullopt;
  }
  TestHandle process(raw.hProcess);
  TestHandle thread(raw.hThread);
  ready_child.reset();
  shutdown_child.reset();
  std::string ready;
  if (!read_bounded(ready_read.get(), process.get(), ready, 10000U)) {
    DWORD exit_code = STILL_ACTIVE;
    GetExitCodeProcess(process.get(), &exit_code);
    std::cerr << "broker readiness failed, exit=" << exit_code << '\n';
    SetEvent(shutdown.get());
    if (WaitForSingleObject(process.get(), 1000U) != WAIT_OBJECT_0) TerminateProcess(process.get(), 1U);
    return std::nullopt;
  }
  return BrokerProcess{std::move(process), std::move(shutdown), std::move(ready)};
}

std::optional<std::string> field(std::string_view line, std::string_view name) {
  const std::size_t begin = line.find(name);
  if (begin == std::string_view::npos) return std::nullopt;
  const std::size_t value = begin + name.size();
  const std::size_t end = line.find_first_of(" \n", value);
  return std::string(line.substr(value, end - value));
}

bool run_ctl(const BrokerProcess& broker, std::string_view action, std::string& output,
             bool allow_action_failure = false, DWORD* actual_exit = nullptr,
             bool allow_other_failure = false) {
  const auto session = field(broker.ready, "session=");
  const auto pid = field(broker.ready, "broker_pid=");
  const auto key = field(broker.ready, "public_key_sha256=");
  if (!session.has_value() || !pid.has_value() || !key.has_value()) return false;
  SECURITY_ATTRIBUTES inherited{sizeof(inherited), nullptr, TRUE};
  HANDLE raw_read = nullptr;
  HANDLE raw_write = nullptr;
  if (!CreatePipe(&raw_read, &raw_write, &inherited, 0U)) return false;
  TestHandle read(raw_read);
  TestHandle write(raw_write);
  SetHandleInformation(read.get(), HANDLE_FLAG_INHERIT, 0U);
  const auto application = sibling(L"faultloom_ctl.exe");
  std::wstring command = L"\"" + application + L"\" --session " +
      std::wstring(session->begin(), session->end()) + L" --expected-broker-pid " +
      std::wstring(pid->begin(), pid->end()) + L" --reviewer-key-sha256 " +
      std::wstring(key->begin(), key->end()) + L" " + std::wstring(action.begin(), action.end());
  STARTUPINFOW startup{sizeof(startup)};
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdOutput = write.get();
  startup.hStdError = write.get();
  startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
  PROCESS_INFORMATION raw{};
  if (!CreateProcessW(application.c_str(), command.data(), nullptr, nullptr, TRUE, 0U,
                      nullptr, nullptr, &startup, &raw)) return false;
  TestHandle process(raw.hProcess);
  TestHandle thread(raw.hThread);
  write.reset();
  if (WaitForSingleObject(process.get(), 10000U) != WAIT_OBJECT_0) return false;
  std::array<char, 512> bytes{};
  DWORD received = 0U;
  ReadFile(read.get(), bytes.data(), static_cast<DWORD>(bytes.size()), &received, nullptr);
  output.assign(bytes.data(), received);
  DWORD code = 1U;
  const bool exited = GetExitCodeProcess(process.get(), &code) != FALSE;
  if (actual_exit != nullptr) *actual_exit = code;
  const bool expected = code == 0U || (allow_action_failure && code == 7U);
  if (!exited || (!expected && !allow_other_failure))
    std::cerr << "ctl exit=" << code << ", output=" << output << '\n';
  return exited && (expected || allow_other_failure);
}

std::optional<std::vector<std::uint8_t>> ping_record() {
  LARGE_INTEGER frequency{};
  LARGE_INTEGER now{};
  if (!QueryPerformanceFrequency(&frequency) || !QueryPerformanceCounter(&now)) return std::nullopt;
  std::array<std::uint8_t, 8> body{};
  const auto deadline = static_cast<std::uint64_t>(now.QuadPart + frequency.QuadPart * 4U);
  for (std::size_t index = 0U; index < body.size(); ++index) {
    body[index] = static_cast<std::uint8_t>(deadline >> (index * 8U));
  }
  faultloom::protocol::RequestId request_id{};
  request_id[0] = 1U;
  const faultloom::protocol::FrameView frame{{faultloom::protocol::MessageType::client_request,
      request_id, faultloom::protocol::Action::ping, faultloom::protocol::Status::ok}, body};
  const auto payload = faultloom::protocol::encode_payload(frame);
  return payload ? faultloom::protocol::encode_record(*payload) : std::nullopt;
}

TestHandle connect_broker(const BrokerProcess& broker) {
  const auto session = field(broker.ready, "session=");
  if (!session.has_value()) return {};
  const std::wstring name = L"\\\\.\\pipe\\FaultLoom.Broker.MVP.v1." +
      std::wstring(session->begin(), session->end());
  return TestHandle(CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0U, nullptr,
                                OPEN_EXISTING, 0U, nullptr));
}

bool duplicate_rejected(BrokerProcess& broker) {
  auto pipe = connect_broker(broker);
  const auto record = ping_record();
  if (!pipe || !record) return false;
  std::vector<std::uint8_t> duplicate = *record;
  duplicate.insert(duplicate.end(), record->begin(), record->end());
  DWORD written = 0U;
  if (!WriteFile(pipe.get(), duplicate.data(), static_cast<DWORD>(duplicate.size()), &written,
                 nullptr) || written != duplicate.size()) return false;
  std::uint8_t byte = 0U;
  DWORD read = 0U;
  const BOOL received = ReadFile(pipe.get(), &byte, 1U, &read, nullptr);
  const DWORD error = received ? ERROR_SUCCESS : GetLastError();
  return !received && (error == ERROR_BROKEN_PIPE || error == ERROR_NO_DATA ||
                       error == ERROR_PIPE_NOT_CONNECTED);
}

bool unavailable_response(BrokerProcess& broker) {
  auto pipe = connect_broker(broker);
  const auto record = ping_record();
  const auto reviewer_pid = field(broker.ready, "reviewer_pid=");
  TestHandle reviewer(reviewer_pid.has_value()
      ? OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE,
                    static_cast<DWORD>(std::stoul(*reviewer_pid))) : nullptr);
  if (!pipe || !record || !reviewer || !TerminateProcess(reviewer.get(), 91U) ||
      WaitForSingleObject(reviewer.get(), 5000U) != WAIT_OBJECT_0) return false;
  DWORD written = 0U;
  if (!WriteFile(pipe.get(), record->data(), static_cast<DWORD>(record->size()), &written,
                 nullptr) || written != record->size()) return false;
  std::array<std::uint8_t, faultloom::protocol::kMaxRecordBytes> response{};
  DWORD read = 0U;
  if (!ReadFile(pipe.get(), response.data(), static_cast<DWORD>(response.size()), &read, nullptr)) {
    return false;
  }
  const auto decoded = faultloom::protocol::decode_record(std::span(response).first(read));
  if (!decoded.frame || decoded.frame->header.status !=
                            faultloom::protocol::Status::reviewer_unavailable) return false;
  const auto body = decoded.frame->body;
  return body.size() == 173U && body[32U] == 0U && body[33U] == 5U && body[34U] == 0U &&
         std::all_of(body.begin(), body.begin() + 32U, [](std::uint8_t value) { return value == 0U; }) &&
         std::all_of(body.begin() + 35U, body.end(), [](std::uint8_t value) { return value == 0U; });
}

}

int main() {
  auto broker = launch_broker();
  bool passed = broker.has_value();
  std::string output;
  if (broker.has_value()) {
    passed &= run_ctl(*broker, "ping", output) && output == "PONG\r\n";
    output.clear();
    passed &= run_ctl(*broker, "query-service --name BFE", output) &&
              output.starts_with("SERVICE_STATUS ");
    for (const std::string_view service : {"EventLog", "WinDefend"}) {
      output.clear();
      passed &= run_ctl(*broker, std::string("query-service --name ") + std::string(service),
                        output, true) &&
                (output.starts_with("SERVICE_STATUS ") || output == "ACTION_FAILED\r\n");
    }
    const std::string trusted_ready = broker->ready;
    const std::size_t key = broker->ready.find("public_key_sha256=") + 18U;
    broker->ready[key] = broker->ready[key] == '0' ? '1' : '0';
    output.clear();
    passed &= !run_ctl(*broker, "ping", output);
    broker->ready = trusted_ready;
    output.clear();
    passed &= !run_ctl(*broker, "query-service --name Spooler", output);
    const bool duplicate_ok = duplicate_rejected(*broker);
    if (!duplicate_ok) std::cerr << "duplicate record was not rejected\n";
    passed &= duplicate_ok;
    output.clear();
    const bool recovery_ok = run_ctl(*broker, "ping", output) && output == "PONG\r\n";
    if (!recovery_ok) std::cerr << "post-duplicate recovery failed\n";
    passed &= recovery_ok;
    const bool unavailable_ok = unavailable_response(*broker);
    if (!unavailable_ok) std::cerr << "Reviewer unavailable response mismatch\n";
    passed &= unavailable_ok;
    passed &= WaitForSingleObject(broker->process.get(), 10000U) == WAIT_OBJECT_0;
    DWORD code = 1U;
    passed &= GetExitCodeProcess(broker->process.get(), &code) && code == 0U;
  }
  if (!passed) {
    std::cerr << "broker process PING failed: " << output << '\n';
    if (broker.has_value()) std::cerr << "broker ready: " << broker->ready;
  }
  return passed ? 0 : 1;
}
