#include "integration_support.h"

#include <psapi.h>

#include <array>
#include <charconv>
#include <sstream>

namespace faultloom::integration {
namespace {

struct Attributes {
  std::vector<std::uint8_t> storage;
  PPROC_THREAD_ATTRIBUTE_LIST list = nullptr;
  ~Attributes() { if (list != nullptr) DeleteProcThreadAttributeList(list); }
};

std::uint64_t file_time(const FILETIME& value) noexcept {
  return (static_cast<std::uint64_t>(value.dwHighDateTime) << 32U) | value.dwLowDateTime;
}

std::optional<std::string> field(std::string_view line, std::string_view name) {
  const auto begin = line.find(name);
  if (begin == std::string_view::npos) return std::nullopt;
  const auto value = begin + name.size();
  const auto end = line.find_first_of(" \n", value);
  return std::string(line.substr(value, end - value));
}

bool decimal(std::string_view value, DWORD& output) noexcept {
  const auto result = std::from_chars(value.data(), value.data() + value.size(), output);
  return result.ec == std::errc{} && result.ptr == value.data() + value.size() && output != 0U;
}

bool read_ready(HANDLE pipe, HANDLE process, std::string& line) noexcept {
  const ULONGLONG deadline = GetTickCount64() + 10000U;
  std::array<char, 193> buffer{};
  while (GetTickCount64() < deadline) {
    DWORD available = 0U;
    if (!PeekNamedPipe(pipe, nullptr, 0U, nullptr, &available, nullptr)) return false;
    if (available != 0U) {
      if (available >= buffer.size()) return false;
      DWORD read = 0U;
      if (!ReadFile(pipe, buffer.data(), available, &read, nullptr) || read != available) return false;
      line.assign(buffer.data(), read);
      return line.ends_with('\n');
    }
    if (WaitForSingleObject(process, 0U) == WAIT_OBJECT_0) return false;
    Sleep(1U);
  }
  return false;
}

}

bool Job::create() noexcept {
  handle_.reset(CreateJobObjectW(nullptr, nullptr));
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  return handle_ && SetInformationJobObject(handle_.get(), JobObjectExtendedLimitInformation,
                                             &limits, sizeof(limits));
}

std::wstring sibling(std::wstring_view name) {
  std::array<wchar_t, 32768> path{};
  const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
  if (length == 0U || length >= path.size()) return {};
  std::wstring result(path.data(), length);
  const auto slash = result.find_last_of(L"\\/");
  if (slash == std::wstring::npos) return {};
  result.resize(slash + 1U);
  result += name;
  return result;
}

std::optional<Child> launch(Job& job, const std::wstring& application,
                            const std::wstring& arguments,
                            const std::vector<HANDLE>& inherited, bool capture) noexcept {
  std::vector<HANDLE> handles = inherited;
  Handle read;
  Handle write;
  if (capture) {
    SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
    HANDLE read_raw = nullptr;
    HANDLE write_raw = nullptr;
    if (!CreatePipe(&read_raw, &write_raw, &security, 0U)) return std::nullopt;
    read.reset(read_raw);
    write.reset(write_raw);
    if (!SetHandleInformation(read.get(), HANDLE_FLAG_INHERIT, 0U)) return std::nullopt;
    handles.push_back(write.get());
  }
  Attributes attributes;
  if (!handles.empty()) {
    SIZE_T bytes = 0U;
    InitializeProcThreadAttributeList(nullptr, 1U, 0U, &bytes);
    attributes.storage.resize(bytes);
    attributes.list = reinterpret_cast<PPROC_THREAD_ATTRIBUTE_LIST>(attributes.storage.data());
    if (!InitializeProcThreadAttributeList(attributes.list, 1U, 0U, &bytes) ||
        !UpdateProcThreadAttribute(attributes.list, 0U, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                   handles.data(), handles.size() * sizeof(HANDLE), nullptr, nullptr)) {
      return std::nullopt;
    }
  }
  STARTUPINFOEXW startup{};
  startup.StartupInfo.cb = handles.empty() ? sizeof(STARTUPINFOW) : sizeof(startup);
  startup.lpAttributeList = attributes.list;
  if (capture) {
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdOutput = write.get();
    startup.StartupInfo.hStdError = write.get();
    startup.StartupInfo.hStdInput = nullptr;
  }
  std::wstring command = L"\"" + application + L"\"" + arguments;
  PROCESS_INFORMATION raw{};
  const DWORD flags = CREATE_SUSPENDED | CREATE_NO_WINDOW |
      (handles.empty() ? 0U : EXTENDED_STARTUPINFO_PRESENT);
  if (!CreateProcessW(application.c_str(), command.data(), nullptr, nullptr,
                      handles.empty() ? FALSE : TRUE, flags,
                      nullptr, nullptr, &startup.StartupInfo, &raw)) return std::nullopt;
  Child child{Handle(raw.hProcess), Handle(raw.hThread), std::move(read), raw.dwProcessId};
  write.reset();
  if (!AssignProcessToJobObject(job.get(), child.process.get()) ||
      ResumeThread(child.thread.get()) == static_cast<DWORD>(-1)) {
    TerminateProcess(child.process.get(), ERROR_OPERATION_ABORTED);
    return std::nullopt;
  }
  FILETIME creation{}, exit{}, kernel{}, user{};
  if (!GetProcessTimes(child.process.get(), &creation, &exit, &kernel, &user)) return std::nullopt;
  child.creation_time = file_time(creation);
  return child;
}

bool peak_private(HANDLE process, std::uint64_t& bytes) noexcept {
  PROCESS_MEMORY_COUNTERS_EX memory{};
  memory.cb = sizeof(memory);
  if (!GetProcessMemoryInfo(process, reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&memory),
                            sizeof(memory))) return false;
  bytes = static_cast<std::uint64_t>(memory.PeakPagefileUsage);
  return bytes != 0U && bytes < 128ULL * 1024ULL * 1024ULL;
}

bool snapshot(Child& child) noexcept {
  return peak_private(child.process.get(), child.peak_private_bytes);
}

bool finish(Child& child, DWORD timeout_ms, DWORD expected_exit) noexcept {
  if (WaitForSingleObject(child.process.get(), timeout_ms) != WAIT_OBJECT_0 ||
      !GetExitCodeProcess(child.process.get(), &child.exit_code) || !snapshot(child)) return false;
  if (child.output) {
    std::array<char, 4096> buffer{};
    DWORD read = 0U;
    while (ReadFile(child.output.get(), buffer.data(), static_cast<DWORD>(buffer.size()), &read,
                    nullptr) && read != 0U) {
      if (child.captured.size() + read > 1024U * 1024U) return false;
      child.captured.append(buffer.data(), read);
    }
  }
  return child.exit_code == expected_exit;
}

std::optional<Broker> launch_broker(Job& job) noexcept {
  HANDLE ready_read_raw = nullptr;
  HANDLE ready_write_raw = nullptr;
  if (!CreatePipe(&ready_read_raw, &ready_write_raw, nullptr, 0U)) return std::nullopt;
  Handle ready_read(ready_read_raw);
  Handle ready_write(ready_write_raw);
  HANDLE child_ready_raw = nullptr;
  if (!DuplicateHandle(GetCurrentProcess(), ready_write.get(), GetCurrentProcess(),
                       &child_ready_raw, FILE_WRITE_DATA | SYNCHRONIZE, TRUE, 0U)) return std::nullopt;
  Handle child_ready(child_ready_raw);
  ready_write.reset();
  Handle shutdown(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  HANDLE child_shutdown_raw = nullptr;
  if (!shutdown || !DuplicateHandle(GetCurrentProcess(), shutdown.get(), GetCurrentProcess(),
                                    &child_shutdown_raw, SYNCHRONIZE, TRUE, 0U)) return std::nullopt;
  Handle child_shutdown(child_shutdown_raw);
  const auto application = sibling(L"faultloom_broker.exe");
  const std::wstring args = L" --ready-handle " +
      std::to_wstring(reinterpret_cast<std::uintptr_t>(child_ready.get())) +
      L" --shutdown-event-handle " +
      std::to_wstring(reinterpret_cast<std::uintptr_t>(child_shutdown.get()));
  auto child = launch(job, application, args, {child_ready.get(), child_shutdown.get()});
  child_ready.reset();
  child_shutdown.reset();
  if (!child) return std::nullopt;
  Ready ready;
  if (!read_ready(ready_read.get(), child->process.get(), ready.line)) return std::nullopt;
  const auto session = field(ready.line, "session=");
  const auto broker_pid = field(ready.line, "broker_pid=");
  const auto reviewer_pid = field(ready.line, "reviewer_pid=");
  const auto key = field(ready.line, "public_key_sha256=");
  if (!session || session->size() != 32U || !broker_pid || !reviewer_pid || !key || key->size() != 64U ||
      !decimal(*broker_pid, ready.broker_pid) || !decimal(*reviewer_pid, ready.reviewer_pid) ||
      ready.broker_pid != child->pid) return std::nullopt;
  const std::string expected = "READY v1 session=" + *session + " broker_pid=" + *broker_pid +
      " reviewer_pid=" + *reviewer_pid + " public_key_sha256=" + *key + "\n";
  if (ready.line != expected) return std::nullopt;
  ready.session = *session;
  ready.key_hash = *key;
  Handle reviewer(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE, FALSE,
                              ready.reviewer_pid));
  FILETIME creation{}, exit{}, kernel{}, user{};
  if (!reviewer || !GetProcessTimes(reviewer.get(), &creation, &exit, &kernel, &user)) return std::nullopt;
  return Broker{std::move(*child), std::move(shutdown), std::move(reviewer), std::move(ready),
                file_time(creation)};
}

bool stop_broker(Broker& broker) noexcept {
  const bool signaled = SetEvent(broker.shutdown.get()) != FALSE;
  const bool broker_exit = WaitForSingleObject(broker.child.process.get(), 10000U) == WAIT_OBJECT_0;
  const bool reviewer_exit = WaitForSingleObject(broker.reviewer.get(), 10000U) == WAIT_OBJECT_0;
  return signaled && broker_exit && reviewer_exit && snapshot(broker.child) &&
      peak_private(broker.reviewer.get(), broker.reviewer_peak_private_bytes) &&
      GetExitCodeProcess(broker.child.process.get(), &broker.child.exit_code) &&
      GetExitCodeProcess(broker.reviewer.get(), &broker.reviewer_exit_code) &&
      broker.child.exit_code == 0U && broker.reviewer_exit_code == 0U;
}

std::optional<Child> run_ctl(Job& job, const Ready& ready, std::wstring_view action,
                             bool allow_action_failure) noexcept {
  const auto application = sibling(L"faultloom_ctl.exe");
  const std::wstring args = L" --session " + std::wstring(ready.session.begin(), ready.session.end()) +
      L" --expected-broker-pid " + std::to_wstring(ready.broker_pid) +
      L" --reviewer-key-sha256 " + std::wstring(ready.key_hash.begin(), ready.key_hash.end()) +
      L" " + std::wstring(action);
  auto child = launch(job, application, args, {}, true);
  if (!child) return std::nullopt;
  if (WaitForSingleObject(child->process.get(), 10000U) != WAIT_OBJECT_0 ||
      !GetExitCodeProcess(child->process.get(), &child->exit_code) || !snapshot(*child)) {
    return std::nullopt;
  }
  std::array<char, 4096> bytes{};
  DWORD read = 0U;
  while (ReadFile(child->output.get(), bytes.data(), static_cast<DWORD>(bytes.size()), &read,
                  nullptr) && read != 0U) {
    if (child->captured.size() + read > 1024U * 1024U) return std::nullopt;
    child->captured.append(bytes.data(), read);
  }
  if (child->exit_code != 0U && !(allow_action_failure && child->exit_code == 7U)) {
    return std::nullopt;
  }
  return child;
}

bool pipe_absent_until(std::string_view kind, std::string_view session,
                       ULONGLONG deadline) noexcept {
  const std::wstring name = L"\\\\.\\pipe\\FaultLoom." + std::wstring(kind.begin(), kind.end()) +
      L".MVP.v1." + std::wstring(session.begin(), session.end());
  for (;;) {
    Handle pipe(CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0U, nullptr,
                            OPEN_EXISTING, 0U, nullptr));
    const DWORD error = pipe ? ERROR_SUCCESS : GetLastError();
    if (!pipe && error == ERROR_FILE_NOT_FOUND) return true;
    if ((!pipe && error != ERROR_PIPE_BUSY) || GetTickCount64() >= deadline) return false;
    Sleep(1U);
  }
}

bool pipe_absent(std::string_view kind, std::string_view session) noexcept {
  return pipe_absent_until(kind, session, GetTickCount64() + 1000U);
}

}
