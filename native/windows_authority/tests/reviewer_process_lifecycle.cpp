#include "reviewer_process_fixture.h"

#include <array>
#include <limits>
#include <string_view>

namespace faultloom::test {
namespace {

std::wstring sibling(std::wstring_view name) {
  std::array<wchar_t, 32768> path{};
  const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
  std::wstring result(path.data(), length);
  result.resize(result.find_last_of(L"\\/") + 1U);
  result += name;
  return result;
}

std::optional<ReadyLine> parse_ready(std::string_view line) {
  constexpr std::string_view prefix = "REVIEWER_READY v1 reviewer_pid=";
  constexpr std::string_view middle = " public_blob=";
  if (!line.starts_with(prefix) || !line.ends_with('\n')) return std::nullopt;
  const std::size_t split = line.find(middle, prefix.size());
  if (split == std::string_view::npos || line.size() - split - middle.size() - 1U != 144U) return std::nullopt;
  std::uint64_t pid = 0U;
  for (const char character : line.substr(prefix.size(), split - prefix.size())) {
    if (character < '0' || character > '9') return std::nullopt;
    pid = pid * 10U + static_cast<unsigned>(character - '0');
  }
  if (pid == 0U || pid > std::numeric_limits<std::uint32_t>::max()) return std::nullopt;
  ReadyLine ready{static_cast<std::uint32_t>(pid), {}};
  const auto source = line.substr(split + middle.size(), 144U);
  for (std::size_t index = 0U; index < ready.public_blob.size(); ++index) {
    const auto digit = [](char value) -> std::optional<std::uint8_t> {
      if (value >= '0' && value <= '9') return static_cast<std::uint8_t>(value - '0');
      if (value >= 'a' && value <= 'f') return static_cast<std::uint8_t>(value - 'a' + 10);
      return std::nullopt;
    };
    const auto high = digit(source[index * 2U]);
    const auto low = digit(source[index * 2U + 1U]);
    if (!high.has_value() || !low.has_value()) return std::nullopt;
    ready.public_blob[index] = static_cast<std::uint8_t>((*high << 4U) | *low);
  }
  return ready;
}

struct LaunchHandles {
  TestHandle ready_read;
  TestHandle ready_child;
  TestHandle shutdown_owner;
  TestHandle shutdown_child;
};

std::optional<LaunchHandles> make_launch_handles() noexcept {
  HANDLE raw_read = nullptr;
  HANDLE raw_write = nullptr;
  if (!CreatePipe(&raw_read, &raw_write, nullptr, 0U)) return std::nullopt;
  TestHandle ready_read(raw_read);
  TestHandle ready_write(raw_write);
  HANDLE raw_ready_child = nullptr;
  if (!DuplicateHandle(GetCurrentProcess(), ready_write.get(), GetCurrentProcess(),
                       &raw_ready_child, FILE_WRITE_DATA | SYNCHRONIZE, TRUE, 0U)) {
    return std::nullopt;
  }
  TestHandle ready_child(raw_ready_child);
  ready_write.reset();
  TestHandle shutdown_owner(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  HANDLE raw_shutdown_child = nullptr;
  if (!shutdown_owner ||
      !DuplicateHandle(GetCurrentProcess(), shutdown_owner.get(), GetCurrentProcess(),
                       &raw_shutdown_child, SYNCHRONIZE, TRUE, 0U)) {
    return std::nullopt;
  }
  return LaunchHandles{std::move(ready_read), std::move(ready_child),
                       std::move(shutdown_owner), TestHandle(raw_shutdown_child)};
}

bool read_ready(HANDLE ready, HANDLE process, std::array<char, 200>& buffer,
                DWORD& received) noexcept {
  const ULONGLONG deadline = GetTickCount64() + 10000U;
  while (GetTickCount64() < deadline) {
    DWORD available = 0U;
    if (!PeekNamedPipe(ready, nullptr, 0U, nullptr, &available, nullptr)) return false;
    if (available != 0U) {
      return ReadFile(ready, buffer.data(), static_cast<DWORD>(buffer.size()), &received,
                      nullptr) != FALSE;
    }
    if (WaitForSingleObject(process, 0U) == WAIT_OBJECT_0) return false;
    Sleep(1U);
  }
  return false;
}

void retire_failed_launch(HANDLE process, HANDLE shutdown) noexcept {
  SetEvent(shutdown);
  if (WaitForSingleObject(process, 1000U) != WAIT_OBJECT_0) {
    TerminateProcess(process, ERROR_OPERATION_ABORTED);
    WaitForSingleObject(process, 1000U);
  }
}

}

std::wstring sibling_reviewer() { return sibling(L"faultloom_reviewer.exe"); }
std::wstring sibling_test() { return sibling(L"faultloom_reviewer_process_tests.exe"); }

std::optional<ReviewerProcess> ReviewerProcess::launch(std::wstring session, std::uint32_t broker_pid) {
  auto handles = make_launch_handles();
  if (!handles.has_value()) return std::nullopt;
  SIZE_T bytes = 0U;
  InitializeProcThreadAttributeList(nullptr, 1U, 0U, &bytes);
  std::vector<std::uint8_t> storage(bytes);
  auto* attributes = reinterpret_cast<PPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
  if (!InitializeProcThreadAttributeList(attributes, 1U, 0U, &bytes)) return std::nullopt;
  const std::array inherited_handles{handles->ready_child.get(), handles->shutdown_child.get()};
  const bool updated = UpdateProcThreadAttribute(attributes, 0U, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                                  const_cast<HANDLE*>(inherited_handles.data()),
                                                  sizeof(inherited_handles),
                                                  nullptr, nullptr) != FALSE;
  const auto reviewer = sibling_reviewer();
  std::wstring command = L"\"" + reviewer + L"\" --session " + session + L" --expected-broker-pid " +
                         std::to_wstring(broker_pid) + L" --ready-handle " +
                         std::to_wstring(reinterpret_cast<std::uintptr_t>(handles->ready_child.get())) +
                         L" --shutdown-event-handle " +
                         std::to_wstring(reinterpret_cast<std::uintptr_t>(handles->shutdown_child.get()));
  STARTUPINFOEXW startup{};
  startup.StartupInfo.cb = sizeof(startup);
  startup.lpAttributeList = attributes;
  PROCESS_INFORMATION process{};
  const bool created = updated && CreateProcessW(reviewer.c_str(), command.data(), nullptr, nullptr, TRUE,
                                                  EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr,
                                                  &startup.StartupInfo, &process) != FALSE;
  DeleteProcThreadAttributeList(attributes);
  if (!created) return std::nullopt;
  TestHandle process_handle(process.hProcess);
  TestHandle thread(process.hThread);
  handles->ready_child.reset();
  handles->shutdown_child.reset();
  std::array<char, 200> buffer{};
  DWORD read = 0U;
  if (!read_ready(handles->ready_read.get(), process_handle.get(), buffer, read)) {
    retire_failed_launch(process_handle.get(), handles->shutdown_owner.get());
    return std::nullopt;
  }
  const auto ready = parse_ready(std::string_view(buffer.data(), read));
  if (!ready.has_value() || ready->pid != process.dwProcessId) {
    retire_failed_launch(process_handle.get(), handles->shutdown_owner.get());
    return std::nullopt;
  }
  ReviewerProcess result;
  result.process_ = std::move(process_handle);
  result.shutdown_ = std::move(handles->shutdown_owner);
  result.ready_ = *ready;
  result.pipe_name_ = L"\\\\.\\pipe\\FaultLoom.Reviewer.MVP.v1." + session;
  return result;
}

ReviewerProcess::~ReviewerProcess() {
  [[maybe_unused]] const bool stopped = stop();
}

bool ReviewerProcess::wait_for_exit(DWORD timeout) const noexcept {
  if (!process_ || WaitForSingleObject(process_.get(), timeout) != WAIT_OBJECT_0) return false;
  DWORD code = STILL_ACTIVE;
  return GetExitCodeProcess(process_.get(), &code) && code == 0U;
}

bool ReviewerProcess::stop() noexcept {
  if (!process_) return true;
  const bool signaled = SetEvent(shutdown_.get()) != FALSE;
  const bool exited = WaitForSingleObject(process_.get(), 10000U) == WAIT_OBJECT_0;
  DWORD code = STILL_ACTIVE;
  const bool status = GetExitCodeProcess(process_.get(), &code) != FALSE;
  TestHandle residue(CreateFileW(pipe_name_.c_str(), GENERIC_READ | GENERIC_WRITE, 0U, nullptr,
                                 OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr));
  const bool pipe_absent = !residue && GetLastError() == ERROR_FILE_NOT_FOUND;
  process_.reset();
  shutdown_.reset();
  return signaled && exited && status && code == 0U && pipe_absent;
}

bool launch_and_wait(std::wstring command, DWORD expected_exit) noexcept {
  const auto application = sibling_test();
  STARTUPINFOW startup{sizeof(startup)};
  PROCESS_INFORMATION process{};
  if (!CreateProcessW(application.c_str(), command.data(), nullptr, nullptr, FALSE, 0U, nullptr, nullptr,
                      &startup, &process)) return false;
  TestHandle process_handle(process.hProcess);
  TestHandle thread(process.hThread);
  if (WaitForSingleObject(process_handle.get(), 10000U) != WAIT_OBJECT_0) return false;
  DWORD code = STILL_ACTIVE;
  return GetExitCodeProcess(process_handle.get(), &code) && code == expected_exit;
}

bool launch_reviewer_failure(std::wstring session, std::uint32_t broker_pid,
                             DWORD expected_exit) noexcept {
  auto handles = make_launch_handles();
  if (!handles.has_value()) return false;
  SIZE_T bytes = 0U;
  InitializeProcThreadAttributeList(nullptr, 1U, 0U, &bytes);
  std::vector<std::uint8_t> storage(bytes);
  auto* attributes = reinterpret_cast<PPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
  if (!InitializeProcThreadAttributeList(attributes, 1U, 0U, &bytes)) return false;
  const std::array inherited_handles{handles->ready_child.get(), handles->shutdown_child.get()};
  const bool updated = UpdateProcThreadAttribute(attributes, 0U,
      PROC_THREAD_ATTRIBUTE_HANDLE_LIST, const_cast<HANDLE*>(inherited_handles.data()),
      sizeof(inherited_handles), nullptr, nullptr) != FALSE;
  const auto reviewer = sibling_reviewer();
  std::wstring command = L"\"" + reviewer + L"\" --session " + session + L" --expected-broker-pid " +
                         std::to_wstring(broker_pid) + L" --ready-handle " +
                         std::to_wstring(reinterpret_cast<std::uintptr_t>(handles->ready_child.get())) +
                         L" --shutdown-event-handle " +
                         std::to_wstring(reinterpret_cast<std::uintptr_t>(handles->shutdown_child.get()));
  STARTUPINFOEXW startup{};
  startup.StartupInfo.cb = sizeof(startup);
  startup.lpAttributeList = attributes;
  PROCESS_INFORMATION process{};
  const bool created = updated && CreateProcessW(
      reviewer.c_str(), command.data(), nullptr, nullptr, TRUE, EXTENDED_STARTUPINFO_PRESENT,
      nullptr, nullptr, &startup.StartupInfo, &process) != FALSE;
  DeleteProcThreadAttributeList(attributes);
  if (!created) return false;
  TestHandle process_handle(process.hProcess);
  TestHandle thread(process.hThread);
  handles->ready_child.reset();
  handles->shutdown_child.reset();
  if (WaitForSingleObject(process_handle.get(), 10000U) != WAIT_OBJECT_0) {
    retire_failed_launch(process_handle.get(), handles->shutdown_owner.get());
    return false;
  }
  DWORD code = STILL_ACTIVE;
  return GetExitCodeProcess(process_handle.get(), &code) && code == expected_exit;
}

}
