#include "reviewer_ready.h"
#include "unique_handle.h"

#include <windows.h>

#include <array>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <string_view>

namespace {

using faultloom::reviewer::IoResult;
using faultloom::reviewer::UniqueHandle;

DWORD natural_timeout_case() noexcept;

struct SignalContext {
  HANDLE event;
  DWORD delay_ms;
};

DWORD WINAPI signal_after(void* raw) noexcept {
  const auto& context = *static_cast<const SignalContext*>(raw);
  Sleep(context.delay_ms);
  return SetEvent(context.event) ? 0U : 1U;
}

bool helper_wait(int argc, wchar_t** argv) noexcept {
  if (argc != 3) return false;
  wchar_t* end = nullptr;
  const unsigned long long value = std::wcstoull(argv[2], &end, 10);
  return end != argv[2] && *end == L'\0' &&
         WaitForSingleObject(reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(value)),
                             10000U) == WAIT_OBJECT_0;
}

bool fill_pipe(HANDLE write, HANDLE read, DWORD& available) noexcept {
  std::array<std::uint8_t, 4096> filler{};
  DWORD written = 0U;
  return WriteFile(write, filler.data(), static_cast<DWORD>(filler.size()), &written, nullptr) &&
         written == filler.size() &&
         PeekNamedPipe(read, nullptr, 0U, nullptr, &available, nullptr) != FALSE &&
         available == filler.size();
}

bool unchanged(HANDLE read, DWORD expected) noexcept {
  DWORD available = 0U;
  return PeekNamedPipe(read, nullptr, 0U, nullptr, &available, nullptr) &&
         available == expected;
}

std::optional<PROCESS_INFORMATION> waiting_broker(HANDLE event) {
  std::array<wchar_t, 32768> path{};
  const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
  if (length == 0U || length == path.size()) return std::nullopt;
  std::wstring command = L"\"" + std::wstring(path.data(), length) + L"\" --broker-wait " +
                         std::to_wstring(reinterpret_cast<std::uintptr_t>(event));
  STARTUPINFOW startup{sizeof(startup)};
  PROCESS_INFORMATION process{};
  return CreateProcessW(path.data(), command.data(), nullptr, nullptr, TRUE, 0U, nullptr,
                        nullptr, &startup, &process)
             ? std::optional<PROCESS_INFORMATION>(process)
             : std::nullopt;
}

bool stalled_shutdown_case() noexcept {
  faultloom::signing::PublicBlob blob{};
  UniqueHandle shutdown(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  UniqueHandle broker(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  HANDLE raw_read = nullptr;
  HANDLE raw_write = nullptr;
  if (!shutdown || !broker || !CreatePipe(&raw_read, &raw_write, nullptr, 4096U)) return false;
  UniqueHandle ready_read(raw_read);
  UniqueHandle ready_write(raw_write);
  DWORD filled = 0U;
  if (!fill_pipe(ready_write.get(), ready_read.get(), filled)) return false;
  SignalContext signal{shutdown.get(), 50U};
  UniqueHandle thread(CreateThread(nullptr, 0U, signal_after, &signal, 0U, nullptr));
  if (!thread) return false;
  const IoResult result = faultloom::reviewer::report_ready(
      ready_write.get(), shutdown.get(), broker.get(), blob);
  return result == IoResult::stopped && unchanged(ready_read.get(), filled);
}

bool stalled_broker_case() noexcept {
  faultloom::signing::PublicBlob blob{};
  SECURITY_ATTRIBUTES inherited{sizeof(inherited), nullptr, TRUE};
  UniqueHandle broker_exit(CreateEventW(&inherited, TRUE, FALSE, nullptr));
  const auto broker = broker_exit ? waiting_broker(broker_exit.get()) : std::nullopt;
  if (!broker.has_value()) return false;
  UniqueHandle broker_process(broker->hProcess);
  UniqueHandle broker_thread(broker->hThread);
  UniqueHandle shutdown(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  HANDLE raw_read = nullptr;
  HANDLE raw_write = nullptr;
  if (!shutdown || !CreatePipe(&raw_read, &raw_write, nullptr, 4096U)) return false;
  UniqueHandle ready_read(raw_read);
  UniqueHandle ready_write(raw_write);
  DWORD filled = 0U;
  if (!fill_pipe(ready_write.get(), ready_read.get(), filled)) return false;
  SignalContext signal{broker_exit.get(), 50U};
  UniqueHandle thread(CreateThread(nullptr, 0U, signal_after, &signal, 0U, nullptr));
  if (!thread) return false;
  const IoResult result = faultloom::reviewer::report_ready(
      ready_write.get(), shutdown.get(), broker_process.get(), blob);
  return result == IoResult::stopped && unchanged(ready_read.get(), filled) &&
         WaitForSingleObject(broker_process.get(), 1000U) == WAIT_OBJECT_0;
}

DWORD natural_timeout_case() noexcept {
  faultloom::signing::PublicBlob blob{};
  UniqueHandle shutdown(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  UniqueHandle broker(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  HANDLE raw_read = nullptr;
  HANDLE raw_write = nullptr;
  if (!shutdown || !broker || !CreatePipe(&raw_read, &raw_write, nullptr, 4096U)) return 1U;
  UniqueHandle ready_read(raw_read);
  UniqueHandle ready_write(raw_write);
  DWORD filled = 0U;
  if (!fill_pipe(ready_write.get(), ready_read.get(), filled)) return 1U;
  const IoResult result = faultloom::reviewer::report_ready(
      ready_write.get(), shutdown.get(), broker.get(), blob);
  return result == IoResult::failed && unchanged(ready_read.get(), filled) ? 4U : 1U;
}

bool run_stalled_helper(std::wstring_view mode) noexcept {
  std::array<wchar_t, 32768> path{};
  const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
  if (length == 0U || length == path.size()) return false;
  std::wstring command = L"\"" + std::wstring(path.data(), length) + L"\" " + mode.data();
  STARTUPINFOW startup{sizeof(startup)};
  PROCESS_INFORMATION raw{};
  const ULONGLONG start = GetTickCount64();
  if (!CreateProcessW(path.data(), command.data(), nullptr, nullptr, FALSE, 0U, nullptr,
                      nullptr, &startup, &raw)) return false;
  UniqueHandle process(raw.hProcess);
  UniqueHandle thread(raw.hThread);
  if (WaitForSingleObject(process.get(), 2500U) != WAIT_OBJECT_0) {
    TerminateProcess(process.get(), ERROR_TIMEOUT);
    WaitForSingleObject(process.get(), 1000U);
    return false;
  }
  DWORD code = STILL_ACTIVE;
  return GetExitCodeProcess(process.get(), &code) &&
         (code == 0U || code == ERROR_OPERATION_ABORTED) &&
         GetTickCount64() - start < 2500U;
}

bool run_natural_timeout_helper() noexcept {
  std::array<wchar_t, 32768> path{};
  const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
  if (length == 0U || length == path.size()) return false;
  std::wstring command = L"\"" + std::wstring(path.data(), length) + L"\" --natural-timeout";
  STARTUPINFOW startup{sizeof(startup)};
  PROCESS_INFORMATION raw{};
  const ULONGLONG start = GetTickCount64();
  if (!CreateProcessW(path.data(), command.data(), nullptr, nullptr, FALSE, 0U, nullptr,
                      nullptr, &startup, &raw)) return false;
  UniqueHandle process(raw.hProcess);
  UniqueHandle thread(raw.hThread);
  if (WaitForSingleObject(process.get(), 7500U) != WAIT_OBJECT_0) {
    TerminateProcess(process.get(), ERROR_TIMEOUT);
    WaitForSingleObject(process.get(), 1000U);
    return false;
  }
  DWORD code = STILL_ACTIVE;
  const ULONGLONG elapsed = GetTickCount64() - start;
  return GetExitCodeProcess(process.get(), &code) && code == 4U &&
         elapsed >= 5000U && elapsed < 7500U;
}

}

int wmain(int argc, wchar_t** argv) {
  if (argc > 1 && std::wstring_view(argv[1]) == L"--broker-wait") {
    return helper_wait(argc, argv) ? 0 : 1;
  }
  if (argc == 2 && std::wstring_view(argv[1]) == L"--stalled-shutdown") {
    return stalled_shutdown_case() ? 0 : 1;
  }
  if (argc == 2 && std::wstring_view(argv[1]) == L"--stalled-broker") {
    return stalled_broker_case() ? 0 : 1;
  }
  if (argc == 2 && std::wstring_view(argv[1]) == L"--natural-timeout") {
    return static_cast<int>(natural_timeout_case());
  }
  bool passed = true;
  faultloom::signing::PublicBlob blob{};
  UniqueHandle shutdown(CreateEventW(nullptr, TRUE, TRUE, nullptr));
  HANDLE raw_read = nullptr;
  HANDLE raw_write = nullptr;
  passed &= shutdown && CreatePipe(&raw_read, &raw_write, nullptr, 4096U);
  UniqueHandle ready_read(raw_read);
  UniqueHandle ready_write(raw_write);
  if (passed) {
    const IoResult result = faultloom::reviewer::report_ready(
        ready_write.get(), shutdown.get(), GetCurrentProcess(), blob);
    DWORD available = 0U;
    passed &= result == IoResult::stopped &&
              PeekNamedPipe(ready_read.get(), nullptr, 0U, nullptr, &available, nullptr) &&
              available == 0U;
  }

  passed &= run_stalled_helper(L"--stalled-shutdown");
  passed &= run_stalled_helper(L"--stalled-broker");
  passed &= run_natural_timeout_helper();
  if (!passed) std::cerr << "readiness revocation boundary failed\n";
  return passed ? 0 : 1;
}
