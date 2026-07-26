#include "scm_query.h"
#include "unique_handle.h"

#include <array>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace {

class FakeApi final : public faultloom::broker::ScmApi {
 public:
  SC_HANDLE open_manager(DWORD access) noexcept override {
    ++actions;
    manager_access = access;
    return manager_result ? reinterpret_cast<SC_HANDLE>(1U) : nullptr;
  }
  SC_HANDLE open_service(SC_HANDLE, const wchar_t* name, DWORD access) noexcept override {
    ++actions;
    service_access = access;
    selected = name;
    return service_result ? reinterpret_cast<SC_HANDLE>(2U) : nullptr;
  }
  bool query(SC_HANDLE, SERVICE_STATUS_PROCESS& output, DWORD& error) noexcept override {
    ++actions;
    if (stall_ms != 0U) Sleep(stall_ms);
    output = status;
    error = query_error;
    return query_result;
  }
  void close(SC_HANDLE) noexcept override { ++closes; }

  unsigned actions = 0U;
  unsigned closes = 0U;
  DWORD manager_access = 0U;
  DWORD service_access = 0U;
  std::wstring selected;
  bool manager_result = true;
  bool service_result = true;
  bool query_result = true;
  DWORD query_error = ERROR_SUCCESS;
  DWORD stall_ms = 0U;
  SERVICE_STATUS_PROCESS status{1U, 2U, 3U, 4U, 5U, 6U, 7U, 8U, 9U};
};

std::array<std::uint8_t, 36> expected() {
  std::array<std::uint8_t, 36> bytes{};
  for (std::size_t field = 0U; field < 9U; ++field) {
    const std::uint32_t value = static_cast<std::uint32_t>(field + 1U);
    for (std::size_t byte = 0U; byte < 4U; ++byte) {
      bytes[field * 4U + byte] = static_cast<std::uint8_t>(value >> (byte * 8U));
    }
  }
  return bytes;
}

std::optional<faultloom::reviewer::UniqueHandle> launch_child(std::wstring_view argument) {
  std::array<wchar_t, 32768> application{};
  const DWORD size = GetModuleFileNameW(nullptr, application.data(),
                                        static_cast<DWORD>(application.size()));
  if (size == 0U || size >= application.size()) return std::nullopt;
  std::wstring command = L"\"" + std::wstring(application.data(), size) + L"\" " +
                         std::wstring(argument);
  STARTUPINFOW startup{sizeof(startup)};
  PROCESS_INFORMATION raw{};
  if (!CreateProcessW(application.data(), command.data(), nullptr, nullptr, FALSE, 0U,
                      nullptr, nullptr, &startup, &raw)) return std::nullopt;
  CloseHandle(raw.hThread);
  return faultloom::reviewer::UniqueHandle(raw.hProcess);
}

DWORD WINAPI terminate_after_delay(void* raw) {
  Sleep(50U);
  TerminateProcess(static_cast<HANDLE>(raw), 9U);
  return 0U;
}

int stall_child(bool client_exit, DWORD worker_delay_ms = 30000U) {
  auto api = std::make_shared<FakeApi>();
  api->stall_ms = worker_delay_ms;
  faultloom::reviewer::UniqueHandle shutdown(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  auto client_process = client_exit ? launch_child(L"--idle") : std::nullopt;
  faultloom::reviewer::UniqueHandle client_event(
      client_exit ? nullptr : CreateEventW(nullptr, TRUE, FALSE, nullptr));
  faultloom::reviewer::UniqueHandle reviewer(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  LARGE_INTEGER frequency{};
  LARGE_INTEGER now{};
  const HANDLE client = client_exit && client_process.has_value()
      ? client_process->get() : client_event.get();
  if (!shutdown || (client_exit ? !client_process.has_value() : !client_event) || !reviewer ||
      !QueryPerformanceFrequency(&frequency) ||
      !QueryPerformanceCounter(&now)) return 2;
  faultloom::reviewer::UniqueHandle signal_thread(client_exit ? CreateThread(
      nullptr, 0U, terminate_after_delay, client, 0U, nullptr) : nullptr);
  const std::uint64_t delay = client_exit ? static_cast<std::uint64_t>(frequency.QuadPart * 5U)
                                          : static_cast<std::uint64_t>(frequency.QuadPart / 20U);
  const auto ignored = faultloom::broker::query_service_bounded_with_api(
      api, faultloom::policy::Service::bfe, shutdown.get(), client, reviewer.get(),
      static_cast<std::uint64_t>(now.QuadPart) + delay,
      static_cast<std::uint64_t>(frequency.QuadPart));
  (void)ignored;
  return 3;
}

bool bounded_child(std::wstring_view argument) {
  std::array<wchar_t, 32768> application{};
  const DWORD size = GetModuleFileNameW(nullptr, application.data(),
                                        static_cast<DWORD>(application.size()));
  if (size == 0U || size >= application.size()) return false;
  std::wstring command = L"\"" + std::wstring(application.data(), size) + L"\" " +
                         std::wstring(argument);
  STARTUPINFOW startup{sizeof(startup)};
  PROCESS_INFORMATION raw{};
  if (!CreateProcessW(application.data(), command.data(), nullptr, nullptr, FALSE, 0U,
                      nullptr, nullptr, &startup, &raw)) return false;
  faultloom::reviewer::UniqueHandle process(raw.hProcess);
  faultloom::reviewer::UniqueHandle thread(raw.hThread);
  const bool exited = WaitForSingleObject(process.get(), 3000U) == WAIT_OBJECT_0;
  DWORD code = 0U;
  const bool status = exited && GetExitCodeProcess(process.get(), &code) &&
                      code == ERROR_OPERATION_ABORTED;
  if (!exited) TerminateProcess(process.get(), ERROR_TIMEOUT);
  return status;
}

}

int main(int argc, char** argv) {
  if (argc == 2 && std::string_view(argv[1]) == "--idle") {
    Sleep(30000U);
    return 0;
  }
  if (argc == 2 && std::string_view(argv[1]) == "--stall-deadline") return stall_child(false);
  if (argc == 2 && std::string_view(argv[1]) == "--just-late-deadline") {
    return stall_child(false, 150U);
  }
  if (argc == 2 && std::string_view(argv[1]) == "--stall-client-exit") return stall_child(true);
  FakeApi api;
  DWORD error = 99U;
  const auto result = faultloom::broker::query_service_exact(
      api, faultloom::policy::Service::event_log, error);
  bool passed = result.has_value() && *result == expected() && error == ERROR_SUCCESS &&
      api.manager_access == SC_MANAGER_CONNECT && api.service_access == SERVICE_QUERY_STATUS &&
      api.selected == L"EventLog" && api.actions == 3U && api.closes == 2U;
  FakeApi absent;
  absent.service_result = false;
  error = ERROR_SERVICE_DOES_NOT_EXIST;
  const auto missing = faultloom::broker::query_service_exact(
      absent, faultloom::policy::Service::win_defend, error);
  passed &= !missing.has_value() && absent.actions == 2U && absent.closes == 1U &&
            absent.service_access == SERVICE_QUERY_STATUS;
  faultloom::reviewer::UniqueHandle shutdown(CreateEventW(nullptr, TRUE, TRUE, nullptr));
  faultloom::reviewer::UniqueHandle client(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  faultloom::reviewer::UniqueHandle reviewer(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  LARGE_INTEGER frequency{};
  LARGE_INTEGER now{};
  passed &= shutdown && client && reviewer && QueryPerformanceFrequency(&frequency) &&
            QueryPerformanceCounter(&now);
  auto revoked = std::make_shared<FakeApi>();
  const auto revoked_result = faultloom::broker::query_service_bounded_with_api(
      revoked, faultloom::policy::Service::bfe, shutdown.get(), client.get(), reviewer.get(),
      static_cast<std::uint64_t>(now.QuadPart + frequency.QuadPart),
      static_cast<std::uint64_t>(frequency.QuadPart));
  passed &= revoked->actions == 0U && !revoked_result.must_terminate &&
            revoked_result.status == faultloom::protocol::Status::reviewer_unavailable;
  ResetEvent(shutdown.get());
  auto expired = std::make_shared<FakeApi>();
  const auto expired_result = faultloom::broker::query_service_bounded_with_api(
      expired, faultloom::policy::Service::bfe, shutdown.get(), client.get(), reviewer.get(),
      static_cast<std::uint64_t>(now.QuadPart),
      static_cast<std::uint64_t>(frequency.QuadPart));
  passed &= expired->actions == 0U && !expired_result.must_terminate &&
            expired_result.status == faultloom::protocol::Status::timeout;
  auto dead_process = launch_child(L"--idle");
  if (dead_process.has_value()) {
    TerminateProcess(dead_process->get(), 10U);
    passed &= WaitForSingleObject(dead_process->get(), 3000U) == WAIT_OBJECT_0;
  }
  auto dead_client = std::make_shared<FakeApi>();
  const auto dead_client_result = dead_process.has_value()
      ? faultloom::broker::query_service_bounded_with_api(
            dead_client, faultloom::policy::Service::bfe, shutdown.get(), dead_process->get(),
            reviewer.get(), static_cast<std::uint64_t>(now.QuadPart + frequency.QuadPart),
            static_cast<std::uint64_t>(frequency.QuadPart))
      : faultloom::broker::BoundedQuery{};
  passed &= dead_process.has_value() && dead_client->actions == 0U &&
            !dead_client_result.must_terminate &&
            dead_client_result.status == faultloom::protocol::Status::unauthorized_client;
  auto dead_reviewer = std::make_shared<FakeApi>();
  const auto dead_reviewer_result = dead_process.has_value()
      ? faultloom::broker::query_service_bounded_with_api(
            dead_reviewer, faultloom::policy::Service::bfe, shutdown.get(), client.get(),
            dead_process->get(), static_cast<std::uint64_t>(now.QuadPart + frequency.QuadPart),
            static_cast<std::uint64_t>(frequency.QuadPart))
      : faultloom::broker::BoundedQuery{};
  passed &= dead_process.has_value() && dead_reviewer->actions == 0U &&
            !dead_reviewer_result.must_terminate &&
            dead_reviewer_result.status == faultloom::protocol::Status::reviewer_unavailable;
  passed &= bounded_child(L"--stall-deadline") && bounded_child(L"--just-late-deadline") &&
            bounded_child(L"--stall-client-exit");
  if (!passed) std::cerr << "SCM exact-byte/read-only contract failed\n";
  return passed ? 0 : 1;
}
