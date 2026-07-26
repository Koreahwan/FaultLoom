#include "scm_query.h"

#include "unique_handle.h"

#include <algorithm>
#include <limits>
#include <memory>
#include <string>

namespace faultloom::broker {
namespace {

const wchar_t* service_name(policy::Service service) noexcept {
  switch (service) {
    case policy::Service::bfe: return L"BFE";
    case policy::Service::event_log: return L"EventLog";
    case policy::Service::win_defend: return L"WinDefend";
    case policy::Service::none: return nullptr;
  }
  return nullptr;
}

void put32(ServiceBytes& output, std::size_t offset, DWORD value) noexcept {
  output[offset] = static_cast<std::uint8_t>(value);
  output[offset + 1U] = static_cast<std::uint8_t>(value >> 8U);
  output[offset + 2U] = static_cast<std::uint8_t>(value >> 16U);
  output[offset + 3U] = static_cast<std::uint8_t>(value >> 24U);
}

class SystemApi final : public ScmApi {
 public:
  SC_HANDLE open_manager(DWORD access) noexcept override {
    return OpenSCManagerW(nullptr, nullptr, access);
  }
  SC_HANDLE open_service(SC_HANDLE manager, const wchar_t* name,
                         DWORD access) noexcept override {
    return OpenServiceW(manager, name, access);
  }
  bool query(SC_HANDLE service, SERVICE_STATUS_PROCESS& status,
             DWORD& error) noexcept override {
#ifdef FAULTLOOM_TEST_POST_APPROVAL_STALL
    const std::wstring event_name = L"Local\\FaultLoom.Test.ScmWorkerStarted." +
        std::to_wstring(GetCurrentProcessId());
    reviewer::UniqueHandle started(CreateEventW(nullptr, TRUE, FALSE, event_name.c_str()));
    if (started) SetEvent(started.get());
    Sleep(30000U);
#endif
    DWORD bytes = 0U;
    const BOOL ok = QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
        reinterpret_cast<LPBYTE>(&status), sizeof(status), &bytes);
    error = ok ? ERROR_SUCCESS : GetLastError();
    return ok != FALSE;
  }
  void close(SC_HANDLE handle) noexcept override { CloseServiceHandle(handle); }
};

struct Context {
  std::shared_ptr<ScmApi> api;
  policy::Service service;
  BoundedQuery result{protocol::Status::action_failed, {}};
};

DWORD WINAPI worker(void* raw) noexcept {
  std::unique_ptr<std::shared_ptr<Context>> argument(
      static_cast<std::shared_ptr<Context>*>(raw));
  const std::shared_ptr<Context> context = std::move(*argument);
  DWORD error = ERROR_SUCCESS;
  const auto bytes = query_service_exact(*context->api, context->service, error);
  if (bytes.has_value()) context->result = {protocol::Status::ok, *bytes};
  return 0U;
}

DWORD remaining(std::uint64_t deadline, std::uint64_t frequency) noexcept {
  LARGE_INTEGER now{};
  if (frequency == 0U || !QueryPerformanceCounter(&now) ||
      static_cast<std::uint64_t>(now.QuadPart) >= deadline) return 0U;
  const std::uint64_t ticks = deadline - static_cast<std::uint64_t>(now.QuadPart);
  const std::uint64_t milliseconds = (ticks * 1000U + frequency - 1U) / frequency;
  return static_cast<DWORD>(std::min<std::uint64_t>(milliseconds,
      std::numeric_limits<DWORD>::max() - 1U));
}

[[noreturn]] void abort_stuck_worker() noexcept {
  TerminateProcess(GetCurrentProcess(), ERROR_OPERATION_ABORTED);
  std::terminate();
}

}

std::optional<ServiceBytes> query_service_exact(
    ScmApi& api, policy::Service service, DWORD& error) noexcept {
  const wchar_t* name = service_name(service);
  if (name == nullptr) {
    error = ERROR_INVALID_PARAMETER;
    return std::nullopt;
  }
  const SC_HANDLE manager = api.open_manager(SC_MANAGER_CONNECT);
  if (manager == nullptr) {
    error = GetLastError();
    return std::nullopt;
  }
  const SC_HANDLE selected = api.open_service(manager, name, SERVICE_QUERY_STATUS);
  if (selected == nullptr) {
    error = GetLastError();
    api.close(manager);
    return std::nullopt;
  }
  SERVICE_STATUS_PROCESS status{};
  const bool queried = api.query(selected, status, error);
  api.close(selected);
  api.close(manager);
  if (!queried) return std::nullopt;
  const std::array fields{status.dwServiceType, status.dwCurrentState,
      status.dwControlsAccepted, status.dwWin32ExitCode, status.dwServiceSpecificExitCode,
      status.dwCheckPoint, status.dwWaitHint, status.dwProcessId, status.dwServiceFlags};
  ServiceBytes output{};
  for (std::size_t index = 0U; index < fields.size(); ++index) {
    put32(output, index * sizeof(DWORD), fields[index]);
  }
  error = ERROR_SUCCESS;
  return output;
}

BoundedQuery query_service_bounded(
    policy::Service service, HANDLE shutdown, HANDLE client, HANDLE reviewer,
    std::uint64_t deadline, std::uint64_t frequency) noexcept {
  return query_service_bounded_with_api(std::make_shared<SystemApi>(), service, shutdown,
                                        client, reviewer,
                                        deadline, frequency);
}

BoundedQuery query_service_bounded_with_api(
    std::shared_ptr<ScmApi> api, policy::Service service, HANDLE shutdown, HANDLE client,
    HANDLE reviewer,
    std::uint64_t deadline, std::uint64_t frequency) noexcept {
  if (WaitForSingleObject(shutdown, 0U) != WAIT_TIMEOUT ||
      WaitForSingleObject(reviewer, 0U) != WAIT_TIMEOUT) {
    return {protocol::Status::reviewer_unavailable, {}};
  }
  if (WaitForSingleObject(client, 0U) != WAIT_TIMEOUT) {
    return {protocol::Status::unauthorized_client, {}};
  }
  if (remaining(deadline, frequency) == 0U) return {protocol::Status::timeout, {}};
  if (!api) return {protocol::Status::action_failed, {}};
  auto context = std::make_shared<Context>(Context{std::move(api), service});
  auto argument = std::make_unique<std::shared_ptr<Context>>(context);
  reviewer::UniqueHandle thread(CreateThread(nullptr, 0U, worker, argument.get(), 0U, nullptr));
  if (!thread) return context->result;
  argument.release();
  const std::array handles{shutdown, client, reviewer, thread.get()};
  const DWORD wait = WaitForMultipleObjects(static_cast<DWORD>(handles.size()), handles.data(),
                                             FALSE, remaining(deadline, frequency));
  if (wait == WAIT_OBJECT_0 + 2U) {
    if (remaining(deadline, frequency) == 0U) abort_stuck_worker();
    return {protocol::Status::reviewer_unavailable, {}, true};
  }
  if (wait != WAIT_OBJECT_0 + 3U) abort_stuck_worker();
  return context->result;
}

}
