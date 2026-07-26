#pragma once

#include "faultloom/policy.h"

#include <windows.h>
#include <winsvc.h>

#include <array>
#include <cstdint>
#include <memory>
#include <optional>

namespace faultloom::broker {

using ServiceBytes = std::array<std::uint8_t, 36>;

class ScmApi {
 public:
  virtual ~ScmApi() = default;
  [[nodiscard]] virtual SC_HANDLE open_manager(DWORD access) noexcept = 0;
  [[nodiscard]] virtual SC_HANDLE open_service(SC_HANDLE manager, const wchar_t* name,
                                                DWORD access) noexcept = 0;
  [[nodiscard]] virtual bool query(SC_HANDLE service, SERVICE_STATUS_PROCESS& status,
                                   DWORD& error) noexcept = 0;
  virtual void close(SC_HANDLE handle) noexcept = 0;
};

[[nodiscard]] std::optional<ServiceBytes> query_service_exact(
    ScmApi& api, policy::Service service, DWORD& error) noexcept;

struct BoundedQuery {
  protocol::Status status;
  ServiceBytes bytes;
  bool must_terminate = false;
};

[[nodiscard]] BoundedQuery query_service_bounded(
    policy::Service service, HANDLE shutdown, HANDLE client, HANDLE reviewer,
    std::uint64_t deadline, std::uint64_t frequency) noexcept;
[[nodiscard]] BoundedQuery query_service_bounded_with_api(
    std::shared_ptr<ScmApi> api, policy::Service service, HANDLE shutdown, HANDLE client,
    HANDLE reviewer,
    std::uint64_t deadline, std::uint64_t frequency) noexcept;

}
