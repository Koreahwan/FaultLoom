#include "scm_query.h"

namespace faultloom::broker {

BoundedQuery query_service_bounded(
    policy::Service, HANDLE, HANDLE, HANDLE, std::uint64_t, std::uint64_t) noexcept {
  TerminateProcess(GetCurrentProcess(), ERROR_ACCESS_DENIED);
  return {protocol::Status::action_failed, {}};
}

}
