#include "reviewer_runtime.h"

#include "faultloom/policy.h"
#include "reviewer_identity.h"
#include "reviewer_decision.h"
#include "reviewer_io.h"
#include "reviewer_ready.h"
#include "unique_handle.h"

#include <algorithm>
#include <array>
#include <string>

namespace faultloom::reviewer {
namespace {

std::uint32_t read32(std::span<const std::uint8_t> value) noexcept {
  return static_cast<std::uint32_t>(value[0]) |
         (static_cast<std::uint32_t>(value[1]) << 8U) |
         (static_cast<std::uint32_t>(value[2]) << 16U) |
         (static_cast<std::uint32_t>(value[3]) << 24U);
}

}

int run(Options options, std::unique_ptr<signing::Signer> signer) noexcept {
  UniqueHandle ready_handle(options.ready_handle);
  UniqueHandle shutdown_event(options.shutdown_event);
  if (signer == nullptr) return 2;
  auto broker = retain_broker(options.expected_broker_pid);
  if (!broker.has_value()) return 3;
  auto pipe = create_reviewer_pipe(options.session, broker->sid);
  if (!pipe.has_value()) return 4;
  const IoResult readiness = report_ready(ready_handle.get(), shutdown_event.get(),
                                          broker->process.get(), signer->public_blob());
  if (readiness == IoResult::stopped) return 0;
  if (readiness != IoResult::complete) return 4;
  ready_handle.reset();
  LARGE_INTEGER frequency_value{};
  if (!QueryPerformanceFrequency(&frequency_value) || frequency_value.QuadPart <= 0) return 5;
  const std::uint64_t frequency = static_cast<std::uint64_t>(frequency_value.QuadPart);
  while (true) {
    const IoResult connected = connect_client(pipe->get(), shutdown_event.get(), broker->process.get());
    if (connected == IoResult::stopped) return 0;
    if (connected != IoResult::complete) return 6;
    ULONG client_pid = 0U;
    bool approved = check_gate(shutdown_event.get(), broker->process.get(), 0U, 0U) == IoResult::complete &&
                    GetNamedPipeClientProcessId(pipe->get(), &client_pid) &&
                    client_pid == options.expected_broker_pid &&
                    check_gate(shutdown_event.get(), broker->process.get(), 0U, 0U) == IoResult::complete;
    LARGE_INTEGER accepted{};
    approved = approved && QueryPerformanceCounter(&accepted) != FALSE;
    const std::uint64_t watchdog = static_cast<std::uint64_t>(accepted.QuadPart) + frequency * 5U;
    approved = approved && check_gate(shutdown_event.get(), broker->process.get(), watchdog,
                                      frequency) == IoResult::complete;
    std::array<std::uint8_t, protocol::kMaxRecordBytes> record{};
    if (approved) {
      approved = read_exact(pipe->get(), std::span(record).first(4U), shutdown_event.get(),
                            broker->process.get(), watchdog, frequency) == IoResult::complete;
    }
    const std::size_t payload_size = approved ? read32(record) : 0U;
    if (approved) {
      approved = payload_size >= 1U && payload_size <= protocol::kMaxPayloadBytes &&
                 read_exact(pipe->get(), std::span(record).subspan(4U, payload_size), shutdown_event.get(),
                            broker->process.get(), watchdog, frequency) == IoResult::complete;
    }
    DWORD extra = 0U;
    if (approved) {
      approved = check_gate(shutdown_event.get(), broker->process.get(), watchdog, frequency) ==
                     IoResult::complete &&
                 PeekNamedPipe(pipe->get(), nullptr, 0U, nullptr, &extra, nullptr) && extra == 0U &&
                 check_gate(shutdown_event.get(), broker->process.get(), watchdog, frequency) ==
                     IoResult::complete;
    }
    const auto payload = std::span(record).subspan(4U, payload_size);
    const auto decoded = approved ? protocol::decode_payload(payload) : protocol::DecodeResult{};
    const auto envelope = decoded.frame.has_value() ? protocol::review_envelope(*decoded.frame) : std::nullopt;
    approved = approved && envelope.has_value() && envelope->sid.size() == broker->sid.size() &&
               std::equal(envelope->sid.begin(), envelope->sid.end(), broker->sid.begin(), broker->sid.end());
    LARGE_INTEGER now{};
    approved = approved && QueryPerformanceCounter(&now) != FALSE;
    const policy::PolicyResult policy_result = approved
        ? policy::parse_review_request(*decoded.frame, {static_cast<std::uint64_t>(now.QuadPart), frequency})
        : policy::PolicyResult{protocol::Status::malformed, std::nullopt};
    approved = approved && policy_result.status == protocol::Status::ok && policy_result.request.has_value();
    if (approved) {
      const std::uint64_t deadline = std::min(watchdog, policy_result.request->deadline_qpc);
      approved = check_gate(shutdown_event.get(), broker->process.get(), deadline, frequency) ==
                 IoResult::complete;
      const DecisionGate gate{shutdown_event.get(), broker->process.get(), deadline, frequency};
      const auto response = approved ? make_decision(*decoded.frame, payload, *signer, gate)
                                     : std::nullopt;
      approved = response.has_value() &&
                 check_gate(shutdown_event.get(), broker->process.get(), deadline, frequency) ==
                     IoResult::complete &&
                 write_exact(pipe->get(), *response, shutdown_event.get(), broker->process.get(), deadline,
                             frequency) == IoResult::complete &&
                 await_client_close(pipe->get(), shutdown_event.get(), broker->process.get(), deadline,
                                    frequency) == IoResult::complete;
    }
    DisconnectNamedPipe(pipe->get());
    if (!approved && (WaitForSingleObject(shutdown_event.get(), 0U) == WAIT_OBJECT_0 ||
                      WaitForSingleObject(broker->process.get(), 0U) == WAIT_OBJECT_0)) {
      return 0;
    }
  }
}

}
