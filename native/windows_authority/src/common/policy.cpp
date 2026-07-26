#include "faultloom/policy.h"

#include <array>
#include <limits>

namespace faultloom::policy {
namespace {

constexpr std::array<std::string_view, 3> kServices{"BFE", "EventLog", "WinDefend"};

std::uint64_t read64(std::span<const std::uint8_t> value) noexcept {
  std::uint64_t result = 0U;
  for (std::size_t index = 0U; index < 8U; ++index) result |= static_cast<std::uint64_t>(value[index]) << (index * 8U);
  return result;
}

std::uint16_t read16(std::span<const std::uint8_t> value, std::size_t offset) noexcept {
  return static_cast<std::uint16_t>(value[offset]) |
         static_cast<std::uint16_t>(value[offset + 1U] << 8U);
}

std::optional<Service> service(std::span<const std::uint8_t> name) noexcept {
  for (const auto byte : name) {
    if (byte > 0x7fU) return std::nullopt;
  }
  if (std::equal(name.begin(), name.end(), kServices[0].begin(), kServices[0].end())) return Service::bfe;
  if (std::equal(name.begin(), name.end(), kServices[1].begin(), kServices[1].end())) return Service::event_log;
  if (std::equal(name.begin(), name.end(), kServices[2].begin(), kServices[2].end())) return Service::win_defend;
  return std::nullopt;
}

PolicyResult denied(protocol::Status status) noexcept { return {status, std::nullopt}; }

}

std::span<const std::string_view> allowed_services() noexcept { return kServices; }

PolicyResult parse_client_request(const protocol::FrameView& frame, DeadlineWindow timing) noexcept {
  if (frame.header.message_type != protocol::MessageType::client_request || frame.header.status != protocol::Status::ok ||
      frame.body.size() < 8U || timing.frequency == 0U || timing.frequency > std::numeric_limits<std::uint64_t>::max() / 5U) {
    return denied(protocol::Status::malformed);
  }
  switch (frame.header.action) {
    case protocol::Action::ping:
      if (frame.body.size() != 8U) return denied(protocol::Status::malformed);
      break;
    case protocol::Action::query_service_status:
      if (frame.body.size() < 10U || read16(frame.body, 8U) != frame.body.size() - 10U) {
        return denied(protocol::Status::malformed);
      }
      break;
  }
  const std::uint64_t deadline = read64(frame.body);
  if (deadline <= timing.now_qpc || deadline - timing.now_qpc > timing.frequency * 5U) return denied(protocol::Status::malformed);
  switch (frame.header.action) {
    case protocol::Action::ping:
      return {protocol::Status::ok, AuthorizedRequest{frame.header.action, Service::none, deadline}};
    case protocol::Action::query_service_status: {
      const auto selected = service(frame.body.subspan(10U));
      return selected.has_value()
                 ? PolicyResult{protocol::Status::ok, AuthorizedRequest{frame.header.action, *selected, deadline}}
                 : denied(protocol::Status::action_denied);
    }
  }
  return denied(protocol::Status::malformed);
}

PolicyResult parse_review_request(const protocol::FrameView& frame, DeadlineWindow timing) noexcept {
  const auto envelope = protocol::review_envelope(frame);
  return envelope.has_value() ? parse_client_request(envelope->original, timing) : denied(protocol::Status::malformed);
}

}
