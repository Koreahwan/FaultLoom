#pragma once

#include "faultloom/protocol.h"

#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

namespace faultloom::policy {

enum class Service : std::uint8_t {
  none,
  bfe,
  event_log,
  win_defend,
};

struct DeadlineWindow {
  std::uint64_t now_qpc;
  std::uint64_t frequency;
};

struct AuthorizedRequest {
  protocol::Action action;
  Service service;
  std::uint64_t deadline_qpc;
};

struct PolicyResult {
  protocol::Status status;
  std::optional<AuthorizedRequest> request;
};

[[nodiscard]] std::span<const std::string_view> allowed_services() noexcept;
[[nodiscard]] PolicyResult parse_client_request(const protocol::FrameView& frame,
                                                DeadlineWindow timing) noexcept;
[[nodiscard]] PolicyResult parse_review_request(const protocol::FrameView& frame,
                                                DeadlineWindow timing) noexcept;

}
