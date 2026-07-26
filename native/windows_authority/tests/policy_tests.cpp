#include "faultloom/policy.h"
#include "faultloom/protocol.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <optional>
#include <string_view>
#include <vector>

namespace {

constexpr std::string_view kPing = "464c4d31010001000102030405060708090a0b0c0d0e0f10010000000800000000000000e803000000000000";
constexpr std::string_view kBfe = "464c4d31010001000102030405060708090a0b0c0d0e0f10020000000d00000000000000e8030000000000000300424645";
constexpr std::string_view kEventLog = "464c4d31010001000102030405060708090a0b0c0d0e0f10020000001200000000000000e80300000000000008004576656e744c6f67";
constexpr std::string_view kWinDefend = "464c4d31010001000102030405060708090a0b0c0d0e0f10020000001300000000000000e803000000000000090057696e446566656e64";
constexpr std::string_view kSpooler = "464c4d31010001000102030405060708090a0b0c0d0e0f10020000001100000000000000e803000000000000070053706f6f6c6572";
constexpr std::string_view kReview = "464c4d31010002000102030405060708090a0b0c0d0e0f10010000004000000000000000785634120c000101000000000005120000002c00464c4d31010001000102030405060708090a0b0c0d0e0f10010000000800000000000000e803000000000000";

std::vector<std::uint8_t> bytes(std::string_view hex) {
  std::vector<std::uint8_t> result;
  result.reserve(hex.size() / 2U);
  for (std::size_t index = 0; index < hex.size(); index += 2U) {
    const auto digit = [](char value) -> std::uint8_t { return static_cast<std::uint8_t>(value <= '9' ? value - '0' : value - 'a' + 10); };
    result.push_back(static_cast<std::uint8_t>((digit(hex[index]) << 4U) | digit(hex[index + 1U])));
  }
  return result;
}

bool expect(bool condition, std::string_view message) {
  if (!condition) std::cerr << message << '\n';
  return condition;
}

faultloom::policy::PolicyResult parse_direct(faultloom::protocol::Action action,
                                             std::span<const std::uint8_t> body,
                                             faultloom::policy::DeadlineWindow timing,
                                             std::uint32_t& action_counter) {
  faultloom::protocol::RequestId request_id{};
  request_id[0] = 1U;
  const faultloom::protocol::FrameView frame{
      {faultloom::protocol::MessageType::client_request, request_id, action,
       faultloom::protocol::Status::ok},
      body};
  const auto result = faultloom::policy::parse_client_request(frame, timing);
  if (result.request.has_value()) ++action_counter;
  return result;
}

std::optional<faultloom::protocol::Status> route(std::span<const std::uint8_t> payload,
                                                 faultloom::policy::DeadlineWindow timing,
                                                 std::uint32_t& action_counter) {
  const auto decoded = faultloom::protocol::decode_payload(payload);
  if (!decoded.frame.has_value()) {
    if (decoded.error == faultloom::protocol::DecodeError::unknown_action) return std::nullopt;
    return decoded.error == faultloom::protocol::DecodeError::unsupported_version
               ? faultloom::protocol::Status::unsupported_version
               : faultloom::protocol::Status::malformed;
  }
  const auto result = faultloom::policy::parse_client_request(*decoded.frame, timing);
  if (result.request.has_value()) ++action_counter;
  return result.status;
}

}

int main() {
  // Given: the exact compile-time action/service table and a one-second future deadline.
  bool passed = true;
  const faultloom::policy::DeadlineWindow timing{900U, 100U};
  const std::array allowed{
      std::pair{kPing, faultloom::policy::Service::none},
      std::pair{kBfe, faultloom::policy::Service::bfe},
      std::pair{kEventLog, faultloom::policy::Service::event_log},
      std::pair{kWinDefend, faultloom::policy::Service::win_defend},
  };

  // When: each exact row is parsed and every denial is routed through the same zero-action seam.
  std::uint32_t allowed_actions = 0U;
  for (const auto& [golden, expected_service] : allowed) {
    const auto payload = bytes(golden);
    const auto decoded = faultloom::protocol::decode_payload(payload);
    passed &= expect(decoded.frame.has_value(), "allowlisted payload did not decode");
    if (decoded.frame.has_value()) {
      const auto result = faultloom::policy::parse_client_request(*decoded.frame, timing);
      passed &= expect(result.status == faultloom::protocol::Status::ok && result.request.has_value(), "allowlisted request denied");
      if (result.request.has_value()) {
        passed &= expect(result.request->service == expected_service && result.request->deadline_qpc == 1000U, "authorized fields changed");
        ++allowed_actions;
      }
    }
  }
  const auto review_payload = bytes(kReview);
  const auto review = faultloom::protocol::decode_payload(review_payload);
  passed &= expect(review.frame.has_value(), "review wrapper did not decode");
  if (review.frame.has_value()) {
    const auto result = faultloom::policy::parse_review_request(*review.frame, timing);
    passed &= expect(result.status == faultloom::protocol::Status::ok && result.request.has_value(), "independent review policy denied PING");
  }

  // Then: bad names, deadlines, fields, caps, duplicates, and unknown actions never reach the mock action counter.
  std::uint32_t denied_actions = 0U;
  passed &= expect(route(bytes(kSpooler), timing, denied_actions) == faultloom::protocol::Status::action_denied, "bad service status mismatch");
  auto value = bytes(kBfe); value[46] = 0xffU;
  passed &= expect(route(value, timing, denied_actions) == faultloom::protocol::Status::action_denied, "non-ASCII service status mismatch");
  value = bytes(kPing); std::fill(value.begin() + 36, value.end(), std::uint8_t{0});
  passed &= expect(route(value, timing, denied_actions) == faultloom::protocol::Status::malformed, "zero deadline status mismatch");
  value = bytes(kPing); value[36] = 0x84U; value[37] = 0x03U;
  passed &= expect(route(value, timing, denied_actions) == faultloom::protocol::Status::malformed, "past deadline status mismatch");
  value = bytes(kPing); value[36] = 0x79U; value[37] = 0x05U;
  passed &= expect(route(value, timing, denied_actions) == faultloom::protocol::Status::malformed, "far deadline status mismatch");
  std::uint32_t boundary_actions = 0U;
  value = bytes(kPing); value[36] = 0x78U; value[37] = 0x05U;
  passed &= expect(route(value, timing, boundary_actions) == faultloom::protocol::Status::ok && boundary_actions == 1U, "five-second deadline boundary denied");
  passed &= expect(route(bytes(kPing), {900U, 0U}, denied_actions) == faultloom::protocol::Status::malformed, "zero QPC frequency accepted");
  passed &= expect(route(bytes(kPing), {900U, UINT64_MAX}, denied_actions) == faultloom::protocol::Status::malformed, "QPC multiplication overflow accepted");
  value = bytes(kPing); value[32] = 1U;
  passed &= expect(route(value, timing, denied_actions) == faultloom::protocol::Status::malformed, "reserved field status mismatch");
  value = bytes(kPing); value.push_back(0U);
  passed &= expect(route(value, timing, denied_actions) == faultloom::protocol::Status::malformed, "trailing byte status mismatch");
  value = bytes(kPing); value[24] = 3U;
  passed &= expect(!route(value, timing, denied_actions).has_value(), "unknown action produced a response status");
  value.assign(faultloom::protocol::kMaxPayloadBytes + 1U, 0U);
  passed &= expect(route(value, timing, denied_actions) == faultloom::protocol::Status::malformed, "oversized payload status mismatch");

  // Given: public callers may construct FrameView without passing through the codec.
  const std::array<std::uint8_t, 9> long_ping{0xe8U, 0x03U, 0U, 0U, 0U, 0U, 0U, 0U, 0U};
  const std::array<std::uint8_t, 8> short_query_8{0xe8U, 0x03U};
  const std::array<std::uint8_t, 9> short_query_9{0xe8U, 0x03U};
  const std::array<std::uint8_t, 13> false_query_length{
      0xe8U, 0x03U, 0U, 0U, 0U, 0U, 0U, 0U, 2U, 0U, 'B', 'F', 'E'};
  const std::array<std::uint8_t, 14> trailing_query{
      0xe8U, 0x03U, 0U, 0U, 0U, 0U, 0U, 0U, 3U, 0U, 'B', 'F', 'E', 'X'};
  const std::array<std::uint8_t, 17> denied_query{
      0xe8U, 0x03U, 0U, 0U, 0U, 0U, 0U, 0U, 7U, 0U, 'S', 'p', 'o', 'o', 'l', 'e', 'r'};
  passed &= expect(parse_direct(faultloom::protocol::Action::ping, long_ping, timing, denied_actions).status ==
                       faultloom::protocol::Status::malformed,
                   "public policy accepted 9-byte PING body");
  passed &= expect(parse_direct(faultloom::protocol::Action::query_service_status, short_query_8, timing, denied_actions).status ==
                       faultloom::protocol::Status::malformed,
                   "public policy misclassified 8-byte QUERY body");
  passed &= expect(parse_direct(faultloom::protocol::Action::query_service_status, short_query_9, timing, denied_actions).status ==
                       faultloom::protocol::Status::malformed,
                   "public policy misclassified 9-byte QUERY body");
  passed &= expect(parse_direct(faultloom::protocol::Action::query_service_status, false_query_length, timing, denied_actions).status ==
                       faultloom::protocol::Status::malformed,
                   "public policy ignored QUERY name length");
  passed &= expect(parse_direct(faultloom::protocol::Action::query_service_status, trailing_query, timing, denied_actions).status ==
                       faultloom::protocol::Status::malformed,
                   "public policy misclassified trailing QUERY byte");
  passed &= expect(parse_direct(faultloom::protocol::Action::query_service_status, denied_query, timing, denied_actions).status ==
                       faultloom::protocol::Status::action_denied,
                   "well-formed nonallowlisted QUERY status mismatch");
  passed &= expect(allowed_actions == 4U, "allowlisted mock action count mismatch");
  passed &= expect(denied_actions == 0U, "negative input reached mock action");
  passed &= expect(faultloom::policy::allowed_services().size() == 3U, "compile-time policy row count changed");
  std::cout << "POLICY_ROWS=3 ALLOWED_ACTIONS=4 NEGATIVE_ACTION_COUNTER=" << denied_actions << '\n';
  return passed ? 0 : 1;
}
