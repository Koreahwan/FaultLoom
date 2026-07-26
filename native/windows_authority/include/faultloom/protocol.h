#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace faultloom::protocol {

inline constexpr std::size_t kHeaderBytes = 36U;
inline constexpr std::size_t kMaxPayloadBytes = 8192U;
inline constexpr std::size_t kMaxRecordBytes = 8196U;
inline constexpr std::size_t kMaxBodyBytes = 8156U;
inline constexpr std::size_t kMaxClientPayloadBytes = 8080U;
inline constexpr std::size_t kMaxSidBytes = 68U;
inline constexpr std::size_t kPublicBlobBytes = 72U;
inline constexpr std::size_t kSignatureBytes = 64U;
inline constexpr std::size_t kApplicationDecoderAllocationLimitBytes = kMaxPayloadBytes;

enum class MessageType : std::uint16_t {
  client_request = 1U,
  review_request = 2U,
  review_decision = 3U,
  broker_response = 4U,
};

enum class Action : std::uint16_t {
  ping = 1U,
  query_service_status = 2U,
};

enum class Status : std::uint16_t {
  ok = 0U,
  malformed = 1U,
  unsupported_version = 2U,
  unauthorized_client = 3U,
  action_denied = 4U,
  reviewer_unavailable = 5U,
  review_signature_invalid = 6U,
  action_failed = 7U,
  timeout = 8U,
};

enum class DecodeError : std::uint8_t {
  none,
  malformed,
  unsupported_version,
  unknown_action,
};

using RequestId = std::array<std::uint8_t, 16>;
using Hash = std::array<std::uint8_t, 32>;

struct Header {
  MessageType message_type;
  RequestId request_id;
  Action action;
  Status status;
};

struct FrameView {
  Header header;
  std::span<const std::uint8_t> body;
};

struct DecodeResult {
  DecodeError error;
  std::optional<FrameView> frame;
};

struct ReviewEnvelope {
  std::uint32_t client_pid;
  std::span<const std::uint8_t> sid;
  std::span<const std::uint8_t> original_payload;
  FrameView original;
};

[[nodiscard]] std::uint16_t version() noexcept;
[[nodiscard]] DecodeResult decode_payload(std::span<const std::uint8_t> payload) noexcept;
[[nodiscard]] DecodeResult decode_record(std::span<const std::uint8_t> record) noexcept;
[[nodiscard]] std::optional<std::vector<std::uint8_t>> encode_payload(const FrameView& frame);
[[nodiscard]] std::optional<std::vector<std::uint8_t>> encode_record(std::span<const std::uint8_t> payload);
[[nodiscard]] std::optional<ReviewEnvelope> review_envelope(const FrameView& frame) noexcept;
[[nodiscard]] std::optional<Hash> sha256(std::span<const std::uint8_t> input) noexcept;
[[nodiscard]] std::optional<Hash> signature_digest(std::span<const std::uint8_t> review_payload,
                                                   std::uint8_t decision,
                                                   Status reason) noexcept;

}
