#include "faultloom/protocol.h"

#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>

namespace faultloom::protocol {
namespace {

constexpr std::array<std::uint8_t, 4> kMagic{0x46U, 0x4cU, 0x4dU, 0x31U};
constexpr std::array<std::uint8_t, 32> kP256Order{
    0xffU, 0xffU, 0xffU, 0xffU, 0x00U, 0x00U, 0x00U, 0x00U,
    0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
    0xbcU, 0xe6U, 0xfaU, 0xadU, 0xa7U, 0x17U, 0x9eU, 0x84U,
    0xf3U, 0xb9U, 0xcaU, 0xc2U, 0xfcU, 0x63U, 0x25U, 0x51U};

std::uint16_t read16(std::span<const std::uint8_t> value, std::size_t offset) noexcept {
  return static_cast<std::uint16_t>(value[offset]) |
         static_cast<std::uint16_t>(value[offset + 1U] << 8U);
}

std::uint32_t read32(std::span<const std::uint8_t> value, std::size_t offset) noexcept {
  return static_cast<std::uint32_t>(value[offset]) |
         (static_cast<std::uint32_t>(value[offset + 1U]) << 8U) |
         (static_cast<std::uint32_t>(value[offset + 2U]) << 16U) |
         (static_cast<std::uint32_t>(value[offset + 3U]) << 24U);
}

void append16(std::vector<std::uint8_t>& value, std::uint16_t part) {
  value.push_back(static_cast<std::uint8_t>(part));
  value.push_back(static_cast<std::uint8_t>(part >> 8U));
}

void append32(std::vector<std::uint8_t>& value, std::uint32_t part) {
  append16(value, static_cast<std::uint16_t>(part));
  append16(value, static_cast<std::uint16_t>(part >> 16U));
}

bool zero(std::span<const std::uint8_t> value) noexcept {
  return std::all_of(value.begin(), value.end(), [](std::uint8_t byte) { return byte == 0U; });
}

bool valid_scalar(std::span<const std::uint8_t> value) noexcept {
  return value.size() == 32U && !zero(value) &&
         std::lexicographical_compare(value.begin(), value.end(), kP256Order.begin(), kP256Order.end());
}

bool valid_blob(std::span<const std::uint8_t> value) noexcept {
  if (value.size() != kPublicBlobBytes || read32(value, 0U) != 0x31534345U ||
      read32(value, 4U) != 32U || zero(value.subspan(8U, 32U)) || zero(value.subspan(40U, 32U))) return false;
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  BCRYPT_KEY_HANDLE key = nullptr;
  const NTSTATUS opened = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0U);
  const NTSTATUS imported = opened < 0 ? opened : BCryptImportKeyPair(
      algorithm, nullptr, BCRYPT_ECCPUBLIC_BLOB, &key, const_cast<PUCHAR>(value.data()),
      static_cast<ULONG>(value.size()), 0U);
  if (key != nullptr) BCryptDestroyKey(key);
  if (algorithm != nullptr) BCryptCloseAlgorithmProvider(algorithm, 0U);
  return opened >= 0 && imported >= 0;
}

bool valid_signature(std::span<const std::uint8_t> value) noexcept {
  return value.size() == kSignatureBytes && valid_scalar(value.first(32U)) && valid_scalar(value.last(32U));
}

bool valid_evidence(std::span<const std::uint8_t> body) noexcept {
  return !zero(body.first(32U)) && body[32U] == 1U && read16(body, 33U) == 0U &&
         valid_blob(body.subspan(35U, 72U)) && valid_signature(body.subspan(107U, 64U));
}

bool zero_evidence(std::span<const std::uint8_t> body, Status status) noexcept {
  return zero(body.first(32U)) && body[32U] == 0U && read16(body, 33U) == static_cast<std::uint16_t>(status) &&
         zero(body.subspan(35U, 72U)) && zero(body.subspan(107U, 64U));
}

bool valid_tuple(MessageType type, Status status) noexcept {
  switch (type) {
    case MessageType::client_request:
    case MessageType::review_request:
    case MessageType::review_decision:
      return status == Status::ok;
    case MessageType::broker_response:
      switch (status) {
        case Status::ok:
        case Status::malformed:
        case Status::unsupported_version:
        case Status::unauthorized_client:
        case Status::action_denied:
        case Status::reviewer_unavailable:
        case Status::review_signature_invalid:
        case Status::action_failed:
        case Status::timeout:
          return true;
      }
  }
  return false;
}

bool valid_client(const FrameView& frame) noexcept {
  if (frame.body.size() < 8U || frame.body.size() + kHeaderBytes > kMaxClientPayloadBytes) return false;
  switch (frame.header.action) {
    case Action::ping:
      return frame.body.size() == 8U;
    case Action::query_service_status:
      return frame.body.size() >= 10U && read16(frame.body, 8U) == frame.body.size() - 10U;
  }
  return false;
}

bool valid_decision(const FrameView& frame) noexcept {
  return frame.body.size() == 171U && valid_evidence(frame.body);
}

bool valid_response(const FrameView& frame) noexcept {
  if (frame.body.size() < 173U || read16(frame.body, 171U) != frame.body.size() - 173U) return false;
  const auto result = frame.body.subspan(173U);
  switch (frame.header.status) {
    case Status::ok:
      if (!valid_evidence(frame.body)) return false;
      return frame.header.action == Action::ping
                 ? result.size() == 4U && std::equal(result.begin(), result.end(), "PONG")
                 : result.size() == 36U;
    case Status::action_failed:
      return frame.header.action == Action::query_service_status && result.empty() && valid_evidence(frame.body);
    case Status::malformed:
    case Status::unsupported_version:
    case Status::unauthorized_client:
    case Status::reviewer_unavailable:
    case Status::review_signature_invalid:
    case Status::timeout:
      return result.empty() && zero_evidence(frame.body, frame.header.status);
    case Status::action_denied:
      return frame.header.action == Action::query_service_status && result.empty() &&
             zero_evidence(frame.body, frame.header.status);
  }
  return false;
}

}

std::uint16_t version() noexcept { return 1U; }

std::optional<ReviewEnvelope> review_envelope(const FrameView& frame) noexcept {
  if (frame.header.message_type != MessageType::review_request || frame.body.size() < 8U) return std::nullopt;
  const std::uint32_t pid = read32(frame.body, 0U);
  const std::size_t sid_size = read16(frame.body, 4U);
  if (pid == 0U || sid_size == 0U || sid_size > kMaxSidBytes || sid_size > frame.body.size() - 8U) return std::nullopt;
  const auto sid = frame.body.subspan(6U, sid_size);
  const PSID sid_pointer = const_cast<std::uint8_t*>(sid.data());
  if (!IsValidSid(sid_pointer) || GetLengthSid(sid_pointer) != sid_size) return std::nullopt;
  const std::size_t length_offset = 6U + sid_size;
  const std::size_t original_size = read16(frame.body, length_offset);
  if (original_size == 0U || original_size > kMaxClientPayloadBytes || original_size != frame.body.size() - length_offset - 2U) return std::nullopt;
  const auto original_payload = frame.body.subspan(length_offset + 2U, original_size);
  const auto decoded = decode_payload(original_payload);
  if (!decoded.frame.has_value() || decoded.frame->header.message_type != MessageType::client_request ||
      decoded.frame->header.request_id != frame.header.request_id || decoded.frame->header.action != frame.header.action) return std::nullopt;
  return ReviewEnvelope{pid, sid, original_payload, *decoded.frame};
}

DecodeResult decode_payload(std::span<const std::uint8_t> payload) noexcept {
  if (payload.size() < kHeaderBytes || payload.size() > kMaxPayloadBytes ||
      !std::equal(kMagic.begin(), kMagic.end(), payload.begin())) return {DecodeError::malformed, std::nullopt};
  if (read16(payload, 4U) != 1U) return {DecodeError::unsupported_version, std::nullopt};
  const auto type_raw = read16(payload, 6U);
  if (type_raw < 1U || type_raw > 4U) return {DecodeError::malformed, std::nullopt};
  RequestId request_id{};
  std::copy_n(payload.begin() + 8U, request_id.size(), request_id.begin());
  if (zero(request_id)) return {DecodeError::malformed, std::nullopt};
  const auto action_raw = read16(payload, 24U);
  if (action_raw < 1U || action_raw > 2U) return {DecodeError::unknown_action, std::nullopt};
  const auto status_raw = read16(payload, 26U);
  if (status_raw > 8U || read32(payload, 28U) != payload.size() - kHeaderBytes || read32(payload, 32U) != 0U) return {DecodeError::malformed, std::nullopt};
  const Header header{static_cast<MessageType>(type_raw), request_id, static_cast<Action>(action_raw), static_cast<Status>(status_raw)};
  const FrameView frame{header, payload.subspan(kHeaderBytes)};
  if (!valid_tuple(header.message_type, header.status)) return {DecodeError::malformed, std::nullopt};
  bool valid = false;
  switch (header.message_type) {
    case MessageType::client_request: valid = valid_client(frame); break;
    case MessageType::review_request: valid = review_envelope(frame).has_value(); break;
    case MessageType::review_decision: valid = valid_decision(frame); break;
    case MessageType::broker_response: valid = valid_response(frame); break;
  }
  return valid ? DecodeResult{DecodeError::none, frame} : DecodeResult{DecodeError::malformed, std::nullopt};
}

DecodeResult decode_record(std::span<const std::uint8_t> record) noexcept {
  if (record.size() < 4U) return {DecodeError::malformed, std::nullopt};
  const std::size_t payload_size = read32(record, 0U);
  if (payload_size == 0U || payload_size > kMaxPayloadBytes || payload_size != record.size() - 4U) return {DecodeError::malformed, std::nullopt};
  return decode_payload(record.subspan(4U));
}

std::optional<std::vector<std::uint8_t>> encode_payload(const FrameView& frame) {
  if (frame.body.size() > kMaxBodyBytes) return std::nullopt;
  std::vector<std::uint8_t> result;
  result.reserve(kHeaderBytes + frame.body.size());
  result.insert(result.end(), kMagic.begin(), kMagic.end());
  append16(result, 1U);
  append16(result, static_cast<std::uint16_t>(frame.header.message_type));
  result.insert(result.end(), frame.header.request_id.begin(), frame.header.request_id.end());
  append16(result, static_cast<std::uint16_t>(frame.header.action));
  append16(result, static_cast<std::uint16_t>(frame.header.status));
  append32(result, static_cast<std::uint32_t>(frame.body.size()));
  append32(result, 0U);
  result.insert(result.end(), frame.body.begin(), frame.body.end());
  return decode_payload(result).error == DecodeError::none ? std::optional<std::vector<std::uint8_t>>(std::move(result)) : std::nullopt;
}

std::optional<std::vector<std::uint8_t>> encode_record(std::span<const std::uint8_t> payload) {
  if (payload.empty() || payload.size() > kMaxPayloadBytes || decode_payload(payload).error != DecodeError::none) return std::nullopt;
  std::vector<std::uint8_t> result;
  result.reserve(4U + payload.size());
  append32(result, static_cast<std::uint32_t>(payload.size()));
  result.insert(result.end(), payload.begin(), payload.end());
  return result;
}

}
