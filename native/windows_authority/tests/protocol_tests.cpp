#include "faultloom/protocol.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace {

using faultloom::protocol::DecodeError;

struct Golden {
  std::string_view name;
  std::string_view hex;
  std::string_view sha256;
};

constexpr std::string_view kPing = "464c4d31010001000102030405060708090a0b0c0d0e0f10010000000800000000000000e803000000000000";
constexpr std::string_view kService = "464c4d31010001000102030405060708090a0b0c0d0e0f10020000001200000000000000e80300000000000008004576656e744c6f67";
constexpr std::string_view kReview = "464c4d31010002000102030405060708090a0b0c0d0e0f10010000004000000000000000785634120c000101000000000005120000002c00464c4d31010001000102030405060708090a0b0c0d0e0f10010000000800000000000000e803000000000000";
constexpr std::string_view kReviewService = "464c4d31010002000102030405060708090a0b0c0d0e0f10020000004a00000000000000785634120c000101000000000005120000003600464c4d31010001000102030405060708090a0b0c0d0e0f10020000001200000000000000e80300000000000008004576656e744c6f67";
constexpr std::string_view kDecision = "464c4d31010003000102030405060708090a0b0c0d0e0f1001000000ab0000000000000091f6f29c22714c6fe36ede4cb64b630f3ec03321adc01b48607c7cebc2da488701000045435331200000006b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f500000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002";
constexpr std::string_view kResponsePing = "464c4d31010004000102030405060708090a0b0c0d0e0f1001000000b10000000000000091f6f29c22714c6fe36ede4cb64b630f3ec03321adc01b48607c7cebc2da488701000045435331200000006b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000020400504f4e47";
constexpr std::string_view kResponseService = "464c4d31010004000102030405060708090a0b0c0d0e0f1002000000d1000000000000009323b436b0c16e9761bd4ed0809cb4ca6beaf4ca8d4cbc312333a66f499835d401000045435331200000006b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000022400010000000200000003000000040000000500000006000000070000000800000009000000";
constexpr std::string_view kResponseFailed = "464c4d31010004000102030405060708090a0b0c0d0e0f1002000700ad000000000000009323b436b0c16e9761bd4ed0809cb4ca6beaf4ca8d4cbc312333a66f499835d401000045435331200000006b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000020000";
constexpr std::string_view kDenied = "464c4d31010004000102030405060708090a0b0c0d0e0f1002000400ad000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
constexpr std::string_view kMalformed = "464c4d31010004000102030405060708090a0b0c0d0e0f1001000100ad000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
constexpr std::string_view kUnsupported = "464c4d31010004000102030405060708090a0b0c0d0e0f1001000200ad000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
constexpr std::string_view kUnauthorized = "464c4d31010004000102030405060708090a0b0c0d0e0f1001000300ad000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
constexpr std::string_view kUnavailable = "464c4d31010004000102030405060708090a0b0c0d0e0f1001000500ad000000000000000000000000000000000000000000000000000000000000000000000000000000000500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
constexpr std::string_view kBadSignature = "464c4d31010004000102030405060708090a0b0c0d0e0f1001000600ad000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
constexpr std::string_view kTimeout = "464c4d31010004000102030405060708090a0b0c0d0e0f1001000800ad000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

constexpr std::array<Golden, 15> kGoldens{{
    {"ping", kPing, "d2dd6d000575822ec93d6687cc6d9fb517c9b07b1c9b076a7e1707ac051085fc"},
    {"service", kService, "d263997e4ee134691472d08276ab042d0396cc379ba5bfae327c1e74e6c7328e"},
    {"review", kReview, "91f6f29c22714c6fe36ede4cb64b630f3ec03321adc01b48607c7cebc2da4887"},
    {"review_service", kReviewService, "9323b436b0c16e9761bd4ed0809cb4ca6beaf4ca8d4cbc312333a66f499835d4"},
    {"decision", kDecision, "d6082daf8fed68a391e61e7bbe2e3a5221a6234f667adb59bfa4549c35c3c199"},
    {"response_ping", kResponsePing, "d06599c19c840dae872e0eb7e0dffb32cd5bce3d312a80cf83df77eb5f4ea539"},
    {"response_service", kResponseService, "dd00e6fc05cd19f4217b0e0b37a6d7de9b49f1b66153fe7fccc8e0d0e45ef266"},
    {"response_failed", kResponseFailed, "24cbac260c5d42b349907864f70b5cdf982240eb7365f67786a058bb4ae16854"},
    {"denied", kDenied, "b4566aac483cc4722546851e2a0e27eeac86a434b797ec3e7dff1c65c44506f4"},
    {"malformed", kMalformed, "f116f8aa485cf69bcb7303335d3d29fde98829f03052638d3e2226a65b42da84"},
    {"unsupported", kUnsupported, "608b26c69ca4a0537ab48c9410cf6db120ed4eb9c76632638176a227735002d6"},
    {"unauthorized", kUnauthorized, "52019921cd0d7e3c73ce124f806745cc29c3054f7caf0d03dd626ac6e3d035e8"},
    {"unavailable", kUnavailable, "d24a04aa270c08841f64805d60cf505fe9927a8052130b0958d1186b68a51ea6"},
    {"bad_signature", kBadSignature, "990d8d9a2b51535d53b7aa50f3bae595417ce9a2a872ffeee398ba6cfbcabfba"},
    {"timeout", kTimeout, "d5f46ccbc1456e85cfa163fdfca1d3de88866651b5342a4c46a3da7a3f3470f6"},
}};

std::vector<std::uint8_t> bytes(std::string_view hex) {
  std::vector<std::uint8_t> result;
  result.reserve(hex.size() / 2U);
  for (std::size_t index = 0; index < hex.size(); index += 2U) {
    const auto digit = [](char value) -> std::uint8_t { return static_cast<std::uint8_t>(value <= '9' ? value - '0' : value - 'a' + 10); };
    result.push_back(static_cast<std::uint8_t>((digit(hex[index]) << 4U) | digit(hex[index + 1U])));
  }
  return result;
}

std::string hex(const faultloom::protocol::Hash& value) {
  constexpr char digits[] = "0123456789abcdef";
  std::string result(value.size() * 2U, '0');
  for (std::size_t index = 0; index < value.size(); ++index) {
    result[index * 2U] = digits[value[index] >> 4U];
    result[index * 2U + 1U] = digits[value[index] & 15U];
  }
  return result;
}

bool expect(bool condition, std::string_view message) {
  if (!condition) std::cerr << message << '\n';
  return condition;
}

bool rejected(std::vector<std::uint8_t> value, DecodeError expected, std::string_view name) {
  const auto result = faultloom::protocol::decode_payload(value);
  return expect(result.error == expected && !result.frame.has_value(), name);
}

void put16(std::vector<std::uint8_t>& value, std::size_t offset, std::uint16_t field) {
  value[offset] = static_cast<std::uint8_t>(field);
  value[offset + 1U] = static_cast<std::uint8_t>(field >> 8U);
}

std::vector<std::uint8_t> response_for(faultloom::protocol::Action action,
                                       faultloom::protocol::Status status) {
  if (status == faultloom::protocol::Status::ok) {
    return bytes(action == faultloom::protocol::Action::ping ? kResponsePing : kResponseService);
  }
  if (status == faultloom::protocol::Status::action_failed) {
    auto result = bytes(kResponseFailed);
    put16(result, 24U, static_cast<std::uint16_t>(action));
    return result;
  }
  auto result = bytes(kMalformed);
  put16(result, 24U, static_cast<std::uint16_t>(action));
  put16(result, 26U, static_cast<std::uint16_t>(status));
  put16(result, 69U, static_cast<std::uint16_t>(status));
  return result;
}

}

int main() {
  // Given: literal payloads and independently checked-in SHA-256 values for every frozen outcome.
  bool passed = expect(faultloom::protocol::version() == 1U, "protocol version mismatch");
  std::size_t truncations = 0U;

  // When: every payload and transport record is decoded, encoded, hashed, and truncated at every byte.
  for (const auto& golden : kGoldens) {
    const auto raw = bytes(golden.hex);
    const auto decoded = faultloom::protocol::decode_payload(raw);
    passed &= expect(decoded.error == DecodeError::none && decoded.frame.has_value(), golden.name);
    for (std::size_t cut = 0U; cut < raw.size(); ++cut) {
      passed &= expect(faultloom::protocol::decode_payload(std::span(raw.data(), cut)).error != DecodeError::none, "truncated payload accepted");
      ++truncations;
    }
    if (decoded.frame.has_value()) {
      const auto encoded = faultloom::protocol::encode_payload(*decoded.frame);
      passed &= expect(encoded.has_value() && *encoded == raw, "payload round-trip mismatch");
    }
    const auto digest = faultloom::protocol::sha256(raw);
    passed &= expect(digest.has_value() && hex(*digest) == golden.sha256, "golden SHA-256 mismatch");
    const auto record = faultloom::protocol::encode_record(raw);
    passed &= expect(record.has_value(), "record encode failed");
    if (record.has_value()) {
      passed &= expect(faultloom::protocol::decode_record(*record).error == DecodeError::none, "record decode failed");
      for (std::size_t cut = 0U; cut < record->size(); ++cut) {
        const std::span<const std::uint8_t> prefix(record->data(), cut);
        passed &= expect(faultloom::protocol::decode_record(prefix).error != DecodeError::none, "truncated record accepted");
        ++truncations;
      }
      auto duplicate = *record;
      duplicate.insert(duplicate.end(), record->begin(), record->end());
      passed &= expect(faultloom::protocol::decode_record(duplicate).error == DecodeError::malformed, "duplicate record accepted");
    }
  }

  // Then: every header/body field, illegal tuple, scalar, cap, overflow, and trailing-byte mutation fails closed.
  auto value = bytes(kPing);
  value[0] = 0U; passed &= rejected(value, DecodeError::malformed, "bad magic accepted");
  value = bytes(kPing); value[4] = 2U; passed &= rejected(value, DecodeError::unsupported_version, "bad version status");
  value = bytes(kPing); value[6] = 9U; passed &= rejected(value, DecodeError::malformed, "unknown type accepted");
  value = bytes(kPing); std::fill(value.begin() + 8, value.begin() + 24, std::uint8_t{0}); passed &= rejected(value, DecodeError::malformed, "zero request ID accepted");
  value = bytes(kPing); value[24] = 3U; passed &= rejected(value, DecodeError::unknown_action, "unknown action status");
  value = bytes(kPing); value[26] = 4U; passed &= rejected(value, DecodeError::malformed, "illegal type/status accepted");
  value = bytes(kReview); value[26] = 4U; passed &= rejected(value, DecodeError::malformed, "illegal review status accepted");
  value = bytes(kDecision); value[26] = 4U; passed &= rejected(value, DecodeError::malformed, "illegal decision status accepted");
  value = bytes(kMalformed); value[26] = 9U; passed &= rejected(value, DecodeError::malformed, "unknown response status accepted");
  value = bytes(kPing); value[28] = 9U; passed &= rejected(value, DecodeError::malformed, "body length mismatch accepted");
  value = bytes(kPing); std::fill(value.begin() + 28, value.begin() + 32, std::uint8_t{0xff}); passed &= rejected(value, DecodeError::malformed, "body length overflow accepted");
  value = bytes(kPing); value[32] = 1U; passed &= rejected(value, DecodeError::malformed, "nonzero reserved accepted");
  value = bytes(kPing); value.push_back(0U); passed &= rejected(value, DecodeError::malformed, "appended payload byte accepted");
  value = bytes(kReview); std::fill(value.begin() + 36, value.begin() + 40, std::uint8_t{0}); passed &= rejected(value, DecodeError::malformed, "zero client PID accepted");
  value = bytes(kReview); value[40] = 69U; passed &= rejected(value, DecodeError::malformed, "oversized SID accepted");
  value = bytes(kReview); value[42] = 2U; passed &= rejected(value, DecodeError::malformed, "invalid SID accepted");
  value = bytes(kReview); value[54] = 45U; passed &= rejected(value, DecodeError::malformed, "original length mismatch accepted");
  value = bytes(kReview); value[64] ^= 1U; passed &= rejected(value, DecodeError::malformed, "embedded request ID mismatch accepted");
  value = bytes(kReview); value[80] = 2U; passed &= rejected(value, DecodeError::malformed, "embedded action mismatch accepted");
  value = bytes(kDecision); std::fill(value.begin() + 36, value.begin() + 68, std::uint8_t{0}); passed &= rejected(value, DecodeError::malformed, "zero H accepted");
  value = bytes(kDecision); value[68] = 0U; passed &= rejected(value, DecodeError::malformed, "deny decision accepted");
  value = bytes(kDecision); value[69] = 4U; passed &= rejected(value, DecodeError::malformed, "bad decision reason accepted");
  value = bytes(kDecision); value[71] = 0U; passed &= rejected(value, DecodeError::malformed, "bad blob magic accepted");
  value = bytes(kDecision); value[75] = 31U; passed &= rejected(value, DecodeError::malformed, "bad blob width accepted");
  value = bytes(kDecision); std::fill(value.begin() + 79, value.begin() + 111, std::uint8_t{0}); passed &= rejected(value, DecodeError::malformed, "zero X accepted");
  value = bytes(kDecision); std::fill(value.begin() + 111, value.begin() + 143, std::uint8_t{0}); passed &= rejected(value, DecodeError::malformed, "zero Y accepted");
  value = bytes(kDecision); value[110] ^= 1U; passed &= rejected(value, DecodeError::malformed, "off-curve blob accepted");
  value = bytes(kDecision); std::fill(value.begin() + 143, value.begin() + 175, std::uint8_t{0}); passed &= rejected(value, DecodeError::malformed, "zero r accepted");
  value = bytes(kDecision); std::fill(value.begin() + 175, value.begin() + 207, std::uint8_t{0}); passed &= rejected(value, DecodeError::malformed, "zero s accepted");
  value = bytes(kDecision); const auto order = bytes("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"); std::copy(order.begin(), order.end(), value.begin() + 143); passed &= rejected(value, DecodeError::malformed, "noncanonical r accepted");
  value = bytes(kDecision); std::copy(order.begin(), order.end(), value.begin() + 175); passed &= rejected(value, DecodeError::malformed, "noncanonical s accepted");
  value = bytes(kDenied); value[36] = 1U; passed &= rejected(value, DecodeError::malformed, "noncanonical zero H accepted");
  value = bytes(kDenied); value[71] = 1U; passed &= rejected(value, DecodeError::malformed, "noncanonical zero blob accepted");
  value = bytes(kDenied); value[143] = 1U; passed &= rejected(value, DecodeError::malformed, "noncanonical zero signature accepted");
  value = bytes(kDenied); value[68] = 1U; passed &= rejected(value, DecodeError::malformed, "zero-evidence decision accepted");
  value = bytes(kDenied); value[69] = 5U; passed &= rejected(value, DecodeError::malformed, "zero-evidence reason mismatch accepted");
  value = bytes(kResponsePing); value[207] = 5U; passed &= rejected(value, DecodeError::malformed, "result length mismatch accepted");
  value = bytes(kResponsePing); value[209] = 'B'; passed &= rejected(value, DecodeError::malformed, "noncanonical PONG accepted");
  value = bytes(kResponseService); value.pop_back(); value[28] = 0xd0U; value[207] = 35U; passed &= rejected(value, DecodeError::malformed, "short service scalar block accepted");
  value = bytes(kResponseFailed); value[24] = 1U; passed &= rejected(value, DecodeError::malformed, "PING action failure accepted");

  // Given: every action/status tuple has an independently constructed canonical body.
  constexpr std::array actions{faultloom::protocol::Action::ping,
                               faultloom::protocol::Action::query_service_status};
  constexpr std::array statuses{
      faultloom::protocol::Status::ok,
      faultloom::protocol::Status::malformed,
      faultloom::protocol::Status::unsupported_version,
      faultloom::protocol::Status::unauthorized_client,
      faultloom::protocol::Status::action_denied,
      faultloom::protocol::Status::reviewer_unavailable,
      faultloom::protocol::Status::review_signature_invalid,
      faultloom::protocol::Status::action_failed,
      faultloom::protocol::Status::timeout};
  for (const auto action : actions) {
    for (const auto status : statuses) {
      const bool query_only = status == faultloom::protocol::Status::action_denied ||
                              status == faultloom::protocol::Status::action_failed;
      const bool expected_legal = !query_only || action == faultloom::protocol::Action::query_service_status;
      const auto decoded = faultloom::protocol::decode_payload(response_for(action, status));
      passed &= expect((decoded.error == DecodeError::none) == expected_legal,
                       "broker response action/status matrix mismatch");
    }
  }

  const std::array<std::uint8_t, 4> zero_prefix{};
  const std::array<std::uint8_t, 4> overflow_prefix{0xffU, 0xffU, 0xffU, 0xffU};
  const std::array<std::uint8_t, 4> oversized_prefix{0x01U, 0x20U, 0x00U, 0x00U};
  passed &= expect(faultloom::protocol::decode_record(zero_prefix).error == DecodeError::malformed, "zero record accepted");
  passed &= expect(faultloom::protocol::decode_record(overflow_prefix).error == DecodeError::malformed, "overflow record accepted");
  passed &= expect(faultloom::protocol::decode_record(oversized_prefix).error == DecodeError::malformed, "oversized record accepted");
  std::vector<std::uint8_t> oversized(faultloom::protocol::kMaxPayloadBytes + 1U);
  passed &= expect(!faultloom::protocol::encode_record(oversized).has_value(), "oversized payload encoded");
  auto client_over_cap = bytes(kService);
  client_over_cap.resize(faultloom::protocol::kMaxClientPayloadBytes + 1U);
  client_over_cap[28] = 0x6dU; client_over_cap[29] = 0x1fU;
  client_over_cap[44] = 0x63U; client_over_cap[45] = 0x1fU;
  passed &= rejected(client_over_cap, DecodeError::malformed, "oversized client payload accepted");

  const auto review_digest = faultloom::protocol::signature_digest(bytes(kReview), 1U, faultloom::protocol::Status::ok);
  passed &= expect(review_digest.has_value() && hex(*review_digest) == "de5c0824a52c5bccaae034b4cad34829f07c49f0176c54dd8595048808a8f549", "signature preimage hash mismatch");
  passed &= expect(!faultloom::protocol::signature_digest(bytes(kPing), 1U, faultloom::protocol::Status::ok).has_value(), "non-R signature input accepted");
  passed &= expect(!faultloom::protocol::signature_digest(bytes(kReview), 0U, faultloom::protocol::Status::action_denied).has_value(), "illegal signature tuple accepted");
  std::cout << "PROTOCOL_GOLDENS=15 TRUNCATION_CASES=" << truncations << '\n';
  return passed ? 0 : 1;
}
