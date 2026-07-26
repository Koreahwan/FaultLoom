#include "faultloom/broker_contract.h"

#include <windows.h>
#include <bcrypt.h>

#include <algorithm>

namespace faultloom::broker_contract {
namespace {

std::uint16_t read16(std::span<const std::uint8_t> value, std::size_t offset) noexcept {
  return static_cast<std::uint16_t>(value[offset]) |
         static_cast<std::uint16_t>(value[offset + 1U] << 8U);
}

void append16(std::vector<std::uint8_t>& value, std::uint16_t field) {
  value.push_back(static_cast<std::uint8_t>(field));
  value.push_back(static_cast<std::uint8_t>(field >> 8U));
}

void append32(std::vector<std::uint8_t>& value, std::uint32_t field) {
  append16(value, static_cast<std::uint16_t>(field));
  append16(value, static_cast<std::uint16_t>(field >> 16U));
}

bool verify_signature(std::span<const std::uint8_t> review_payload,
                      const signing::PublicBlob& blob,
                      std::span<const std::uint8_t> signature) noexcept {
  const auto digest = protocol::signature_digest(review_payload, 1U, protocol::Status::ok);
  if (!digest.has_value() || signature.size() != blob.size() - 8U) return false;
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  BCRYPT_KEY_HANDLE key = nullptr;
  const NTSTATUS opened = BCryptOpenAlgorithmProvider(
      &algorithm, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0U);
  const NTSTATUS imported = opened >= 0 ? BCryptImportKeyPair(
      algorithm, nullptr, BCRYPT_ECCPUBLIC_BLOB, &key,
      const_cast<PUCHAR>(blob.data()), static_cast<ULONG>(blob.size()), 0U) : -1;
  const NTSTATUS verified = imported >= 0 ? BCryptVerifySignature(
      key, nullptr, const_cast<PUCHAR>(digest->data()), static_cast<ULONG>(digest->size()),
      const_cast<PUCHAR>(signature.data()), static_cast<ULONG>(signature.size()), 0U) : -1;
  if (key != nullptr) BCryptDestroyKey(key);
  if (algorithm != nullptr) BCryptCloseAlgorithmProvider(algorithm, 0U);
  return verified >= 0;
}

bool same_request(const protocol::FrameView& response,
                  std::span<const std::uint8_t> review_payload) noexcept {
  const auto review = protocol::decode_payload(review_payload);
  const auto envelope = review.frame.has_value()
      ? protocol::review_envelope(*review.frame)
      : std::nullopt;
  return envelope.has_value() &&
         response.header.request_id == envelope->original.header.request_id &&
         response.header.action == envelope->original.header.action;
}

}

std::optional<std::vector<std::uint8_t>> build_review_payload(
    std::uint32_t client_pid, std::span<const std::uint8_t> sid,
    std::span<const std::uint8_t> client_payload) {
  const auto client = protocol::decode_payload(client_payload);
  if (client_pid == 0U || sid.empty() || sid.size() > protocol::kMaxSidBytes ||
      !IsValidSid(const_cast<std::uint8_t*>(sid.data())) ||
      GetLengthSid(const_cast<std::uint8_t*>(sid.data())) != sid.size() ||
      !client.frame.has_value() ||
      client.frame->header.message_type != protocol::MessageType::client_request ||
      client_payload.size() > protocol::kMaxClientPayloadBytes) return std::nullopt;
  std::vector<std::uint8_t> body;
  body.reserve(8U + sid.size() + client_payload.size());
  append32(body, client_pid);
  append16(body, static_cast<std::uint16_t>(sid.size()));
  body.insert(body.end(), sid.begin(), sid.end());
  append16(body, static_cast<std::uint16_t>(client_payload.size()));
  body.insert(body.end(), client_payload.begin(), client_payload.end());
  const protocol::FrameView review{{protocol::MessageType::review_request,
                                    client.frame->header.request_id,
                                    client.frame->header.action,
                                    protocol::Status::ok}, body};
  return protocol::encode_payload(review);
}

std::optional<Evidence> verify_review_decision(
    std::span<const std::uint8_t> decision_payload,
    std::span<const std::uint8_t> exact_review_payload,
    const signing::PublicBlob& pinned_blob) noexcept {
  const auto decoded = protocol::decode_payload(decision_payload);
  const auto review = protocol::decode_payload(exact_review_payload);
  if (!decoded.frame.has_value() || !review.frame.has_value() ||
      decoded.frame->header.message_type != protocol::MessageType::review_decision ||
      decoded.frame->header.request_id != review.frame->header.request_id ||
      decoded.frame->header.action != review.frame->header.action) return std::nullopt;
  const auto hash = protocol::sha256(exact_review_payload);
  const auto body = decoded.frame->body;
  if (!hash.has_value() || !std::equal(hash->begin(), hash->end(), body.begin()) ||
      body[32U] != 1U || read16(body, 33U) != 0U ||
      !std::equal(pinned_blob.begin(), pinned_blob.end(), body.begin() + 35U) ||
      !verify_signature(exact_review_payload, pinned_blob, body.subspan(107U, 64U))) {
    return std::nullopt;
  }
  Evidence evidence{};
  evidence.review_hash = *hash;
  evidence.decision = body[32U];
  evidence.reason = protocol::Status::ok;
  evidence.public_blob = pinned_blob;
  std::copy_n(body.begin() + 107U, evidence.signature.size(), evidence.signature.begin());
  return evidence;
}

std::optional<std::vector<std::uint8_t>> build_response(
    const protocol::Header& request, protocol::Status status, const Evidence* evidence,
    std::span<const std::uint8_t> result) {
  std::vector<std::uint8_t> body(171U, 0U);
  if (evidence != nullptr) {
    std::copy(evidence->review_hash.begin(), evidence->review_hash.end(), body.begin());
    body[32U] = evidence->decision;
    body[33U] = static_cast<std::uint8_t>(evidence->reason);
    body[34U] = static_cast<std::uint8_t>(static_cast<std::uint16_t>(evidence->reason) >> 8U);
    std::copy(evidence->public_blob.begin(), evidence->public_blob.end(), body.begin() + 35U);
    std::copy(evidence->signature.begin(), evidence->signature.end(), body.begin() + 107U);
  } else {
    body[33U] = static_cast<std::uint8_t>(status);
    body[34U] = static_cast<std::uint8_t>(static_cast<std::uint16_t>(status) >> 8U);
  }
  append16(body, static_cast<std::uint16_t>(result.size()));
  body.insert(body.end(), result.begin(), result.end());
  const protocol::FrameView response{{protocol::MessageType::broker_response,
                                      request.request_id, request.action, status}, body};
  return protocol::encode_payload(response);
}

bool verify_response(std::span<const std::uint8_t> response_payload,
                     std::span<const std::uint8_t> exact_review_payload,
                     const signing::PublicBlob& pinned_blob) noexcept {
  const auto decoded = protocol::decode_payload(response_payload);
  if (!decoded.frame.has_value() ||
      decoded.frame->header.message_type != protocol::MessageType::broker_response ||
      !same_request(*decoded.frame, exact_review_payload)) return false;
  if (decoded.frame->header.status != protocol::Status::ok &&
      decoded.frame->header.status != protocol::Status::action_failed) return true;
  const auto hash = protocol::sha256(exact_review_payload);
  const auto body = decoded.frame->body;
  return hash.has_value() && std::equal(hash->begin(), hash->end(), body.begin()) &&
         body[32U] == 1U && read16(body, 33U) == 0U &&
         std::equal(pinned_blob.begin(), pinned_blob.end(), body.begin() + 35U) &&
         verify_signature(exact_review_payload, pinned_blob, body.subspan(107U, 64U));
}

}
