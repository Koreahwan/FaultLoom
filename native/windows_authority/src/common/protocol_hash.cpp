#include "faultloom/protocol.h"

#include <windows.h>
#include <bcrypt.h>

#include <array>
#include <limits>
#include <string_view>

namespace faultloom::protocol {
namespace {

std::optional<Hash> hash_chunks(std::span<const std::span<const std::uint8_t>> chunks) noexcept {
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  BCRYPT_HASH_HANDLE hash_handle = nullptr;
  std::array<std::uint8_t, 512> object{};
  Hash result{};
  DWORD object_bytes = 0U;
  DWORD copied = 0U;
  if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0U) < 0 ||
      BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_bytes),
                        sizeof(object_bytes), &copied, 0U) < 0 || object_bytes > object.size() ||
      BCryptCreateHash(algorithm, &hash_handle, object.data(), object_bytes, nullptr, 0U, 0U) < 0) {
    if (hash_handle != nullptr) BCryptDestroyHash(hash_handle);
    if (algorithm != nullptr) BCryptCloseAlgorithmProvider(algorithm, 0U);
    return std::nullopt;
  }
  bool valid = true;
  for (const auto chunk : chunks) {
    if (chunk.size() > std::numeric_limits<ULONG>::max() ||
        BCryptHashData(hash_handle, const_cast<PUCHAR>(chunk.data()), static_cast<ULONG>(chunk.size()), 0U) < 0) {
      valid = false;
      break;
    }
  }
  if (valid && BCryptFinishHash(hash_handle, result.data(), static_cast<ULONG>(result.size()), 0U) < 0) valid = false;
  BCryptDestroyHash(hash_handle);
  BCryptCloseAlgorithmProvider(algorithm, 0U);
  return valid ? std::optional<Hash>(result) : std::nullopt;
}

}

std::optional<Hash> sha256(std::span<const std::uint8_t> input) noexcept {
  const std::array chunks{input};
  return hash_chunks(chunks);
}

std::optional<Hash> signature_digest(std::span<const std::uint8_t> review_payload,
                                     std::uint8_t decision, Status reason) noexcept {
  const auto review = decode_payload(review_payload);
  if (!review.frame.has_value() || review.frame->header.message_type != MessageType::review_request ||
      decision != 1U || reason != Status::ok) return std::nullopt;
  constexpr std::string_view domain = "FaultLoom-Reviewer-MVP-v1";
  const std::array<std::uint8_t, 1> separator{0U};
  const std::array<std::uint8_t, 1> decision_bytes{decision};
  const auto reason_value = static_cast<std::uint16_t>(reason);
  const std::array<std::uint8_t, 2> reason_bytes{
      static_cast<std::uint8_t>(reason_value), static_cast<std::uint8_t>(reason_value >> 8U)};
  const auto domain_bytes = std::span(reinterpret_cast<const std::uint8_t*>(domain.data()), domain.size());
  const std::array<std::span<const std::uint8_t>, 5> chunks{
      domain_bytes, separator, review_payload, decision_bytes, reason_bytes};
  return hash_chunks(chunks);
}

}
