#include "reviewer_decision.h"

#include "reviewer_io.h"

#include <algorithm>
#include <array>

namespace faultloom::reviewer {
namespace {

void put16(std::span<std::uint8_t> value, std::size_t offset, std::uint16_t field) noexcept {
  value[offset] = static_cast<std::uint8_t>(field);
  value[offset + 1U] = static_cast<std::uint8_t>(field >> 8U);
}

}

std::optional<std::vector<std::uint8_t>> make_decision(
    const protocol::FrameView& frame, std::span<const std::uint8_t> review_payload,
    signing::Signer& signer, const DecisionGate& gate) {
  const auto review_hash = protocol::sha256(review_payload);
  const auto signing_hash = protocol::signature_digest(review_payload, 1U, protocol::Status::ok);
  if (!review_hash.has_value() || !signing_hash.has_value()) return std::nullopt;
  if (check_gate(gate.shutdown, gate.broker, gate.deadline, gate.frequency) !=
      IoResult::complete) return std::nullopt;
  const auto signature = signer.sign(*signing_hash);
  if (!signature.has_value() ||
      check_gate(gate.shutdown, gate.broker, gate.deadline, gate.frequency) !=
          IoResult::complete) return std::nullopt;
  std::array<std::uint8_t, 171> body{};
  std::copy(review_hash->begin(), review_hash->end(), body.begin());
  body[32] = 1U;
  put16(body, 33U, 0U);
  std::copy(signer.public_blob().begin(), signer.public_blob().end(), body.begin() + 35U);
  std::copy(signature->begin(), signature->end(), body.begin() + 107U);
#ifdef FAULTLOOM_TEST_CORRUPT_SIGNATURE
  body.back() ^= 1U;
#endif
  const protocol::FrameView output{
      {protocol::MessageType::review_decision, frame.header.request_id, frame.header.action,
       protocol::Status::ok},
      body};
  const auto payload = protocol::encode_payload(output);
  return payload.has_value() ? protocol::encode_record(*payload) : std::nullopt;
}

}
