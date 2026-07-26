#pragma once

#include "faultloom/protocol.h"
#include "faultloom/signer.h"

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace faultloom::broker_contract {

struct Evidence {
  protocol::Hash review_hash;
  std::uint8_t decision;
  protocol::Status reason;
  signing::PublicBlob public_blob;
  signing::Signature signature;
};

[[nodiscard]] std::optional<std::vector<std::uint8_t>> build_review_payload(
    std::uint32_t client_pid, std::span<const std::uint8_t> sid,
    std::span<const std::uint8_t> client_payload);
[[nodiscard]] std::optional<Evidence> verify_review_decision(
    std::span<const std::uint8_t> decision_payload,
    std::span<const std::uint8_t> exact_review_payload,
    const signing::PublicBlob& pinned_blob) noexcept;
[[nodiscard]] std::optional<std::vector<std::uint8_t>> build_response(
    const protocol::Header& request, protocol::Status status, const Evidence* evidence,
    std::span<const std::uint8_t> result);
[[nodiscard]] bool verify_response(std::span<const std::uint8_t> response_payload,
                                   std::span<const std::uint8_t> exact_review_payload,
                                   const signing::PublicBlob& pinned_blob) noexcept;

}
