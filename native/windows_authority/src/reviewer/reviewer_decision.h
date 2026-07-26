#pragma once

#include "faultloom/protocol.h"
#include "faultloom/signer.h"

#include <windows.h>

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace faultloom::reviewer {

struct DecisionGate {
  HANDLE shutdown;
  HANDLE broker;
  std::uint64_t deadline;
  std::uint64_t frequency;
};

[[nodiscard]] std::optional<std::vector<std::uint8_t>> make_decision(
    const protocol::FrameView& frame, std::span<const std::uint8_t> review_payload,
    signing::Signer& signer, const DecisionGate& gate);

}
