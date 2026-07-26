#pragma once

#include "faultloom/protocol.h"

#include <array>
#include <cstddef>
#include <memory>
#include <optional>
#include <span>

namespace faultloom::signing {

using PublicBlob = std::array<std::uint8_t, protocol::kPublicBlobBytes>;
using Signature = std::array<std::uint8_t, protocol::kSignatureBytes>;

class Signer {
 public:
  virtual ~Signer() = default;
  [[nodiscard]] virtual const PublicBlob& public_blob() const noexcept = 0;
  [[nodiscard]] virtual std::optional<Signature> sign(std::span<const std::uint8_t> digest) noexcept = 0;
};

[[nodiscard]] constexpr std::size_t public_blob_bytes() noexcept { return protocol::kPublicBlobBytes; }
[[nodiscard]] std::unique_ptr<Signer> make_ephemeral_signer() noexcept;

}
