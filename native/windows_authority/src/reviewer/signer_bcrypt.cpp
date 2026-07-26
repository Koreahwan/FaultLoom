#include "faultloom/signer.h"

#include <windows.h>
#include <bcrypt.h>

#include <memory>
#include <new>

namespace faultloom::signing {
namespace {

class BcryptSigner final : public Signer {
 public:
  ~BcryptSigner() override {
    if (key_ != nullptr) BCryptDestroyKey(key_);
    if (algorithm_ != nullptr) BCryptCloseAlgorithmProvider(algorithm_, 0U);
  }

  bool initialize() noexcept {
    if (BCryptOpenAlgorithmProvider(&algorithm_, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0U) < 0 ||
        BCryptGenerateKeyPair(algorithm_, &key_, 256U, 0U) < 0 || BCryptFinalizeKeyPair(key_, 0U) < 0) {
      return false;
    }
    ULONG exported = 0U;
    if (BCryptExportKey(key_, nullptr, BCRYPT_ECCPUBLIC_BLOB, blob_.data(),
                        static_cast<ULONG>(blob_.size()), &exported, 0U) < 0 ||
        exported != blob_.size()) {
      return false;
    }
    const auto* header = reinterpret_cast<const BCRYPT_ECCKEY_BLOB*>(blob_.data());
    return header->dwMagic == BCRYPT_ECDSA_PUBLIC_P256_MAGIC && header->cbKey == 32U;
  }

  const PublicBlob& public_blob() const noexcept override { return blob_; }

  std::optional<Signature> sign(std::span<const std::uint8_t> digest) noexcept override {
    if (key_ == nullptr || digest.size() != protocol::Hash{}.size()) return std::nullopt;
    Signature signature{};
    ULONG written = 0U;
    const NTSTATUS status = BCryptSignHash(
        key_, nullptr, const_cast<PUCHAR>(digest.data()), static_cast<ULONG>(digest.size()),
        signature.data(), static_cast<ULONG>(signature.size()), &written, 0U);
    return status >= 0 && written == signature.size() ? std::optional<Signature>(signature) : std::nullopt;
  }

 private:
  BCRYPT_ALG_HANDLE algorithm_ = nullptr;
  BCRYPT_KEY_HANDLE key_ = nullptr;
  PublicBlob blob_{};
};

}

std::unique_ptr<Signer> make_ephemeral_signer() noexcept {
  auto signer = std::unique_ptr<BcryptSigner>(new (std::nothrow) BcryptSigner());
  return signer != nullptr && signer->initialize() ? std::unique_ptr<Signer>(std::move(signer)) : nullptr;
}

}
