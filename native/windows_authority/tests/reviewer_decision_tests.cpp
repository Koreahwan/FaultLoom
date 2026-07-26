#include "fake_signer.h"
#include "reviewer_decision.h"
#include "reviewer_process_fixture.h"
#include "unique_handle.h"

#include <windows.h>

#include <cstdint>
#include <iostream>

namespace {

using faultloom::reviewer::UniqueHandle;

class TrackingSigner final : public faultloom::signing::Signer {
 public:
  explicit TrackingSigner(HANDLE revoke = nullptr)
      : revoke_(revoke), inner_(faultloom::test::make_fake_signer()) {}

  const faultloom::signing::PublicBlob& public_blob() const noexcept override {
    return inner_->public_blob();
  }

  std::optional<faultloom::signing::Signature> sign(
      std::span<const std::uint8_t> digest) noexcept override {
    ++calls_;
    if (digest.size() != 32U) return std::nullopt;
    const auto signature = inner_->sign(digest);
    if (revoke_ != nullptr) SetEvent(revoke_);
    return signature;
  }

  [[nodiscard]] unsigned calls() const noexcept { return calls_; }

 private:
  HANDLE revoke_;
  unsigned calls_ = 0U;
  std::unique_ptr<faultloom::signing::Signer> inner_;
};

bool no_bytes(HANDLE read) noexcept {
  DWORD available = 0U;
  return PeekNamedPipe(read, nullptr, 0U, nullptr, &available, nullptr) && available == 0U;
}

bool emit_if_present(HANDLE write,
                     const std::optional<std::vector<std::uint8_t>>& response) noexcept {
  if (!response.has_value()) return true;
  DWORD written = 0U;
  return WriteFile(write, response->data(), static_cast<DWORD>(response->size()), &written,
                   nullptr) && written == response->size();
}

}

int main() {
  UniqueHandle shutdown(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  UniqueHandle broker(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  HANDLE raw_read = nullptr;
  HANDLE raw_write = nullptr;
  bool passed = shutdown && broker && CreatePipe(&raw_read, &raw_write, nullptr, 0U);
  UniqueHandle read(raw_read);
  UniqueHandle write(raw_write);
  LARGE_INTEGER frequency{};
  LARGE_INTEGER now{};
  passed &= QueryPerformanceFrequency(&frequency) && QueryPerformanceCounter(&now);
  const auto review = faultloom::test::make_review(faultloom::protocol::Action::ping);
  const auto decoded = review.has_value()
      ? faultloom::protocol::decode_payload(review->payload)
      : faultloom::protocol::DecodeResult{};
  passed &= decoded.frame.has_value();
  const faultloom::reviewer::DecisionGate gate{
      shutdown.get(), broker.get(), static_cast<std::uint64_t>(now.QuadPart + frequency.QuadPart),
      static_cast<std::uint64_t>(frequency.QuadPart)};

  if (!decoded.frame.has_value()) return 1;
  SetEvent(shutdown.get());
  TrackingSigner before;
  const auto before_response = faultloom::reviewer::make_decision(
      *decoded.frame, review->payload, before, gate);
  const bool before_ok = !before_response.has_value() && before.calls() == 0U &&
                         emit_if_present(write.get(), before_response) && no_bytes(read.get());
  passed &= before_ok;

  ResetEvent(shutdown.get());
  TrackingSigner after_shutdown(shutdown.get());
  const auto after_shutdown_response =
      faultloom::reviewer::make_decision(*decoded.frame, review->payload, after_shutdown, gate);
  const bool after_shutdown_ok = !after_shutdown_response.has_value() &&
                                 after_shutdown.calls() == 1U &&
                                 emit_if_present(write.get(), after_shutdown_response) &&
                                 no_bytes(read.get());
  passed &= after_shutdown_ok;

  ResetEvent(shutdown.get());
  TrackingSigner after_broker(broker.get());
  const auto after_broker_response =
      faultloom::reviewer::make_decision(*decoded.frame, review->payload, after_broker, gate);
  const bool after_broker_ok = !after_broker_response.has_value() &&
                               after_broker.calls() == 1U &&
                               emit_if_present(write.get(), after_broker_response) &&
                               no_bytes(read.get());
  passed &= after_broker_ok;

  if (!passed) {
    std::cerr << "decision revocation boundary failed before=" << before_ok
              << " after_shutdown=" << after_shutdown_ok
              << " after_broker=" << after_broker_ok << '\n';
  }
  return passed ? 0 : 1;
}
