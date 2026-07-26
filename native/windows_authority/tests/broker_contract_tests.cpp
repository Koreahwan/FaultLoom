#include "faultloom/broker_contract.h"
#include "reviewer_decision.h"
#include "reviewer_process_fixture.h"
#include "reviewer_child.h"
#include "unique_handle.h"

#include <windows.h>

#include <algorithm>
#include <iostream>

namespace {

bool replacement_race_denied() {
  std::array<wchar_t, 32768> module{};
  const DWORD size = GetModuleFileNameW(nullptr, module.data(), static_cast<DWORD>(module.size()));
  if (size == 0U || size >= module.size()) return false;
  std::wstring base(module.data(), size);
  base.resize(base.find_last_of(L"\\/") + 1U);
  const std::wstring directory = base + L"reviewer-race-" + std::to_wstring(GetCurrentProcessId());
  const std::wstring renamed = directory + L"-renamed";
  const std::wstring file = directory + L"\\probe.exe";
  if (!CreateDirectoryW(directory.c_str(), nullptr)) return false;
  faultloom::reviewer::UniqueHandle created(CreateFileW(
      file.c_str(), GENERIC_WRITE, 0U, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
  if (!created) { RemoveDirectoryW(directory.c_str()); return false; }
  created.reset();
  auto identity = faultloom::broker::open_sibling_identity(directory, L"probe.exe");
  const bool moved = identity.has_value() && MoveFileExW(directory.c_str(), renamed.c_str(), 0U);
  const DWORD error = moved ? ERROR_SUCCESS : GetLastError();
  identity.reset();
  if (moved) MoveFileExW(renamed.c_str(), directory.c_str(), 0U);
  DeleteFileW(file.c_str());
  RemoveDirectoryW(directory.c_str());
  return !moved && (error == ERROR_SHARING_VIOLATION || error == ERROR_ACCESS_DENIED);
}

}

int main() {
  const auto review = faultloom::test::make_review(faultloom::protocol::Action::ping);
  const auto sid = faultloom::test::current_sid();
  bool passed = review.has_value() && sid.has_value();
  if (!passed) return 1;
  const auto envelope_frame = faultloom::protocol::decode_payload(review->payload);
  const auto envelope = envelope_frame.frame.has_value()
      ? faultloom::protocol::review_envelope(*envelope_frame.frame)
      : std::nullopt;
  passed &= envelope.has_value();
  if (!envelope.has_value()) return 1;
  const auto rebuilt = faultloom::broker_contract::build_review_payload(
      GetCurrentProcessId(), *sid, envelope->original_payload);
  passed &= rebuilt.has_value() && *rebuilt == review->payload;

  faultloom::reviewer::UniqueHandle shutdown(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  faultloom::reviewer::UniqueHandle broker(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  LARGE_INTEGER frequency{};
  LARGE_INTEGER now{};
  passed &= shutdown && broker && QueryPerformanceFrequency(&frequency) &&
            QueryPerformanceCounter(&now);
  auto signer = faultloom::signing::make_ephemeral_signer();
  passed &= signer != nullptr;
  if (signer == nullptr) return 1;
  constexpr char digits[] = "0123456789abcdef";
  std::string ready = "REVIEWER_READY v1 reviewer_pid=" +
      std::to_string(GetCurrentProcessId()) + " public_blob=";
  for (const std::uint8_t byte : signer->public_blob()) {
    ready.push_back(digits[byte >> 4U]);
    ready.push_back(digits[byte & 15U]);
  }
  ready.push_back('\n');
  faultloom::signing::PublicBlob parsed_blob{};
  passed &= faultloom::broker::parse_reviewer_ready(
      ready, GetCurrentProcessId(), parsed_blob) && parsed_blob == signer->public_blob();
  passed &= !faultloom::broker::parse_reviewer_ready(
      ready, GetCurrentProcessId() + 1U, parsed_blob);
  passed &= replacement_race_denied();
  const faultloom::reviewer::DecisionGate gate{
      shutdown.get(), broker.get(),
      static_cast<std::uint64_t>(now.QuadPart + frequency.QuadPart),
      static_cast<std::uint64_t>(frequency.QuadPart)};
  const auto decision = faultloom::reviewer::make_decision(
      *envelope_frame.frame, review->payload, *signer, gate);
  const auto decision_frame = decision.has_value()
      ? faultloom::protocol::decode_record(*decision)
      : faultloom::protocol::DecodeResult{};
  const auto evidence = decision_frame.frame.has_value()
      ? faultloom::broker_contract::verify_review_decision(
            std::span(*decision).subspan(4U), review->payload, signer->public_blob())
      : std::nullopt;
  passed &= evidence.has_value();

  const std::array<std::uint8_t, 4> pong{'P', 'O', 'N', 'G'};
  const auto response = evidence.has_value()
      ? faultloom::broker_contract::build_response(envelope->original.header,
                                                   faultloom::protocol::Status::ok,
                                                   &*evidence, pong)
      : std::nullopt;
  passed &= response.has_value() && faultloom::broker_contract::verify_response(
                                        *response, review->payload, signer->public_blob());
  for (const auto status : {faultloom::protocol::Status::reviewer_unavailable,
                            faultloom::protocol::Status::review_signature_invalid}) {
    const auto zero = faultloom::broker_contract::build_response(
        envelope->original.header, status, nullptr, {});
    const auto decoded_zero = zero ? faultloom::protocol::decode_payload(*zero)
                                   : faultloom::protocol::DecodeResult{};
    passed &= decoded_zero.frame.has_value() && decoded_zero.frame->header.status == status &&
              decoded_zero.frame->body.size() == 173U && decoded_zero.frame->body[32U] == 0U &&
              decoded_zero.frame->body[33U] == static_cast<std::uint8_t>(status) &&
              decoded_zero.frame->body[34U] == 0U &&
              std::all_of(decoded_zero.frame->body.begin(), decoded_zero.frame->body.begin() + 32U,
                          [](std::uint8_t value) { return value == 0U; }) &&
              std::all_of(decoded_zero.frame->body.begin() + 35U, decoded_zero.frame->body.end(),
                          [](std::uint8_t value) { return value == 0U; });
  }
  if (decision.has_value()) {
    auto corrupted = std::vector<std::uint8_t>(decision->begin() + 4U, decision->end());
    corrupted.back() ^= 1U;
    passed &= !faultloom::broker_contract::verify_review_decision(
        corrupted, review->payload, signer->public_blob()).has_value();
  }
  if (!passed) std::cerr << "broker trust contract failed\n";
  return passed ? 0 : 1;
}
