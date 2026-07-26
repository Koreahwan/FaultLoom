#include "reviewer_process_fixture.h"

#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <limits>
#include <span>
#include <string_view>

namespace faultloom::test {
namespace {

void put16(std::vector<std::uint8_t>& value, std::uint16_t field) {
  value.push_back(static_cast<std::uint8_t>(field));
  value.push_back(static_cast<std::uint8_t>(field >> 8U));
}

void put32(std::vector<std::uint8_t>& value, std::uint32_t field) {
  for (unsigned shift = 0U; shift < 32U; shift += 8U) value.push_back(static_cast<std::uint8_t>(field >> shift));
}

void put64(std::vector<std::uint8_t>& value, std::uint64_t field) {
  for (unsigned shift = 0U; shift < 64U; shift += 8U) value.push_back(static_cast<std::uint8_t>(field >> shift));
}

bool transfer(HANDLE pipe, std::span<std::uint8_t> bytes, bool write) noexcept {
  std::size_t offset = 0U;
  const ULONGLONG deadline = GetTickCount64() + 7000U;
  while (offset < bytes.size()) {
    TestHandle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!event) return false;
    OVERLAPPED operation{};
    operation.hEvent = event.get();
    DWORD transferred = 0U;
    const DWORD count = static_cast<DWORD>(bytes.size() - offset);
    const BOOL started = write ? WriteFile(pipe, bytes.data() + offset, count, &transferred, &operation)
                               : ReadFile(pipe, bytes.data() + offset, count, &transferred, &operation);
    if (!started) {
      if (GetLastError() != ERROR_IO_PENDING) return false;
      const ULONGLONG now = GetTickCount64();
      if (now >= deadline || WaitForSingleObject(event.get(), static_cast<DWORD>(deadline - now)) != WAIT_OBJECT_0 ||
          !GetOverlappedResult(pipe, &operation, &transferred, FALSE)) {
        CancelIoEx(pipe, &operation);
        GetOverlappedResult(pipe, &operation, &transferred, TRUE);
        return false;
      }
    }
    if (transferred == 0U) return false;
    offset += transferred;
  }
  return true;
}

std::optional<TestHandle> connect(const std::wstring& name) noexcept {
  if (!WaitNamedPipeW(name.c_str(), 7000U)) return std::nullopt;
  TestHandle pipe(CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0U, nullptr, OPEN_EXISTING,
                              FILE_FLAG_OVERLAPPED, nullptr));
  return pipe ? std::optional<TestHandle>(std::move(pipe)) : std::nullopt;
}

}

std::optional<std::vector<std::uint8_t>> current_sid() {
  TestHandle token;
  HANDLE raw = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw)) return std::nullopt;
  token.reset(raw);
  DWORD required = 0U;
  GetTokenInformation(token.get(), TokenUser, nullptr, 0U, &required);
  std::vector<std::uint8_t> storage(required);
  if (required == 0U || !GetTokenInformation(token.get(), TokenUser, storage.data(), required, &required)) return std::nullopt;
  const auto* user = reinterpret_cast<const TOKEN_USER*>(storage.data());
  const DWORD length = GetLengthSid(user->User.Sid);
  std::vector<std::uint8_t> sid(length);
  return CopySid(length, sid.data(), user->User.Sid) ? std::optional<std::vector<std::uint8_t>>(sid) : std::nullopt;
}

std::optional<ReviewRecord> make_review(protocol::Action action, std::string service,
                                        std::int64_t deadline_seconds) {
  LARGE_INTEGER now{};
  LARGE_INTEGER frequency{};
  if (!QueryPerformanceCounter(&now) || !QueryPerformanceFrequency(&frequency)) return std::nullopt;
  std::vector<std::uint8_t> body;
  put64(body, static_cast<std::uint64_t>(now.QuadPart + frequency.QuadPart * deadline_seconds));
  if (action == protocol::Action::query_service_status) {
    put16(body, static_cast<std::uint16_t>(service.size()));
    body.insert(body.end(), service.begin(), service.end());
  }
  protocol::RequestId id{};
  id[0] = 1U;
  const protocol::FrameView client{{protocol::MessageType::client_request, id, action, protocol::Status::ok}, body};
  const auto client_payload = protocol::encode_payload(client);
  const auto sid = current_sid();
  if (!client_payload.has_value() || !sid.has_value()) return std::nullopt;
  std::vector<std::uint8_t> review_body;
  put32(review_body, GetCurrentProcessId());
  put16(review_body, static_cast<std::uint16_t>(sid->size()));
  const std::size_t sid_offset = protocol::kHeaderBytes + review_body.size();
  review_body.insert(review_body.end(), sid->begin(), sid->end());
  put16(review_body, static_cast<std::uint16_t>(client_payload->size()));
  const std::size_t client_offset = protocol::kHeaderBytes + review_body.size();
  review_body.insert(review_body.end(), client_payload->begin(), client_payload->end());
  const protocol::FrameView outer{{protocol::MessageType::review_request, id, action, protocol::Status::ok}, review_body};
  auto payload = protocol::encode_payload(outer);
  if (!payload.has_value()) return std::nullopt;
  auto record = protocol::encode_record(*payload);
  return record.has_value() ? std::optional<ReviewRecord>(ReviewRecord{*payload, *record, sid_offset, client_offset})
                            : std::nullopt;
}

std::optional<std::vector<std::uint8_t>> exchange(const std::wstring& pipe_name,
                                                  std::span<const std::uint8_t> request) {
  auto pipe = connect(pipe_name);
  if (!pipe.has_value()) return std::nullopt;
  std::vector<std::uint8_t> writable(request.begin(), request.end());
  if (!transfer(pipe->get(), writable, true)) return std::nullopt;
  std::array<std::uint8_t, 4> prefix{};
  if (!transfer(pipe->get(), prefix, false)) return std::nullopt;
  const std::uint32_t size = static_cast<std::uint32_t>(prefix[0]) |
                             (static_cast<std::uint32_t>(prefix[1]) << 8U) |
                             (static_cast<std::uint32_t>(prefix[2]) << 16U) |
                             (static_cast<std::uint32_t>(prefix[3]) << 24U);
  if (size == 0U || size > protocol::kMaxPayloadBytes) return std::nullopt;
  std::vector<std::uint8_t> response(prefix.begin(), prefix.end());
  response.resize(4U + size);
  return transfer(pipe->get(), std::span(response).subspan(4U), false)
             ? std::optional<std::vector<std::uint8_t>>(response)
             : std::nullopt;
}

bool send_short(const std::wstring& pipe_name, std::span<const std::uint8_t> request) noexcept {
  auto pipe = connect(pipe_name);
  if (!pipe.has_value() || request.size() < 5U) return false;
  std::vector<std::uint8_t> short_request(request.begin(), request.begin() + 5U);
  return transfer(pipe->get(), short_request, true);
}

bool verify_decision(const ReadyLine& ready, const ReviewRecord& review,
                     std::span<const std::uint8_t> response) noexcept {
  const auto decoded = protocol::decode_record(response);
  if (!decoded.frame.has_value() || decoded.frame->header.message_type != protocol::MessageType::review_decision ||
      decoded.frame->body.size() != 171U || decoded.frame->body[32] != 1U ||
      decoded.frame->body[33] != 0U || decoded.frame->body[34] != 0U) return false;
  const auto hash = protocol::sha256(review.payload);
  const auto digest = protocol::signature_digest(review.payload, 1U, protocol::Status::ok);
  if (!hash.has_value() || !digest.has_value() ||
      !std::equal(hash->begin(), hash->end(), decoded.frame->body.begin()) ||
      !std::equal(ready.public_blob.begin(), ready.public_blob.end(), decoded.frame->body.begin() + 35U)) return false;
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  BCRYPT_KEY_HANDLE key = nullptr;
  const NTSTATUS opened = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0U);
  const NTSTATUS imported = opened >= 0 ? BCryptImportKeyPair(
      algorithm, nullptr, BCRYPT_ECCPUBLIC_BLOB, &key,
      const_cast<PUCHAR>(ready.public_blob.data()), static_cast<ULONG>(ready.public_blob.size()), 0U) : -1;
  const NTSTATUS verified = imported >= 0 ? BCryptVerifySignature(
      key, nullptr, const_cast<PUCHAR>(digest->data()), static_cast<ULONG>(digest->size()),
      const_cast<PUCHAR>(decoded.frame->body.data() + 107U), 64U, 0U) : -1;
  if (key != nullptr) BCryptDestroyKey(key);
  if (algorithm != nullptr) BCryptCloseAlgorithmProvider(algorithm, 0U);
  return verified >= 0;
}

}
