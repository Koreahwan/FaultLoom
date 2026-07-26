#include "reviewer_identity.h"
#include "reviewer_security.h"

#include <aclapi.h>
#include <sddl.h>

#include <algorithm>
#include <string>

namespace faultloom::reviewer {

std::optional<std::vector<std::uint8_t>> process_sid(HANDLE process) noexcept {
  HANDLE raw_token = nullptr;
  if (!OpenProcessToken(process, TOKEN_QUERY, &raw_token)) return std::nullopt;
  UniqueHandle token(raw_token);
  DWORD required = 0U;
  GetTokenInformation(token.get(), TokenUser, nullptr, 0U, &required);
  if (required == 0U || required > 4096U) return std::nullopt;
  std::vector<std::uint8_t> storage(required);
  if (!GetTokenInformation(token.get(), TokenUser, storage.data(), required, &required)) return std::nullopt;
  const auto* user = reinterpret_cast<const TOKEN_USER*>(storage.data());
  if (!IsValidSid(user->User.Sid)) return std::nullopt;
  const DWORD sid_length = GetLengthSid(user->User.Sid);
  if (sid_length == 0U || sid_length > protocol::kMaxSidBytes) return std::nullopt;
  std::vector<std::uint8_t> sid(sid_length);
  if (!CopySid(sid_length, sid.data(), user->User.Sid)) return std::nullopt;
  return sid;
}

std::optional<BrokerIdentity> retain_broker(std::uint32_t pid) noexcept {
  UniqueHandle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid));
  if (!process || WaitForSingleObject(process.get(), 0U) != WAIT_TIMEOUT) return std::nullopt;
  const auto broker_sid = process_sid(process.get());
  const auto reviewer_sid = process_sid(GetCurrentProcess());
  if (!broker_sid.has_value() || !reviewer_sid.has_value() || *broker_sid != *reviewer_sid) return std::nullopt;
  return BrokerIdentity{std::move(process), *broker_sid};
}

std::optional<UniqueHandle> create_reviewer_pipe(const std::wstring& session,
                                                 std::span<const std::uint8_t> sid) noexcept {
  LPWSTR sid_text = nullptr;
  if (!ConvertSidToStringSidW(const_cast<std::uint8_t*>(sid.data()), &sid_text)) return std::nullopt;
  const std::wstring sddl = L"O:" + std::wstring(sid_text) + L"G:" + sid_text +
                            L"D:P(A;;GRGW;;;SY)(A;;GRGW;;;" + sid_text + L")S:(ML;;NW;;;ME)";
  LocalFree(sid_text);
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
          sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) {
    return std::nullopt;
  }
  SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor, FALSE};
  const std::wstring name = L"\\\\.\\pipe\\FaultLoom.Reviewer.MVP.v1." + session;
  UniqueHandle pipe(CreateNamedPipeW(
      name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
      PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1U,
      static_cast<DWORD>(protocol::kMaxRecordBytes), static_cast<DWORD>(protocol::kMaxRecordBytes),
      0U, &attributes));
  const bool verified = pipe && verify_reviewer_pipe_security(pipe.get(), descriptor, sid);
  LocalFree(descriptor);
  return verified ? std::optional<UniqueHandle>(std::move(pipe)) : std::nullopt;
}

}
