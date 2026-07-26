#include "broker_security.h"

#include "faultloom/protocol.h"
#include "reviewer_identity.h"
#include "reviewer_security.h"

#include <sddl.h>
#include <bcrypt.h>

#include <array>

namespace faultloom::broker {

std::optional<std::vector<std::uint8_t>> current_sid() noexcept {
  return reviewer::process_sid(GetCurrentProcess());
}

std::optional<std::wstring> random_session() noexcept {
  std::array<std::uint8_t, 16> bytes{};
  if (BCryptGenRandom(nullptr, bytes.data(), static_cast<ULONG>(bytes.size()),
                      BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) return std::nullopt;
  constexpr wchar_t digits[] = L"0123456789abcdef";
  std::wstring value(bytes.size() * 2U, L'0');
  for (std::size_t index = 0U; index < bytes.size(); ++index) {
    value[index * 2U] = digits[bytes[index] >> 4U];
    value[index * 2U + 1U] = digits[bytes[index] & 15U];
  }
  return value;
}

std::optional<DWORD> client_pipe_mode(bool reject_remote) noexcept {
  return reject_remote
      ? std::optional<DWORD>(PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT |
                             PIPE_REJECT_REMOTE_CLIENTS)
      : std::nullopt;
}

std::optional<reviewer::UniqueHandle> create_client_pipe(
    const std::wstring& session, std::span<const std::uint8_t> sid) noexcept {
  LPWSTR text = nullptr;
  if (!ConvertSidToStringSidW(const_cast<std::uint8_t*>(sid.data()), &text)) return std::nullopt;
  const std::wstring sddl = L"O:" + std::wstring(text) + L"G:" + text +
      L"D:P(A;;GRGW;;;SY)(A;;GRGW;;;" + text + L")S:(ML;;NW;;;ME)";
  LocalFree(text);
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
          sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) return std::nullopt;
  SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor, FALSE};
  const std::wstring name = L"\\\\.\\pipe\\FaultLoom.Broker.MVP.v1." + session;
  const auto mode = client_pipe_mode(true);
  if (!mode.has_value()) { LocalFree(descriptor); return std::nullopt; }
  reviewer::UniqueHandle pipe(CreateNamedPipeW(
      name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
      *mode, 1U,
      static_cast<DWORD>(protocol::kMaxRecordBytes), static_cast<DWORD>(protocol::kMaxRecordBytes),
      0U, &attributes));
  const bool verified = pipe && reviewer::verify_reviewer_pipe_security(pipe.get(), descriptor, sid);
  LocalFree(descriptor);
  return verified ? std::optional<reviewer::UniqueHandle>(std::move(pipe)) : std::nullopt;
}

}
