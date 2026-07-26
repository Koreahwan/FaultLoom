#include "reviewer_security.h"

#include "unique_handle.h"

#include <aclapi.h>
#include <sddl.h>

#include <array>

namespace faultloom::reviewer {
namespace {

bool exact_dacl(PACL dacl, PSID expected_sid) noexcept {
  ACL_SIZE_INFORMATION size{};
  if (dacl == nullptr || !GetAclInformation(dacl, &size, sizeof(size), AclSizeInformation) ||
      size.AceCount != 2U) return false;
  BYTE system_storage[SECURITY_MAX_SID_SIZE]{};
  DWORD system_size = sizeof(system_storage);
  if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, system_storage, &system_size)) return false;
  bool found_system = false;
  bool found_user = false;
  GENERIC_MAPPING mapping{FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE,
                          FILE_ALL_ACCESS};
  DWORD expected_mask = GENERIC_READ | GENERIC_WRITE;
  MapGenericMask(&expected_mask, &mapping);
  for (DWORD index = 0U; index < size.AceCount; ++index) {
    void* raw = nullptr;
    if (!GetAce(dacl, index, &raw)) return false;
    const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(raw);
    const PSID ace_sid = const_cast<DWORD*>(&ace->SidStart);
    DWORD actual_mask = ace->Mask;
    MapGenericMask(&actual_mask, &mapping);
    if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE || ace->Header.AceFlags != 0U ||
        actual_mask != expected_mask || !IsValidSid(ace_sid)) return false;
    if (EqualSid(ace_sid, system_storage)) found_system = !found_system;
    else if (EqualSid(ace_sid, expected_sid)) found_user = !found_user;
    else return false;
  }
  return found_system && found_user;
}

bool token_write_allowed(PSECURITY_DESCRIPTOR descriptor, HANDLE token) noexcept {
  HANDLE raw_impersonation = nullptr;
  if (!DuplicateToken(token, SecurityImpersonation, &raw_impersonation)) return false;
  UniqueHandle impersonation(raw_impersonation);
  GENERIC_MAPPING mapping{FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE,
                          FILE_ALL_ACCESS};
  DWORD desired = GENERIC_WRITE;
  MapGenericMask(&desired, &mapping);
  alignas(PRIVILEGE_SET) std::array<std::byte, 1024> privileges{};
  auto* privilege_set = reinterpret_cast<PRIVILEGE_SET*>(privileges.data());
  DWORD privilege_bytes = static_cast<DWORD>(privileges.size());
  DWORD granted = 0U;
  BOOL access = FALSE;
  return AccessCheck(descriptor, impersonation.get(), desired, &mapping, privilege_set,
                     &privilege_bytes, &granted, &access) && access != FALSE;
}

bool startup_write_allowed(PSECURITY_DESCRIPTOR descriptor, HANDLE token) noexcept {
  const DWORD bytes = GetSecurityDescriptorLength(descriptor);
  if (bytes == 0U) return false;
  auto* mapped = static_cast<PSECURITY_DESCRIPTOR>(LocalAlloc(LMEM_FIXED, bytes));
  if (mapped == nullptr) return false;
  CopyMemory(mapped, descriptor, bytes);
  BOOL present = FALSE;
  BOOL defaulted = FALSE;
  PACL dacl = nullptr;
  bool valid = GetSecurityDescriptorDacl(mapped, &present, &dacl, &defaulted) != FALSE &&
               present != FALSE && dacl != nullptr;
  ACL_SIZE_INFORMATION size{};
  valid = valid && GetAclInformation(dacl, &size, sizeof(size), AclSizeInformation) != FALSE;
  GENERIC_MAPPING mapping{FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE,
                          FILE_ALL_ACCESS};
  for (DWORD index = 0U; valid && index < size.AceCount; ++index) {
    void* raw = nullptr;
    valid = GetAce(dacl, index, &raw) != FALSE;
    if (valid) {
      auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
      valid = ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE;
      if (valid) MapGenericMask(&ace->Mask, &mapping);
    }
  }
  const bool allowed = valid && token_write_allowed(mapped, token);
  LocalFree(mapped);
  return allowed;
}

bool low_integrity_write_denied(PSECURITY_DESCRIPTOR descriptor, HANDLE source_token) noexcept {
  HANDLE raw_restricted = nullptr;
  if (!CreateRestrictedToken(source_token, DISABLE_MAX_PRIVILEGE, 0U, nullptr, 0U, nullptr,
                             0U, nullptr, &raw_restricted)) return false;
  UniqueHandle restricted(raw_restricted);
  PSID low_sid = nullptr;
  if (!ConvertStringSidToSidW(L"S-1-16-4096", &low_sid)) return false;
  TOKEN_MANDATORY_LABEL label{};
  label.Label.Sid = low_sid;
  label.Label.Attributes = SE_GROUP_INTEGRITY;
  const DWORD label_bytes = static_cast<DWORD>(sizeof(label) + GetLengthSid(low_sid));
  const bool lowered = SetTokenInformation(restricted.get(), TokenIntegrityLevel, &label,
                                            label_bytes) != FALSE;
  LocalFree(low_sid);
  return lowered && !token_write_allowed(descriptor, restricted.get());
}

}

bool verify_reviewer_pipe_security(HANDLE pipe, PSECURITY_DESCRIPTOR creation_descriptor,
                                   std::span<const std::uint8_t> expected_sid) noexcept {
  if (creation_descriptor == nullptr || expected_sid.empty() ||
      !IsValidSid(const_cast<std::uint8_t*>(expected_sid.data()))) return false;
  PSID owner = nullptr;
  PACL dacl = nullptr;
  PSECURITY_DESCRIPTOR queried = nullptr;
  const DWORD query = GetSecurityInfo(pipe, SE_KERNEL_OBJECT,
                                      OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                                      &owner, nullptr, &dacl, nullptr, &queried);
  if (query != ERROR_SUCCESS || queried == nullptr) return false;
  SECURITY_DESCRIPTOR_CONTROL control = 0U;
  DWORD revision = 0U;
  const bool owner_ok = IsValidSid(owner) &&
                        EqualSid(owner, const_cast<std::uint8_t*>(expected_sid.data()));
  const bool control_ok = GetSecurityDescriptorControl(queried, &control, &revision) != FALSE &&
                          (control & SE_DACL_PROTECTED) != 0U;
  const bool dacl_ok = exact_dacl(dacl, const_cast<std::uint8_t*>(expected_sid.data()));
  const bool requery_ok = owner_ok && control_ok && dacl_ok;
  HANDLE raw_token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(),
                        TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT, &raw_token)) {
    LocalFree(queried);
    return false;
  }
  UniqueHandle token(raw_token);
  const bool startup_allowed = startup_write_allowed(creation_descriptor, token.get());
  const bool low_denied = low_integrity_write_denied(creation_descriptor, token.get());
  LocalFree(queried);
  return requery_ok && startup_allowed && low_denied;
}

}
