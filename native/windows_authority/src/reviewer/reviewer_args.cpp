#include "reviewer_runtime.h"

#include <winternl.h>

#include <array>
#include <cstddef>
#include <limits>
#include <string_view>

namespace faultloom::reviewer {
namespace {

constexpr OBJECT_INFORMATION_CLASS kObjectNameInformation =
    static_cast<OBJECT_INFORMATION_CLASS>(1);

std::optional<std::uint64_t> decimal(std::wstring_view value) noexcept {
  if (value.empty()) return std::nullopt;
  std::uint64_t result = 0U;
  for (const wchar_t character : value) {
    if (character < L'0' || character > L'9') return std::nullopt;
    const std::uint64_t digit = static_cast<std::uint64_t>(character - L'0');
    if (result > (std::numeric_limits<std::uint64_t>::max() - digit) / 10U) return std::nullopt;
    result = result * 10U + digit;
  }
  return result;
}

bool nonce(std::wstring_view value) noexcept {
  if (value.size() != 32U) return false;
  for (const wchar_t character : value) {
    if (!((character >= L'0' && character <= L'9') || (character >= L'a' && character <= L'f'))) return false;
  }
  return true;
}

bool object_type(HANDLE handle, std::wstring_view expected) noexcept {
  alignas(PUBLIC_OBJECT_TYPE_INFORMATION) std::array<std::byte, 512> storage{};
  ULONG returned = 0U;
  if (NtQueryObject(handle, ObjectTypeInformation, storage.data(),
                    static_cast<ULONG>(storage.size()), &returned) < 0 ||
      returned > storage.size()) {
    return false;
  }
  const auto* information = reinterpret_cast<const PUBLIC_OBJECT_TYPE_INFORMATION*>(storage.data());
  if (information->TypeName.Buffer == nullptr || information->TypeName.Length % sizeof(wchar_t) != 0U ||
      information->TypeName.MaximumLength < information->TypeName.Length) {
    return false;
  }
  const auto begin = reinterpret_cast<std::uintptr_t>(storage.data());
  const auto end = begin + storage.size();
  const auto name = reinterpret_cast<std::uintptr_t>(information->TypeName.Buffer);
  if (name < begin || name > end || information->TypeName.Length > end - name) return false;
  return std::wstring_view(information->TypeName.Buffer,
                           information->TypeName.Length / sizeof(wchar_t)) == expected;
}

bool exact_access(HANDLE handle, ACCESS_MASK expected) noexcept {
  PUBLIC_OBJECT_BASIC_INFORMATION information{};
  ULONG returned = 0U;
  return NtQueryObject(handle, ObjectBasicInformation, &information, sizeof(information),
                       &returned) >= 0 &&
         information.GrantedAccess == expected;
}

bool unnamed(HANDLE handle) noexcept {
  alignas(UNICODE_STRING) std::array<std::byte, 1024> storage{};
  ULONG returned = 0U;
  if (NtQueryObject(handle, kObjectNameInformation, storage.data(),
                    static_cast<ULONG>(storage.size()), &returned) < 0 ||
      returned > storage.size()) {
    return false;
  }
  const auto* information = reinterpret_cast<const UNICODE_STRING*>(storage.data());
  return information->Length == 0U;
}

}

std::optional<Options> parse_options(int argc, wchar_t** argv) noexcept {
  if (argc != 9 || std::wstring_view(argv[1]) != L"--session" ||
      std::wstring_view(argv[3]) != L"--expected-broker-pid" ||
      std::wstring_view(argv[5]) != L"--ready-handle" ||
      std::wstring_view(argv[7]) != L"--shutdown-event-handle" || !nonce(argv[2])) {
    return std::nullopt;
  }
  const auto pid = decimal(argv[4]);
  const auto ready = decimal(argv[6]);
  const auto shutdown = decimal(argv[8]);
  if (!pid.has_value() || *pid == 0U || *pid > std::numeric_limits<std::uint32_t>::max() ||
      !ready.has_value() || *ready == 0U || !shutdown.has_value() || *shutdown == 0U ||
      *ready > std::numeric_limits<std::uintptr_t>::max() ||
      *shutdown > std::numeric_limits<std::uintptr_t>::max()) {
    return std::nullopt;
  }
  const HANDLE ready_handle = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(*ready));
  const HANDLE shutdown_event = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(*shutdown));
  DWORD ready_flags = 0U;
  DWORD shutdown_flags = 0U;
  const DWORD shutdown_state = WaitForSingleObject(shutdown_event, 0U);
  if (!object_type(ready_handle, L"File") || GetFileType(ready_handle) != FILE_TYPE_PIPE ||
      !exact_access(ready_handle, FILE_WRITE_DATA | SYNCHRONIZE) ||
      !GetHandleInformation(ready_handle, &ready_flags) ||
      (ready_flags & HANDLE_FLAG_INHERIT) == 0U || !object_type(shutdown_event, L"Event") ||
      !exact_access(shutdown_event, SYNCHRONIZE) || !unnamed(shutdown_event) ||
      !GetHandleInformation(shutdown_event, &shutdown_flags) ||
      (shutdown_flags & HANDLE_FLAG_INHERIT) == 0U ||
      (shutdown_state != WAIT_TIMEOUT && shutdown_state != WAIT_OBJECT_0)) {
    return std::nullopt;
  }
  return Options{argv[2], static_cast<std::uint32_t>(*pid), ready_handle, shutdown_event};
}

}
