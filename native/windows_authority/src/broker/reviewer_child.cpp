#include "reviewer_child.h"

#include <bcrypt.h>

#include <array>
#include <charconv>
#include <vector>

namespace faultloom::broker {
namespace {

struct Attributes {
  std::vector<std::uint8_t> bytes;
  PPROC_THREAD_ATTRIBUTE_LIST value = nullptr;
  ~Attributes() { if (value != nullptr) DeleteProcThreadAttributeList(value); }
};

std::optional<SiblingIdentity> sibling_path() {
  std::array<wchar_t, 32768> path{};
  const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
  if (length == 0U || length >= path.size()) return std::nullopt;
  std::wstring result(path.data(), length);
  const auto slash = result.find_last_of(L"\\/");
  if (slash == std::wstring::npos) return std::nullopt;
  result.resize(slash);
#ifdef FAULTLOOM_TEST_CORRUPT_REVIEWER
  return open_sibling_identity(result, L"faultloom_reviewer_corrupt.exe");
#else
  return open_sibling_identity(result, L"faultloom_reviewer.exe");
#endif
}

bool parse_hex(std::string_view value, signing::PublicBlob& blob) noexcept {
  if (value.size() != blob.size() * 2U) return false;
  for (std::size_t index = 0U; index < blob.size(); ++index) {
    const auto digit = [](char c) -> int {
      if (c >= '0' && c <= '9') return c - '0';
      if (c >= 'a' && c <= 'f') return c - 'a' + 10;
      return -1;
    };
    const int high = digit(value[index * 2U]);
    const int low = digit(value[index * 2U + 1U]);
    if (high < 0 || low < 0) return false;
    blob[index] = static_cast<std::uint8_t>((high << 4) | low);
  }
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  BCRYPT_KEY_HANDLE key = nullptr;
  const NTSTATUS opened = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_ECDSA_P256_ALGORITHM,
                                                       nullptr, 0U);
  const NTSTATUS imported = opened >= 0 ? BCryptImportKeyPair(
      algorithm, nullptr, BCRYPT_ECCPUBLIC_BLOB, &key, blob.data(),
      static_cast<ULONG>(blob.size()), 0U) : -1;
  if (key != nullptr) BCryptDestroyKey(key);
  if (algorithm != nullptr) BCryptCloseAlgorithmProvider(algorithm, 0U);
  return imported >= 0;
}

bool read_ready(HANDLE pipe, HANDLE process, HANDLE shutdown, DWORD pid,
                signing::PublicBlob& blob) noexcept {
  const ULONGLONG deadline = GetTickCount64() + 5000U;
  std::array<char, 200> bytes{};
  std::size_t used = 0U;
  while (GetTickCount64() < deadline && used < bytes.size() - 1U) {
    if (WaitForSingleObject(shutdown, 0U) == WAIT_OBJECT_0 ||
        WaitForSingleObject(process, 0U) == WAIT_OBJECT_0) return false;
    DWORD available = 0U;
    if (!PeekNamedPipe(pipe, nullptr, 0U, nullptr, &available, nullptr)) return false;
    if (available == 0U) { Sleep(1U); continue; }
    DWORD read = 0U;
    const DWORD wanted = static_cast<DWORD>(std::min<std::size_t>(available, bytes.size() - 1U - used));
    if (!ReadFile(pipe, bytes.data() + used, wanted, &read, nullptr) || read == 0U) return false;
    used += read;
    if (bytes[used - 1U] == '\n') break;
  }
  return parse_reviewer_ready(std::string_view(bytes.data(), used), pid, blob);
}

}

std::optional<SiblingIdentity> open_sibling_identity(
    const std::wstring& directory_path, const std::wstring& filename) noexcept {
  if (directory_path.empty() || filename.empty() || filename.find_first_of(L"\\/") != std::wstring::npos) {
    return std::nullopt;
  }
  reviewer::UniqueHandle directory(CreateFileW(
      directory_path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
      nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
  BY_HANDLE_FILE_INFORMATION info{};
  if (!directory || !GetFileInformationByHandle(directory.get(), &info) ||
      (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0U) return std::nullopt;
  const std::wstring path = directory_path + L"\\" + filename;
  reviewer::UniqueHandle file(CreateFileW(
      path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ, nullptr,
      OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
  if (!file || !GetFileInformationByHandle(file.get(), &info) ||
      (info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) != 0U) {
    return std::nullopt;
  }
  std::array<wchar_t, 32768> final{};
  const DWORD final_size = GetFinalPathNameByHandleW(file.get(), final.data(),
                                                      static_cast<DWORD>(final.size()), 0U);
  std::array<wchar_t, 32768> full{};
  const DWORD full_size = GetFullPathNameW(path.c_str(), static_cast<DWORD>(full.size()),
                                            full.data(), nullptr);
  if (final_size == 0U || final_size >= final.size() || full_size == 0U ||
      full_size >= full.size()) return std::nullopt;
  const std::wstring expected = L"\\\\?\\" + std::wstring(full.data(), full_size);
  if (_wcsicmp(final.data(), expected.c_str()) != 0) return std::nullopt;
  return SiblingIdentity{path, directory_path, std::move(directory), std::move(file)};
}

bool parse_reviewer_ready(std::string_view line, DWORD expected_pid,
                          signing::PublicBlob& blob) noexcept {
  const std::string prefix = "REVIEWER_READY v1 reviewer_pid=" +
      std::to_string(expected_pid) + " public_blob=";
  return line.size() == prefix.size() + blob.size() * 2U + 1U &&
         line.starts_with(prefix) && line.back() == '\n' &&
         parse_hex(line.substr(prefix.size(), blob.size() * 2U), blob);
}

std::optional<ReviewerChild> launch_reviewer(const std::wstring& session,
                                             HANDLE broker_shutdown) noexcept {
  const auto application = sibling_path();
  if (!application.has_value()) return std::nullopt;
  HANDLE read_raw = nullptr;
  HANDLE write_raw = nullptr;
  if (!CreatePipe(&read_raw, &write_raw, nullptr, 0U)) return std::nullopt;
  reviewer::UniqueHandle ready_read(read_raw);
  reviewer::UniqueHandle ready_write(write_raw);
  HANDLE ready_child_raw = nullptr;
  if (!DuplicateHandle(GetCurrentProcess(), ready_write.get(), GetCurrentProcess(), &ready_child_raw,
                       FILE_WRITE_DATA | SYNCHRONIZE, TRUE, 0U)) return std::nullopt;
  reviewer::UniqueHandle ready_child(ready_child_raw);
  ready_write.reset();
  reviewer::UniqueHandle shutdown(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  HANDLE shutdown_child_raw = nullptr;
  if (!shutdown || !DuplicateHandle(GetCurrentProcess(), shutdown.get(), GetCurrentProcess(),
                                    &shutdown_child_raw, SYNCHRONIZE, TRUE, 0U)) return std::nullopt;
  reviewer::UniqueHandle shutdown_child(shutdown_child_raw);
  Attributes attributes;
  SIZE_T size = 0U;
  InitializeProcThreadAttributeList(nullptr, 1U, 0U, &size);
  attributes.bytes.resize(size);
  attributes.value = reinterpret_cast<PPROC_THREAD_ATTRIBUTE_LIST>(attributes.bytes.data());
  if (!InitializeProcThreadAttributeList(attributes.value, 1U, 0U, &size)) return std::nullopt;
  const std::array inherited{ready_child.get(), shutdown_child.get()};
  if (!UpdateProcThreadAttribute(attributes.value, 0U, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                 const_cast<HANDLE*>(inherited.data()), sizeof(inherited),
                                 nullptr, nullptr)) return std::nullopt;
  std::wstring command = L"\"" + application->path + L"\" --session " + session +
      L" --expected-broker-pid " + std::to_wstring(GetCurrentProcessId()) +
      L" --ready-handle " + std::to_wstring(reinterpret_cast<std::uintptr_t>(ready_child.get())) +
      L" --shutdown-event-handle " +
      std::to_wstring(reinterpret_cast<std::uintptr_t>(shutdown_child.get()));
  std::array<wchar_t, MAX_PATH> windows{};
  const UINT windows_size = GetWindowsDirectoryW(windows.data(), static_cast<UINT>(windows.size()));
  if (windows_size == 0U || windows_size >= windows.size()) return std::nullopt;
  std::wstring environment = L"SystemRoot=" + std::wstring(windows.data(), windows_size) + L'\0' +
      L"WINDIR=" + std::wstring(windows.data(), windows_size) + L'\0' + L'\0';
  STARTUPINFOEXW startup{};
  startup.StartupInfo.cb = sizeof(startup);
  startup.lpAttributeList = attributes.value;
  PROCESS_INFORMATION raw{};
  if (!CreateProcessW(application->path.c_str(), command.data(), nullptr, nullptr, TRUE,
                      EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
                      environment.data(), application->directory_path.c_str(),
                      &startup.StartupInfo, &raw)) return std::nullopt;
  reviewer::UniqueHandle process(raw.hProcess);
  reviewer::UniqueHandle thread(raw.hThread);
  ready_child.reset();
  shutdown_child.reset();
  signing::PublicBlob blob{};
  if (!read_ready(ready_read.get(), process.get(), broker_shutdown, raw.dwProcessId, blob)) {
    SetEvent(shutdown.get());
    if (WaitForSingleObject(process.get(), 1000U) != WAIT_OBJECT_0) TerminateProcess(process.get(), 1U);
    return std::nullopt;
  }
  return ReviewerChild{std::move(process), std::move(shutdown), raw.dwProcessId, blob};
}

}
