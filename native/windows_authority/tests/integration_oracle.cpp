#include "integration_support.h"

#include <winsvc.h>

#include <array>
#include <charconv>
#include <iostream>
#include <sstream>

namespace faultloom::integration {
namespace {

class ServiceHandle {
 public:
  explicit ServiceHandle(SC_HANDLE value) noexcept : value_(value) {}
  ~ServiceHandle() { if (value_ != nullptr) CloseServiceHandle(value_); }
  ServiceHandle(const ServiceHandle&) = delete;
  ServiceHandle& operator=(const ServiceHandle&) = delete;
  explicit operator bool() const noexcept { return value_ != nullptr; }
  SC_HANDLE get() const noexcept { return value_; }

 private:
  SC_HANDLE value_ = nullptr;
};

std::string error_name(DWORD error) {
  if (error == ERROR_SERVICE_DOES_NOT_EXIST) return "NOT_FOUND";
  if (error == ERROR_ACCESS_DENIED) return "ACCESS_DENIED";
  return "ERROR_" + std::to_string(error);
}

std::string narrow(std::wstring_view value) {
  std::string output;
  output.reserve(value.size());
  for (const wchar_t character : value) output.push_back(static_cast<char>(character));
  return output;
}

std::optional<std::vector<std::uint8_t>> sid(HANDLE process) noexcept {
  Handle token;
  HANDLE raw = nullptr;
  if (!OpenProcessToken(process, TOKEN_QUERY, &raw)) return std::nullopt;
  token.reset(raw);
  DWORD needed = 0U;
  GetTokenInformation(token.get(), TokenUser, nullptr, 0U, &needed);
  if (needed == 0U || needed > 65536U) return std::nullopt;
  std::vector<std::uint8_t> storage(needed);
  if (!GetTokenInformation(token.get(), TokenUser, storage.data(), needed, &needed)) return std::nullopt;
  const auto* user = reinterpret_cast<const TOKEN_USER*>(storage.data());
  if (!IsValidSid(user->User.Sid)) return std::nullopt;
  const DWORD length = GetLengthSid(user->User.Sid);
  std::vector<std::uint8_t> result(length);
  if (!CopySid(length, result.data(), user->User.Sid)) return std::nullopt;
  return result;
}

std::optional<std::uint32_t> number(std::string_view value) noexcept {
  std::uint32_t output = 0U;
  const auto parsed = std::from_chars(value.data(), value.data() + value.size(), output);
  return parsed.ec == std::errc{} && parsed.ptr == value.data() + value.size()
      ? std::optional<std::uint32_t>(output) : std::nullopt;
}

std::optional<std::string> item(std::string_view line, std::string_view key) {
  const auto begin = line.find(key);
  if (begin == std::string_view::npos) return std::nullopt;
  const auto value = begin + key.size();
  const auto end = line.find_first_of(" \r\n", value);
  return std::string(line.substr(value, end - value));
}

}

bool same_sid(HANDLE first, HANDLE second) noexcept {
  const auto one = sid(first);
  const auto two = sid(second);
  return one && two && *one == *two;
}

int oracle_main(int argc, wchar_t** argv) noexcept {
  if (argc != 3 || std::wstring_view(argv[1]) != L"--oracle") return 2;
  const std::wstring name(argv[2]);
  if (name != L"BFE" && name != L"EventLog" && name != L"WinDefend") return 2;
  ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
  if (!manager) {
    std::cout << "ORACLE name=" << narrow(name)
              << " start=" << error_name(GetLastError())
              << " status=" << error_name(GetLastError()) << '\n';
    return 0;
  }
  ServiceHandle config(OpenServiceW(manager.get(), name.c_str(), SERVICE_QUERY_CONFIG));
  std::string start;
  if (!config) {
    start = error_name(GetLastError());
  } else {
    DWORD needed = 0U;
    QueryServiceConfigW(config.get(), nullptr, 0U, &needed);
    if (needed == 0U || needed > 65536U) return 3;
    std::vector<std::uint8_t> buffer(needed);
    auto* query = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data());
    if (!QueryServiceConfigW(config.get(), query, needed, &needed)) return 3;
    start = std::to_string(query->dwStartType);
  }
  ServiceHandle status_handle(OpenServiceW(manager.get(), name.c_str(), SERVICE_QUERY_STATUS));
  if (!status_handle) {
    std::cout << "ORACLE name=" << narrow(name) << " start=" << start
              << " status=" << error_name(GetLastError()) << '\n';
    return 0;
  }
  SERVICE_STATUS_PROCESS status{};
  DWORD returned = 0U;
  if (!QueryServiceStatusEx(status_handle.get(), SC_STATUS_PROCESS_INFO,
                            reinterpret_cast<BYTE*>(&status), sizeof(status), &returned) ||
      returned != sizeof(status)) return 3;
  std::cout << "ORACLE name=" << narrow(name) << " start=" << start
            << " status=OK fields=" << status.dwServiceType << ',' << status.dwCurrentState << ','
            << status.dwControlsAccepted << ',' << status.dwWin32ExitCode << ','
            << status.dwServiceSpecificExitCode << ',' << status.dwCheckPoint << ','
            << status.dwWaitHint << ',' << status.dwProcessId << ',' << status.dwServiceFlags << '\n';
  return 0;
}

std::optional<Oracle> run_oracle(Job& job, std::wstring_view name) noexcept {
  const auto application = sibling(L"faultloom_integration_tests.exe");
  auto child = launch(job, application, L" --oracle " + std::wstring(name), {}, true);
  if (!child || !finish(*child, 10000U, 0U)) return std::nullopt;
  Oracle result;
  result.name = narrow(name);
  result.child = std::move(*child);
  const auto start = item(result.child.captured, "start=");
  const auto status = item(result.child.captured, "status=");
  if (!start || !status || !result.child.captured.starts_with("ORACLE name=" + result.name + " ")) {
    return std::nullopt;
  }
  result.start = *start;
  result.status = *status;
  const auto fields = item(result.child.captured, "fields=");
  if (result.status == "OK") {
    if (!fields) return std::nullopt;
    std::string_view remaining(*fields);
    while (!remaining.empty()) {
      const auto comma = remaining.find(',');
      const auto value = number(remaining.substr(0U, comma));
      if (!value) return std::nullopt;
      result.fields.push_back(*value);
      if (comma == std::string_view::npos) break;
      remaining.remove_prefix(comma + 1U);
    }
    if (result.fields.size() != 9U) return std::nullopt;
  } else if (fields) {
    return std::nullopt;
  }
  return result;
}

}
