#include "ctl_runtime.h"

#include <limits>
#include <string_view>

namespace faultloom::ctl {
namespace {

bool lower_hex(std::wstring_view value, std::span<std::uint8_t> output) noexcept {
  if (value.size() != output.size() * 2U) return false;
  for (std::size_t index = 0U; index < output.size(); ++index) {
    const auto digit = [](wchar_t character) -> int {
      if (character >= L'0' && character <= L'9') return character - L'0';
      if (character >= L'a' && character <= L'f') return character - L'a' + 10;
      return -1;
    };
    const int high = digit(value[index * 2U]);
    const int low = digit(value[index * 2U + 1U]);
    if (high < 0 || low < 0) return false;
    output[index] = static_cast<std::uint8_t>((high << 4) | low);
  }
  return true;
}

std::optional<DWORD> decimal(std::wstring_view value) noexcept {
  if (value.empty()) return std::nullopt;
  std::uint64_t result = 0U;
  for (const wchar_t character : value) {
    if (character < L'0' || character > L'9') return std::nullopt;
    result = result * 10U + static_cast<std::uint64_t>(character - L'0');
    if (result > std::numeric_limits<DWORD>::max()) return std::nullopt;
  }
  return result == 0U ? std::nullopt : std::optional<DWORD>(static_cast<DWORD>(result));
}

#ifdef FAULTLOOM_TEST_RAW
std::optional<std::vector<std::uint8_t>> raw_hex(std::wstring_view value) {
  if (value.empty() || value.size() % 2U != 0U ||
      value.size() / 2U > protocol::kMaxPayloadBytes) return std::nullopt;
  std::vector<std::uint8_t> output(value.size() / 2U);
  return lower_hex(value, output) ? std::optional<std::vector<std::uint8_t>>(std::move(output))
                                  : std::nullopt;
}
#endif

}

std::optional<Options> parse_options(int argc, wchar_t** argv) noexcept {
  if ((argc != 8 && argc != 10) || std::wstring_view(argv[1]) != L"--session" ||
      std::wstring_view(argv[3]) != L"--expected-broker-pid" ||
      std::wstring_view(argv[5]) != L"--reviewer-key-sha256") return std::nullopt;
  Options result{};
  result.session = argv[2];
  const auto pid = decimal(argv[4]);
  std::array<std::uint8_t, 16> session_bytes{};
  if (result.session.size() != 32U || !lower_hex(result.session, session_bytes) ||
      !pid.has_value() || !lower_hex(argv[6], result.key_hash)) return std::nullopt;
  result.broker_pid = *pid;
#ifdef FAULTLOOM_TEST_RAW
  if (argc == 10 && std::wstring_view(argv[7]) == L"raw" &&
      std::wstring_view(argv[8]) == L"--hex") {
    const auto raw = raw_hex(argv[9]);
    if (!raw.has_value()) return std::nullopt;
    result.action = protocol::Action::ping;
    result.raw_payload = *raw;
    return result;
  }
#endif
  if (argc == 8 && std::wstring_view(argv[7]) == L"ping") {
    result.action = protocol::Action::ping;
  } else if (argc == 10 && std::wstring_view(argv[7]) == L"query-service" &&
             std::wstring_view(argv[8]) == L"--name" &&
             (std::wstring_view(argv[9]) == L"BFE" || std::wstring_view(argv[9]) == L"EventLog" ||
              std::wstring_view(argv[9]) == L"WinDefend")) {
    result.action = protocol::Action::query_service_status;
    result.service = argv[9];
  } else {
    return std::nullopt;
  }
  return result;
}

}
