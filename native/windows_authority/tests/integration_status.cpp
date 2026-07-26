#include "integration_support.h"

#include <winsvc.h>

#include <charconv>
#include <iostream>

namespace faultloom::integration {
namespace {

bool parse_status(std::string_view output, std::vector<std::uint32_t>& fields) noexcept {
  constexpr std::string_view prefix = "SERVICE_STATUS ";
  if (!output.starts_with(prefix) || !output.ends_with("\r\n")) return false;
  std::string_view rest = output.substr(prefix.size(), output.size() - prefix.size() - 2U);
  std::vector<std::uint32_t> parsed_fields;
  for (std::size_t index = 0U; index < 9U; ++index) {
    const auto separator = rest.find(' ');
    if ((index != 8U && separator == std::string_view::npos) ||
        (index == 8U && separator != std::string_view::npos)) return false;
    const std::string_view token = rest.substr(0U, separator);
    std::uint32_t value = 0U;
    const auto parsed = std::from_chars(token.data(), token.data() + token.size(), value);
    if (token.empty() || parsed.ec != std::errc{} || parsed.ptr != token.data() + token.size()) {
      return false;
    }
    parsed_fields.push_back(value);
    if (separator != std::string_view::npos) rest.remove_prefix(separator + 1U);
  }
  fields = std::move(parsed_fields);
  return true;
}

bool valid_state_pid(const std::vector<std::uint32_t>& fields) noexcept {
  if (fields.size() != 9U) return false;
  const auto state = fields[1];
  const auto pid = fields[7];
  switch (state) {
    case SERVICE_STOPPED:
      return pid == 0U;
    case SERVICE_START_PENDING:
    case SERVICE_STOP_PENDING:
      return true;  // Windows does not define dwProcessId as valid in these states.
    case SERVICE_RUNNING:
    case SERVICE_CONTINUE_PENDING:
    case SERVICE_PAUSE_PENDING:
    case SERVICE_PAUSED:
      return pid != 0U;  // QueryServiceStatusEx documents dwProcessId as valid here.
    default:
      return false;
  }
}

Oracle status_oracle(std::uint32_t state, std::uint32_t pid) {
  Oracle oracle;
  oracle.start = "2";
  oracle.status = "OK";
  oracle.fields = {16U, state, 0U, 0U, 0U, 0U, 0U, pid, 0U};
  return oracle;
}

Child status_child(std::string output) {
  Child child;
  child.exit_code = 0U;
  child.captured = std::move(output);
  return child;
}

}

bool bracketed(const Oracle& before, const Oracle& after, const Child& ctl) noexcept {
  if (before.start != after.start) return false;
  if (ctl.exit_code == 7U) return ctl.captured == "ACTION_FAILED\r\n" &&
      before.status != "OK" && after.status != "OK";
  std::vector<std::uint32_t> result;
  if (before.status != "OK" || after.status != "OK" || !parse_status(ctl.captured, result) ||
      !valid_state_pid(before.fields) || !valid_state_pid(after.fields) ||
      !valid_state_pid(result)) return false;
  if (result == before.fields || result == after.fields) return true;
  return before.fields[1] != after.fields[1] &&
      result[0] == before.fields[0] && result[0] == after.fields[0] &&
      result[8] == before.fields[8] && result[8] == after.fields[8];
}

bool status_predicates_self_test() noexcept {
  bool passed = true;
  std::vector<std::uint32_t> parsed;
  if (parse_status("SERVICE_STATUS 16 4x 0 0 0 0 0 42 0\r\n", parsed)) {
    std::cerr << "partial service-status token accepted\n";
    passed = false;
  }
  auto running_zero = status_oracle(SERVICE_RUNNING, 0U);
  auto running_zero_ctl = status_child("SERVICE_STATUS 16 4 0 0 0 0 0 0 0\r\n");
  if (bracketed(running_zero, running_zero, running_zero_ctl)) {
    std::cerr << "running service with PID zero accepted\n";
    passed = false;
  }
  auto stopped_pid = status_oracle(SERVICE_STOPPED, 77U);
  auto stopped_pid_ctl = status_child("SERVICE_STATUS 16 1 0 0 0 0 0 77 0\r\n");
  if (bracketed(stopped_pid, stopped_pid, stopped_pid_ctl)) {
    std::cerr << "stopped service with nonzero PID accepted\n";
    passed = false;
  }
  auto unknown = status_oracle(99U, 42U);
  auto unknown_ctl = status_child("SERVICE_STATUS 16 99 0 0 0 0 0 42 0\r\n");
  if (bracketed(unknown, unknown, unknown_ctl)) {
    std::cerr << "unknown service state accepted\n";
    passed = false;
  }
  auto starting = status_oracle(SERVICE_START_PENDING, 0U);
  auto starting_ctl = status_child("SERVICE_STATUS 16 2 0 0 0 0 0 0 0\r\n");
  if (!bracketed(starting, starting, starting_ctl)) {
    std::cerr << "documented pending-state PID semantics rejected\n";
    passed = false;
  }
  auto running = status_oracle(SERVICE_RUNNING, 42U);
  auto unbracketed = status_child("SERVICE_STATUS 16 7 0 0 0 0 0 42 0\r\n");
  if (bracketed(running, running, unbracketed)) {
    std::cerr << "status transition without changing brackets accepted\n";
    passed = false;
  }
  auto stopped = status_oracle(SERVICE_STOPPED, 0U);
  auto transitioning = status_child("SERVICE_STATUS 16 3 0 0 0 0 0 42 0\r\n");
  if (!bracketed(running, stopped, transitioning)) {
    std::cerr << "valid status transition rejected\n";
    passed = false;
  }
  return passed;
}

}
