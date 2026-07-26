#include "integration_support.h"

#include <cstdio>
#include <iostream>

namespace faultloom::integration {
namespace {

bool process_peak_cases() noexcept {
  Job job;
  if (!job.create()) return false;
  const auto application = sibling(L"faultloom_integration_tests.exe");
  auto fast = launch(job, application, L" --fast-exit");
  if (!fast || !finish(*fast, 10000U) || fast->peak_private_bytes <= 1U) {
    std::cerr << "fast-exit OS peak was not retained\n";
    return false;
  }
  auto over = launch(job, application, L" --memory-over-limit");
  if (!over || finish(*over, 10000U)) {
    std::cerr << "released >128 MiB peak was accepted\n";
    return false;
  }
  return over->peak_private_bytes >= 128ULL * 1024ULL * 1024ULL;
}

bool busy_pipe_case() noexcept {
  char session_buffer[33]{};
  const int count = std::snprintf(session_buffer, sizeof(session_buffer), "%016llx%016llx",
                                  static_cast<unsigned long long>(GetCurrentProcessId()),
                                  static_cast<unsigned long long>(GetTickCount64()));
  if (count != 32) return false;
  const std::string session(session_buffer);
  const std::wstring name = L"\\\\.\\pipe\\FaultLoom.Broker.MVP.v1." +
      std::wstring(session.begin(), session.end());
  Handle server(CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                                 PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1U,
                                 4096U, 4096U, 0U, nullptr));
  Handle client(server ? CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0U, nullptr,
                                     OPEN_EXISTING, 0U, nullptr) : INVALID_HANDLE_VALUE);
  if (!server || !client) return false;
  if (pipe_absent("Broker", session)) {
    std::cerr << "busy named pipe was reported absent\n";
    return false;
  }
  client.reset();
  server.reset();
  if (!pipe_absent("Broker", session)) {
    std::cerr << "removed named pipe did not recover to absent\n";
    return false;
  }
  return true;
}

}

int predicate_self_test() noexcept {
  bool passed = true;
  if (!process_peak_cases()) passed = false;
  if (!busy_pipe_case()) passed = false;
  if (death_cleanup_within(1000U, 10999U, 20998U)) {
    std::cerr << "near-20-second death cleanup was accepted\n";
    passed = false;
  }
  if (!death_cleanup_within(1000U, 10500U, 10999U)) {
    std::cerr << "sub-10-second death cleanup was rejected\n";
    passed = false;
  }
  if (!status_predicates_self_test()) passed = false;
  return passed ? 0 : 1;
}

}
