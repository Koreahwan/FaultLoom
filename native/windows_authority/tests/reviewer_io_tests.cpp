#include "reviewer_io.h"

#include <windows.h>

#include <cstdint>
#include <iostream>

int main() {
  HANDLE shutdown = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  HANDLE broker = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  LARGE_INTEGER frequency{};
  LARGE_INTEGER now{};
  bool passed = shutdown != nullptr && broker != nullptr &&
                QueryPerformanceFrequency(&frequency) && QueryPerformanceCounter(&now);
  if (passed) {
    const auto hz = static_cast<std::uint64_t>(frequency.QuadPart);
    const auto tick = static_cast<std::uint64_t>(now.QuadPart);
    passed &= faultloom::reviewer::check_gate(shutdown, broker, tick + hz, hz) ==
              faultloom::reviewer::IoResult::complete;
    passed &= faultloom::reviewer::check_gate(shutdown, broker, tick, hz) ==
              faultloom::reviewer::IoResult::timeout;
    SetEvent(shutdown);
    passed &= faultloom::reviewer::check_gate(shutdown, broker, tick, hz) ==
              faultloom::reviewer::IoResult::stopped;
    passed &= faultloom::reviewer::resolve_immediate_error(shutdown, broker, tick, hz) ==
              faultloom::reviewer::IoResult::stopped;
    passed &= faultloom::reviewer::connect_client(INVALID_HANDLE_VALUE, shutdown, broker) ==
              faultloom::reviewer::IoResult::stopped;
    passed &= faultloom::reviewer::await_client_close(
                  INVALID_HANDLE_VALUE, shutdown, broker, tick, hz) ==
              faultloom::reviewer::IoResult::stopped;
    passed &= faultloom::reviewer::check_gate(shutdown, broker, tick + hz, hz) ==
              faultloom::reviewer::IoResult::stopped;
    ResetEvent(shutdown);
    SetEvent(broker);
    passed &= faultloom::reviewer::check_gate(shutdown, broker, tick + hz, hz) ==
              faultloom::reviewer::IoResult::stopped;
  }
  if (broker != nullptr) CloseHandle(broker);
  if (shutdown != nullptr) CloseHandle(shutdown);
  if (!passed) std::cerr << "Reviewer deadline/revocation gate failed\n";
  return passed ? 0 : 1;
}
