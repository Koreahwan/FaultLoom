#include "reviewer_io.h"

#include <algorithm>
#include <array>
#include <limits>
#include <type_traits>

namespace faultloom::reviewer {
namespace {

constexpr DWORD kCancellationBoundMs = 1000U;

DWORD remaining_ms(std::uint64_t deadline, std::uint64_t frequency) noexcept {
  LARGE_INTEGER now{};
  if (frequency == 0U || !QueryPerformanceCounter(&now) ||
      static_cast<std::uint64_t>(now.QuadPart) >= deadline) return 0U;
  const std::uint64_t ticks = deadline - static_cast<std::uint64_t>(now.QuadPart);
  const std::uint64_t milliseconds = (ticks * 1000U + frequency - 1U) / frequency;
  return static_cast<DWORD>(std::min<std::uint64_t>(milliseconds,
                                                    std::numeric_limits<DWORD>::max() - 1U));
}

[[noreturn]] void abort_stuck_cancellation() noexcept {
  TerminateProcess(GetCurrentProcess(), ERROR_OPERATION_ABORTED);
  std::terminate();
}

void cancel_and_retire(HANDLE pipe, OVERLAPPED& operation) noexcept {
  CancelIoEx(pipe, &operation);
  if (WaitForSingleObject(operation.hEvent, kCancellationBoundMs) != WAIT_OBJECT_0) {
    abort_stuck_cancellation();
  }
  DWORD transferred = 0U;
  GetOverlappedResult(pipe, &operation, &transferred, FALSE);
}

IoResult finish(HANDLE pipe, OVERLAPPED& operation, HANDLE shutdown, HANDLE broker,
                std::uint64_t deadline, std::uint64_t frequency, DWORD& transferred,
                bool eof_is_complete) noexcept {
  const IoResult initial = check_gate(shutdown, broker, deadline, frequency);
  if (initial != IoResult::complete) {
    cancel_and_retire(pipe, operation);
    return initial;
  }
  const std::array handles{shutdown, broker, operation.hEvent};
  const DWORD timeout = deadline == 0U ? INFINITE : remaining_ms(deadline, frequency);
  const DWORD wait = WaitForMultipleObjects(static_cast<DWORD>(handles.size()), handles.data(), FALSE, timeout);
  if (wait == WAIT_OBJECT_0 || wait == WAIT_OBJECT_0 + 1U) {
    cancel_and_retire(pipe, operation);
    return IoResult::stopped;
  }
  if (wait == WAIT_TIMEOUT) {
    cancel_and_retire(pipe, operation);
    return IoResult::timeout;
  }
  if (wait != WAIT_OBJECT_0 + 2U) {
    cancel_and_retire(pipe, operation);
    return IoResult::failed;
  }
  const IoResult before_completion = check_gate(shutdown, broker, deadline, frequency);
  const BOOL completed = GetOverlappedResult(pipe, &operation, &transferred, FALSE);
  const DWORD error = completed ? ERROR_SUCCESS : GetLastError();
  if (before_completion != IoResult::complete) return before_completion;
  const IoResult after_completion = check_gate(shutdown, broker, deadline, frequency);
  if (after_completion != IoResult::complete) return after_completion;
  if (completed) return IoResult::complete;
  return eof_is_complete && (error == ERROR_BROKEN_PIPE || error == ERROR_NO_DATA)
             ? IoResult::complete
             : IoResult::failed;
}

template <typename Buffer>
IoResult transfer(HANDLE pipe, Buffer buffer, HANDLE shutdown, HANDLE broker,
                  std::uint64_t deadline, std::uint64_t frequency) noexcept {
  std::size_t offset = 0U;
  while (offset < buffer.size()) {
    const IoResult before = check_gate(shutdown, broker, deadline, frequency);
    if (before != IoResult::complete) return before;
    UniqueHandle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!event) return IoResult::failed;
    OVERLAPPED operation{};
    operation.hEvent = event.get();
    DWORD transferred = 0U;
    const DWORD requested = static_cast<DWORD>(buffer.size() - offset);
    BOOL started = FALSE;
    if constexpr (std::is_const_v<typename Buffer::element_type>) {
      started = WriteFile(pipe, buffer.data() + offset, requested, &transferred, &operation);
    } else {
      started = ReadFile(pipe, buffer.data() + offset, requested, &transferred, &operation);
    }
    if (!started && GetLastError() != ERROR_IO_PENDING) {
      const IoResult gate = check_gate(shutdown, broker, deadline, frequency);
      return gate == IoResult::complete ? IoResult::failed : gate;
    }
    if (!started) {
      const IoResult result = finish(pipe, operation, shutdown, broker, deadline, frequency,
                                     transferred, false);
      if (result != IoResult::complete) return result;
    } else {
      const IoResult after = check_gate(shutdown, broker, deadline, frequency);
      if (after != IoResult::complete) return after;
    }
    if (transferred == 0U) return IoResult::failed;
    offset += transferred;
  }
  return check_gate(shutdown, broker, deadline, frequency);
}

}

IoResult check_gate(HANDLE shutdown, HANDLE broker, std::uint64_t deadline,
                    std::uint64_t frequency) noexcept {
  const DWORD shutdown_state = WaitForSingleObject(shutdown, 0U);
  const DWORD broker_state = WaitForSingleObject(broker, 0U);
  if (shutdown_state == WAIT_OBJECT_0 || broker_state == WAIT_OBJECT_0) return IoResult::stopped;
  if (shutdown_state != WAIT_TIMEOUT || broker_state != WAIT_TIMEOUT) return IoResult::failed;
  if (deadline == 0U) return IoResult::complete;
  LARGE_INTEGER now{};
  if (frequency == 0U || !QueryPerformanceCounter(&now)) return IoResult::failed;
  return static_cast<std::uint64_t>(now.QuadPart) >= deadline ? IoResult::timeout
                                                              : IoResult::complete;
}

IoResult resolve_immediate_error(HANDLE shutdown, HANDLE broker, std::uint64_t deadline,
                                 std::uint64_t frequency) noexcept {
  const IoResult gate = check_gate(shutdown, broker, deadline, frequency);
  return gate == IoResult::complete ? IoResult::failed : gate;
}

IoResult connect_client(HANDLE pipe, HANDLE shutdown, HANDLE broker) noexcept {
  const IoResult before = check_gate(shutdown, broker, 0U, 0U);
  if (before != IoResult::complete) return before;
  UniqueHandle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  if (!event) return IoResult::failed;
  OVERLAPPED operation{};
  operation.hEvent = event.get();
  if (ConnectNamedPipe(pipe, &operation)) return check_gate(shutdown, broker, 0U, 0U);
  const DWORD error = GetLastError();
  if (error == ERROR_PIPE_CONNECTED) return check_gate(shutdown, broker, 0U, 0U);
  if (error != ERROR_IO_PENDING) {
    return resolve_immediate_error(shutdown, broker, 0U, 0U);
  }
  DWORD transferred = 0U;
  return finish(pipe, operation, shutdown, broker, 0U, 0U, transferred, false);
}

IoResult read_exact(HANDLE pipe, std::span<std::uint8_t> output, HANDLE shutdown,
                    HANDLE broker, std::uint64_t deadline, std::uint64_t frequency) noexcept {
  return transfer(pipe, output, shutdown, broker, deadline, frequency);
}

IoResult write_exact(HANDLE pipe, std::span<const std::uint8_t> input, HANDLE shutdown,
                     HANDLE broker, std::uint64_t deadline, std::uint64_t frequency) noexcept {
  return transfer(pipe, input, shutdown, broker, deadline, frequency);
}

IoResult await_client_close(HANDLE pipe, HANDLE shutdown, HANDLE broker,
                            std::uint64_t deadline, std::uint64_t frequency) noexcept {
  const IoResult before = check_gate(shutdown, broker, deadline, frequency);
  if (before != IoResult::complete) return before;
  UniqueHandle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  if (!event) return IoResult::failed;
  OVERLAPPED operation{};
  operation.hEvent = event.get();
  std::uint8_t extra = 0U;
  DWORD transferred = 0U;
  if (ReadFile(pipe, &extra, 1U, &transferred, &operation)) {
    const IoResult after = check_gate(shutdown, broker, deadline, frequency);
    return after == IoResult::complete && transferred == 0U ? IoResult::complete
                                                             : after == IoResult::complete
                                                                   ? IoResult::failed
                                                                   : after;
  }
  const DWORD error = GetLastError();
  if (error == ERROR_BROKEN_PIPE || error == ERROR_NO_DATA) {
    return check_gate(shutdown, broker, deadline, frequency);
  }
  if (error != ERROR_IO_PENDING) {
    return resolve_immediate_error(shutdown, broker, deadline, frequency);
  }
  const IoResult result = finish(pipe, operation, shutdown, broker, deadline, frequency,
                                 transferred, true);
  return result == IoResult::complete && transferred != 0U ? IoResult::failed : result;
}

}
