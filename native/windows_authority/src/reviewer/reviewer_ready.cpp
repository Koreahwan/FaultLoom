#include "reviewer_ready.h"

#include "unique_handle.h"

#include <algorithm>
#include <array>
#include <string>

namespace faultloom::reviewer {
namespace {

constexpr DWORD kReadinessBoundMs = 5000U;
constexpr DWORD kCancellationBoundMs = 1000U;

std::string hex(std::span<const std::uint8_t> value) {
  constexpr char digits[] = "0123456789abcdef";
  std::string result(value.size() * 2U, '0');
  for (std::size_t index = 0U; index < value.size(); ++index) {
    result[index * 2U] = digits[value[index] >> 4U];
    result[index * 2U + 1U] = digits[value[index] & 15U];
  }
  return result;
}

struct WriteContext {
  HANDLE ready;
  const std::string* line;
  DWORD written = 0U;
  BOOL succeeded = FALSE;
};

DWORD WINAPI write_line(void* raw) noexcept {
  auto& context = *static_cast<WriteContext*>(raw);
  context.succeeded = WriteFile(context.ready, context.line->data(),
                                static_cast<DWORD>(context.line->size()),
                                &context.written, nullptr);
  return 0U;
}

[[noreturn]] void abort_stuck_writer() noexcept {
  TerminateProcess(GetCurrentProcess(), ERROR_OPERATION_ABORTED);
  std::terminate();
}

void cancel_and_retire(HANDLE thread) noexcept {
  CancelSynchronousIo(thread);
  if (WaitForSingleObject(thread, kCancellationBoundMs) != WAIT_OBJECT_0) {
    abort_stuck_writer();
  }
}

}

IoResult report_ready(HANDLE ready, HANDLE shutdown, HANDLE broker,
                      const signing::PublicBlob& blob) noexcept {
  const IoResult before = check_gate(shutdown, broker, 0U, 0U);
  if (before != IoResult::complete) return before;
  const std::string line = "REVIEWER_READY v1 reviewer_pid=" +
                           std::to_string(GetCurrentProcessId()) + " public_blob=" +
                           hex(blob) + "\n";
  if (line.size() > 199U) return IoResult::failed;
  WriteContext context{ready, &line};
  UniqueHandle thread(CreateThread(nullptr, 0U, write_line, &context, 0U, nullptr));
  if (!thread) return IoResult::failed;
  const std::array handles{shutdown, broker, thread.get()};
  const DWORD wait = WaitForMultipleObjects(static_cast<DWORD>(handles.size()), handles.data(),
                                             FALSE, kReadinessBoundMs);
  if (wait == WAIT_OBJECT_0 || wait == WAIT_OBJECT_0 + 1U) {
    cancel_and_retire(thread.get());
    return IoResult::stopped;
  }
  if (wait == WAIT_TIMEOUT) {
    cancel_and_retire(thread.get());
    return IoResult::failed;
  }
  if (wait != WAIT_OBJECT_0 + 2U) {
    cancel_and_retire(thread.get());
    return IoResult::failed;
  }
  const IoResult after = check_gate(shutdown, broker, 0U, 0U);
  if (after != IoResult::complete) return after;
  return context.succeeded && context.written == line.size() ? IoResult::complete
                                                              : IoResult::failed;
}

}
