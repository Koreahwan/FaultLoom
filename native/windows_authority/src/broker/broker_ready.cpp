#include "broker_ready.h"

#include "unique_handle.h"

#include <array>

namespace faultloom::broker {
namespace {

struct Context { HANDLE ready; std::string_view line; DWORD written; BOOL ok; };

DWORD WINAPI writer(void* raw) noexcept {
  auto& context = *static_cast<Context*>(raw);
  context.ok = WriteFile(context.ready, context.line.data(),
                         static_cast<DWORD>(context.line.size()), &context.written, nullptr);
  return 0U;
}

}

bool write_ready(HANDLE ready, HANDLE shutdown, HANDLE reviewer,
                 std::string_view line) noexcept {
  if (line.size() > 192U || WaitForSingleObject(shutdown, 0U) != WAIT_TIMEOUT ||
      WaitForSingleObject(reviewer, 0U) != WAIT_TIMEOUT) return false;
  Context context{ready, line, 0U, FALSE};
  reviewer::UniqueHandle thread(CreateThread(nullptr, 0U, writer, &context, 0U, nullptr));
  if (!thread) return false;
  const std::array handles{shutdown, reviewer, thread.get()};
  const DWORD wait = WaitForMultipleObjects(static_cast<DWORD>(handles.size()), handles.data(),
                                             FALSE, 5000U);
  if (wait != WAIT_OBJECT_0 + 2U) {
    CancelSynchronousIo(thread.get());
    if (WaitForSingleObject(thread.get(), 1000U) != WAIT_OBJECT_0) {
      TerminateProcess(GetCurrentProcess(), ERROR_OPERATION_ABORTED);
    }
    return false;
  }
  return context.ok && context.written == line.size() &&
         WaitForSingleObject(shutdown, 0U) == WAIT_TIMEOUT &&
         WaitForSingleObject(reviewer, 0U) == WAIT_TIMEOUT;
}

}
