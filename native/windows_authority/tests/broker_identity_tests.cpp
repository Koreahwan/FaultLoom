#include "client_identity.h"
#include "reviewer_process_fixture.h"

#include <windows.h>

#include <iostream>

namespace {

std::optional<PROCESS_INFORMATION> suspended_exit_process() {
  std::wstring command = L"cmd.exe /d /c exit 0";
  STARTUPINFOW startup{sizeof(startup)};
  PROCESS_INFORMATION process{};
  return CreateProcessW(nullptr, command.data(), nullptr, nullptr, FALSE, CREATE_SUSPENDED,
                        nullptr, nullptr, &startup, &process)
      ? std::optional<PROCESS_INFORMATION>(process) : std::nullopt;
}

}

int main() {
  auto first = suspended_exit_process();
  bool passed = first.has_value();
  if (!first.has_value()) return 1;
  faultloom::test::TestHandle first_process(first->hProcess);
  faultloom::test::TestHandle first_thread(first->hThread);
  passed &= faultloom::broker::identity_live(first_process.get(), first->dwProcessId);
  ResumeThread(first_thread.get());
  passed &= WaitForSingleObject(first_process.get(), 5000U) == WAIT_OBJECT_0;
  passed &= !faultloom::broker::identity_live(first_process.get(), first->dwProcessId);
  auto replacement = suspended_exit_process();
  passed &= replacement.has_value();
  if (replacement.has_value()) {
    faultloom::test::TestHandle replacement_process(replacement->hProcess);
    faultloom::test::TestHandle replacement_thread(replacement->hThread);
    passed &= !faultloom::broker::identity_live(replacement_process.get(), first->dwProcessId);
    ResumeThread(replacement_thread.get());
    WaitForSingleObject(replacement_process.get(), 5000U);
  }
  if (!passed) std::cerr << "retained client exit/PID-reuse identity contract failed\n";
  return passed ? 0 : 1;
}
