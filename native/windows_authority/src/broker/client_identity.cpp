#include "client_identity.h"

namespace faultloom::broker {

bool identity_live(HANDLE retained_process, DWORD expected_pid) noexcept {
  return retained_process != nullptr && expected_pid != 0U &&
         GetProcessId(retained_process) == expected_pid &&
         WaitForSingleObject(retained_process, 0U) == WAIT_TIMEOUT;
}

}
