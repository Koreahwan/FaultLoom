#pragma once

#include <windows.h>

namespace faultloom::broker {

[[nodiscard]] bool identity_live(HANDLE retained_process, DWORD expected_pid) noexcept;

}
