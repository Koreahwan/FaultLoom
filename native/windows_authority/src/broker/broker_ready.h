#pragma once

#include <windows.h>

#include <string_view>

namespace faultloom::broker {

[[nodiscard]] bool write_ready(HANDLE ready, HANDLE shutdown, HANDLE reviewer,
                               std::string_view line) noexcept;

}
