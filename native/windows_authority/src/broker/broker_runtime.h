#pragma once

#include <windows.h>

#include <optional>

namespace faultloom::broker {

struct Options {
  HANDLE ready_handle;
  HANDLE shutdown_event;
};

[[nodiscard]] std::optional<Options> parse_options(int argc, wchar_t** argv) noexcept;
[[nodiscard]] int run(Options options) noexcept;

}
