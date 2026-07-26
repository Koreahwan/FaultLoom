#pragma once

#include "faultloom/signer.h"

#include <windows.h>

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

namespace faultloom::reviewer {

struct Options {
  std::wstring session;
  std::uint32_t expected_broker_pid;
  HANDLE ready_handle;
  HANDLE shutdown_event;
};

[[nodiscard]] std::optional<Options> parse_options(int argc, wchar_t** argv) noexcept;
[[nodiscard]] int run(Options options, std::unique_ptr<signing::Signer> signer) noexcept;

}
