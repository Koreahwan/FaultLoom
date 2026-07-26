#pragma once

#include <windows.h>

#include "faultloom/protocol.h"

#include <optional>
#include <string>
#include <vector>

namespace faultloom::ctl {

struct Options {
  std::wstring session;
  DWORD broker_pid;
  protocol::Hash key_hash;
  protocol::Action action;
  std::wstring service;
#ifdef FAULTLOOM_TEST_RAW
  std::vector<std::uint8_t> raw_payload;
#endif
};

[[nodiscard]] std::optional<Options> parse_options(int argc, wchar_t** argv) noexcept;
[[nodiscard]] int run(const Options& options) noexcept;

}
