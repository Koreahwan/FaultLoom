#pragma once

#include "unique_handle.h"

#include <cstdint>
#include <span>

namespace faultloom::reviewer {

enum class IoResult : std::uint8_t { complete, failed, stopped, timeout };

[[nodiscard]] IoResult check_gate(HANDLE shutdown, HANDLE broker,
                                  std::uint64_t deadline, std::uint64_t frequency) noexcept;
[[nodiscard]] IoResult resolve_immediate_error(HANDLE shutdown, HANDLE broker,
                                               std::uint64_t deadline,
                                               std::uint64_t frequency) noexcept;
[[nodiscard]] IoResult connect_client(HANDLE pipe, HANDLE shutdown, HANDLE broker) noexcept;
[[nodiscard]] IoResult read_exact(HANDLE pipe, std::span<std::uint8_t> output,
                                  HANDLE shutdown, HANDLE broker, std::uint64_t deadline,
                                  std::uint64_t frequency) noexcept;
[[nodiscard]] IoResult write_exact(HANDLE pipe, std::span<const std::uint8_t> input,
                                   HANDLE shutdown, HANDLE broker, std::uint64_t deadline,
                                   std::uint64_t frequency) noexcept;
[[nodiscard]] IoResult await_client_close(HANDLE pipe, HANDLE shutdown, HANDLE broker,
                                          std::uint64_t deadline,
                                          std::uint64_t frequency) noexcept;

}
