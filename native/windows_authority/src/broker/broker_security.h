#pragma once

#include "unique_handle.h"

#include <optional>
#include <span>
#include <string>
#include <vector>

namespace faultloom::broker {

[[nodiscard]] std::optional<std::vector<std::uint8_t>> current_sid() noexcept;
[[nodiscard]] std::optional<std::wstring> random_session() noexcept;
[[nodiscard]] std::optional<DWORD> client_pipe_mode(bool reject_remote) noexcept;
[[nodiscard]] std::optional<reviewer::UniqueHandle> create_client_pipe(
    const std::wstring& session, std::span<const std::uint8_t> sid) noexcept;

}
