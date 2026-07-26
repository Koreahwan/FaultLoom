#pragma once

#include "faultloom/protocol.h"
#include "unique_handle.h"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace faultloom::reviewer {

struct BrokerIdentity {
  UniqueHandle process;
  std::vector<std::uint8_t> sid;
};

[[nodiscard]] std::optional<std::vector<std::uint8_t>> process_sid(HANDLE process) noexcept;
[[nodiscard]] std::optional<BrokerIdentity> retain_broker(std::uint32_t pid) noexcept;
[[nodiscard]] std::optional<UniqueHandle> create_reviewer_pipe(const std::wstring& session,
                                                               std::span<const std::uint8_t> sid) noexcept;

}
