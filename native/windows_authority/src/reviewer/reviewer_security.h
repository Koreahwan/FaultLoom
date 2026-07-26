#pragma once

#include <windows.h>

#include <cstdint>
#include <span>

namespace faultloom::reviewer {

[[nodiscard]] bool verify_reviewer_pipe_security(
    HANDLE pipe, PSECURITY_DESCRIPTOR creation_descriptor,
    std::span<const std::uint8_t> expected_sid) noexcept;

}
