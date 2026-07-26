#pragma once

#include "faultloom/signer.h"
#include "unique_handle.h"

#include <optional>
#include <string>
#include <string_view>

namespace faultloom::broker {

struct ReviewerChild {
  reviewer::UniqueHandle process;
  reviewer::UniqueHandle shutdown;
  DWORD pid;
  signing::PublicBlob blob;
};

struct SiblingIdentity {
  std::wstring path;
  std::wstring directory_path;
  reviewer::UniqueHandle directory;
  reviewer::UniqueHandle file;
};

[[nodiscard]] std::optional<ReviewerChild> launch_reviewer(
    const std::wstring& session, HANDLE broker_shutdown) noexcept;
[[nodiscard]] bool parse_reviewer_ready(std::string_view line, DWORD expected_pid,
                                        signing::PublicBlob& blob) noexcept;
[[nodiscard]] std::optional<SiblingIdentity> open_sibling_identity(
    const std::wstring& directory, const std::wstring& filename) noexcept;

}
