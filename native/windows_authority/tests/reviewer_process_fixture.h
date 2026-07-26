#pragma once

#include "faultloom/protocol.h"
#include "faultloom/signer.h"

#include <windows.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace faultloom::test {

class TestHandle final {
 public:
  TestHandle() noexcept = default;
  explicit TestHandle(HANDLE value) noexcept : value_(value) {}
  ~TestHandle() { reset(); }
  TestHandle(const TestHandle&) = delete;
  TestHandle& operator=(const TestHandle&) = delete;
  TestHandle(TestHandle&& other) noexcept : value_(other.release()) {}
  TestHandle& operator=(TestHandle&& other) noexcept {
    if (this != &other) reset(other.release());
    return *this;
  }
  [[nodiscard]] HANDLE get() const noexcept { return value_; }
  [[nodiscard]] explicit operator bool() const noexcept {
    return value_ != nullptr && value_ != INVALID_HANDLE_VALUE;
  }
  [[nodiscard]] HANDLE release() noexcept {
    const HANDLE value = value_;
    value_ = nullptr;
    return value;
  }
  void reset(HANDLE value = nullptr) noexcept {
    if (*this) CloseHandle(value_);
    value_ = value;
  }

 private:
  HANDLE value_ = nullptr;
};

struct ReadyLine {
  std::uint32_t pid;
  signing::PublicBlob public_blob;
};

struct ReviewRecord {
  std::vector<std::uint8_t> payload;
  std::vector<std::uint8_t> record;
  std::size_t sid_offset;
  std::size_t client_offset;
};

class ReviewerProcess final {
 public:
  static std::optional<ReviewerProcess> launch(std::wstring session, std::uint32_t broker_pid);
  ReviewerProcess(ReviewerProcess&&) noexcept = default;
  ReviewerProcess& operator=(ReviewerProcess&&) noexcept = default;
  ReviewerProcess(const ReviewerProcess&) = delete;
  ReviewerProcess& operator=(const ReviewerProcess&) = delete;
  ~ReviewerProcess();

  [[nodiscard]] const ReadyLine& ready() const noexcept { return ready_; }
  [[nodiscard]] const std::wstring& pipe_name() const noexcept { return pipe_name_; }
  [[nodiscard]] bool wait_for_exit(DWORD timeout) const noexcept;
  [[nodiscard]] bool stop() noexcept;

 private:
  ReviewerProcess() noexcept = default;
  TestHandle process_;
  TestHandle shutdown_;
  ReadyLine ready_{};
  std::wstring pipe_name_;
};

[[nodiscard]] std::optional<std::vector<std::uint8_t>> current_sid();
[[nodiscard]] std::optional<ReviewRecord> make_review(protocol::Action action,
                                                      std::string service = {},
                                                      std::int64_t deadline_seconds = 4);
[[nodiscard]] std::optional<std::vector<std::uint8_t>> exchange(
    const std::wstring& pipe_name, std::span<const std::uint8_t> request);
[[nodiscard]] bool send_short(const std::wstring& pipe_name,
                              std::span<const std::uint8_t> request) noexcept;
[[nodiscard]] bool verify_decision(const ReadyLine& ready, const ReviewRecord& review,
                                   std::span<const std::uint8_t> response) noexcept;
[[nodiscard]] std::wstring sibling_reviewer();
[[nodiscard]] std::wstring sibling_test();
[[nodiscard]] bool launch_and_wait(std::wstring command, DWORD expected_exit) noexcept;
[[nodiscard]] bool launch_reviewer_failure(std::wstring session, std::uint32_t broker_pid,
                                           DWORD expected_exit) noexcept;

}
