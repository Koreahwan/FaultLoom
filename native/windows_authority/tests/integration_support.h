#pragma once

#include <windows.h>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace faultloom::integration {

class Handle {
 public:
  Handle() = default;
  explicit Handle(HANDLE value) noexcept : value_(value) {}
  ~Handle() { reset(); }
  Handle(const Handle&) = delete;
  Handle& operator=(const Handle&) = delete;
  Handle(Handle&& other) noexcept : value_(other.release()) {}
  Handle& operator=(Handle&& other) noexcept {
    if (this != &other) reset(other.release());
    return *this;
  }
  explicit operator bool() const noexcept { return value_ != nullptr && value_ != INVALID_HANDLE_VALUE; }
  HANDLE get() const noexcept { return value_; }
  HANDLE release() noexcept { const HANDLE value = value_; value_ = nullptr; return value; }
  void reset(HANDLE value = nullptr) noexcept {
    if (*this) CloseHandle(value_);
    value_ = value;
  }

 private:
  HANDLE value_ = nullptr;
};

struct Child {
  Handle process;
  Handle thread;
  Handle output;
  DWORD pid = 0U;
  std::uint64_t creation_time = 0U;
  std::uint64_t peak_private_bytes = 0U;
  DWORD exit_code = STILL_ACTIVE;
  std::string captured;
};

struct Ready {
  std::string line;
  std::string session;
  std::string key_hash;
  DWORD broker_pid = 0U;
  DWORD reviewer_pid = 0U;
};

struct Broker {
  Child child;
  Handle shutdown;
  Handle reviewer;
  Ready ready;
  std::uint64_t reviewer_creation_time = 0U;
  std::uint64_t reviewer_peak_private_bytes = 0U;
  DWORD reviewer_exit_code = STILL_ACTIVE;
};

struct Oracle {
  std::string name;
  std::string start;
  std::string status;
  std::vector<std::uint32_t> fields;
  Child child;
};

class Job {
 public:
  bool create() noexcept;
  HANDLE get() const noexcept { return handle_.get(); }
 private:
  Handle handle_;
};

std::wstring sibling(std::wstring_view name);
std::optional<Child> launch(Job& job, const std::wstring& application,
                            const std::wstring& arguments,
                            const std::vector<HANDLE>& inherited = {},
                            bool capture = false) noexcept;
bool finish(Child& child, DWORD timeout_ms, DWORD expected_exit = 0U) noexcept;
bool peak_private(HANDLE process, std::uint64_t& bytes) noexcept;
bool snapshot(Child& child) noexcept;
std::optional<Broker> launch_broker(Job& job) noexcept;
bool stop_broker(Broker& broker) noexcept;
std::optional<Child> run_ctl(Job& job, const Ready& ready,
                             std::wstring_view action,
                             bool allow_action_failure = false) noexcept;
std::optional<Oracle> run_oracle(Job& job, std::wstring_view name) noexcept;
bool same_sid(HANDLE first, HANDLE second) noexcept;
bool pipe_absent(std::string_view kind, std::string_view session) noexcept;
bool pipe_absent_until(std::string_view kind, std::string_view session,
                       ULONGLONG deadline) noexcept;
bool bracketed(const Oracle& before, const Oracle& after, const Child& ctl) noexcept;
bool death_cleanup_within(ULONGLONG action_tick, ULONGLONG supervisor_tick,
                          ULONGLONG cleanup_tick) noexcept;
bool status_predicates_self_test() noexcept;
int predicate_self_test() noexcept;

int oracle_main(int argc, wchar_t** argv) noexcept;
int death_supervisor_main(std::uintptr_t report_handle) noexcept;
bool supervisor_death_case() noexcept;
int smoke_main() noexcept;

}
