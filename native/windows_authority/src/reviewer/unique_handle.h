#pragma once

#include <windows.h>

namespace faultloom::reviewer {

class UniqueHandle {
 public:
  UniqueHandle() = default;
  explicit UniqueHandle(HANDLE value) noexcept : value_(value) {}
  ~UniqueHandle() { reset(); }
  UniqueHandle(const UniqueHandle&) = delete;
  UniqueHandle& operator=(const UniqueHandle&) = delete;
  UniqueHandle(UniqueHandle&& other) noexcept : value_(other.release()) {}
  UniqueHandle& operator=(UniqueHandle&& other) noexcept {
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

}
