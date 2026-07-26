#include "faultloom/signer.h"
#include "fake_signer.h"
#include "reviewer_runtime.h"

#include <windows.h>

#include <array>
#include <iostream>
#include <string>
#include <vector>

namespace {

std::optional<faultloom::reviewer::Options> parse(std::vector<std::wstring>& values) {
  std::vector<wchar_t*> arguments;
  arguments.reserve(values.size());
  for (auto& value : values) arguments.push_back(value.data());
  return faultloom::reviewer::parse_options(static_cast<int>(arguments.size()), arguments.data());
}

}

int main() {
  bool passed = faultloom::signing::public_blob_bytes() == 72U;
  const std::array<std::uint8_t, 32> digest{1U};
  auto fake_one = faultloom::test::make_fake_signer();
  auto fake_two = faultloom::test::make_fake_signer();
  passed &= fake_one->public_blob() == fake_two->public_blob();
  passed &= fake_one->sign(digest) == fake_two->sign(digest);
  auto production_one = faultloom::signing::make_ephemeral_signer();
  auto production_two = faultloom::signing::make_ephemeral_signer();
  passed &= production_one != nullptr && production_two != nullptr;
  if (production_one != nullptr && production_two != nullptr) {
    passed &= production_one->public_blob() != production_two->public_blob();
    passed &= production_one->public_blob() != fake_one->public_blob();
    passed &= production_one->sign(digest).has_value();
  }
  HANDLE ready_read = nullptr;
  HANDLE ready_write = nullptr;
  HANDLE child_ready = nullptr;
  HANDLE shutdown_owner = nullptr;
  HANDLE child_shutdown = nullptr;
  passed &= CreatePipe(&ready_read, &ready_write, nullptr, 0U) != FALSE;
  passed &= DuplicateHandle(GetCurrentProcess(), ready_write, GetCurrentProcess(), &child_ready,
                            FILE_WRITE_DATA | SYNCHRONIZE, TRUE, 0U) != FALSE;
  shutdown_owner = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  passed &= shutdown_owner != nullptr;
  passed &= DuplicateHandle(GetCurrentProcess(), shutdown_owner, GetCurrentProcess(),
                            &child_shutdown, SYNCHRONIZE, TRUE, 0U) != FALSE;
  std::vector<std::wstring> arguments{
      L"faultloom_reviewer.exe", L"--session", L"0123456789abcdef0123456789abcdef",
      L"--expected-broker-pid", std::to_wstring(GetCurrentProcessId()), L"--ready-handle",
      std::to_wstring(reinterpret_cast<std::uintptr_t>(child_ready)), L"--shutdown-event-handle",
      std::to_wstring(reinterpret_cast<std::uintptr_t>(child_shutdown))};
  passed &= parse(arguments).has_value();
  arguments[2] = L"0123456789abcdef0123456789abcdeF";
  passed &= !parse(arguments).has_value();
  arguments[2] = L"0123456789abcdef0123456789abcdef";
  std::swap(arguments[1], arguments[3]);
  passed &= !parse(arguments).has_value();
  std::swap(arguments[1], arguments[3]);
  arguments.push_back(L"extra");
  passed &= !parse(arguments).has_value();
  arguments.pop_back();
  HANDLE wrong_shutdown = OpenProcess(SYNCHRONIZE, TRUE, GetCurrentProcessId());
  if (wrong_shutdown != nullptr) {
    arguments[8] = std::to_wstring(reinterpret_cast<std::uintptr_t>(wrong_shutdown));
    passed &= !parse(arguments).has_value();
    arguments[8] = std::to_wstring(reinterpret_cast<std::uintptr_t>(child_shutdown));
    CloseHandle(wrong_shutdown);
  } else {
    passed = false;
  }
  passed &= SetHandleInformation(ready_write, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) != FALSE;
  arguments[6] = std::to_wstring(reinterpret_cast<std::uintptr_t>(ready_write));
  passed &= !parse(arguments).has_value();
  passed &= SetHandleInformation(ready_read, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) != FALSE;
  arguments[6] = std::to_wstring(reinterpret_cast<std::uintptr_t>(ready_read));
  passed &= !parse(arguments).has_value();
  arguments[6] = std::to_wstring(reinterpret_cast<std::uintptr_t>(child_ready));
  passed &= SetHandleInformation(shutdown_owner, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) != FALSE;
  arguments[8] = std::to_wstring(reinterpret_cast<std::uintptr_t>(shutdown_owner));
  passed &= !parse(arguments).has_value();
  HANDLE named_owner = CreateEventW(nullptr, TRUE, FALSE, L"Local\\FaultLoom.Reviewer.Named.Test");
  HANDLE named_child = nullptr;
  passed &= named_owner != nullptr && DuplicateHandle(
      GetCurrentProcess(), named_owner, GetCurrentProcess(), &named_child, SYNCHRONIZE, TRUE, 0U);
  arguments[8] = std::to_wstring(reinterpret_cast<std::uintptr_t>(named_child));
  passed &= !parse(arguments).has_value();
  arguments[8] = std::to_wstring(reinterpret_cast<std::uintptr_t>(child_shutdown));
  passed &= SetHandleInformation(child_ready, HANDLE_FLAG_INHERIT, 0U) != FALSE;
  passed &= !parse(arguments).has_value();
  if (named_child != nullptr) CloseHandle(named_child);
  if (named_owner != nullptr) CloseHandle(named_owner);
  if (child_shutdown != nullptr) CloseHandle(child_shutdown);
  if (shutdown_owner != nullptr) CloseHandle(shutdown_owner);
  if (child_ready != nullptr) CloseHandle(child_ready);
  if (ready_write != nullptr) CloseHandle(ready_write);
  if (ready_read != nullptr) CloseHandle(ready_read);
  if (!passed) std::cerr << "signer seam contract failed\n";
  return passed ? 0 : 1;
}
