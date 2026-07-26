#include "broker_security.h"

#include <iostream>

int main() {
  const auto sid = faultloom::broker::current_sid();
  const std::wstring squat_session = L"0123456789abcdef0123456789abcdea";
  const std::wstring squat_name = L"\\\\.\\pipe\\FaultLoom.Broker.MVP.v1." + squat_session;
  faultloom::reviewer::UniqueHandle squatter(CreateNamedPipeW(
      squat_name.c_str(), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT |
      PIPE_REJECT_REMOTE_CLIENTS, 1U, 8196U, 8196U, 0U, nullptr));
  auto squatted = sid.has_value()
      ? faultloom::broker::create_client_pipe(squat_session, *sid)
      : std::nullopt;
  const std::wstring session = L"0123456789abcdef0123456789abcdef";
  auto first = sid.has_value()
      ? faultloom::broker::create_client_pipe(session, *sid)
      : std::nullopt;
  auto second = sid.has_value()
      ? faultloom::broker::create_client_pipe(session, *sid)
      : std::nullopt;
  BYTE system_storage[SECURITY_MAX_SID_SIZE]{};
  DWORD system_size = sizeof(system_storage);
  const bool system_sid = CreateWellKnownSid(WinLocalSystemSid, nullptr, system_storage,
                                              &system_size) != FALSE;
  auto wrong_sid = system_sid ? faultloom::broker::create_client_pipe(
      L"0123456789abcdef0123456789abcdeb",
      std::span<const std::uint8_t>(system_storage, system_size)) : std::nullopt;
  const auto remote = faultloom::broker::client_pipe_mode(true);
  const bool passed = sid.has_value() && squatter && !squatted.has_value() &&
      first.has_value() && !second.has_value() && !wrong_sid.has_value() &&
      remote.has_value() && (*remote & PIPE_REJECT_REMOTE_CLIENTS) != 0U &&
      !faultloom::broker::client_pipe_mode(false).has_value();
  if (!passed) std::cerr << "Broker secure first-instance pipe contract failed\n";
  return passed ? 0 : 1;
}
