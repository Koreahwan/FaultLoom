#include "broker_runtime.h"

#include "broker_ready.h"
#include "broker_security.h"
#include "client_identity.h"
#include "faultloom/broker_contract.h"
#include "faultloom/policy.h"
#include "faultloom/protocol.h"
#include "reviewer_child.h"
#include "scm_query.h"
#include "reviewer_identity.h"
#include "reviewer_io.h"
#include "unique_handle.h"

#include <algorithm>
#include <array>
#include <exception>
#include <string>

namespace faultloom::broker {
namespace {

std::uint32_t read32(std::span<const std::uint8_t> input) noexcept {
  return static_cast<std::uint32_t>(input[0]) |
      (static_cast<std::uint32_t>(input[1]) << 8U) |
      (static_cast<std::uint32_t>(input[2]) << 16U) |
      (static_cast<std::uint32_t>(input[3]) << 24U);
}

std::string hex(std::span<const std::uint8_t> input) {
  constexpr char digits[] = "0123456789abcdef";
  std::string output(input.size() * 2U, '0');
  for (std::size_t index = 0U; index < input.size(); ++index) {
    output[index * 2U] = digits[input[index] >> 4U];
    output[index * 2U + 1U] = digits[input[index] & 15U];
  }
  return output;
}

std::string narrow_session(std::wstring_view input) {
  std::string output;
  output.reserve(input.size());
  for (const wchar_t character : input) output.push_back(static_cast<char>(character));
  return output;
}

std::optional<reviewer::UniqueHandle> connect_reviewer(
    const std::wstring& session, HANDLE shutdown, HANDLE process,
    std::uint64_t deadline, std::uint64_t frequency, DWORD expected_pid) noexcept {
  const std::wstring name = L"\\\\.\\pipe\\FaultLoom.Reviewer.MVP.v1." + session;
  while (reviewer::check_gate(shutdown, process, deadline, frequency) == reviewer::IoResult::complete) {
    reviewer::UniqueHandle pipe(CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0U,
                                            nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr));
    if (pipe) {
      ULONG pid = 0U;
      if (GetNamedPipeServerProcessId(pipe.get(), &pid) && pid == expected_pid) return pipe;
      return std::nullopt;
    }
    if (GetLastError() != ERROR_PIPE_BUSY && GetLastError() != ERROR_FILE_NOT_FOUND) return std::nullopt;
    Sleep(1U);
  }
  return std::nullopt;
}

bool send_zero(HANDLE pipe, HANDLE shutdown, HANDLE client,
               const protocol::Header& request, protocol::Status status,
               std::uint64_t deadline, std::uint64_t frequency) noexcept {
  const auto payload = broker_contract::build_response(request, status, nullptr, {});
  const auto record = payload ? protocol::encode_record(*payload) : std::nullopt;
  return record && reviewer::write_exact(pipe, *record, shutdown, client, deadline, frequency) ==
                       reviewer::IoResult::complete &&
         reviewer::await_client_close(pipe, shutdown, client, deadline, frequency) ==
                       reviewer::IoResult::complete;
}

[[noreturn]] void terminate_self() noexcept {
  TerminateProcess(GetCurrentProcess(), ERROR_OPERATION_ABORTED);
  std::terminate();
}

bool process_client(HANDLE pipe, HANDLE shutdown, ReviewerChild& child,
                    const std::wstring& session, std::span<const std::uint8_t> broker_sid,
                    std::uint64_t frequency) noexcept {
  ULONG pid = 0U;
  LARGE_INTEGER accepted{};
  if (!GetNamedPipeClientProcessId(pipe, &pid) || pid == 0U ||
      !QueryPerformanceCounter(&accepted)) return false;
  reviewer::UniqueHandle client(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                                             FALSE, pid));
  const auto sid = client ? reviewer::process_sid(client.get()) : std::nullopt;
  if (!client || !identity_live(client.get(), pid) ||
      !sid.has_value() || sid->size() != broker_sid.size() ||
      !std::equal(sid->begin(), sid->end(), broker_sid.begin())) return false;
  const std::uint64_t watchdog = static_cast<std::uint64_t>(accepted.QuadPart) + frequency * 5U;
  std::array<std::uint8_t, protocol::kMaxRecordBytes> record{};
  if (reviewer::read_exact(pipe, std::span(record).first(4U), shutdown, client.get(),
                           watchdog, frequency) != reviewer::IoResult::complete) return false;
  const std::size_t size = read32(record);
  if (size == 0U || size > protocol::kMaxPayloadBytes ||
      reviewer::read_exact(pipe, std::span(record).subspan(4U, size), shutdown, client.get(),
                           watchdog, frequency) != reviewer::IoResult::complete) return false;
  DWORD extra = 0U;
  if (!PeekNamedPipe(pipe, nullptr, 0U, nullptr, &extra, nullptr) || extra != 0U) return false;
  const auto payload = std::span(record).subspan(4U, size);
  const auto decoded = protocol::decode_payload(payload);
  LARGE_INTEGER now{};
  if (!decoded.frame.has_value() || !QueryPerformanceCounter(&now)) return false;
  const auto policy_result = policy::parse_client_request(
      *decoded.frame, {static_cast<std::uint64_t>(now.QuadPart), frequency});
  if (policy_result.status != protocol::Status::ok || !policy_result.request.has_value()) {
    const auto denied = broker_contract::build_response(decoded.frame->header, policy_result.status,
                                                         nullptr, {});
    const auto output = denied ? protocol::encode_record(*denied) : std::nullopt;
    return output && reviewer::write_exact(pipe, *output, shutdown, client.get(), watchdog,
                                            frequency) == reviewer::IoResult::complete &&
           reviewer::await_client_close(pipe, shutdown, client.get(), watchdog, frequency) ==
               reviewer::IoResult::complete;
  }
  const std::uint64_t deadline = std::min(watchdog, policy_result.request->deadline_qpc);
  const auto review_payload = broker_contract::build_review_payload(pid, *sid, payload);
  const auto review_record = review_payload ? protocol::encode_record(*review_payload) : std::nullopt;
  auto review_pipe = connect_reviewer(session, shutdown, child.process.get(), deadline,
                                      frequency, child.pid);
  if (!review_record || !identity_live(client.get(), pid)) return false;
  if (!review_pipe) return send_zero(pipe, shutdown, client.get(), decoded.frame->header,
                                     protocol::Status::reviewer_unavailable, deadline, frequency);
  if (reviewer::write_exact(review_pipe->get(), *review_record, shutdown, child.process.get(),
                            deadline, frequency) != reviewer::IoResult::complete) {
    review_pipe.reset();
    return send_zero(pipe, shutdown, client.get(), decoded.frame->header,
                     protocol::Status::reviewer_unavailable, deadline, frequency);
  }
  std::array<std::uint8_t, protocol::kMaxRecordBytes> decision{};
  if (reviewer::read_exact(review_pipe->get(), std::span(decision).first(4U), shutdown,
                           child.process.get(), deadline, frequency) != reviewer::IoResult::complete) {
    review_pipe.reset();
    return send_zero(pipe, shutdown, client.get(), decoded.frame->header,
                     protocol::Status::reviewer_unavailable, deadline, frequency);
  }
  const std::size_t decision_size = read32(decision);
  if (decision_size == 0U || decision_size > protocol::kMaxPayloadBytes) {
    review_pipe.reset();
    return send_zero(pipe, shutdown, client.get(), decoded.frame->header,
                     protocol::Status::review_signature_invalid, deadline, frequency);
  }
  if (reviewer::read_exact(review_pipe->get(), std::span(decision).subspan(4U, decision_size), shutdown,
                           child.process.get(), deadline, frequency) != reviewer::IoResult::complete) {
    review_pipe.reset();
    return send_zero(pipe, shutdown, client.get(), decoded.frame->header,
                     protocol::Status::reviewer_unavailable, deadline, frequency);
  }
  review_pipe.reset();
  const auto evidence = broker_contract::verify_review_decision(
      std::span(decision).subspan(4U, decision_size), *review_payload, child.blob);
  if (!identity_live(client.get(), pid)) return false;
  if (!evidence) return send_zero(pipe, shutdown, client.get(), decoded.frame->header,
                                  protocol::Status::review_signature_invalid, deadline, frequency);
  static constexpr std::array<std::uint8_t, 4> pong{'P', 'O', 'N', 'G'};
  protocol::Status status = protocol::Status::ok;
  bool must_terminate = false;
  ServiceBytes service_bytes{};
  std::span<const std::uint8_t> result = pong;
  if (decoded.frame->header.action == protocol::Action::query_service_status) {
    const auto query = query_service_bounded(policy_result.request->service, shutdown, client.get(),
                                             child.process.get(), deadline, frequency);
    status = query.status;
    must_terminate = query.must_terminate;
    service_bytes = query.bytes;
    result = status == protocol::Status::ok ? std::span<const std::uint8_t>(service_bytes)
                                             : std::span<const std::uint8_t>{};
  }
  const bool signed_status = status == protocol::Status::ok ||
                             status == protocol::Status::action_failed;
  const auto response = broker_contract::build_response(decoded.frame->header, status,
                                                         signed_status ? &*evidence : nullptr,
                                                         result);
  const auto response_record = response ? protocol::encode_record(*response) : std::nullopt;
  const bool sent = response_record &&
      reviewer::write_exact(pipe, *response_record, shutdown, client.get(), deadline,
                            frequency) == reviewer::IoResult::complete &&
      reviewer::await_client_close(pipe, shutdown, client.get(), deadline, frequency) ==
          reviewer::IoResult::complete;
  if (must_terminate) terminate_self();
  return sent;
}

}

int run(Options options) noexcept {
  reviewer::UniqueHandle ready(options.ready_handle);
  reviewer::UniqueHandle shutdown(options.shutdown_event);
  const auto sid = current_sid();
  const auto session = random_session();
  if (!sid || !session) return 3;
  auto client_pipe = create_client_pipe(*session, *sid);
  if (!client_pipe) return 4;
  auto child = launch_reviewer(*session, shutdown.get());
  if (!child) return WaitForSingleObject(shutdown.get(), 0U) == WAIT_OBJECT_0 ? 0 : 5;
  const auto key_hash = protocol::sha256(child->blob);
  if (!key_hash) return 5;
  const std::string line = "READY v1 session=" + narrow_session(*session) +
      " broker_pid=" + std::to_string(GetCurrentProcessId()) + " reviewer_pid=" +
      std::to_string(child->pid) + " public_key_sha256=" + hex(*key_hash) + "\n";
  if (!write_ready(ready.get(), shutdown.get(), child->process.get(), line)) return 5;
  ready.reset();
  LARGE_INTEGER frequency_value{};
  if (!QueryPerformanceFrequency(&frequency_value) || frequency_value.QuadPart <= 0) return 6;
  const auto frequency = static_cast<std::uint64_t>(frequency_value.QuadPart);
  while (true) {
    const auto connected = reviewer::connect_client(client_pipe->get(), shutdown.get(),
                                                     child->process.get());
    if (connected == reviewer::IoResult::stopped) break;
    if (connected != reviewer::IoResult::complete) return 6;
    process_client(client_pipe->get(), shutdown.get(), *child, *session, *sid, frequency);
    DisconnectNamedPipe(client_pipe->get());
  }
  SetEvent(child->shutdown.get());
  if (WaitForSingleObject(child->process.get(), 1000U) != WAIT_OBJECT_0) {
    TerminateProcess(child->process.get(), 1U);
  }
  return 0;
}

}
