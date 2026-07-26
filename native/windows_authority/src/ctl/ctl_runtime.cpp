#include "ctl_runtime.h"

#include "faultloom/broker_contract.h"
#include "reviewer_identity.h"
#include "reviewer_io.h"
#include "unique_handle.h"

#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <iostream>

namespace faultloom::ctl {
namespace {

void append64(std::vector<std::uint8_t>& output, std::uint64_t value) {
  for (unsigned index = 0U; index < 8U; ++index) {
    output.push_back(static_cast<std::uint8_t>(value >> (index * 8U)));
  }
}

std::uint32_t read32(std::span<const std::uint8_t> input) noexcept {
  return static_cast<std::uint32_t>(input[0]) |
      (static_cast<std::uint32_t>(input[1]) << 8U) |
      (static_cast<std::uint32_t>(input[2]) << 16U) |
      (static_cast<std::uint32_t>(input[3]) << 24U);
}

std::uint32_t read32(std::span<const std::uint8_t> input, std::size_t offset) noexcept {
  return read32(input.subspan(offset, 4U));
}

std::optional<reviewer::UniqueHandle> connect(const Options& options, HANDLE stop,
                                               HANDLE broker, std::uint64_t deadline,
                                               std::uint64_t frequency) noexcept {
  const std::wstring name = L"\\\\.\\pipe\\FaultLoom.Broker.MVP.v1." + options.session;
  while (reviewer::check_gate(stop, broker, deadline, frequency) == reviewer::IoResult::complete) {
    reviewer::UniqueHandle pipe(CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0U,
                                            nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr));
    if (pipe) {
      ULONG pid = 0U;
      if (GetNamedPipeServerProcessId(pipe.get(), &pid) && pid == options.broker_pid) return pipe;
      return std::nullopt;
    }
    if (GetLastError() != ERROR_PIPE_BUSY && GetLastError() != ERROR_FILE_NOT_FOUND) return std::nullopt;
    Sleep(1U);
  }
  return std::nullopt;
}

}

int run(const Options& options) noexcept {
  LARGE_INTEGER frequency_value{};
  LARGE_INTEGER now{};
  if (!QueryPerformanceFrequency(&frequency_value) || frequency_value.QuadPart <= 0 ||
      !QueryPerformanceCounter(&now)) return 2;
  const auto frequency = static_cast<std::uint64_t>(frequency_value.QuadPart);
  const auto deadline = static_cast<std::uint64_t>(now.QuadPart) + frequency * 5U;
  reviewer::UniqueHandle broker(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                                             FALSE, options.broker_pid));
  const auto own_sid = reviewer::process_sid(GetCurrentProcess());
  const auto broker_sid = broker ? reviewer::process_sid(broker.get()) : std::nullopt;
  if (!broker || WaitForSingleObject(broker.get(), 0U) != WAIT_TIMEOUT || !own_sid ||
      !broker_sid || *own_sid != *broker_sid) return 2;
  reviewer::UniqueHandle stop(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  auto pipe = stop ? connect(options, stop.get(), broker.get(), deadline, frequency) : std::nullopt;
  if (!pipe) return 3;
  protocol::RequestId request_id{};
  if (BCryptGenRandom(nullptr, request_id.data(), static_cast<ULONG>(request_id.size()),
                      BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0 ||
      std::all_of(request_id.begin(), request_id.end(), [](std::uint8_t byte) { return byte == 0U; })) {
    return 3;
  }
  std::vector<std::uint8_t> body;
  append64(body, deadline);
  if (options.action == protocol::Action::query_service_status) {
    body.push_back(static_cast<std::uint8_t>(options.service.size()));
    body.push_back(0U);
    for (const wchar_t character : options.service) body.push_back(static_cast<std::uint8_t>(character));
  }
  const protocol::FrameView frame{{protocol::MessageType::client_request, request_id,
                                   options.action, protocol::Status::ok}, body};
  auto payload = protocol::encode_payload(frame);
#ifdef FAULTLOOM_TEST_RAW
  if (!options.raw_payload.empty()) payload = options.raw_payload;
#endif
  auto record = payload ? protocol::encode_record(*payload) : std::nullopt;
#ifdef FAULTLOOM_TEST_RAW
  const bool raw_mode = !options.raw_payload.empty();
  if (raw_mode) {
    std::vector<std::uint8_t> raw_record(4U + options.raw_payload.size());
    const auto raw_size = static_cast<std::uint32_t>(options.raw_payload.size());
    for (std::size_t index = 0U; index < 4U; ++index) {
      raw_record[index] = static_cast<std::uint8_t>(raw_size >> (index * 8U));
    }
    std::copy(options.raw_payload.begin(), options.raw_payload.end(), raw_record.begin() + 4U);
    record = std::move(raw_record);
  }
#endif
  const auto review_payload = payload ? broker_contract::build_review_payload(
      GetCurrentProcessId(), *own_sid, *payload) : std::nullopt;
  if (!record ||
#ifdef FAULTLOOM_TEST_RAW
      (!raw_mode && !review_payload) ||
#else
      !review_payload ||
#endif
      reviewer::write_exact(pipe->get(), *record, stop.get(),
      broker.get(), deadline, frequency) != reviewer::IoResult::complete) return 4;
#ifdef FAULTLOOM_TEST_RAW
  if (raw_mode) {
    return reviewer::await_client_close(pipe->get(), stop.get(), broker.get(), deadline,
                                        frequency) == reviewer::IoResult::complete ? 0 : 8;
  }
#endif
  std::array<std::uint8_t, protocol::kMaxRecordBytes> response{};
  if (reviewer::read_exact(pipe->get(), std::span(response).first(4U), stop.get(), broker.get(),
                           deadline, frequency) != reviewer::IoResult::complete) return 4;
  const std::size_t size = read32(response);
  if (size == 0U || size > protocol::kMaxPayloadBytes ||
      reviewer::read_exact(pipe->get(), std::span(response).subspan(4U, size), stop.get(), broker.get(),
                           deadline, frequency) != reviewer::IoResult::complete) return 4;
  pipe.reset();
  const auto response_payload = std::span(response).subspan(4U, size);
  const auto decoded = protocol::decode_payload(response_payload);
  if (!decoded.frame || decoded.frame->body.size() < 173U) return 5;
  signing::PublicBlob blob{};
  std::copy_n(decoded.frame->body.begin() + 35U, blob.size(), blob.begin());
  const auto hash = protocol::sha256(blob);
  const bool evidence_status = decoded.frame->header.status == protocol::Status::ok ||
                               decoded.frame->header.status == protocol::Status::action_failed;
  if ((evidence_status && (!hash || *hash != options.key_hash)) ||
      !broker_contract::verify_response(response_payload, *review_payload, blob)) return 5;
  if (decoded.frame->header.status == protocol::Status::action_failed) {
    std::cout << "ACTION_FAILED\n";
    return 7;
  }
  if (decoded.frame->header.status != protocol::Status::ok) return 6;
  const auto result = decoded.frame->body.subspan(173U);
  if (options.action == protocol::Action::ping &&
      result.size() == 4U && std::equal(result.begin(), result.end(), "PONG")) {
    std::cout << "PONG\n";
    return 0;
  }
  if (options.action == protocol::Action::query_service_status && result.size() == 36U) {
    std::cout << "SERVICE_STATUS";
    for (std::size_t offset = 0U; offset < result.size(); offset += 4U) {
      std::cout << ' ' << read32(result, offset);
    }
    std::cout << '\n';
    return 0;
  }
  return 6;
}

}
