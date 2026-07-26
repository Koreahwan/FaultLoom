#define main broker_process_normal_main
#include "broker_process_tests.cpp"
#undef main

namespace {

bool absent(std::string_view kind, const BrokerProcess& broker, ULONGLONG deadline) {
  const auto session = field(broker.ready, "session=");
  if (!session) return false;
  const std::wstring name = L"\\\\.\\pipe\\FaultLoom." +
      std::wstring(kind.begin(), kind.end()) + L".MVP.v1." +
      std::wstring(session->begin(), session->end());
  while (GetTickCount64() < deadline) {
    TestHandle pipe(CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0U, nullptr,
                                OPEN_EXISTING, 0U, nullptr));
    const DWORD error = pipe ? ERROR_SUCCESS : GetLastError();
    if (!pipe && error == ERROR_FILE_NOT_FOUND) return true;
    if (!pipe && error != ERROR_PIPE_BUSY) return false;
    Sleep(1U);
  }
  return false;
}

std::optional<std::vector<std::uint8_t>> query_record(std::string_view service) {
  LARGE_INTEGER frequency{};
  LARGE_INTEGER now{};
  if (!QueryPerformanceFrequency(&frequency) || !QueryPerformanceCounter(&now)) return std::nullopt;
  std::vector<std::uint8_t> body(10U + service.size());
  const auto deadline = static_cast<std::uint64_t>(now.QuadPart + frequency.QuadPart * 4U);
  for (std::size_t index = 0U; index < 8U; ++index) {
    body[index] = static_cast<std::uint8_t>(deadline >> (index * 8U));
  }
  body[8U] = static_cast<std::uint8_t>(service.size());
  std::copy(service.begin(), service.end(), body.begin() + 10U);
  faultloom::protocol::RequestId request_id{};
  request_id[0U] = 2U;
  const faultloom::protocol::FrameView frame{{faultloom::protocol::MessageType::client_request,
      request_id, faultloom::protocol::Action::query_service_status,
      faultloom::protocol::Status::ok}, body};
  const auto payload = faultloom::protocol::encode_payload(frame);
  return payload ? faultloom::protocol::encode_record(*payload) : std::nullopt;
}

bool read_record(HANDLE pipe, HANDLE process, ULONGLONG deadline,
                 std::vector<std::uint8_t>& output) {
  while (GetTickCount64() < deadline) {
    DWORD available = 0U;
    if (!PeekNamedPipe(pipe, nullptr, 0U, nullptr, &available, nullptr)) return false;
    if (available != 0U) {
      const std::size_t prior = output.size();
      output.resize(prior + available);
      DWORD read = 0U;
      if (!ReadFile(pipe, output.data() + prior, available, &read, nullptr) || read != available)
        return false;
      if (output.size() >= 4U) {
        const std::size_t size = static_cast<std::size_t>(output[0U]) |
            (static_cast<std::size_t>(output[1U]) << 8U) |
            (static_cast<std::size_t>(output[2U]) << 16U) |
            (static_cast<std::size_t>(output[3U]) << 24U);
        if (output.size() == size + 4U) return true;
        if (output.size() > size + 4U) return false;
      }
    }
    if (WaitForSingleObject(process, 0U) == WAIT_OBJECT_0) return false;
    Sleep(1U);
  }
  return false;
}

bool exact_unavailable(std::span<const std::uint8_t> record) {
  const auto decoded = faultloom::protocol::decode_record(record);
  if (!decoded.frame || decoded.frame->header.status !=
      faultloom::protocol::Status::reviewer_unavailable) return false;
  const auto body = decoded.frame->body;
  return body.size() == 173U && body[32U] == 0U && body[33U] == 5U && body[34U] == 0U &&
      std::all_of(body.begin(), body.begin() + 32U,
                  [](std::uint8_t value) { return value == 0U; }) &&
      std::all_of(body.begin() + 35U, body.end(),
                  [](std::uint8_t value) { return value == 0U; });
}

bool revoked_case() {
  auto broker = launch_broker(L"faultloom_broker_post_approval_fixture.exe");
  if (!broker) return false;
  const auto reviewer_pid = field(broker->ready, "reviewer_pid=");
  TestHandle reviewer(reviewer_pid
      ? OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | SYNCHRONIZE, FALSE,
                    static_cast<DWORD>(std::stoul(*reviewer_pid)))
      : nullptr);
  if (!reviewer) return false;
  const auto broker_pid = field(broker->ready, "broker_pid=");
  if (!broker_pid) return false;
  const std::wstring event_name = L"Local\\FaultLoom.Test.ScmWorkerStarted." +
      std::wstring(broker_pid->begin(), broker_pid->end());
  TestHandle worker_started(CreateEventW(nullptr, TRUE, FALSE, event_name.c_str()));
  auto pipe = connect_broker(*broker);
  const auto record = query_record("BFE");
  if (!worker_started || !pipe || !record) return false;
  const ULONGLONG started = GetTickCount64();
  DWORD written = 0U;
  if (!WriteFile(pipe.get(), record->data(), static_cast<DWORD>(record->size()), &written,
                 nullptr) || written != record->size() ||
      WaitForSingleObject(worker_started.get(), 3000U) != WAIT_OBJECT_0 ||
      !TerminateProcess(reviewer.get(), 91U) ||
      WaitForSingleObject(reviewer.get(), 3000U) != WAIT_OBJECT_0) return false;
  std::vector<std::uint8_t> response;
  const ULONGLONG deadline = started + 5000U;
  const bool exact = read_record(pipe.get(), broker->process.get(), deadline, response) &&
      exact_unavailable(response);
  pipe.reset();
  const DWORD broker_wait = GetTickCount64() < deadline
      ? static_cast<DWORD>(deadline - GetTickCount64()) : 0U;
  if (broker_wait == 0U || WaitForSingleObject(broker->process.get(), broker_wait) != WAIT_OBJECT_0)
    return false;
  return exact && absent("Broker", *broker, deadline) && absent("Reviewer", *broker, deadline);
}

bool stalled_case() {
  auto broker = launch_broker(L"faultloom_broker_post_approval_fixture.exe");
  if (!broker) return false;
  const auto reviewer_pid = field(broker->ready, "reviewer_pid=");
  TestHandle reviewer(reviewer_pid
      ? OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE,
                    static_cast<DWORD>(std::stoul(*reviewer_pid)))
      : nullptr);
  const auto broker_pid = field(broker->ready, "broker_pid=");
  if (!broker_pid) return false;
  const std::wstring event_name = L"Local\\FaultLoom.Test.ScmWorkerStarted." +
      std::wstring(broker_pid->begin(), broker_pid->end());
  TestHandle worker_started(CreateEventW(nullptr, TRUE, FALSE, event_name.c_str()));
  auto pipe = connect_broker(*broker);
  const auto record = query_record("EventLog");
  DWORD written = 0U;
  if (!reviewer || !worker_started || !pipe || !record ||
      !WriteFile(pipe.get(), record->data(), static_cast<DWORD>(record->size()), &written,
                 nullptr) || written != record->size() ||
      WaitForSingleObject(worker_started.get(), 3000U) != WAIT_OBJECT_0) return false;
  const ULONGLONG deadline = GetTickCount64() + 6000U;
  std::vector<std::uint8_t> response;
  const bool closed_without_response = !read_record(pipe.get(), broker->process.get(), deadline,
                                                     response) && response.empty();
  pipe.reset();
  const DWORD broker_wait = GetTickCount64() < deadline
      ? static_cast<DWORD>(deadline - GetTickCount64()) : 0U;
  const bool broker_stopped = broker_wait != 0U &&
      WaitForSingleObject(broker->process.get(), broker_wait) == WAIT_OBJECT_0;
  const DWORD reviewer_wait = GetTickCount64() < deadline
      ? static_cast<DWORD>(deadline - GetTickCount64()) : 0U;
  return closed_without_response && broker_stopped && reviewer_wait != 0U &&
      WaitForSingleObject(reviewer.get(), reviewer_wait) == WAIT_OBJECT_0 &&
      absent("Broker", *broker, deadline) && absent("Reviewer", *broker, deadline);
}

}

int main() {
  const bool reviewer_death = revoked_case();
  const bool worker_stall = stalled_case();
  if (!reviewer_death) std::cerr << "post-approval Reviewer death was not bounded\n";
  if (!worker_stall) std::cerr << "post-approval SCM stall was not bounded\n";
  return reviewer_death && worker_stall ? 0 : 1;
}
