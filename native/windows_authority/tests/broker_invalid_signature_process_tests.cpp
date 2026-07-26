#include "faultloom/protocol.h"
#include "reviewer_process_fixture.h"

#include <windows.h>

#include <algorithm>
#include <array>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>

namespace {

using faultloom::test::TestHandle;

std::wstring sibling(std::wstring_view name) {
  std::array<wchar_t, 32768> path{};
  const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
  std::wstring result(path.data(), length);
  result.resize(result.find_last_of(L"\\/") + 1U);
  result += name;
  return result;
}

std::optional<std::string> field(std::string_view line, std::string_view name) {
  const std::size_t begin = line.find(name);
  if (begin == std::string_view::npos) return std::nullopt;
  const std::size_t value = begin + name.size();
  const std::size_t end = line.find_first_of(" \n", value);
  return std::string(line.substr(value, end - value));
}

struct BrokerProcess {
  TestHandle process;
  TestHandle shutdown;
  std::string ready;
};

std::optional<BrokerProcess> launch_broker() {
  HANDLE read_raw = nullptr;
  HANDLE write_raw = nullptr;
  if (!CreatePipe(&read_raw, &write_raw, nullptr, 0U)) return std::nullopt;
  TestHandle ready_read(read_raw);
  TestHandle ready_write(write_raw);
  HANDLE ready_child_raw = nullptr;
  if (!DuplicateHandle(GetCurrentProcess(), ready_write.get(), GetCurrentProcess(),
                       &ready_child_raw, FILE_WRITE_DATA | SYNCHRONIZE, TRUE, 0U)) {
    return std::nullopt;
  }
  TestHandle ready_child(ready_child_raw);
  ready_write.reset();
  TestHandle shutdown(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  HANDLE shutdown_child_raw = nullptr;
  if (!shutdown || !DuplicateHandle(GetCurrentProcess(), shutdown.get(), GetCurrentProcess(),
                                    &shutdown_child_raw, SYNCHRONIZE, TRUE, 0U)) {
    return std::nullopt;
  }
  TestHandle shutdown_child(shutdown_child_raw);
  SIZE_T bytes = 0U;
  InitializeProcThreadAttributeList(nullptr, 1U, 0U, &bytes);
  std::vector<std::uint8_t> storage(bytes);
  auto* attributes = reinterpret_cast<PPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
  if (!InitializeProcThreadAttributeList(attributes, 1U, 0U, &bytes)) return std::nullopt;
  const std::array inherited{ready_child.get(), shutdown_child.get()};
  const bool updated = UpdateProcThreadAttribute(
      attributes, 0U, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
      const_cast<HANDLE*>(inherited.data()), sizeof(inherited), nullptr, nullptr) != FALSE;
  const auto application = sibling(L"faultloom_broker_invalid_signature_fixture.exe");
  std::wstring command = L"\"" + application + L"\" --ready-handle " +
      std::to_wstring(reinterpret_cast<std::uintptr_t>(ready_child.get())) +
      L" --shutdown-event-handle " +
      std::to_wstring(reinterpret_cast<std::uintptr_t>(shutdown_child.get()));
  STARTUPINFOEXW startup{};
  startup.StartupInfo.cb = sizeof(startup);
  startup.lpAttributeList = attributes;
  PROCESS_INFORMATION raw{};
  const bool created = updated && CreateProcessW(
      application.c_str(), command.data(), nullptr, nullptr, TRUE, EXTENDED_STARTUPINFO_PRESENT,
      nullptr, nullptr, &startup.StartupInfo, &raw) != FALSE;
  DeleteProcThreadAttributeList(attributes);
  if (!created) return std::nullopt;
  TestHandle process(raw.hProcess);
  TestHandle thread(raw.hThread);
  ready_child.reset();
  shutdown_child.reset();
  const ULONGLONG deadline = GetTickCount64() + 10000U;
  std::array<char, 512> buffer{};
  std::string ready;
  while (GetTickCount64() < deadline) {
    DWORD available = 0U;
    if (!PeekNamedPipe(ready_read.get(), nullptr, 0U, nullptr, &available, nullptr)) break;
    if (available != 0U) {
      DWORD received = 0U;
      if (ReadFile(ready_read.get(), buffer.data(), static_cast<DWORD>(buffer.size()),
                   &received, nullptr)) ready.assign(buffer.data(), received);
      break;
    }
    if (WaitForSingleObject(process.get(), 0U) == WAIT_OBJECT_0) break;
    Sleep(1U);
  }
  if (ready.empty()) {
    SetEvent(shutdown.get());
    if (WaitForSingleObject(process.get(), 1000U) != WAIT_OBJECT_0) {
      TerminateProcess(process.get(), ERROR_TIMEOUT);
    }
    return std::nullopt;
  }
  return BrokerProcess{std::move(process), std::move(shutdown), std::move(ready)};
}

std::optional<std::vector<std::uint8_t>> request_record() {
  LARGE_INTEGER frequency{};
  LARGE_INTEGER now{};
  if (!QueryPerformanceFrequency(&frequency) || !QueryPerformanceCounter(&now)) return std::nullopt;
  std::array<std::uint8_t, 13> body{};
  const auto deadline = static_cast<std::uint64_t>(now.QuadPart + frequency.QuadPart * 4U);
  for (std::size_t index = 0U; index < 8U; ++index) {
    body[index] = static_cast<std::uint8_t>(deadline >> (index * 8U));
  }
  body[8] = 3U;
  std::copy_n("BFE", 3U, body.begin() + 10U);
  faultloom::protocol::RequestId request_id{};
  request_id[0] = 0x51U;
  const faultloom::protocol::FrameView frame{{
      faultloom::protocol::MessageType::client_request, request_id,
      faultloom::protocol::Action::query_service_status, faultloom::protocol::Status::ok}, body};
  const auto payload = faultloom::protocol::encode_payload(frame);
  return payload ? faultloom::protocol::encode_record(*payload) : std::nullopt;
}

bool exact_invalid_signature(std::span<const std::uint8_t> record) {
  const auto decoded = faultloom::protocol::decode_record(record);
  if (!decoded.frame || decoded.frame->header.message_type !=
                            faultloom::protocol::MessageType::broker_response ||
      decoded.frame->header.action != faultloom::protocol::Action::query_service_status ||
      decoded.frame->header.status != faultloom::protocol::Status::review_signature_invalid ||
      decoded.frame->header.request_id[0] != 0x51U ||
      !std::all_of(decoded.frame->header.request_id.begin() + 1U,
                   decoded.frame->header.request_id.end(),
                   [](std::uint8_t value) { return value == 0U; })) {
    return false;
  }
  const auto body = decoded.frame->body;
  return body.size() == 173U && body[32U] == 0U && body[33U] == 6U && body[34U] == 0U &&
         std::all_of(body.begin(), body.begin() + 32U,
                     [](std::uint8_t value) { return value == 0U; }) &&
         std::all_of(body.begin() + 35U, body.end(),
                     [](std::uint8_t value) { return value == 0U; });
}

bool exercise(BrokerProcess& broker) {
  const auto session = field(broker.ready, "session=");
  const auto request = request_record();
  if (!session || !request) return false;
  const std::wstring pipe_name = L"\\\\.\\pipe\\FaultLoom.Broker.MVP.v1." +
      std::wstring(session->begin(), session->end());
  TestHandle pipe(CreateFileW(pipe_name.c_str(), GENERIC_READ | GENERIC_WRITE, 0U, nullptr,
                              OPEN_EXISTING, 0U, nullptr));
  if (!pipe) return false;
  DWORD written = 0U;
  if (!WriteFile(pipe.get(), request->data(), static_cast<DWORD>(request->size()), &written,
                 nullptr) || written != request->size()) return false;
  std::array<std::uint8_t, faultloom::protocol::kMaxRecordBytes> response{};
  DWORD received = 0U;
  if (!ReadFile(pipe.get(), response.data(), static_cast<DWORD>(response.size()), &received,
                nullptr)) return false;
  pipe.reset();
  return exact_invalid_signature(std::span(response).first(received));
}

}

int main() {
  auto broker = launch_broker();
  bool passed = broker.has_value() && exercise(*broker);
  if (broker.has_value()) {
    SetEvent(broker->shutdown.get());
    passed &= WaitForSingleObject(broker->process.get(), 5000U) == WAIT_OBJECT_0;
    DWORD code = 1U;
    passed &= GetExitCodeProcess(broker->process.get(), &code) && code == 0U;
    if (WaitForSingleObject(broker->process.get(), 0U) != WAIT_OBJECT_0) {
      TerminateProcess(broker->process.get(), ERROR_TIMEOUT);
    }
  }
  if (!passed) std::cerr << "runtime invalid-signature boundary failed\n";
  return passed ? 0 : 1;
}
