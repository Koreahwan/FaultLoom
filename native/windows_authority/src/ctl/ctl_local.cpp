#include "ctl_local.h"

#include "ctl_runtime.h"
#include "unique_handle.h"

#include <array>
#include <charconv>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace faultloom::ctl {
namespace {

using reviewer::UniqueHandle;

struct Attributes {
  std::vector<std::uint8_t> storage;
  PPROC_THREAD_ATTRIBUTE_LIST list = nullptr;
  ~Attributes() {
    if (list != nullptr) DeleteProcThreadAttributeList(list);
  }
};

struct Ready {
  std::wstring session;
  protocol::Hash key_hash{};
  DWORD broker_pid = 0U;
  DWORD reviewer_pid = 0U;
};

std::wstring sibling(std::wstring_view name) {
  std::array<wchar_t, 32768> path{};
  const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
  if (length == 0U || length >= path.size()) return {};
  std::wstring result(path.data(), length);
  const auto slash = result.find_last_of(L"\\/");
  if (slash == std::wstring::npos) return {};
  result.resize(slash + 1U);
  result += name;
  return result;
}

bool same_image(HANDLE process, const std::wstring& expected) noexcept {
  std::array<wchar_t, 32768> actual{};
  DWORD actual_size = static_cast<DWORD>(actual.size());
  std::array<wchar_t, 32768> canonical{};
  const DWORD canonical_size = GetFullPathNameW(expected.c_str(), static_cast<DWORD>(canonical.size()),
                                                canonical.data(), nullptr);
  return canonical_size != 0U && canonical_size < canonical.size() &&
      QueryFullProcessImageNameW(process, 0U, actual.data(), &actual_size) &&
      CompareStringOrdinal(actual.data(), static_cast<int>(actual_size), canonical.data(),
                           static_cast<int>(canonical_size), TRUE) == CSTR_EQUAL;
}

bool lower_hex(std::string_view value, std::span<std::uint8_t> output) noexcept {
  if (value.size() != output.size() * 2U) return false;
  for (std::size_t index = 0U; index < output.size(); ++index) {
    const auto digit = [](char character) -> int {
      if (character >= '0' && character <= '9') return character - '0';
      if (character >= 'a' && character <= 'f') return character - 'a' + 10;
      return -1;
    };
    const int high = digit(value[index * 2U]);
    const int low = digit(value[index * 2U + 1U]);
    if (high < 0 || low < 0) return false;
    output[index] = static_cast<std::uint8_t>((high << 4) | low);
  }
  return true;
}

std::optional<std::string> field(std::string_view line, std::string_view name) {
  const auto begin = line.find(name);
  if (begin == std::string_view::npos) return std::nullopt;
  const auto value = begin + name.size();
  const auto end = line.find_first_of(" \n", value);
  return std::string(line.substr(value, end - value));
}

bool decimal(std::string_view value, DWORD& output) noexcept {
  const auto result = std::from_chars(value.data(), value.data() + value.size(), output);
  return result.ec == std::errc{} && result.ptr == value.data() + value.size() && output != 0U;
}

bool read_ready(HANDLE pipe, HANDLE process, ULONGLONG deadline, std::string& line) noexcept {
  std::array<char, 193> buffer{};
  while (GetTickCount64() < deadline) {
    DWORD available = 0U;
    if (!PeekNamedPipe(pipe, nullptr, 0U, nullptr, &available, nullptr)) return false;
    if (available != 0U) {
      if (available >= buffer.size()) return false;
      DWORD read = 0U;
      if (!ReadFile(pipe, buffer.data(), available, &read, nullptr) || read != available) return false;
      line.assign(buffer.data(), read);
      return line.ends_with('\n');
    }
    if (WaitForSingleObject(process, 0U) == WAIT_OBJECT_0) return false;
    Sleep(1U);
  }
  return false;
}

std::optional<Ready> parse_ready(const std::string& line, DWORD child_pid) noexcept {
  const auto session = field(line, "session=");
  const auto broker_pid = field(line, "broker_pid=");
  const auto reviewer_pid = field(line, "reviewer_pid=");
  const auto key = field(line, "public_key_sha256=");
  Ready ready;
  std::array<std::uint8_t, 16> session_bytes{};
  if (!session || !broker_pid || !reviewer_pid || !key || session->size() != 32U ||
      key->size() != 64U || !lower_hex(*session, session_bytes) ||
      !lower_hex(*key, ready.key_hash) || !decimal(*broker_pid, ready.broker_pid) ||
      !decimal(*reviewer_pid, ready.reviewer_pid) || ready.broker_pid != child_pid) return std::nullopt;
  const std::string expected = "READY v1 session=" + *session + " broker_pid=" + *broker_pid +
      " reviewer_pid=" + *reviewer_pid + " public_key_sha256=" + *key + "\n";
  if (line != expected) return std::nullopt;
  ready.session.assign(session->begin(), session->end());
  return ready;
}

DWORD remaining(ULONGLONG deadline) noexcept {
  const ULONGLONG now = GetTickCount64();
  if (now >= deadline) return 0U;
  const ULONGLONG value = deadline - now;
  return value > MAXDWORD ? MAXDWORD : static_cast<DWORD>(value);
}

bool pipe_absent(std::wstring_view kind, std::wstring_view session, ULONGLONG deadline) noexcept {
  const std::wstring name = L"\\\\.\\pipe\\FaultLoom." + std::wstring(kind) +
      L".MVP.v1." + std::wstring(session);
  for (;;) {
    UniqueHandle pipe(CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0U, nullptr,
                                  OPEN_EXISTING, 0U, nullptr));
    const DWORD error = pipe ? ERROR_SUCCESS : GetLastError();
    if (!pipe && error == ERROR_FILE_NOT_FOUND) return true;
    if ((!pipe && error != ERROR_PIPE_BUSY) || GetTickCount64() >= deadline) return false;
    Sleep(1U);
  }
}

std::optional<Options> local_options(int argc, wchar_t** argv) noexcept {
  Options options{};
  if (argc == 3 && std::wstring_view(argv[1]) == L"local" &&
      std::wstring_view(argv[2]) == L"ping") {
    options.action = protocol::Action::ping;
    return options;
  }
  if (argc == 5 && std::wstring_view(argv[1]) == L"local" &&
      std::wstring_view(argv[2]) == L"query-service" &&
      std::wstring_view(argv[3]) == L"--name" &&
      (std::wstring_view(argv[4]) == L"BFE" || std::wstring_view(argv[4]) == L"EventLog" ||
       std::wstring_view(argv[4]) == L"WinDefend")) {
    options.action = protocol::Action::query_service_status;
    options.service = argv[4];
    return options;
  }
  return std::nullopt;
}

}

bool is_local_command(int argc, wchar_t** argv) noexcept {
  return argc >= 2 && std::wstring_view(argv[1]) == L"local";
}

int run_local(int argc, wchar_t** argv) noexcept {
  auto options = local_options(argc, argv);
  if (!options) return 1;
  const ULONGLONG deadline = GetTickCount64() + 10000U;

  UniqueHandle job(CreateJobObjectW(nullptr, nullptr));
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  if (!job || !SetInformationJobObject(job.get(), JobObjectExtendedLimitInformation,
                                        &limits, sizeof(limits))) return 2;

  HANDLE ready_read_raw = nullptr;
  HANDLE ready_write_raw = nullptr;
  if (!CreatePipe(&ready_read_raw, &ready_write_raw, nullptr, 0U)) return 2;
  UniqueHandle ready_read(ready_read_raw);
  UniqueHandle ready_write(ready_write_raw);
  HANDLE child_ready_raw = nullptr;
  if (!DuplicateHandle(GetCurrentProcess(), ready_write.get(), GetCurrentProcess(),
                       &child_ready_raw, FILE_WRITE_DATA | SYNCHRONIZE, TRUE, 0U)) return 2;
  UniqueHandle child_ready(child_ready_raw);
  ready_write.reset();

  UniqueHandle shutdown(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  HANDLE child_shutdown_raw = nullptr;
  if (!shutdown || !DuplicateHandle(GetCurrentProcess(), shutdown.get(), GetCurrentProcess(),
                                    &child_shutdown_raw, SYNCHRONIZE, TRUE, 0U)) return 2;
  UniqueHandle child_shutdown(child_shutdown_raw);

  const std::array<HANDLE, 2> inherited{child_ready.get(), child_shutdown.get()};
  Attributes attributes;
  SIZE_T bytes = 0U;
  InitializeProcThreadAttributeList(nullptr, 1U, 0U, &bytes);
  attributes.storage.resize(bytes);
  attributes.list = reinterpret_cast<PPROC_THREAD_ATTRIBUTE_LIST>(attributes.storage.data());
  if (!InitializeProcThreadAttributeList(attributes.list, 1U, 0U, &bytes) ||
      !UpdateProcThreadAttribute(attributes.list, 0U, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                 const_cast<HANDLE*>(inherited.data()),
                                 inherited.size() * sizeof(HANDLE), nullptr, nullptr)) return 2;

  const std::wstring broker_path = sibling(L"faultloom_broker.exe");
  const std::wstring reviewer_path = sibling(L"faultloom_reviewer.exe");
  std::wstring command = L"\"" + broker_path + L"\" --ready-handle " +
      std::to_wstring(reinterpret_cast<std::uintptr_t>(child_ready.get())) +
      L" --shutdown-event-handle " +
      std::to_wstring(reinterpret_cast<std::uintptr_t>(child_shutdown.get()));
  STARTUPINFOEXW startup{};
  startup.StartupInfo.cb = sizeof(startup);
  startup.lpAttributeList = attributes.list;
  PROCESS_INFORMATION raw{};
  if (broker_path.empty() || reviewer_path.empty() ||
      !CreateProcessW(broker_path.c_str(), command.data(), nullptr, nullptr, TRUE,
                      CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
                      nullptr, nullptr, &startup.StartupInfo, &raw)) return 2;
  UniqueHandle broker(raw.hProcess);
  UniqueHandle broker_thread(raw.hThread);
  const DWORD broker_pid = raw.dwProcessId;
  if (!AssignProcessToJobObject(job.get(), broker.get()) ||
      ResumeThread(broker_thread.get()) == static_cast<DWORD>(-1)) {
    TerminateProcess(broker.get(), ERROR_OPERATION_ABORTED);
    return 2;
  }
  child_ready.reset();
  child_shutdown.reset();

  std::string ready_line;
  if (!read_ready(ready_read.get(), broker.get(), deadline, ready_line)) return 2;
  auto ready = parse_ready(ready_line, broker_pid);
  if (!ready || !same_image(broker.get(), broker_path)) return 2;
  UniqueHandle reviewer(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE,
                                    ready->reviewer_pid));
  if (!reviewer || WaitForSingleObject(reviewer.get(), 0U) != WAIT_TIMEOUT ||
      !same_image(reviewer.get(), reviewer_path)) return 2;

  options->session = ready->session;
  options->broker_pid = ready->broker_pid;
  options->key_hash = ready->key_hash;
  const int request_result = run(*options);
  const bool signaled = SetEvent(shutdown.get()) != FALSE;
  const DWORD broker_wait = remaining(deadline);
  const bool broker_stopped = broker_wait != 0U &&
      WaitForSingleObject(broker.get(), broker_wait) == WAIT_OBJECT_0;
  const DWORD reviewer_wait = remaining(deadline);
  const bool reviewer_stopped = reviewer_wait != 0U &&
      WaitForSingleObject(reviewer.get(), reviewer_wait) == WAIT_OBJECT_0;
  DWORD broker_exit = STILL_ACTIVE;
  DWORD reviewer_exit = STILL_ACTIVE;
  const bool clean = signaled && broker_stopped && reviewer_stopped &&
      GetExitCodeProcess(broker.get(), &broker_exit) && broker_exit == 0U &&
      GetExitCodeProcess(reviewer.get(), &reviewer_exit) && reviewer_exit == 0U &&
      pipe_absent(L"Broker", ready->session, deadline) &&
      pipe_absent(L"Reviewer", ready->session, deadline);
  return clean ? request_result : 2;
}

}
