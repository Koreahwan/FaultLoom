#include "reviewer_process_fixture.h"

#include <windows.h>

#include <array>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace {

using faultloom::test::ReviewerProcess;
using faultloom::test::TestHandle;

constexpr std::size_t readiness_size(std::size_t pid_digits) noexcept {
  return sizeof("REVIEWER_READY v1 reviewer_pid=") - 1U + pid_digits +
         sizeof(" public_blob=") - 1U + 144U + 1U;
}

static_assert(readiness_size(1U) == 190U);
static_assert(readiness_size(10U) == 199U);

bool expect(bool condition, std::string_view message) {
  if (!condition) std::cerr << message << '\n';
  return condition;
}

struct WaitBroker {
  TestHandle process;
  TestHandle thread;
  DWORD pid;
};

std::optional<WaitBroker> start_wait_broker(HANDLE event) {
  const auto test = faultloom::test::sibling_test();
  std::wstring command = L"\"" + test + L"\" --broker-wait " +
                         std::to_wstring(reinterpret_cast<std::uintptr_t>(event));
  STARTUPINFOW startup{sizeof(startup)};
  PROCESS_INFORMATION process{};
  if (!CreateProcessW(test.c_str(), command.data(), nullptr, nullptr, TRUE, 0U, nullptr, nullptr,
                      &startup, &process)) return std::nullopt;
  return WaitBroker{TestHandle(process.hProcess), TestHandle(process.hThread), process.dwProcessId};
}

bool helper_wait(int argc, wchar_t** argv) noexcept {
  if (argc != 3) return false;
  wchar_t* end = nullptr;
  const unsigned long long value = std::wcstoull(argv[2], &end, 10);
  if (end == argv[2] || *end != L'\0') return false;
  return WaitForSingleObject(reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(value)), 10000U) == WAIT_OBJECT_0;
}

bool wrong_client(int argc, wchar_t** argv) {
  if (argc != 3) return false;
  const auto review = faultloom::test::make_review(faultloom::protocol::Action::ping);
  return review.has_value() && !faultloom::test::exchange(argv[2], review->record).has_value();
}

bool build_review(int argc, wchar_t** argv) {
  if (argc != 4) return false;
  wchar_t* end = nullptr;
  const unsigned long long write_value = std::wcstoull(argv[2], &end, 10);
  const auto review = faultloom::test::make_review(faultloom::protocol::Action::ping);
  if (end == argv[2] || *end != L'\0' || !review.has_value()) return false;
  end = nullptr;
  const unsigned long long release_value = std::wcstoull(argv[3], &end, 10);
  if (end == argv[3] || *end != L'\0') return false;
  DWORD written = 0U;
  return WriteFile(reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(write_value)),
                   review->record.data(), static_cast<DWORD>(review->record.size()),
                   &written, nullptr) && written == review->record.size() &&
         WaitForSingleObject(
             reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(release_value)), 10000U) ==
             WAIT_OBJECT_0;
}

struct LiveReview {
  faultloom::test::ReviewRecord review;
  TestHandle process;
  TestHandle release;

  LiveReview(faultloom::test::ReviewRecord value, TestHandle child, TestHandle release_event)
      : review(std::move(value)), process(std::move(child)), release(std::move(release_event)) {}

  [[nodiscard]] bool finish() noexcept {
    if (!process) return true;
    const bool signaled = SetEvent(release.get()) != FALSE;
    const bool exited = WaitForSingleObject(process.get(), 10000U) == WAIT_OBJECT_0;
    DWORD code = STILL_ACTIVE;
    const bool status = exited && GetExitCodeProcess(process.get(), &code) != FALSE && code == 0U;
    if (!exited) {
      TerminateProcess(process.get(), ERROR_TIMEOUT);
      WaitForSingleObject(process.get(), 1000U);
    }
    process.reset();
    release.reset();
    return signaled && status;
  }

  ~LiveReview() { [[maybe_unused]] const bool cleaned = finish(); }
  LiveReview(LiveReview&&) noexcept = default;
  LiveReview& operator=(LiveReview&&) noexcept = default;
  LiveReview(const LiveReview&) = delete;
  LiveReview& operator=(const LiveReview&) = delete;
};

std::optional<LiveReview> make_child_ping() {
  SECURITY_ATTRIBUTES inherited{sizeof(inherited), nullptr, TRUE};
  HANDLE raw_read = nullptr;
  HANDLE raw_write = nullptr;
  if (!CreatePipe(&raw_read, &raw_write, &inherited, 0U)) return std::nullopt;
  TestHandle read(raw_read);
  TestHandle write(raw_write);
  if (!SetHandleInformation(read.get(), HANDLE_FLAG_INHERIT, 0U)) return std::nullopt;
  TestHandle release_owner(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  HANDLE raw_release_child = nullptr;
  if (!release_owner ||
      !DuplicateHandle(GetCurrentProcess(), release_owner.get(), GetCurrentProcess(),
                       &raw_release_child, SYNCHRONIZE, TRUE, 0U)) return std::nullopt;
  TestHandle release_child(raw_release_child);
  const auto test = faultloom::test::sibling_test();
  std::wstring command = L"\"" + test + L"\" --build-review " +
                         std::to_wstring(reinterpret_cast<std::uintptr_t>(write.get())) + L" " +
                         std::to_wstring(reinterpret_cast<std::uintptr_t>(release_child.get()));
  STARTUPINFOW startup{sizeof(startup)};
  PROCESS_INFORMATION process{};
  if (!CreateProcessW(test.c_str(), command.data(), nullptr, nullptr, TRUE, 0U, nullptr, nullptr,
                      &startup, &process)) return std::nullopt;
  TestHandle child(process.hProcess);
  TestHandle thread(process.hThread);
  write.reset();
  release_child.reset();
  std::array<std::uint8_t, faultloom::protocol::kMaxRecordBytes> bytes{};
  DWORD received = 0U;
  if (!ReadFile(read.get(), bytes.data(), static_cast<DWORD>(bytes.size()), &received, nullptr) ||
      received < 4U) return std::nullopt;
  std::vector<std::uint8_t> record(bytes.begin(), bytes.begin() + received);
  const auto decoded = faultloom::protocol::decode_record(record);
  const auto envelope = decoded.frame.has_value()
      ? faultloom::protocol::review_envelope(*decoded.frame)
      : std::nullopt;
  if (!envelope.has_value()) return std::nullopt;
  if (WaitForSingleObject(child.get(), 0U) != WAIT_TIMEOUT) return std::nullopt;
  std::vector<std::uint8_t> payload(record.begin() + 4U, record.end());
  return LiveReview{faultloom::test::ReviewRecord{
                        std::move(payload), std::move(record),
                        faultloom::protocol::kHeaderBytes + 6U,
                        faultloom::protocol::kHeaderBytes + 8U + envelope->sid.size()},
                    std::move(child), std::move(release_owner)};
}

bool denied(const ReviewerProcess& reviewer, std::span<const std::uint8_t> record,
            std::string_view message) {
  return expect(!faultloom::test::exchange(reviewer.pipe_name(), record).has_value(), message);
}

bool valid_ping(const ReviewerProcess& reviewer, const faultloom::test::ReviewRecord& review) {
  const auto response = faultloom::test::exchange(reviewer.pipe_name(), review.record);
  return response.has_value() && faultloom::test::verify_decision(reviewer.ready(), review, *response);
}

}

int wmain(int argc, wchar_t** argv) {
  if (argc > 1 && std::wstring_view(argv[1]) == L"--broker-wait") return helper_wait(argc, argv) ? 0 : 1;
  if (argc > 1 && std::wstring_view(argv[1]) == L"--wrong-client") return wrong_client(argc, argv) ? 0 : 1;
  if (argc > 1 && std::wstring_view(argv[1]) == L"--build-review") return build_review(argc, argv) ? 0 : 1;

  bool passed = true;
  auto first = ReviewerProcess::launch(L"0123456789abcdef0123456789abcdea", GetCurrentProcessId());
  auto ping = make_child_ping();
  passed &= expect(first.has_value() && ping.has_value(), "first Reviewer launch failed");
  faultloom::signing::PublicBlob first_blob{};
  if (first.has_value() && ping.has_value()) {
    first_blob = first->ready().public_blob;
    passed &= expect(valid_ping(*first, ping->review), "valid live-ctl PING signature did not verify independently");
    passed &= expect(ping->finish(), "live ctl helper did not cleanly release after decision");
    passed &= expect(first->stop(), "first Reviewer did not stop cleanly");
  }

  auto reviewer = ReviewerProcess::launch(L"0123456789abcdef0123456789abcdeb", GetCurrentProcessId());
  passed &= expect(reviewer.has_value(), "second Reviewer launch failed");
  if (!reviewer.has_value() || !ping.has_value()) return 1;
  passed &= expect(reviewer->ready().public_blob != first_blob, "separate Reviewer launches reused a public key");

  auto wrong_pid = ping->review;
  std::fill_n(wrong_pid.record.begin() + 4U + faultloom::protocol::kHeaderBytes, 4U,
              std::uint8_t{0});
  passed &= denied(*reviewer, wrong_pid.record, "zero embedded ctl PID produced a decision");

  const auto sid = faultloom::test::current_sid();
  if (sid.has_value()) {
    auto wrong_sid = ping->review;
    wrong_sid.record[4U + wrong_sid.sid_offset + sid->size() - 1U] ^= 1U;
    passed &= denied(*reviewer, wrong_sid.record, "embedded SID mismatch produced a decision");
  } else {
    passed = false;
  }

  auto malformed = ping->review.record;
  malformed[4U + 32U] = 1U;
  passed &= denied(*reviewer, malformed, "malformed frame produced a decision");

  auto embedded = ping->review.record;
  embedded[4U + ping->review.client_offset + 8U] ^= 1U;
  passed &= denied(*reviewer, embedded, "altered embedded request produced a decision");

  const auto expired = faultloom::test::make_review(faultloom::protocol::Action::ping, {}, -1);
  const auto overlong = faultloom::test::make_review(faultloom::protocol::Action::ping, {}, 6);
  const auto spooler = faultloom::test::make_review(
      faultloom::protocol::Action::query_service_status, "Spooler");
  passed &= expired.has_value() && denied(*reviewer, expired->record, "expired deadline produced a decision");
  passed &= overlong.has_value() && denied(*reviewer, overlong->record, "overlong deadline produced a decision");
  passed &= spooler.has_value() && denied(*reviewer, spooler->record, "nonallowlisted service produced a decision");

  auto duplicate = ping->review.record;
  duplicate.insert(duplicate.end(), ping->review.record.begin(), ping->review.record.end());
  passed &= denied(*reviewer, duplicate, "duplicate record produced a decision");
  auto trailing = ping->review.record;
  trailing.push_back(0U);
  passed &= denied(*reviewer, trailing, "trailing record byte produced a decision");
  auto serial_ping = make_child_ping();
  passed &= expect(serial_ping.has_value() && valid_ping(*reviewer, serial_ping->review),
                   "second serial record was not isolated from prior denials");
  if (serial_ping.has_value()) passed &= expect(serial_ping->finish(), "serial ctl helper leaked");

  passed &= expect(faultloom::test::send_short(reviewer->pipe_name(), ping->review.record), "short record write failed");
  auto recovery_ping = make_child_ping();
  passed &= expect(recovery_ping.has_value() && valid_ping(*reviewer, recovery_ping->review),
                   "Reviewer did not recover after EOF-short record");
  if (recovery_ping.has_value()) passed &= expect(recovery_ping->finish(), "recovery ctl helper leaked");
  const std::span<const std::uint8_t> stalled(ping->review.record.data(), 5U);
  passed &= denied(*reviewer, stalled, "five-second partial-body stall produced a decision");

  const auto test = faultloom::test::sibling_test();
  const std::wstring wrong_client_command = L"\"" + test + L"\" --wrong-client " + reviewer->pipe_name();
  passed &= expect(faultloom::test::launch_and_wait(wrong_client_command, 0U),
                   "same-user wrong process was not rejected");
  passed &= expect(reviewer->stop(), "second Reviewer did not stop cleanly");

  SECURITY_ATTRIBUTES inherited{sizeof(inherited), nullptr, TRUE};
  TestHandle broker_exit(CreateEventW(&inherited, TRUE, FALSE, nullptr));
  auto broker = broker_exit ? start_wait_broker(broker_exit.get()) : std::nullopt;
  passed &= expect(broker.has_value(), "Broker-lifetime helper launch failed");
  if (broker.has_value()) {
    auto orphan = ReviewerProcess::launch(L"0123456789abcdef0123456789abcdec", broker->pid);
    passed &= expect(orphan.has_value(), "Broker-death Reviewer launch failed");
    passed &= expect(SetEvent(broker_exit.get()) != FALSE, "Broker-lifetime helper signal failed");
    passed &= expect(WaitForSingleObject(broker->process.get(), 10000U) == WAIT_OBJECT_0,
                     "Broker-lifetime helper did not exit");
    if (orphan.has_value()) {
      passed &= expect(orphan->wait_for_exit(10000U), "Reviewer survived retained Broker death");
      passed &= expect(orphan->stop(), "Broker-death Reviewer cleanup status failed");
    }
    passed &= expect(faultloom::test::launch_reviewer_failure(
                         L"0123456789abcdef0123456789abcded", broker->pid, 3U),
                     "dead expected Broker PID was accepted");
  }

  std::cout << "REVIEWER_PROCESS_KEYS=2 DENIAL_CLASSES=11 STALL_BOUND_MS=7000\n";
  return passed ? 0 : 1;
}
