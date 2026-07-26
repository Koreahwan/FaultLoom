#include "faultloom/protocol.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <new>
#include <span>
#include <string_view>
#include <vector>

namespace {

struct alignas(std::max_align_t) AllocationHeader {
  std::size_t size;
  bool tracked;
};

std::atomic<bool> g_tracking{false};
std::atomic<std::size_t> g_current_bytes{0U};
std::atomic<std::size_t> g_maximum_single{0U};
std::atomic<std::size_t> g_peak_bytes{0U};

void update_maximum(std::atomic<std::size_t>& target, std::size_t value) noexcept {
  std::size_t current = target.load();
  while (current < value && !target.compare_exchange_weak(current, value)) {}
}

void* allocate(std::size_t size) {
  if (size > std::numeric_limits<std::size_t>::max() - sizeof(AllocationHeader)) throw std::bad_alloc();
  auto* header = static_cast<AllocationHeader*>(std::malloc(sizeof(AllocationHeader) + size));
  if (header == nullptr) throw std::bad_alloc();
  header->size = size;
  header->tracked = g_tracking.load();
  if (header->tracked) {
    update_maximum(g_maximum_single, size);
    update_maximum(g_peak_bytes, g_current_bytes.fetch_add(size) + size);
  }
  return header + 1;
}

void deallocate(void* memory) noexcept {
  if (memory == nullptr) return;
  auto* header = static_cast<AllocationHeader*>(memory) - 1;
  if (header->tracked) g_current_bytes.fetch_sub(header->size);
  std::free(header);
}

void reset_measurement() noexcept {
  g_current_bytes.store(0U);
  g_maximum_single.store(0U);
  g_peak_bytes.store(0U);
}

std::vector<std::uint8_t> bytes(std::string_view hex) {
  std::vector<std::uint8_t> result;
  result.reserve(hex.size() / 2U);
  for (std::size_t index = 0U; index < hex.size(); index += 2U) {
    const auto digit = [](char value) -> std::uint8_t {
      return static_cast<std::uint8_t>(value <= '9' ? value - '0' : value - 'a' + 10);
    };
    result.push_back(static_cast<std::uint8_t>((digit(hex[index]) << 4U) | digit(hex[index + 1U])));
  }
  return result;
}

bool expect(bool condition, std::string_view message) {
  if (!condition) std::cerr << message << '\n';
  return condition;
}

}

void* operator new(std::size_t size) { return allocate(size); }
void* operator new[](std::size_t size) { return allocate(size); }
void operator delete(void* memory) noexcept { deallocate(memory); }
void operator delete[](void* memory) noexcept { deallocate(memory); }
void operator delete(void* memory, std::size_t) noexcept { deallocate(memory); }
void operator delete[](void* memory, std::size_t) noexcept { deallocate(memory); }

int main() {
  static_assert(faultloom::protocol::kApplicationDecoderAllocationLimitBytes ==
                faultloom::protocol::kMaxPayloadBytes);
  bool passed = true;
  std::array<std::uint8_t, faultloom::protocol::kMaxPayloadBytes + 1U> generated{};
  std::uint64_t state = 0x4d595df4d0f33173ULL;
  reset_measurement();
  for (std::size_t iteration = 0U; iteration < 10000U; ++iteration) {
    const std::array<std::size_t, 4> lengths{43U, 44U, 207U, 209U};
    const std::size_t length = lengths[iteration % lengths.size()];
    for (std::size_t index = 0U; index < length; ++index) {
      state ^= state << 13U; state ^= state >> 7U; state ^= state << 17U;
      generated[index] = static_cast<std::uint8_t>(state);
    }
    std::copy_n(std::array<std::uint8_t, 6>{0x46U, 0x4cU, 0x4dU, 0x31U, 1U, 0U}.begin(), 6U, generated.begin());
    generated[8] = 1U;
    std::fill(generated.begin() + 9U, generated.begin() + 24U, std::uint8_t{0});
    const auto put16 = [&](std::size_t offset, std::uint16_t field) {
      generated[offset] = static_cast<std::uint8_t>(field);
      generated[offset + 1U] = static_cast<std::uint8_t>(field >> 8U);
    };
    const auto put32 = [&](std::size_t offset, std::uint32_t field) {
      put16(offset, static_cast<std::uint16_t>(field));
      put16(offset + 2U, static_cast<std::uint16_t>(field >> 16U));
    };
    const std::uint16_t type = static_cast<std::uint16_t>((iteration % 4U) + 1U);
    put16(6U, type); put16(24U, type == 1U ? 1U : 2U); put16(26U, type == 4U ? 4U : 0U);
    put32(28U, static_cast<std::uint32_t>(length - faultloom::protocol::kHeaderBytes)); put32(32U, 0U);
    if (type == 2U) put16(40U, 0U);
    if (type == 3U) generated[68] = 0U;
    if (type == 4U) generated[68] = 1U;
    g_tracking.store(true);
    const auto result = faultloom::protocol::decode_payload(std::span(generated.data(), length));
    g_tracking.store(false);
    passed &= expect(result.error != faultloom::protocol::DecodeError::none, "generated malformed input accepted");
  }
  const std::size_t malformed_maximum_single = g_maximum_single.load();
  const std::size_t malformed_peak_bytes = g_peak_bytes.load();
  passed &= expect(g_current_bytes.load() == 0U, "malformed decoder retained application allocation");

  constexpr std::string_view kValidP256Decision = "464c4d31010003000102030405060708090a0b0c0d0e0f1001000000ab0000000000000091f6f29c22714c6fe36ede4cb64b630f3ec03321adc01b48607c7cebc2da488701000045435331200000006b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f500000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002";
  const auto valid_p256_decision = bytes(kValidP256Decision);
  reset_measurement();
  g_tracking.store(true);
  const auto valid_result = faultloom::protocol::decode_payload(valid_p256_decision);
  g_tracking.store(false);
  const std::size_t evidence_maximum_single = g_maximum_single.load();
  const std::size_t evidence_peak_bytes = g_peak_bytes.load();
  passed &= expect(valid_result.error == faultloom::protocol::DecodeError::none && valid_result.frame.has_value(),
                   "valid P256 signed evidence did not decode");
  passed &= expect(g_current_bytes.load() == 0U, "evidence decoder retained application allocation");
  passed &= expect(malformed_maximum_single <= faultloom::protocol::kApplicationDecoderAllocationLimitBytes &&
                       malformed_peak_bytes <= faultloom::protocol::kApplicationDecoderAllocationLimitBytes &&
                       evidence_maximum_single <= faultloom::protocol::kApplicationDecoderAllocationLimitBytes &&
                       evidence_peak_bytes <= faultloom::protocol::kApplicationDecoderAllocationLimitBytes,
                   "application decoder allocation exceeded frame cap");
  std::cout << "GENERATED_INPUTS=10000 MALFORMED_APPLICATION_NEW_MAX_SINGLE=" << malformed_maximum_single
            << " MALFORMED_APPLICATION_NEW_PEAK=" << malformed_peak_bytes
            << " VALID_P256_EVIDENCE_DECODES=1 EVIDENCE_APPLICATION_NEW_MAX_SINGLE=" << evidence_maximum_single
            << " EVIDENCE_APPLICATION_NEW_PEAK=" << evidence_peak_bytes
            << " CNG_INTERNAL_ALLOCATION=OPAQUE\n";
  return passed ? 0 : 1;
}
