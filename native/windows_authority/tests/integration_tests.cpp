#include "integration_support.h"

#include <cstdlib>
#include <iostream>
#include <string_view>

int wmain(int argc, wchar_t** argv) {
  using namespace faultloom::integration;
  if (argc == 2 && std::wstring_view(argv[1]) == L"--fast-exit") return 0;
  if (argc == 2 && std::wstring_view(argv[1]) == L"--memory-over-limit") {
    void* memory = VirtualAlloc(nullptr, 192ULL * 1024ULL * 1024ULL,
                                MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (memory == nullptr) return 3;
    *static_cast<volatile unsigned char*>(memory) = 1U;
    return VirtualFree(memory, 0U, MEM_RELEASE) ? 0 : 3;
  }
  if (argc == 2 && std::wstring_view(argv[1]) == L"--predicate-self-test") {
    return predicate_self_test();
  }
  if (argc >= 2 && std::wstring_view(argv[1]) == L"--oracle") return oracle_main(argc, argv);
  if (argc == 2 && std::wstring_view(argv[1]) == L"--oracle-stall") {
    Sleep(30000U);
    return 0;
  }
  if (argc == 3 && std::wstring_view(argv[1]) == L"--death-supervisor") {
    wchar_t* end = nullptr;
    const auto value = std::wcstoull(argv[2], &end, 10);
    return end != argv[2] && *end == L'\0' ? death_supervisor_main(
        static_cast<std::uintptr_t>(value)) : 2;
  }
  if (argc != 1) {
    std::cerr << "invalid integration arguments\n";
    return 2;
  }
  return smoke_main();
}
