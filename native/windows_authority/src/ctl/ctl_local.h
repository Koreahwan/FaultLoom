#pragma once

namespace faultloom::ctl {

[[nodiscard]] bool is_local_command(int argc, wchar_t** argv) noexcept;
[[nodiscard]] int run_local(int argc, wchar_t** argv) noexcept;

}
