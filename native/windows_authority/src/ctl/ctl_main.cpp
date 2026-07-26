#include "ctl_local.h"
#include "ctl_runtime.h"

int wmain(int argc, wchar_t** argv) {
  if (faultloom::ctl::is_local_command(argc, argv)) return faultloom::ctl::run_local(argc, argv);
  const auto options = faultloom::ctl::parse_options(argc, argv);
  return options.has_value() ? faultloom::ctl::run(*options) : 1;
}
