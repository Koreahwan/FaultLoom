#include "broker_runtime.h"

int wmain(int argc, wchar_t** argv) {
  const auto options = faultloom::broker::parse_options(argc, argv);
  return options.has_value() ? faultloom::broker::run(*options) : 1;
}
