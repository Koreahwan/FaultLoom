#include "reviewer_runtime.h"

int wmain(int argc, wchar_t** argv) {
  const auto options = faultloom::reviewer::parse_options(argc, argv);
  if (!options.has_value()) return 1;
  return faultloom::reviewer::run(*options, faultloom::signing::make_ephemeral_signer());
}
