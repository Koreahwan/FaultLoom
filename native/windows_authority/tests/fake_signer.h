#pragma once

#include "faultloom/signer.h"

#include <memory>

namespace faultloom::test {

[[nodiscard]] std::unique_ptr<signing::Signer> make_fake_signer();

}
