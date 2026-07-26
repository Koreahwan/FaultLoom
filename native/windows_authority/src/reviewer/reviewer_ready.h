#pragma once

#include "faultloom/signer.h"
#include "reviewer_io.h"

namespace faultloom::reviewer {

[[nodiscard]] IoResult report_ready(HANDLE ready, HANDLE shutdown, HANDLE broker,
                                    const signing::PublicBlob& blob) noexcept;

}
