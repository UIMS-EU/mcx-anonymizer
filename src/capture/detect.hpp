// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "mcxanon/error.hpp"

#include "bytes/bytes.hpp"
#include "capture/record.hpp"

namespace mcxanon {

// Detects the capture format from the first bytes of a file. Compressed files
// and unknown formats are input errors.
Result<CaptureFormat> detect_format(ByteView head);

}  // namespace mcxanon
