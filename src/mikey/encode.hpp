// SPDX-License-Identifier: GPL-3.0-or-later
//
// Re-serialises a Message (decode.hpp) with every next-payload field and length recomputed from
// its contents (spec FR-005).
#pragma once

#include "bytes/bytes.hpp"
#include "mikey/decode.hpp"

namespace mcxanon::mikey {

Bytes encode(const Message& m);
Bytes encode_sakke_payload(std::uint8_t next, const Sakke& s);

}  // namespace mcxanon::mikey
