// SPDX-License-Identifier: GPL-3.0-or-later
//
// MSRP for MCData (RFC 4975; TS 24.582 §6; FR-026 to FR-028): framing of requests
// and responses on a TCP stream, and the rule-driven rewrite. To-Path and From-Path use the a=path
// mapping of feature 002, transaction ids and Message-IDs keep their length and `ident` grammar,
// content is zeroed with its length kept, and every header without a rule is removed.
#pragma once

#include "mcxanon/error.hpp"

#include "media/counters.hpp"
#include "policy/media_rules.hpp"
#include "rewrite/address_mapper.hpp"
#include "sip/value_map.hpp"

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace mcxanon::media {

// RFC 4975 §9: "MSRP" SP transact-id SP ...; nullopt while too few bytes are there to decide.
std::optional<bool> msrp_is_start(std::string_view data);

enum class MsrpFrameKind { more, message, invalid };
struct MsrpFrame {
  MsrpFrameKind kind = MsrpFrameKind::more;
  std::size_t len = 0;  // message: its length up to and including the end-line's CRLF
};
// The message at the start of `data`: it ends with "-------" transact-id flag CRLF at a line
// start, where transact-id is the start line's (RFC 4975 §7.1).
MsrpFrame msrp_frame(std::string_view data);

struct MsrpRewrite {
  std::string bytes;
  std::size_t head_orig = 0;  // start line and header section of the input...
  std::size_t head_out = 0;   // ...and of the output; the rest keeps its length
  bool zeroed = false;        // the message is zeroed with its length (method, malformed)
};

// One framed message. Errors are tool failures (pseudonym collision).
Result<MsrpRewrite> rewrite_msrp(std::string_view message, const MediaRuleSet& rules, sip::Context& sip,
                                 AddressMapper& mapper, MediaCounters& counters);

}  // namespace mcxanon::media
