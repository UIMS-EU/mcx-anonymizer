// SPDX-License-Identifier: GPL-3.0-or-later
//
// The bounded MIKEY parser of feature 005 (RFC 3830 §6, RFC 6043 §6,
// RFC 6509 §4, TS 33.180 §E.1.2). A message is parsed as a chain of payloads that starts with the
// common header and ends with the SIGN payload; the verdict says whether it is MIKEY-SAKKE as the
// rule set defines it. Parsing is linear in the input and never reads past a declared length.
#pragma once

#include "bytes/bytes.hpp"
#include "policy/mikey_rules.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace mcxanon::mikey {

enum class Verdict { sakke, not_sakke, malformed, limit };

// A GENERIC-ID crypto session block (RFC 6043 §6.1.1).
struct CsBlock {
  std::uint8_t cs_id = 0;
  std::uint8_t prot_type = 0;
  bool s = false;
  std::vector<std::uint8_t> policies;
  Bytes session_data;
  Bytes spi;
};

struct Hdr {
  std::uint8_t version = 1;
  std::uint8_t data_type = 26;
  bool v = false;
  std::uint8_t prf = 0;
  std::uint32_t csb_id = 0;
  std::uint8_t cs_count = 0;
  std::uint8_t map_type = 1;
  std::vector<CsBlock> blocks;  // map type 2
};

struct T {
  std::uint8_t ts_type = 0;
  Bytes value;  // 8 octets (NTP-UTC, NTP) or 4 (COUNTER)
};
struct Rand {
  Bytes rand;
};
struct Idr {
  std::uint8_t role = 0;
  std::uint8_t id_type = 0;
  Bytes data;
};
struct Sp {
  std::uint8_t policy_no = 0;
  std::uint8_t prot_type = 0;
  std::vector<std::pair<std::uint8_t, Bytes>> params;
};
struct Sakke {
  std::uint8_t params = 0;
  std::uint8_t id_scheme = 0;
  Bytes data;
};
struct Ext {
  std::uint8_t type = 0;
  Bytes data;  // type 6: one complete SAKKE payload (next octet included)
};
struct Sign {
  std::uint8_t s_type = 0;
  Bytes signature;
};

struct Payload {
  std::uint8_t type = 0;  // the next-payload value that announced it
  std::variant<T, Rand, Idr, Sp, Sakke, Ext, Sign> v;
};

struct Message {
  Hdr hdr;
  std::vector<Payload> payloads;  // the last one is SIGN
};

struct Decoded {
  Verdict verdict = Verdict::malformed;
  std::string reason;            // "not-sakke", "malformed", "unknown-payload", "limit"
  std::optional<Message> message;  // only for Verdict::sakke
  std::uint8_t data_type = 0;    // as found, for the report
};

Decoded decode(ByteView in, const MikeyRuleSet& rules);

// A SAKKE payload inside a SAKKE-to-self extension (TS 33.180 §E.5): {next, params, scheme, data}.
std::optional<std::pair<std::uint8_t, Sakke>> decode_sakke_payload(ByteView in);

}  // namespace mcxanon::mikey
