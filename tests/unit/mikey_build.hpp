// SPDX-License-Identifier: GPL-3.0-or-later
//
// A small MIKEY-SAKKE message builder for the unit tests of feature 005 (the C++ twin of
// tools/fixturegen/mikey.py; RFC 3830 §6, RFC 6043 §6, RFC 6509 §4).
#pragma once

#include "bytes/bytes.hpp"

#include <cstdint>
#include <string_view>
#include <utility>
#include <vector>

namespace mikey_test {

using mcxanon::Bytes;

inline void put16(Bytes& b, unsigned v) {
  b.push_back(static_cast<std::uint8_t>(v >> 8));
  b.push_back(static_cast<std::uint8_t>(v));
}
inline void put32(Bytes& b, std::uint32_t v) {
  for (int s = 24; s >= 0; s -= 8) b.push_back(static_cast<std::uint8_t>(v >> s));
}
inline Bytes text(std::string_view s) { return Bytes(s.begin(), s.end()); }

struct Part {
  std::uint8_t type;  // the next-payload value that announces this payload
  Bytes body;         // everything after the payload's own next-payload octet (SIGN: everything)
};

inline Part t(std::uint64_t ntp, std::uint8_t ts_type = 0) {
  Part p{5, {ts_type}};
  if (ts_type == 2) {
    put32(p.body, static_cast<std::uint32_t>(ntp));
  } else {
    put32(p.body, static_cast<std::uint32_t>(ntp >> 32));
    put32(p.body, static_cast<std::uint32_t>(ntp));
  }
  return p;
}
inline Part rand(const Bytes& r) {
  Part p{11, {static_cast<std::uint8_t>(r.size())}};
  p.body.insert(p.body.end(), r.begin(), r.end());
  return p;
}
inline Part idr(std::uint8_t role, std::uint8_t type, const Bytes& data) {
  Part p{14, {role, type}};
  put16(p.body, static_cast<unsigned>(data.size()));
  p.body.insert(p.body.end(), data.begin(), data.end());
  return p;
}
inline Part sp(std::uint8_t policy, std::uint8_t prot, const std::vector<std::pair<std::uint8_t, Bytes>>& params) {
  Bytes body;
  for (const auto& [ty, v] : params) {
    body.push_back(ty);
    body.push_back(static_cast<std::uint8_t>(v.size()));
    body.insert(body.end(), v.begin(), v.end());
  }
  Part p{10, {policy, prot}};
  put16(p.body, static_cast<unsigned>(body.size()));
  p.body.insert(p.body.end(), body.begin(), body.end());
  return p;
}
inline Bytes sakke_payload(std::uint8_t next, const Bytes& data, std::uint8_t params = 1, std::uint8_t scheme = 2) {
  Bytes b{next, params, scheme};
  put16(b, static_cast<unsigned>(data.size()));
  b.insert(b.end(), data.begin(), data.end());
  return b;
}
inline Part sakke(const Bytes& data) {
  Bytes full = sakke_payload(0, data);
  return Part{26, Bytes(full.begin() + 1, full.end())};
}
inline Part ext(std::uint8_t type, const Bytes& data) {
  Part p{21, {type}};
  put16(p.body, static_cast<unsigned>(data.size()));
  p.body.insert(p.body.end(), data.begin(), data.end());
  return p;
}
inline Part sign(const Bytes& sig, std::uint8_t s_type = 2) {
  Part p{4, {}};
  put16(p.body, (static_cast<unsigned>(s_type) << 12) | static_cast<unsigned>(sig.size() & 0x0FFF));
  p.body.insert(p.body.end(), sig.begin(), sig.end());
  return p;
}

// A GENERIC-ID block (RFC 6043 §6.1.1).
inline Bytes block(std::uint8_t cs_id, std::uint8_t prot, const std::vector<std::uint8_t>& policies,
                   const std::vector<std::pair<std::uint32_t, std::uint32_t>>& session, const Bytes& spi) {
  Bytes b{cs_id, prot, static_cast<std::uint8_t>(policies.size() & 0x7F)};
  b.insert(b.end(), policies.begin(), policies.end());
  put16(b, static_cast<unsigned>(session.size() * 8));
  for (const auto& [ssrc, roc] : session) {
    put32(b, ssrc);
    put32(b, roc);
  }
  b.push_back(static_cast<std::uint8_t>(spi.size()));
  b.insert(b.end(), spi.begin(), spi.end());
  return b;
}

struct Header {
  std::uint8_t version = 1;
  std::uint8_t data_type = 26;
  bool v = false;
  std::uint8_t prf = 1;
  std::uint32_t csb_id = 0x1ABCDEF0u;
  std::vector<Bytes> blocks;  // GENERIC-ID when non-empty
};

// Header + parts with the chain filled in. The last part should be SIGN.
inline Bytes message(const Header& h, const std::vector<Part>& parts) {
  Bytes b{h.version, h.data_type, parts.empty() ? std::uint8_t{0} : parts[0].type,
          static_cast<std::uint8_t>((h.v ? 0x80 : 0) | (h.prf & 0x7F))};
  put32(b, h.csb_id);
  if (h.blocks.empty()) {
    b.push_back(0);
    b.push_back(1);
  } else {
    b.push_back(static_cast<std::uint8_t>(h.blocks.size()));
    b.push_back(2);
    for (const auto& blk : h.blocks) b.insert(b.end(), blk.begin(), blk.end());
  }
  for (std::size_t i = 0; i < parts.size(); ++i) {
    if (parts[i].type != 4) b.push_back(i + 1 < parts.size() ? parts[i + 1].type : std::uint8_t{0});
    b.insert(b.end(), parts[i].body.begin(), parts[i].body.end());
  }
  return b;
}

// The private call I_MESSAGE of TS 33.180 §E.3.1 with recognisable bytes.
inline Bytes private_call(std::uint32_t pck_id = 0x1ABCDEF0u) {
  Header h;
  h.csb_id = pck_id;
  return message(h, {t(0xE9A1B2C380000000ull), rand(Bytes(16, 0x52)),
                     idr(1, 1, text("sip:alice@example.org")), idr(2, 1, text("sip:bob@example.org")),
                     idr(6, 1, text("kms.example.org")), idr(7, 1, text("kms.example.org")),
                     sakke(Bytes(273, 0x53)), sign(Bytes(129, 0x47))});
}

}  // namespace mikey_test
