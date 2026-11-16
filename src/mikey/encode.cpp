// SPDX-License-Identifier: GPL-3.0-or-later
#include "mikey/encode.hpp"

#include <type_traits>

namespace mcxanon::mikey {

namespace {

void put16(Bytes& b, std::size_t v) {
  b.push_back(static_cast<std::uint8_t>(v >> 8));
  b.push_back(static_cast<std::uint8_t>(v));
}
void put32(Bytes& b, std::uint32_t v) {
  for (int s = 24; s >= 0; s -= 8) b.push_back(static_cast<std::uint8_t>(v >> s));
}
void append(Bytes& b, const Bytes& x) { b.insert(b.end(), x.begin(), x.end()); }

}  // namespace

Bytes encode_sakke_payload(std::uint8_t next, const Sakke& s) {
  Bytes b{next, s.params, s.id_scheme};
  put16(b, s.data.size());
  append(b, s.data);
  return b;
}

Bytes encode(const Message& m) {
  Bytes b;
  const auto& h = m.hdr;
  b.push_back(h.version);
  b.push_back(h.data_type);
  b.push_back(m.payloads.empty() ? std::uint8_t{0} : m.payloads.front().type);
  b.push_back(static_cast<std::uint8_t>((h.v ? 0x80 : 0) | (h.prf & 0x7F)));
  put32(b, h.csb_id);
  b.push_back(h.map_type == 2 ? static_cast<std::uint8_t>(h.blocks.size()) : h.cs_count);
  b.push_back(h.map_type);
  for (const auto& blk : h.blocks) {
    b.push_back(blk.cs_id);
    b.push_back(blk.prot_type);
    b.push_back(static_cast<std::uint8_t>((blk.s ? 0x80 : 0) | (blk.policies.size() & 0x7F)));
    b.insert(b.end(), blk.policies.begin(), blk.policies.end());
    put16(b, blk.session_data.size());
    append(b, blk.session_data);
    b.push_back(static_cast<std::uint8_t>(blk.spi.size()));
    append(b, blk.spi);
  }
  for (std::size_t i = 0; i < m.payloads.size(); ++i) {
    const auto& p = m.payloads[i];
    const std::uint8_t following = i + 1 < m.payloads.size() ? m.payloads[i + 1].type : std::uint8_t{0};
    std::visit(
        [&](const auto& v) {
          using V = std::decay_t<decltype(v)>;
          if constexpr (std::is_same_v<V, Sign>) {
            put16(b, (static_cast<std::size_t>(v.s_type) << 12) | (v.signature.size() & 0x0FFF));
            append(b, v.signature);
          } else {
            b.push_back(following);
            if constexpr (std::is_same_v<V, T>) {
              b.push_back(v.ts_type);
              append(b, v.value);
            } else if constexpr (std::is_same_v<V, Rand>) {
              b.push_back(static_cast<std::uint8_t>(v.rand.size()));
              append(b, v.rand);
            } else if constexpr (std::is_same_v<V, Idr>) {
              b.push_back(v.role);
              b.push_back(v.id_type);
              put16(b, v.data.size());
              append(b, v.data);
            } else if constexpr (std::is_same_v<V, Sp>) {
              b.push_back(v.policy_no);
              b.push_back(v.prot_type);
              std::size_t len = 0;
              for (const auto& [ty, val] : v.params) len += 2 + val.size();
              put16(b, len);
              for (const auto& [ty, val] : v.params) {
                b.push_back(ty);
                b.push_back(static_cast<std::uint8_t>(val.size()));
                append(b, val);
              }
            } else if constexpr (std::is_same_v<V, Sakke>) {
              b.push_back(v.params);
              b.push_back(v.id_scheme);
              put16(b, v.data.size());
              append(b, v.data);
            } else if constexpr (std::is_same_v<V, Ext>) {
              b.push_back(v.type);
              put16(b, v.data.size());
              append(b, v.data);
            }
          }
        },
        p.v);
  }
  return b;
}

}  // namespace mcxanon::mikey
