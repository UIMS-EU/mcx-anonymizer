// SPDX-License-Identifier: GPL-3.0-or-later
#include "mikey/decode.hpp"

#include "mikey/limits.hpp"

namespace mcxanon::mikey {

namespace {

constexpr std::uint8_t kSign = 4;
constexpr std::uint8_t kT = 5;
constexpr std::uint8_t kSp = 10;
constexpr std::uint8_t kRand = 11;
constexpr std::uint8_t kIdr = 14;
constexpr std::uint8_t kExt = 21;
constexpr std::uint8_t kSakke = 26;

struct Cursor {
  ByteView b;
  std::size_t i = 0;
  [[nodiscard]] bool has(std::size_t n) const { return i <= b.size() && b.size() - i >= n; }
  std::uint8_t u8() { return b[i++]; }
  unsigned u16() {
    const unsigned v = (static_cast<unsigned>(b[i]) << 8) | b[i + 1];
    i += 2;
    return v;
  }
  std::uint32_t u32() {
    std::uint32_t v = 0;
    for (int k = 0; k < 4; ++k) v = (v << 8) | b[i++];
    return v;
  }
  Bytes take(std::size_t n) {
    Bytes out(b.begin() + static_cast<std::ptrdiff_t>(i), b.begin() + static_cast<std::ptrdiff_t>(i + n));
    i += n;
    return out;
  }
};

Decoded verdict(Verdict v, const char* reason, std::uint8_t data_type) {
  Decoded d;
  d.verdict = v;
  d.reason = reason;
  d.data_type = data_type;
  return d;
}

}  // namespace

std::optional<std::pair<std::uint8_t, Sakke>> decode_sakke_payload(ByteView in) {
  Cursor c{in};
  if (!c.has(5)) return std::nullopt;
  const std::uint8_t next = c.u8();
  Sakke s;
  s.params = c.u8();
  s.id_scheme = c.u8();
  const unsigned len = c.u16();
  if (!c.has(len) || c.i + len != in.size()) return std::nullopt;
  s.data = c.take(len);
  return std::pair{next, s};
}

Decoded decode(ByteView in, const MikeyRuleSet& rules) {
  const auto& m = rules.message;
  if (in.size() > m.max_size || in.size() > kMaxMessage) return verdict(Verdict::limit, "limit", 0);
  Cursor c{in};
  if (!c.has(10)) return verdict(Verdict::malformed, "malformed", in.empty() ? 0 : (in.size() > 1 ? in[1] : 0));
  Message msg;
  auto& h = msg.hdr;
  h.version = c.u8();
  h.data_type = c.u8();
  std::uint8_t next = c.u8();
  const std::uint8_t vprf = c.u8();
  h.v = (vprf & 0x80) != 0;
  h.prf = vprf & 0x7F;
  h.csb_id = c.u32();
  h.cs_count = c.u8();
  h.map_type = c.u8();
  if (h.version != m.version || h.data_type != m.data_type || (h.v ? 1u : 0u) != m.v_flag) {
    return verdict(Verdict::not_sakke, "not-sakke", h.data_type);
  }
  if (h.cs_count == 0) {
    if (h.map_type != 1 && h.map_type != 0) return verdict(Verdict::malformed, "malformed", h.data_type);
  } else if (h.map_type == 2) {
    for (unsigned k = 0; k < h.cs_count; ++k) {
      CsBlock blk;
      if (!c.has(3)) return verdict(Verdict::malformed, "malformed", h.data_type);
      blk.cs_id = c.u8();
      blk.prot_type = c.u8();
      const std::uint8_t sp = c.u8();
      blk.s = (sp & 0x80) != 0;
      const unsigned np = sp & 0x7F;
      if (!c.has(np + 2)) return verdict(Verdict::malformed, "malformed", h.data_type);
      for (unsigned p = 0; p < np; ++p) blk.policies.push_back(c.u8());
      const unsigned sl = c.u16();
      if (!c.has(sl + 1)) return verdict(Verdict::malformed, "malformed", h.data_type);
      blk.session_data = c.take(sl);
      const unsigned spl = c.u8();
      if (!c.has(spl)) return verdict(Verdict::malformed, "malformed", h.data_type);
      blk.spi = c.take(spl);
      h.blocks.push_back(std::move(blk));
    }
  } else {
    return verdict(Verdict::malformed, "malformed", h.data_type);
  }
  bool signed_last = false;
  while (true) {
    if (msg.payloads.size() >= m.max_payloads || msg.payloads.size() >= kMaxPayloads) {
      return verdict(Verdict::limit, "limit", h.data_type);
    }
    const auto* rule = rules.payload(next);
    if (next == 0) break;  // the chain ended without SIGN
    if (rule == nullptr || rule->action == MikeyAction::fallback) {
      return verdict(Verdict::not_sakke, "unknown-payload", h.data_type);
    }
    Payload p;
    p.type = next;
    if (next == kSign) {
      if (!c.has(2)) return verdict(Verdict::malformed, "malformed", h.data_type);
      const unsigned w = c.u16();
      Sign s;
      s.s_type = static_cast<std::uint8_t>(w >> 12);
      const unsigned len = w & 0x0FFF;
      if (!c.has(len)) return verdict(Verdict::malformed, "malformed", h.data_type);
      s.signature = c.take(len);
      if (s.s_type != m.sign_s_type) return verdict(Verdict::not_sakke, "not-sakke", h.data_type);
      p.v = std::move(s);
      msg.payloads.push_back(std::move(p));
      signed_last = true;
      break;
    }
    if (!c.has(1)) return verdict(Verdict::malformed, "malformed", h.data_type);
    const std::uint8_t following = c.u8();
    switch (next) {
      case kT: {
        if (!c.has(1)) return verdict(Verdict::malformed, "malformed", h.data_type);
        T t;
        t.ts_type = c.u8();
        if (!rules.ts_types.contains(t.ts_type)) return verdict(Verdict::malformed, "malformed", h.data_type);
        const std::size_t len = t.ts_type == 2 ? 4 : 8;
        if (!c.has(len)) return verdict(Verdict::malformed, "malformed", h.data_type);
        t.value = c.take(len);
        p.v = std::move(t);
        break;
      }
      case kRand: {
        if (!c.has(1)) return verdict(Verdict::malformed, "malformed", h.data_type);
        const unsigned len = c.u8();
        if (len == 0 || !c.has(len)) return verdict(Verdict::malformed, "malformed", h.data_type);
        p.v = Rand{c.take(len)};
        break;
      }
      case kIdr: {
        if (!c.has(4)) return verdict(Verdict::malformed, "malformed", h.data_type);
        Idr r;
        r.role = c.u8();
        r.id_type = c.u8();
        const unsigned len = c.u16();
        if (len > m.max_id_data || len > kMaxIdData) return verdict(Verdict::limit, "limit", h.data_type);
        if (!c.has(len)) return verdict(Verdict::malformed, "malformed", h.data_type);
        r.data = c.take(len);
        if (const auto* role = rules.id_role(r.role, r.id_type); role != nullptr && role->action == MikeyAction::fallback) {
          return verdict(Verdict::not_sakke, "unknown-payload", h.data_type);
        }
        p.v = std::move(r);
        break;
      }
      case kSp: {
        if (!c.has(4)) return verdict(Verdict::malformed, "malformed", h.data_type);
        Sp s;
        s.policy_no = c.u8();
        s.prot_type = c.u8();
        const unsigned len = c.u16();
        if (!c.has(len)) return verdict(Verdict::malformed, "malformed", h.data_type);
        const std::size_t end = c.i + len;
        while (c.i < end) {
          if (end - c.i < 2) return verdict(Verdict::malformed, "malformed", h.data_type);
          const std::uint8_t ty = c.u8();
          const unsigned vl = c.u8();
          if (end - c.i < vl) return verdict(Verdict::malformed, "malformed", h.data_type);
          s.params.emplace_back(ty, c.take(vl));
        }
        p.v = std::move(s);
        break;
      }
      case kSakke: {
        if (!c.has(4)) return verdict(Verdict::malformed, "malformed", h.data_type);
        Sakke s;
        s.params = c.u8();
        s.id_scheme = c.u8();
        const unsigned len = c.u16();
        if (!c.has(len)) return verdict(Verdict::malformed, "malformed", h.data_type);
        s.data = c.take(len);
        p.v = std::move(s);
        break;
      }
      case kExt: {
        if (!c.has(3)) return verdict(Verdict::malformed, "malformed", h.data_type);
        Ext e;
        e.type = c.u8();
        const unsigned len = c.u16();
        if (!c.has(len)) return verdict(Verdict::malformed, "malformed", h.data_type);
        e.data = c.take(len);
        if (const auto it = rules.extensions.find(e.type);
            it != rules.extensions.end() && it->second.action == MikeyAction::sakke && !decode_sakke_payload(e.data)) {
          return verdict(Verdict::malformed, "malformed", h.data_type);  // SAKKE-to-self holds one SAKKE payload
        }
        p.v = std::move(e);
        break;
      }
      default:
        return verdict(Verdict::not_sakke, "unknown-payload", h.data_type);
    }
    msg.payloads.push_back(std::move(p));
    next = following;
  }
  if (!signed_last) return verdict(Verdict::malformed, "malformed", h.data_type);
  if (c.i != in.size()) return verdict(Verdict::malformed, "malformed", h.data_type);  // trailing bytes
  Decoded d;
  d.verdict = Verdict::sakke;
  d.data_type = h.data_type;
  d.message = std::move(msg);
  return d;
}

}  // namespace mcxanon::mikey
