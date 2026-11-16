// SPDX-License-Identifier: GPL-3.0-or-later
#include "mikey/rewrite.hpp"

#include "bytes/base64.hpp"
#include "bytes/ntp.hpp"
#include "mikey/keyparams.hpp"
#include "mikey/uid.hpp"
#include "policy/xml_rules.hpp"
#include "sip/rewrite.hpp"
#include "xml/categories.hpp"

#include <algorithm>
#include <string>
#include <string_view>
#include <type_traits>

namespace mcxanon::mikey {

namespace {

std::uint32_t be32(const Bytes& b, std::size_t at) {
  return (std::uint32_t{b[at]} << 24) | (std::uint32_t{b[at + 1]} << 16) | (std::uint32_t{b[at + 2]} << 8) | b[at + 3];
}
void put32(Bytes& b, std::size_t at, std::uint32_t v) {
  b[at] = static_cast<std::uint8_t>(v >> 24);
  b[at + 1] = static_cast<std::uint8_t>(v >> 16);
  b[at + 2] = static_cast<std::uint8_t>(v >> 8);
  b[at + 3] = static_cast<std::uint8_t>(v);
}
std::string_view as_text(const Bytes& b) { return {reinterpret_cast<const char*>(b.data()), b.size()}; }
Bytes as_bytes(std::string_view s) { return Bytes(s.begin(), s.end()); }

std::string lower(std::string_view s) {
  std::string out(s);
  for (auto& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return out;
}

std::string scheme_of(std::string_view v) {
  const auto c = v.find(':');
  if (c == std::string_view::npos || c == 0) return {};
  return lower(v.substr(0, c));
}

void zero(Bytes& b) { std::fill(b.begin(), b.end(), std::uint8_t{0}); }

// An identity (IDRi / IDRr): a SIP, SIPS or tel URI through the 002 mapping, an HTTP(S) URI (the
// GMS XCAP URI) through the 003 xcap-selector mapping, an NAI through the user and
// domain mappings. nullopt: the value does not fit (zeroed by the caller).
Result<std::optional<std::string>> identity(std::string_view v, std::uint8_t id_type, RewriteEnv& env) {
  if (id_type == 0) {  // NAI: user@realm (RFC 3830 Table 6.7.a)
    const auto at = v.rfind('@');
    if (at == std::string_view::npos || at == 0 || at + 1 == v.size()) return std::optional<std::string>{};
    auto u = sip::map_value(SipCategory::sip_user, v.substr(0, at), env.ctx);
    if (!u) return std::unexpected(u.error());
    auto h = sip::map_host(v.substr(at + 1), env.ctx);
    if (!h) return std::unexpected(h.error());
    if (!*u || !*h) return std::optional<std::string>{};
    return std::optional<std::string>(**u + "@" + **h);
  }
  const std::string scheme = scheme_of(v);
  if (scheme == "sip" || scheme == "sips" || scheme == "tel") {
    auto r = sip::rewrite_uri_text(v, env.ctx);
    if (r && *r && env.ctx.uris != nullptr) env.ctx.uris->on_uri(v, **r);
    return r;
  }
  if (scheme == "http" || scheme == "https") {
    auto r = xml::map_category(XmlCategory::xcap_selector, v, env.ctx);
    if (r && *r && env.ctx.uris != nullptr) env.ctx.uris->on_uri(v, **r);
    return r;
  }
  return std::optional<std::string>{};
}

// What the UID resolution needs from the whole message, read before any payload is rewritten.
struct Prescan {
  std::optional<std::uint64_t> ntp_in;   // seconds of the input T (NTP-UTC or NTP)
  std::optional<std::uint64_t> ntp_out;  // the same after --time-shift
  std::optional<std::string> kms, kmsi, kmsr;  // original KMS identities by role (3, 6, 7)
};

Prescan prescan(const Message& m, const RewriteEnv& env) {
  Prescan p;
  for (const auto& pl : m.payloads) {
    if (const auto* t = std::get_if<T>(&pl.v); t != nullptr && t->value.size() == 8 && t->ts_type <= 1) {
      std::uint64_t ntp = 0;
      for (auto b : t->value) ntp = (ntp << 8) | b;
      p.ntp_in = ntp >> 32;
      p.ntp_out = (env.options.time_shift_ns ? shift_ntp64(ntp, *env.options.time_shift_ns) : ntp) >> 32;
    } else if (const auto* i = std::get_if<Idr>(&pl.v); i != nullptr) {
      const std::string v(as_text(i->data));
      if (i->role == 3) p.kms = v;
      if (i->role == 6) p.kmsi = v;
      if (i->role == 7) p.kmsr = v;
    }
  }
  return p;
}

// TS 33.180 §F.2.1.1 with the user's key period of the KMS: the UID of the unique candidate
// identity whose UID equals `original`, recomputed from the pseudonyms; nullopt when no candidate,
// or more than one, matches.
Result<std::optional<Bytes>> resolve_uid(const Bytes& original, unsigned role, const Prescan& pre, RewriteEnv& env) {
  const bool initiator = role == 8 || role == 241;
  const auto& kms = initiator ? (pre.kmsi ? pre.kmsi : pre.kms) : (pre.kmsr ? pre.kmsr : pre.kms);
  if (!kms || !pre.ntp_in || !pre.ntp_out) return std::optional<Bytes>{};
  const KmsPeriod* period = nullptr;
  for (const auto& k : env.options.kms_periods) {
    if (k.kms == *kms) period = &k;
  }
  if (period == nullptr || period->length_s == 0) return std::optional<Bytes>{};
  const auto p5 = period_number(*pre.ntp_in, period->length_s, period->offset_s);
  std::set<std::string> candidates;
  if (env.ctx.message_uris != nullptr) candidates.insert(env.ctx.message_uris->begin(), env.ctx.message_uris->end());
  if (env.ledger != nullptr) candidates.insert(env.ledger->originals().begin(), env.ledger->originals().end());
  const std::string* match = nullptr;
  for (const auto& c : candidates) {
    if (uid(c, *kms, period->length_s, period->offset_s, p5) != original) continue;
    if (match != nullptr) return std::optional<Bytes>{};  // ambiguous
    match = &c;
  }
  if (match == nullptr) return std::optional<Bytes>{};
  auto id = identity(*match, 1, env);
  if (!id) return std::unexpected(id.error());
  auto pk = xml::map_category(XmlCategory::kms_uri, *kms, env.ctx);
  if (!pk) return std::unexpected(pk.error());
  if (!*id || !*pk) return std::optional<Bytes>{};
  const auto p5_out = period_number(*pre.ntp_out, period->length_s, period->offset_s);
  return std::optional<Bytes>(uid(**id, **pk, period->length_s, period->offset_s, p5_out));
}

// The '3GPP key parameters' extension (TS 33.180 §E.6.1, Table 8.5.4.1-1): with a
// unique layout, the Date and Time is shifted (seconds since 1970 in 5 octets, §E.6.4), the IV
// takes the nonce mapping, the DPPK-ID the key identifier mapping, the Payload is kept (the
// ciphertext of the plan decision) and a nested off-network I-MESSAGE value is zeroed (NOTE 4).
// Anything else zeroes the whole extension data.
Result<void> key_parameters(Bytes& d, std::uint32_t csb_id, RewriteEnv& env);

}  // namespace

Result<std::uint32_t> map_key_id(std::uint32_t original, RewriteEnv& env) {
  auto k = env.ctx.mapper.key_id(original);
  if (!k) return std::unexpected(k.error());
  if (env.seen_key_ids == nullptr || env.seen_key_ids->insert(original).second) {
    const unsigned tag = original >> 28;
    const auto it = env.rules.purpose_tags.find(tag);
    ++env.counters.key_ids[it != env.rules.purpose_tags.end() ? it->second.name : std::string("undefined-purpose")];
  }
  return *k;
}

Result<void> rewrite_message(Message& m, RewriteEnv& env) {
  auto& c = env.counters;
  const std::uint32_t original_csb = m.hdr.csb_id;
  // Common header (FR-006, FR-007).
  auto csb = map_key_id(m.hdr.csb_id, env);
  if (!csb) return std::unexpected(csb.error());
  m.hdr.csb_id = *csb;
  for (auto& blk : m.hdr.blocks) {
    if (!env.rules.cs_ids.contains(blk.cs_id)) ++c.cs_ids["undefined-cs-id"];
    // SRTP session data: (SSRC, ROC) pairs; the SSRC takes the 002 mapping, the ROC is kept.
    for (std::size_t i = 0; i + 8 <= blk.session_data.size(); i += 8) {
      auto s = env.ctx.mapper.ssrc(be32(blk.session_data, i));
      if (!s) return std::unexpected(s.error());
      put32(blk.session_data, i, *s);
    }
    if (blk.spi.size() == 4 || blk.spi.size() == 8) {
      for (std::size_t i = 0; i < blk.spi.size(); i += 4) {
        auto k = map_key_id(be32(blk.spi, i), env);
        if (!k) return std::unexpected(k.error());
        put32(blk.spi, i, *k);
      }
    } else {
      zero(blk.spi);
    }
  }
  std::set<std::string> present;
  const Prescan pre = prescan(m, env);
  for (auto& p : m.payloads) {
    const auto* rule = env.rules.payload(p.type);
    if (rule != nullptr) present.insert(rule->name);
    auto r = std::visit(
        [&](auto& v) -> Result<void> {
          using V = std::decay_t<decltype(v)>;
          if constexpr (std::is_same_v<V, T>) {
            const auto it = env.rules.ts_types.find(v.ts_type);
            if (it != env.rules.ts_types.end() && it->second.action == MikeyAction::shift && v.value.size() == 8) {
              if (env.options.time_shift_ns) {
                std::uint64_t ntp = 0;
                for (auto b : v.value) ntp = (ntp << 8) | b;
                ntp = shift_ntp64(ntp, *env.options.time_shift_ns);
                for (int k = 7; k >= 0; --k) {
                  v.value[static_cast<std::size_t>(7 - k)] = static_cast<std::uint8_t>(ntp >> (8 * k));
                }
              }
              ++c.payloads["T"]["shifted"];
            } else {
              ++c.payloads["T"]["kept"];
            }
          } else if constexpr (std::is_same_v<V, Rand>) {
            auto n = env.ctx.mapper.bytes(Category::nonce, v.rand);
            if (!n) return std::unexpected(n.error());
            v.rand = std::move(*n);
            ++c.payloads["RAND"]["pseudonymised"];
          } else if constexpr (std::is_same_v<V, Idr>) {
            const auto* role = env.rules.id_role(v.role, v.id_type);
            std::optional<std::string> out;
            std::string action = "unknown-identity";
            if (role != nullptr && role->action == MikeyAction::identity) {
              auto x = identity(as_text(v.data), v.id_type, env);
              if (!x) return std::unexpected(x.error());
              if (*x) {
                out = **x;
                action = "identity";
              }
            } else if (role != nullptr && role->action == MikeyAction::kms) {
              auto x = xml::map_category(XmlCategory::kms_uri, as_text(v.data), env.ctx);
              if (!x) return std::unexpected(x.error());
              if (*x) {
                out = **x;
                action = "kms";
              }
            } else if (role != nullptr && role->action == MikeyAction::uid) {
              // A hidden identity (TS 33.180 §E.7): raw 32 octets or the 44-character base64 text.
              // Resolved from the pseudonymised identity when the KMS key period is known,
              // otherwise an opaque pseudonym (FR-010).
              const auto replace = [&](const Bytes& orig) -> Result<Bytes> {
                auto res = resolve_uid(orig, v.role, pre, env);
                if (!res) return std::unexpected(res.error());
                if (*res) {
                  ++c.uids_resolved;
                  return std::move(**res);
                }
                ++c.uids_unresolved;
                return env.ctx.mapper.bytes(Category::uid, orig);
              };
              if (v.data.size() == 32) {
                auto u = replace(v.data);
                if (!u) return std::unexpected(u.error());
                v.data = std::move(*u);
                ++c.payloads["IDR"]["uid"];
                return {};
              }
              if (auto d = base64::decode(as_text(v.data)); d && d->bytes.size() == 32) {
                auto u = replace(d->bytes);
                if (!u) return std::unexpected(u.error());
                v.data = as_bytes(base64::encode(*u, d->layout));
                ++c.payloads["IDR"]["uid"];
                return {};
              }
              // A URI in a hidden role (TS 24.481 §7.4.2 e 4): classified by content.
              auto x = identity(as_text(v.data), 1, env);
              if (!x) return std::unexpected(x.error());
              if (*x) {
                out = **x;
                action = "identity";
              }
            }
            if (out) {
              v.data = as_bytes(*out);
            } else {
              zero(v.data);
            }
            ++c.payloads["IDR"][action];
          } else if constexpr (std::is_same_v<V, Sp>) {
            const auto table = env.rules.sp.find(v.prot_type);
            for (auto& [ty, val] : v.params) {
              if (table != env.rules.sp.end() && table->second.contains(ty)) {
                ++c.payloads["SP"]["kept"];
              } else {
                zero(val);
                ++c.payloads["SP"]["zeroed"];
              }
            }
          } else if constexpr (std::is_same_v<V, Sakke>) {
            ++c.payloads["SAKKE"]["kept"];
          } else if constexpr (std::is_same_v<V, Ext>) {
            const auto it = env.rules.extensions.find(v.type);
            const MikeyAction a = it == env.rules.extensions.end() ? MikeyAction::zero : it->second.action;
            if (a == MikeyAction::sakke) {
              ++c.payloads["SAKKE-to-self"]["kept"];
            } else if (a == MikeyAction::key_parameters) {
              if (auto kp = key_parameters(v.data, original_csb, env); !kp) return kp;
            } else {
              zero(v.data);
              ++c.payloads["unknown-extension"]["zeroed"];
            }
          } else if constexpr (std::is_same_v<V, Sign>) {
            zero(v.signature);
            ++c.payloads["SIGN"]["invalidated"];
          }
          return {};
        },
        p.v);
    if (!r) return r;
  }
  for (const auto& name : env.rules.message.mandatory) {
    if (!present.contains(name)) {
      ++c.incomplete;
      break;
    }
  }
  return {};
}

namespace {

Result<void> key_parameters(Bytes& d, std::uint32_t csb_id, RewriteEnv& env) {
  auto& counts = env.counters.payloads["key-parameters"];
  const auto k = delimit_key_parameters(d, csb_id);
  if (!k) {
    zero(d);
    ++counts["undelimited"];
    return {};
  }
  if (env.options.time_shift_ns) {
    std::uint64_t t = 0;
    for (std::size_t i = 0; i < kKpDateLen; ++i) t = (t << 8) | d[kKpDateOff + i];
    const std::int64_t shift = *env.options.time_shift_ns / 1'000'000'000;
    const std::int64_t out = static_cast<std::int64_t>(t) + shift;
    if (out < 0 || out >= (std::int64_t{1} << 40)) {
      std::fill_n(d.begin() + std::ptrdiff_t{kKpDateOff}, kKpDateLen, std::uint8_t{0});
    } else {
      for (std::size_t i = 0; i < kKpDateLen; ++i) {
        d[kKpDateOff + i] = static_cast<std::uint8_t>(static_cast<std::uint64_t>(out) >> (8 * (kKpDateLen - 1 - i)));
      }
    }
  }
  const auto iv_at = d.begin() + static_cast<std::ptrdiff_t>(k->iv_off);
  auto iv = env.ctx.mapper.bytes(Category::nonce, Bytes(iv_at, iv_at + std::ptrdiff_t{kKpIvLen}));
  if (!iv) return std::unexpected(iv.error());
  std::copy(iv->begin(), iv->end(), d.begin() + static_cast<std::ptrdiff_t>(k->iv_off));
  auto dppk = map_key_id(be32(d, k->dppk_off), env);
  if (!dppk) return std::unexpected(dppk.error());
  put32(d, k->dppk_off, *dppk);
  if (k->i_message) {
    std::fill_n(d.begin() + static_cast<std::ptrdiff_t>(k->i_message->first), k->i_message->second, std::uint8_t{0});
  }
  ++counts["rewritten"];
  return {};
}

}  // namespace

}  // namespace mcxanon::mikey
