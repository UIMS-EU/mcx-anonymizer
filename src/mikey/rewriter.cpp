// SPDX-License-Identifier: GPL-3.0-or-later
#include "mikey/rewriter.hpp"

#include "mikey/carrier.hpp"
#include "mikey/decode.hpp"
#include "mikey/encode.hpp"
#include "mikey/rewrite.hpp"

#include <algorithm>
#include <variant>

namespace mcxanon::mikey {

std::string_view to_string(sip::MikeyCarrierKind k) {
  switch (k) {
    case sip::MikeyCarrierKind::sdp: return "sdp";
    case sip::MikeyCarrierKind::body: return "body";
    case sip::MikeyCarrierKind::gktp: return "gktp";
    case sip::MikeyCarrierKind::mcpc: return "mcpc";
  }
  return "?";
}

void Rewriter::on_uri(std::string_view original, std::string_view pseudonym) {
  (void)pseudonym;  // the pseudonym is recomputed through the mapping when a UID matches
  ledger_.add(original);
}

// Research R11: the original key identifiers of a recognised I_MESSAGE (CSB ID, SPI words) and the
// SRTP and SRTCP tag octets after the MKI, from the SP payload (RFC 3830 type 11, TS 33.180 types
// 18 and 19, all in octets) or else from the default profile of the key's purpose tag.
sip::KeyContext Rewriter::key_context(const Message& m) const {
  sip::KeyContext k;
  k.key_ids.push_back(m.hdr.csb_id);
  for (const auto& b : m.hdr.blocks) {
    if (b.spi.size() != 4 && b.spi.size() != 8) continue;
    for (std::size_t i = 0; i < b.spi.size(); i += 4) {
      const std::uint32_t w = (std::uint32_t{b.spi[i]} << 24) | (std::uint32_t{b.spi[i + 1]} << 16) |
                              (std::uint32_t{b.spi[i + 2]} << 8) | b.spi[i + 3];
      if (std::find(k.key_ids.begin(), k.key_ids.end(), w) == k.key_ids.end()) k.key_ids.push_back(w);
    }
  }
  std::optional<std::size_t> t11, t18, t19;
  for (const auto& p : m.payloads) {
    const auto* sp = std::get_if<Sp>(&p.v);
    if (sp == nullptr || sp->prot_type != 0) continue;
    for (const auto& [ty, val] : sp->params) {
      if (val.empty() || val.size() > 2) continue;
      std::size_t v = 0;
      for (auto x : val) v = (v << 8) | x;
      if (ty == 11) t11 = v;
      if (ty == 18) t18 = v;
      if (ty == 19) t19 = v;
    }
  }
  const auto tag = rules_.purpose_tags.find(m.hdr.csb_id >> 28);
  const auto profile = tag == rules_.purpose_tags.end() ? rules_.default_trailer.end()
                                                        : rules_.default_trailer.find(tag->second.name);
  const bool known = profile != rules_.default_trailer.end();
  k.srtp_tag = t18 ? t18 : t11 ? t11 : known ? std::optional<std::size_t>(profile->second.first) : std::nullopt;
  k.srtcp_tag = t19 ? t19 : known ? std::optional<std::size_t>(0) : std::nullopt;
  return k;
}

Result<std::uint32_t> Rewriter::key_identifier(std::uint32_t original, sip::Context& ctx) {
  RewriteEnv env{rules_, options_, ctx, counters_, &seen_key_ids_, &ledger_};
  return map_key_id(original, env);
}

void Rewriter::encrypted_uri(bool structured) {
  ++(structured ? counters_.encrypted_uri_structured : counters_.encrypted_uri_whole_user_part);
}

void Rewriter::fallback(sip::MikeyCarrierKind kind, std::string_view reason) {
  ++counters_.carriers[std::string(to_string(kind))].fallback[std::string(reason)];
}

Result<std::optional<std::string>> Rewriter::rewrite(sip::MikeyCarrierKind kind, std::string_view value,
                                                     std::string_view cte, sip::MikeyOutcome& outcome,
                                                     sip::Context& ctx) {
  auto& counts = counters_.carriers[std::string(to_string(kind))];
  // FR-004 b: application/mikey is expected in the requests of the rule set only.
  if (kind == sip::MikeyCarrierKind::body && !rules_.body_methods.contains(std::string(ctx.method))) {
    ++counters_.unexpected_carrier;
  }
  const auto fallback = [&](std::string reason) -> Result<std::optional<std::string>> {
    outcome.kind = sip::MikeyOutcome::Kind::fallback;
    outcome.reason = reason;
    ++counts.fallback[reason];
    return std::optional<std::string>{};
  };
  auto form = decode_carrier(kind, value, cte, rules_);
  if (!form) return fallback("encoding");
  auto d = decode(form->bytes, rules_);
  if (d.verdict != Verdict::sakke) return fallback(d.reason.empty() ? "malformed" : d.reason);
  outcome.keys = key_context(*d.message);
  if (options_.passthrough) {
    // FR-017: a recognised I_MESSAGE is copied byte for byte, in its original text.
    outcome.kind = sip::MikeyOutcome::Kind::passed_through;
    ++counts.passed_through;
    return std::optional<std::string>(std::string(value));
  }
  RewriteEnv env{rules_, options_, ctx, counters_, &seen_key_ids_, &ledger_};
  if (auto r = rewrite_message(*d.message, env); !r) return std::unexpected(r.error());
  const Bytes out = encode(*d.message);
  if (out.size() > rules_.message.max_size) return fallback("limit");
  outcome.kind = sip::MikeyOutcome::Kind::rewritten;
  ++counts.rewritten;
  return std::optional<std::string>(encode_carrier(*form, out));
}

}  // namespace mcxanon::mikey
