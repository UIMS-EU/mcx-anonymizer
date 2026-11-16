// SPDX-License-Identifier: GPL-3.0-or-later
#include "sip/value_map.hpp"

#include "sip/render.hpp"
#include "sip/uri.hpp"

#include <algorithm>

namespace mcxanon::sip {
namespace {

using Opt = Result<std::optional<std::string>>;

Opt some(std::string s) { return std::optional<std::string>(std::move(s)); }
Opt none() { return std::optional<std::string>{}; }

template <class R>
Opt lift(R r) {
  if (!r) return std::unexpected(r.error());
  return std::optional<std::string>(std::move(*r));
}

bool all_digits(std::string_view s) {
  return !s.empty() && std::all_of(s.begin(), s.end(), [](char c) { return c >= '0' && c <= '9'; });
}

std::optional<std::uint32_t> u32(std::string_view s) {
  if (!all_digits(s) || s.size() > 10) return std::nullopt;
  const auto v = std::stoull(std::string(s));
  if (v > 0xFFFFFFFFull) return std::nullopt;
  return static_cast<std::uint32_t>(v);
}

Category text_category(SipCategory c) {
  switch (c) {
    case SipCategory::sip_user: return Category::sip_user;
    case SipCategory::display_name: return Category::display_name;
    case SipCategory::call_id: return Category::call_id;
    case SipCategory::tag: return Category::tag;
    case SipCategory::branch: return Category::branch;
    case SipCategory::entity_tag: return Category::entity_tag;
    case SipCategory::charging_id: return Category::charging_id;
    case SipCategory::session_id: return Category::session_id;
    case SipCategory::imei: return Category::imei;
    case SipCategory::uuid: return Category::uuid;
    case SipCategory::cell_id: return Category::cell_id;
    case SipCategory::digest: return Category::digest;
    case SipCategory::sdp_sess: return Category::sdp_sess;
    case SipCategory::boundary: return Category::boundary;
    case SipCategory::msrp_session: return Category::msrp_session;
    case SipCategory::reg_token: return Category::reg_token;
    case SipCategory::cname: return Category::cname;
    default: return Category::sip_user;
  }
}

}  // namespace

Opt map_host(std::string_view host, Context& ctx) {
  if (host.empty()) return none();
  auto a = map_address_text(host, ctx.mapper);
  if (!a) return std::unexpected(a.error());
  if (*a) return a;
  if (host.starts_with('[')) return none();
  return lift(ctx.mapper.domain(host));
}

Opt map_value(SipCategory c, std::string_view v, Context& ctx) {
  switch (c) {
    case SipCategory::host:
      return map_host(v, ctx);
    case SipCategory::ip: {
      auto a = map_address_text(v, ctx.mapper);
      if (!a) return std::unexpected(a.error());
      return *a;
    }
    case SipCategory::domain:
      if (v.empty()) return none();
      return lift(ctx.mapper.domain(v));
    case SipCategory::port: {
      auto p = map_port_text(v, ctx.mapper, ctx.options.pseudonymise_ports);
      if (!p) return std::unexpected(p.error());
      return *p;
    }
    case SipCategory::tel:
      if (std::none_of(v.begin(), v.end(), [](char ch) { return ch >= '0' && ch <= '9'; })) return none();
      return lift(ctx.mapper.tel(v));
    case SipCategory::sip_user: {
      // Canonical original: the user part after percent-decoding, case kept.
      if (v.empty()) return none();
      // A private user identity "username@realm" (TS 23.003 §13.3) binds component by
      // component: the user mapping and the domain mapping (FR-012).
      if (const auto at = v.rfind('@'); at != std::string_view::npos && at > 0 && at + 1 < v.size()) {
        auto u = ctx.mapper.text(Category::sip_user, percent_decode(v.substr(0, at)));
        if (!u) return std::unexpected(u.error());
        auto d = map_host(v.substr(at + 1), ctx);
        if (!d) return std::unexpected(d.error());
        if (!*d) return none();
        return some(*u + "@" + **d);
      }
      return lift(ctx.mapper.text(Category::sip_user, percent_decode(v)));
    }
    case SipCategory::call_id: {
      // c-<16 hex> for the whole value; an "@host" part becomes "@" + its host pseudonym.
      if (v.empty()) return none();
      auto local = ctx.mapper.text(Category::call_id, v);
      if (!local) return std::unexpected(local.error());
      const auto at = v.find('@');
      if (at == std::string_view::npos) return some(*local);
      auto h = map_host(v.substr(at + 1), ctx);
      if (!h) return std::unexpected(h.error());
      if (!*h) return some(*local);  // not a host: the local pseudonym alone
      return some(*local + "@" + **h);
    }
    case SipCategory::spi:
    case SipCategory::ssrc: {
      const auto n = u32(v);
      if (!n) return none();
      auto r = c == SipCategory::spi ? ctx.mapper.spi(*n) : ctx.mapper.ssrc(*n);
      if (!r) return std::unexpected(r.error());
      return some(std::to_string(*r));
    }
    case SipCategory::sdp_sess:
      if (!all_digits(v)) return none();
      return lift(ctx.mapper.text(Category::sdp_sess, v));
    case SipCategory::imei: {
      // 14 digits of TAC and SNR (a check or spare digit is recomputed by the caller).
      if (!all_digits(v) || v.size() != 14) return none();
      return lift(ctx.mapper.text(Category::imei, v));
    }
    case SipCategory::uuid:
    case SipCategory::session_id:
      if (v.empty()) return none();
      return lift(ctx.mapper.text(text_category(c), v));
    case SipCategory::instance:
      return none();  // handled by the feature-tag rewriting (URN forms)
    default:
      if (v.empty()) return none();
      return lift(ctx.mapper.text(text_category(c), v));
  }
}

}  // namespace mcxanon::sip
