// SPDX-License-Identifier: GPL-3.0-or-later
#include "sip/sdp.hpp"

#include "sip/render.hpp"
#include "sip/uri.hpp"

#include <algorithm>
#include <cctype>
#include <map>
#include <vector>

namespace mcxanon::sip {
namespace {

using Opt = Result<std::optional<std::string>>;

bool all_digits(std::string_view s) {
  return !s.empty() && std::all_of(s.begin(), s.end(), [](char c) { return c >= '0' && c <= '9'; });
}

bool iequal(std::string_view a, std::string_view b) {
  return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), [](char x, char y) {
           return std::tolower(static_cast<unsigned char>(x)) ==
                  std::tolower(static_cast<unsigned char>(y));
         });
}

std::vector<std::string_view> split(std::string_view s, char sep) {
  std::vector<std::string_view> out;
  std::size_t start = 0;
  for (;;) {
    const auto p = s.find(sep, start);
    out.push_back(s.substr(start, p == std::string_view::npos ? p : p - start));
    if (p == std::string_view::npos) break;
    start = p + 1;
  }
  return out;
}

std::string join(const std::vector<std::string>& v, std::string_view sep) {
  std::string out;
  for (std::size_t i = 0; i < v.size(); ++i) {
    if (i) out += sep;
    out += v[i];
  }
  return out;
}

const SipItemRule* field(const std::map<std::string, SipItemRule>& fields, const char* name) {
  const auto it = fields.find(name);
  return it == fields.end() ? nullptr : &it->second;
}

// Applies a field rule to a value: keep, pseudonymise with the rule's category, otherwise the
// field cannot be kept (nullopt).
Opt apply(const SipItemRule* r, std::string_view v, Context& ctx) {
  if (r == nullptr || r->action == SipAction::remove) return std::optional<std::string>{};
  if (r->action == SipAction::keep) return std::optional<std::string>(std::string(v));
  if (r->action == SipAction::blank) return std::optional<std::string>(r->value);
  if (r->action == SipAction::pseudonymise && r->category) return map_value(*r->category, v, ctx);
  return std::optional<std::string>{};
}

// A host in an SDP connection field: 0.0.0.0 and :: are kept by the address rules; a name
// under the reserved TLD ".invalid" is an MBMS placeholder (TS 24.379 §14.2.2.2) and is kept.
Opt sdp_host(const SipItemRule* r, std::string_view v, Context& ctx) {
  const auto bare = v.ends_with('.') ? v.substr(0, v.size() - 1) : v;
  if (bare.size() > 8 && iequal(bare.substr(bare.size() - 8), ".invalid")) {
    return std::optional<std::string>(std::string(v));
  }
  return apply(r, v, ctx);
}

struct Line {
  std::string_view text;
  std::string_view end;  // "\r\n", "\n" or ""
};

// o=<username> <sess-id> <sess-version> <nettype> <addrtype> <unicast-address>
Opt origin(std::string_view v, const SdpLineRule& rule, Context& ctx) {
  const auto f = split(v, ' ');
  if (f.size() != 6 || !all_digits(f[1]) || !all_digits(f[2]) || f[3].empty() || f[4].empty() ||
      f[5].empty() || f[0].empty()) {
    return std::optional<std::string>{};
  }
  std::string user(f[0]);
  if (user != "-") {
    auto u = apply(field(rule.fields, "username"), f[0], ctx);
    if (!u || !*u) return u;
    user = **u;
  }
  auto id = apply(field(rule.fields, "sess-id"), f[1], ctx);
  if (!id || !*id) return id;
  std::string version(f[2]);
  if (**id != f[1]) {
    auto ver = ctx.mapper.sdp_version(f[1], f[2]);
    if (!ver) return std::unexpected(ver.error());
    version = *ver;
  }
  auto addr = sdp_host(field(rule.fields, "address"), f[5], ctx);
  if (!addr || !*addr) return addr;
  return std::optional<std::string>(user + " " + **id + " " + version + " " + std::string(f[3]) + " " +
                                    std::string(f[4]) + " " + **addr);
}

// c=<nettype> <addrtype> <connection-address>[/<ttl>][/<number of addresses>]
Opt connection(std::string_view v, const SdpLineRule& rule, Context& ctx) {
  const auto f = split(v, ' ');
  if (f.size() != 3 || f[0].empty() || f[1].empty() || f[2].empty()) return std::optional<std::string>{};
  const auto slash = f[2].find('/');
  const auto base = f[2].substr(0, slash);
  const auto suffix = slash == std::string_view::npos ? std::string_view() : f[2].substr(slash);
  if (!suffix.empty() && !std::all_of(suffix.begin(), suffix.end(), [](char c) {
        return c == '/' || (c >= '0' && c <= '9');
      })) {
    return std::optional<std::string>{};
  }
  auto a = sdp_host(field(rule.fields, "address"), base, ctx);
  if (!a || !*a) return a;
  return std::optional<std::string>(std::string(f[0]) + " " + std::string(f[1]) + " " + **a +
                                    std::string(suffix));
}

// m=<media> <port>[/<number of ports>] <proto> <fmt> ...
Opt media(std::string_view v, const SdpLineRule& rule, Context& ctx) {
  const auto f = split(v, ' ');
  if (f.size() < 4 || f[0].empty() || f[2].empty()) return std::optional<std::string>{};
  const auto slash = f[1].find('/');
  const auto port = f[1].substr(0, slash);
  const auto count = slash == std::string_view::npos ? std::string_view() : f[1].substr(slash + 1);
  if (!all_digits(port) || (slash != std::string_view::npos && !all_digits(count))) {
    return std::optional<std::string>{};
  }
  auto p = apply(field(rule.fields, "port"), port, ctx);
  if (!p || !*p) return p;
  std::string out = std::string(f[0]) + " " + **p + (slash == std::string_view::npos ? "" : "/" + std::string(count));
  for (std::size_t i = 2; i < f.size(); ++i) {
    if (f[i].empty()) return std::optional<std::string>{};
    out += " " + std::string(f[i]);
  }
  return std::optional<std::string>(out);
}

// a=rtcp:<port> [<nettype> <addrtype> <connection-address>] (RFC 3605 §2.1)
Opt rtcp(std::string_view v, const SdpAttributeRule& rule, Context& ctx) {
  const auto f = split(v, ' ');
  if (f.size() != 1 && f.size() != 4) return std::optional<std::string>{};
  if (!all_digits(f[0])) return std::optional<std::string>{};
  auto p = apply(field(rule.fields, "port"), f[0], ctx);
  if (!p || !*p) return p;
  if (f.size() == 1) return p;
  auto a = sdp_host(field(rule.fields, "address"), f[3], ctx);
  if (!a || !*a) return a;
  return std::optional<std::string>(**p + " " + std::string(f[1]) + " " + std::string(f[2]) + " " + **a);
}

// A CNAME (RFC 5576 §6.1, RFC 3550 §6.5.1): "user@host" and "host" use their own mappings,
// anything else the cname category.
Opt cname(std::string_view v, const SipItemRule* r, Context& ctx) {
  if (r == nullptr || r->action != SipAction::pseudonymise) return apply(r, v, ctx);
  const auto at = v.find('@');
  if (at != std::string_view::npos && at > 0) {
    auto user = map_value(SipCategory::sip_user, v.substr(0, at), ctx);
    if (!user || !*user) return user;
    auto host = map_host(v.substr(at + 1), ctx);
    if (!host) return host;
    if (*host) return std::optional<std::string>(**user + "@" + **host);
  }
  if (parse_address_text(v)) return map_host(v, ctx);
  return map_value(SipCategory::cname, v, ctx);
}

// a=ssrc:<ssrc-id> <attribute>[:<value>] (RFC 5576 §4.1)
// a=key-mgmt (RFC 4567 §3.1, feature 005): only the protocol identifier "mikey" is understood;
// its base64 data goes to the MIKEY rewriter. nullopt: the attribute is removed (002 FR-019).
// `kept` is set when the rewriter passed the message through unchanged (--encrypted passthrough).
Opt key_mgmt(std::string_view v, Context& ctx, bool& kept, KeyContext& keys) {
  std::string lead;
  if (!v.empty() && v.front() == ' ') {
    lead = " ";
    v.remove_prefix(1);
  }
  const auto sp = v.find(' ');
  if (sp == std::string_view::npos || ctx.mikey == nullptr) return std::optional<std::string>{};
  const auto prtcl = v.substr(0, sp);
  if (prtcl != "mikey") return std::optional<std::string>{};
  MikeyOutcome outcome;
  auto r = ctx.mikey->rewrite(MikeyCarrierKind::sdp, v.substr(sp + 1), "", outcome, ctx);
  if (!r) return std::unexpected(r.error());
  keys.merge(outcome.keys);
  if (!*r) return std::optional<std::string>{};
  kept = outcome.kind == MikeyOutcome::Kind::passed_through;
  return std::optional<std::string>(lead + std::string(prtcl) + " " + **r);
}

Opt ssrc(std::string_view v, const SdpAttributeRule& rule, Context& ctx) {
  const auto sp = v.find(' ');
  if (sp == std::string_view::npos) return std::optional<std::string>{};
  auto id = apply(field(rule.fields, "ssrc-id"), v.substr(0, sp), ctx);
  if (!id || !*id) return id;
  const auto attr = v.substr(sp + 1);
  const auto colon = attr.find(':');
  const auto name = attr.substr(0, colon);
  const auto value = colon == std::string_view::npos ? std::string_view() : attr.substr(colon + 1);
  if (!is_token(name)) return std::optional<std::string>{};
  std::string out = **id + " " + std::string(name);
  if (iequal(name, "cname")) {
    auto c = cname(value, field(rule.fields, "cname"), ctx);
    if (!c || !*c) return c;
    return std::optional<std::string>(out + ":" + **c);
  }
  if (iequal(name, "previous-ssrc")) {
    std::vector<std::string> ids;
    for (auto x : split(value, ' ')) {
      auto m = apply(field(rule.fields, "previous-ssrc"), x, ctx);
      if (!m || !*m) return m;
      ids.push_back(**m);
    }
    return std::optional<std::string>(out + ":" + join(ids, " "));
  }
  if (iequal(name, "fmtp") && field(rule.fields, "fmtp") != nullptr &&
      field(rule.fields, "fmtp")->action == SipAction::keep) {
    return std::optional<std::string>(out + (colon == std::string_view::npos ? "" : ":" + std::string(value)));
  }
  // An unknown source attribute: the line is removed (fail-closed).
  ctx.counters.count(ctx.counters.removed_unknown, "sip-param", std::string(name));
  return std::optional<std::string>{};
}

// a=ssrc-group:<semantics> *(SP <ssrc-id>) (RFC 5576 §4.2)
Opt ssrc_group(std::string_view v, const SdpAttributeRule& rule, Context& ctx) {
  const auto f = split(v, ' ');
  if (f.size() < 2 || !is_token(f[0])) return std::optional<std::string>{};
  std::vector<std::string> out{std::string(f[0])};
  for (std::size_t i = 1; i < f.size(); ++i) {
    auto m = apply(field(rule.fields, "ssrc-id"), f[i], ctx);
    if (!m || !*m) return m;
    out.push_back(**m);
  }
  return std::optional<std::string>(join(out, " "));
}

// a=candidate:<foundation> <component> <transport> <priority> <address> <port> typ <type>
// [raddr <address>] [rport <port>] *(<extension name> <value>) (RFC 8839 §5.1). Extensions are
// removed: their values are not classified.
Opt candidate(std::string_view v, const SdpAttributeRule& rule, Context& ctx) {
  const auto f = split(v, ' ');
  if (f.size() < 8 || !iequal(f[6], "typ") || !all_digits(f[5]) || !all_digits(f[1]) ||
      !all_digits(f[3])) {
    return std::optional<std::string>{};
  }
  auto addr = sdp_host(field(rule.fields, "address"), f[4], ctx);
  if (!addr || !*addr) return addr;
  auto port = apply(field(rule.fields, "port"), f[5], ctx);
  if (!port || !*port) return port;
  std::string out = std::string(f[0]) + " " + std::string(f[1]) + " " + std::string(f[2]) + " " +
                    std::string(f[3]) + " " + **addr + " " + **port + " typ " + std::string(f[7]);
  for (std::size_t i = 8; i + 1 < f.size(); i += 2) {
    if (iequal(f[i], "raddr")) {
      auto r = sdp_host(field(rule.fields, "address"), f[i + 1], ctx);
      if (!r || !*r) return r;
      out += " raddr " + **r;
    } else if (iequal(f[i], "rport")) {
      if (!all_digits(f[i + 1])) return std::optional<std::string>{};
      auto r = apply(field(rule.fields, "port"), f[i + 1], ctx);
      if (!r || !*r) return r;
      out += " rport " + **r;
    } else {
      ctx.counters.count(ctx.counters.removed_unknown, "sip-param", std::string(f[i]));
    }
  }
  if ((f.size() - 8) % 2 != 0) return std::optional<std::string>{};
  return std::optional<std::string>(out);
}

// a=remote-candidates:<component> <address> <port> *(SP ...) (RFC 8839 §5.2)
Opt remote_candidates(std::string_view v, const SdpAttributeRule& rule, Context& ctx) {
  const auto f = split(v, ' ');
  if (f.empty() || f.size() % 3 != 0) return std::optional<std::string>{};
  std::vector<std::string> out;
  for (std::size_t i = 0; i < f.size(); i += 3) {
    if (!all_digits(f[i]) || !all_digits(f[i + 2])) return std::optional<std::string>{};
    auto a = sdp_host(field(rule.fields, "address"), f[i + 1], ctx);
    if (!a || !*a) return a;
    auto p = apply(field(rule.fields, "port"), f[i + 2], ctx);
    if (!p || !*p) return p;
    out.push_back(std::string(f[i]) + " " + **a + " " + **p);
  }
  return std::optional<std::string>(join(out, " "));
}

// One MSRP URI (RFC 4975 §9):
//   MSRP-URI = msrp-scheme "://" authority ["/" session-id] ";" transport *( ";" URI-parameter)
// URI parameters other than the transport are removed.
Opt msrp_uri(std::string_view u, const SdpAttributeRule& rule, Context& ctx) {
  const auto sep = u.find("://");
  if (sep == std::string_view::npos) return std::optional<std::string>{};
  const auto scheme = u.substr(0, sep);
  if (!iequal(scheme, "msrp") && !iequal(scheme, "msrps")) return std::optional<std::string>{};
  auto rest = u.substr(sep + 3);
  const auto semi = rest.find(';');
  if (semi == std::string_view::npos) return std::optional<std::string>{};
  const auto params = split(rest.substr(semi + 1), ';');
  const auto transport = params[0];
  if (transport.empty() || !std::all_of(transport.begin(), transport.end(),
                                        [](char c) { return std::isalnum(static_cast<unsigned char>(c)) != 0; })) {
    return std::optional<std::string>{};
  }
  for (std::size_t i = 1; i < params.size(); ++i) {
    ctx.counters.count(ctx.counters.removed_unknown, "sip-param",
                       std::string(params[i].substr(0, params[i].find('='))));
  }
  rest = rest.substr(0, semi);
  const auto slash = rest.find('/');
  auto authority = rest.substr(0, slash);
  const auto session = slash == std::string_view::npos ? std::string_view() : rest.substr(slash + 1);
  std::string out = std::string(scheme) + "://";
  const auto at = authority.rfind('@');
  if (at != std::string_view::npos) {
    auto user = apply(field(rule.fields, "user"), authority.substr(0, at), ctx);
    if (!user || !*user) return user;
    out += **user + "@";
    authority = authority.substr(at + 1);
  }
  std::string_view host = authority;
  std::string_view port;
  if (authority.starts_with('[')) {
    const auto close = authority.find(']');
    if (close == std::string_view::npos) return std::optional<std::string>{};
    host = authority.substr(0, close + 1);
    if (close + 1 < authority.size()) {
      if (authority[close + 1] != ':') return std::optional<std::string>{};
      port = authority.substr(close + 2);
    }
  } else if (const auto colon = authority.find(':'); colon != std::string_view::npos) {
    host = authority.substr(0, colon);
    port = authority.substr(colon + 1);
  }
  auto h = apply(field(rule.fields, "host"), host, ctx);
  if (!h || !*h) return h;
  out += **h;
  if (!port.empty() || authority.ends_with(':')) {
    if (!all_digits(port)) return std::optional<std::string>{};
    auto p = apply(field(rule.fields, "port"), port, ctx);
    if (!p || !*p) return p;
    out += ":" + **p;
  }
  if (slash != std::string_view::npos) {
    // session-id = 1*( unreserved / "+" / "=" / "/" )
    if (session.empty()) return std::optional<std::string>{};
    auto s = apply(field(rule.fields, "session-id"), session, ctx);
    if (!s || !*s) return s;
    out += "/" + **s;
  }
  return std::optional<std::string>(out + ";" + std::string(transport));
}

Opt path(std::string_view v, const SdpAttributeRule& rule, Context& ctx) {
  std::vector<std::string> out;
  for (auto u : split(v, ' ')) {
    if (u.empty()) return std::optional<std::string>{};
    auto m = msrp_uri(u, rule, ctx);
    if (!m || !*m) return m;
    out.push_back(**m);
  }
  return std::optional<std::string>(join(out, " "));
}

// a=fmtp:<format> <param><sep><param>... with the separators the rule allows.
Opt fmtp_params(std::string_view format, std::string_view params, const SdpAttributeRule& rule,
                Context& ctx) {
  char sep = ';';
  if (params.find(';') == std::string_view::npos && params.find(':') != std::string_view::npos) sep = ':';
  if (std::find(rule.separators.begin(), rule.separators.end(), std::string(1, sep)) ==
      rule.separators.end()) {
    return std::optional<std::string>{};
  }
  auto items = split(params, sep);
  const bool trailing = items.size() > 1 && items.back().empty();
  if (trailing) items.pop_back();
  std::vector<std::string> out;
  for (auto it : items) {
    const auto eq = it.find('=');
    const auto name = it.substr(0, eq);
    const auto value = eq == std::string_view::npos ? std::optional<std::string_view>() : it.substr(eq + 1);
    const SipParamRule* pr = nullptr;
    for (const auto& p : rule.fmtp_params) {
      if (iequal(p.name, name)) pr = &p;
    }
    const bool shape_ok = pr != nullptr && (pr->value == ParamValue::flag ? !value
                                            : pr->value == ParamValue::number ? value && all_digits(*value)
                                                                              : value.has_value());
    if (!shape_ok || pr->rule.action == SipAction::remove) {
      ctx.counters.count(ctx.counters.removed_unknown, "sip-param", std::string(name));
      continue;
    }
    if (!value) {
      out.emplace_back(name);
      continue;
    }
    auto m = apply(&pr->rule, *value, ctx);
    if (!m) return std::unexpected(m.error());
    if (!*m) {
      ctx.counters.count(ctx.counters.removed_unknown, "sip-param", std::string(name));
      continue;
    }
    out.push_back(std::string(name) + "=" + **m);
  }
  if (out.empty()) return std::optional<std::string>{};
  return std::optional<std::string>(std::string(format) + " " + join(out, std::string(1, sep)) +
                                    (trailing ? std::string(1, sep) : ""));
}

// The media descriptions of an SDP with their original values (feature 004).
// Only lines whose syntax the rewriter also accepts are read; a value that does not parse is
// left empty and the endpoint layer skips it.
std::vector<SdpMedia> media_descriptions(const std::vector<Line>& lines) {
  std::vector<SdpMedia> out;
  std::string session_addrtype, session_address;
  bool session_suffix = false;
  bool in_media = false;
  const auto parse_port = [](std::string_view p) -> std::optional<std::uint32_t> {
    if (!all_digits(p) || p.size() > 5) return std::nullopt;
    std::uint32_t v = 0;
    for (char c : p) v = v * 10 + static_cast<std::uint32_t>(c - '0');
    if (v > 65535) return std::nullopt;
    return v;
  };
  for (const auto& l : lines) {
    const char type = l.text[0];
    const auto value = l.text.substr(2);
    if (type == 'm') {
      in_media = true;
      SdpMedia m;
      const auto f = split(value, ' ');
      if (f.size() >= 4) {
        m.media = std::string(f[0]);
        const auto port = parse_port(f[1].substr(0, f[1].find('/')));
        m.port = port.value_or(0);
        m.proto = std::string(f[2]);
        m.fmt = std::string(f[3]);
        if (!port) m.media.clear();  // unusable
      }
      m.addrtype = session_addrtype;
      m.address = session_address;
      m.multicast_suffix = session_suffix;
      out.push_back(std::move(m));
      continue;
    }
    if (type == 'c') {
      const auto f = split(value, ' ');
      std::string at, addr;
      bool suffix = false;
      if (f.size() == 3) {
        at = std::string(f[1]);
        const auto slash = f[2].find('/');
        addr = std::string(f[2].substr(0, slash));
        suffix = slash != std::string_view::npos;
      }
      if (in_media) {
        out.back().addrtype = at;
        out.back().address = addr;
        out.back().multicast_suffix = suffix;
      } else {
        session_addrtype = at;
        session_address = addr;
        session_suffix = suffix;
      }
      continue;
    }
    if (type != 'a' || !in_media) continue;
    const auto colon = value.find(':');
    const auto name = value.substr(0, colon);
    const auto avalue = colon == std::string_view::npos ? std::string_view() : value.substr(colon + 1);
    auto& m = out.back();
    if (iequal(name, "rtcp")) {
      const auto f = split(avalue, ' ');
      if (const auto p = parse_port(f[0])) {
        m.rtcp_port = *p;
        if (f.size() == 4) {
          m.rtcp_addrtype = std::string(f[2]);
          m.rtcp_address = std::string(f[3]);
        }
      }
    } else if (iequal(name, "rtcp-mux") || iequal(name, "rtcp-mux-only")) {
      m.rtcp_mux = true;
    } else if (iequal(name, "path")) {
      for (auto u : split(avalue, ' ')) {
        if (!u.empty()) m.paths.emplace_back(u);
      }
    }
  }
  return out;
}

}  // namespace

Result<std::optional<std::string>> map_msrp_uri(std::string_view uri, Context& ctx) {
  const auto* rule = ctx.rules.find_sdp_attribute("path");
  if (rule == nullptr) return std::optional<std::string>{};
  return msrp_uri(uri, *rule, ctx);
}

Result<std::optional<std::string>> map_cname(std::string_view value, Context& ctx) {
  const SipItemRule pseudonymise{SipAction::pseudonymise, SipCategory::cname, {}};
  return cname(value, &pseudonymise, ctx);
}

Result<std::optional<std::string>> rewrite_sdp(std::string_view body, Context& ctx) {
  const auto malformed = std::optional<std::string>{};
  std::vector<Line> lines;
  for (std::size_t pos = 0; pos < body.size();) {
    const auto nl = body.find('\n', pos);
    Line l;
    if (nl == std::string_view::npos) {
      l.text = body.substr(pos);
      pos = body.size();
    } else {
      const bool cr = nl > pos && body[nl - 1] == '\r';
      l.text = body.substr(pos, nl - pos - (cr ? 1 : 0));
      l.end = body.substr(nl - (cr ? 1 : 0), cr ? 2 : 1);
      pos = nl + 1;
    }
    // type "=" value; the type is one lowercase letter (RFC 8866 §5), no control characters.
    if (l.text.size() < 2 || l.text[1] != '=' || l.text[0] < 'a' || l.text[0] > 'z') return malformed;
    if (std::any_of(l.text.begin(), l.text.end(), [](char c) {
          const auto u = static_cast<unsigned char>(c);
          return (u < 0x20 && u != '\t') || u == 0x7F;
        })) {
      return malformed;
    }
    lines.push_back(l);
  }
  if (lines.empty() || lines.front().text != "v=0") return malformed;

  std::string out;
  // Feature 005: the key identifiers announced at session and media level.
  KeyContext session_keys;
  std::map<int, KeyContext> media_keys;
  int media_index = -1;
  for (const auto& l : lines) {
    const char type = l.text[0];
    const auto value = l.text.substr(2);
    if (type == 'm') ++media_index;
    if (type != 'a') {
      const std::string key = std::string(1, type) + "=";
      const auto* rule = ctx.rules.find_sdp_line(type);
      if (rule == nullptr) {
        ctx.counters.count(ctx.counters.sdp, key, "remove");
        continue;
      }
      std::optional<std::string> kept;
      std::string action = std::string(to_string(rule->action));
      switch (rule->action) {
        case SipAction::keep:
          kept = std::string(value);
          break;
        case SipAction::blank:
          kept = rule->value;
          ctx.counters.removed(value);
          break;
        case SipAction::pseudonymise: {
          Opt r = type == 'o'   ? origin(value, *rule, ctx)
                  : type == 'c' ? connection(value, *rule, ctx)
                  : type == 'm' ? media(value, *rule, ctx)
                                : Opt(std::optional<std::string>{});
          if (!r) return std::unexpected(r.error());
          if (!*r) return malformed;  // a line the SDP structure depends on
          kept = **r;
          break;
        }
        default:
          if (std::find(rule->keep_values.begin(), rule->keep_values.end(), value) !=
              rule->keep_values.end()) {
            kept = std::string(value);
            action = "keep";
          } else {
            ctx.counters.removed(value);
          }
          break;
      }
      ctx.counters.count(ctx.counters.sdp, key, action);
      if (kept) out += std::string(1, type) + "=" + *kept + std::string(l.end);
      continue;
    }
    // a=<attribute>[:<value>]
    const auto colon = value.find(':');
    const auto name = value.substr(0, colon);
    const auto avalue = colon == std::string_view::npos ? std::string_view() : value.substr(colon + 1);
    if (!is_token(name)) {
      ctx.counters.count(ctx.counters.removed_unknown, "sdp-attribute", std::string(name));
      continue;
    }
    std::string_view format;
    const SdpAttributeRule* rule = nullptr;
    if (iequal(name, "fmtp")) {
      format = avalue.substr(0, avalue.find(' '));
      rule = ctx.rules.find_sdp_attribute(name, format);
      // The generic fmtp rule covers numeric (RTP payload type) formats only.
      if (rule != nullptr && !rule->format && !all_digits(format)) rule = nullptr;
    } else {
      rule = ctx.rules.find_sdp_attribute(name);
    }
    if (rule == nullptr) {
      ctx.counters.count(ctx.counters.removed_unknown, "sdp-attribute", std::string(name));
      continue;
    }
    const std::string key = "a=" + rule->name + (rule->format ? ":" + *rule->format : "");
    if (rule->action == SipAction::remove) {
      ctx.counters.count(ctx.counters.sdp, key, "remove");
      ctx.counters.removed(avalue);
      continue;
    }
    if (rule->action == SipAction::keep) {
      if (rule->grammar == SdpGrammar::flag && colon != std::string_view::npos) {
        ctx.counters.count(ctx.counters.sdp, key, "malformed");
        continue;
      }
      ctx.counters.count(ctx.counters.sdp, key, "keep");
      out += std::string(l.text) + std::string(l.end);
      continue;
    }
    if (rule->grammar == SdpGrammar::key_mgmt) {
      // Feature 005: RFC 4567 §3.1 key-mgmt-attribute = 0*1SP prtcl-id SP keymgmt-data.
      bool kept = false;
      auto r = key_mgmt(avalue, ctx, kept, media_index < 0 ? session_keys : media_keys[media_index]);
      if (!r) return std::unexpected(r.error());
      if (!*r) {
        ctx.counters.count(ctx.counters.sdp, key, "remove");
        ctx.counters.removed(avalue);
        continue;
      }
      ctx.counters.count(ctx.counters.sdp, key, kept ? "keep" : "pseudonymise");
      out += "a=" + std::string(name) + ":" + **r + std::string(l.end);
      continue;
    }
    Opt r = std::optional<std::string>{};
    switch (rule->grammar) {
      case SdpGrammar::rtcp: r = rtcp(avalue, *rule, ctx); break;
      case SdpGrammar::ssrc: r = ssrc(avalue, *rule, ctx); break;
      case SdpGrammar::ssrc_group: r = ssrc_group(avalue, *rule, ctx); break;
      case SdpGrammar::candidate: r = candidate(avalue, *rule, ctx); break;
      case SdpGrammar::remote_candidates: r = remote_candidates(avalue, *rule, ctx); break;
      case SdpGrammar::path: r = path(avalue, *rule, ctx); break;
      case SdpGrammar::fmtp_params: {
        const auto sp = avalue.find(' ');
        if (sp != std::string_view::npos) r = fmtp_params(format, avalue.substr(sp + 1), *rule, ctx);
        break;
      }
      default: break;
    }
    if (!r) return std::unexpected(r.error());
    if (!*r) {
      ctx.counters.count(ctx.counters.sdp, key, "malformed");
      continue;
    }
    ctx.counters.count(ctx.counters.sdp, key, "pseudonymise");
    out += "a=" + std::string(name) + ":" + **r + std::string(l.end);
  }
  if (ctx.media != nullptr) {
    auto ms = media_descriptions(lines);
    for (std::size_t i = 0; i < ms.size(); ++i) {
      if (const auto it = media_keys.find(static_cast<int>(i)); it != media_keys.end()) ms[i].keys = it->second;
      ms[i].keys.merge(session_keys);
      ctx.media->announce(ms[i]);
    }
  }
  return std::optional<std::string>(out);
}

}  // namespace mcxanon::sip
