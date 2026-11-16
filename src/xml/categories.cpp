// SPDX-License-Identifier: GPL-3.0-or-later
#include "xml/categories.hpp"

#include "bytes/base64.hpp"

#include "sip/rewrite.hpp"
#include "xml/location.hpp"
#include "xml/xcap.hpp"

#include <algorithm>
#include <cctype>
#include <vector>

namespace mcxanon::xml {
namespace {

std::optional<SipCategory> simple_category(XmlCategory c) {
  switch (c) {
    case XmlCategory::display_name: return SipCategory::display_name;
    case XmlCategory::uuid: return SipCategory::uuid;
    case XmlCategory::imei: return SipCategory::imei;
    case XmlCategory::call_id: return SipCategory::call_id;
    case XmlCategory::tag: return SipCategory::tag;
    case XmlCategory::entity_tag: return SipCategory::entity_tag;
    case XmlCategory::host: return SipCategory::host;
    case XmlCategory::ip: return SipCategory::ip;
    case XmlCategory::port: return SipCategory::port;
    default: return std::nullopt;
  }
}

// RFC 3986 §3.1: scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ), followed by ":".
bool has_scheme(std::string_view v) {
  const auto colon = v.find(':');
  if (colon == std::string_view::npos || colon == 0) return false;
  if (std::isalpha(static_cast<unsigned char>(v[0])) == 0) return false;
  for (std::size_t i = 1; i < colon; ++i) {
    const auto c = static_cast<unsigned char>(v[i]);
    if (std::isalnum(c) == 0 && c != '+' && c != '-' && c != '.') return false;
  }
  return true;
}

// A3: a KMS URI with a scheme goes through the 002 URI mapping; a bare host name (TS 33.180
// §D.3.4.1 shows <KmsUri>kms.example.org</KmsUri>) through the host mapping.
// A host name (RFC 1123 §2.1: labels of letters, digits and hyphens, separated by dots) or an
// IP literal (dotted IPv4, bracketed IPv6).
bool host_shaped(std::string_view v) {
  if (v.empty() || v.size() > 253) return false;
  if (v.front() == '[' && v.back() == ']') return v.size() > 2;
  std::size_t label = 0;
  for (const char c : v) {
    if (c == '.') {
      if (label == 0) return false;
      label = 0;
    } else if (std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '-') {
      if (++label > 63) return false;
    } else {
      return false;
    }
  }
  return label > 0;
}

Result<std::optional<std::string>> kms_uri(std::string_view v, sip::Context& ctx) {
  if (has_scheme(v)) return sip::rewrite_uri_text(v, ctx);
  if (!host_shaped(v)) return std::optional<std::string>{};
  return sip::map_host(v, ctx);
}

// A10, TS 24.379 §F.1.3 item ad: the Call-ID, the from-tag and the to-tag joined by ";" (a
// Call-ID has no ";", RFC 3261 §25.1 `word`). A tag part may carry its RFC 3891 parameter name
// ("from-tag=", "to-tag="), which is kept. Any other shape does not fit.
Result<std::optional<std::string>> replaces(std::string_view v, sip::Context& ctx) {
  std::vector<std::string_view> parts;
  std::size_t start = 0;
  while (true) {
    const auto semi = v.find(';', start);
    parts.push_back(v.substr(start, semi == std::string_view::npos ? std::string_view::npos : semi - start));
    if (semi == std::string_view::npos) break;
    start = semi + 1;
  }
  if (parts.size() != 3) return std::optional<std::string>{};
  auto call_id = sip::map_value(SipCategory::call_id, parts[0], ctx);
  if (!call_id) return std::unexpected(call_id.error());
  if (!*call_id || parts[0].empty()) return std::optional<std::string>{};
  std::string out = **call_id;
  for (std::size_t i = 1; i < 3; ++i) {
    auto p = parts[i];
    std::string_view name;
    for (std::string_view prefix : {std::string_view("from-tag="), std::string_view("to-tag=")}) {
      if (p.size() >= prefix.size()) {
        bool same = true;
        for (std::size_t k = 0; k < prefix.size() && same; ++k) {
          same = std::tolower(static_cast<unsigned char>(p[k])) == prefix[k];
        }
        if (same) {
          name = p.substr(0, prefix.size());
          p.remove_prefix(prefix.size());
          break;
        }
      }
    }
    if (p.empty()) return std::optional<std::string>{};
    auto tag = sip::map_value(SipCategory::tag, p, ctx);
    if (!tag) return std::unexpected(tag.error());
    if (!*tag) return std::optional<std::string>{};
    out.push_back(';');
    out.append(name);
    out += **tag;
  }
  return std::optional<std::string>(std::move(out));
}

// E2: identifiers without a grammar; same length, character classes kept.
Result<std::optional<std::string>> opaque(std::string_view v, sip::Context& ctx) {
  if (v.empty()) return std::optional<std::string>{};
  auto p = ctx.mapper.text(Category::opaque, v);
  if (!p) return std::unexpected(p.error());
  return std::optional<std::string>(std::move(*p));
}

// An XML NCName (Namespaces in XML 1.0 [4]), ASCII form.
bool ncname(std::string_view v) {
  if (v.empty()) return false;
  const auto c0 = static_cast<unsigned char>(v[0]);
  if (std::isalpha(c0) == 0 && v[0] != '_') return false;
  return std::all_of(v.begin(), v.end(), [](char ch) {
    return std::isalnum(static_cast<unsigned char>(ch)) != 0 || ch == '_' || ch == '-' || ch == '.';
  });
}

bool scheme_is(std::string_view v, std::string_view s) {
  if (v.size() < s.size()) return false;
  for (std::size_t i = 0; i < s.size(); ++i) {
    if (std::tolower(static_cast<unsigned char>(v[i])) != s[i]) return false;
  }
  return true;
}

// RFC 9562 text form: 8-4-4-4-12 hex digits.
bool bare_uuid(std::string_view v) {
  if (v.size() != 36) return false;
  for (std::size_t i = 0; i < v.size(); ++i) {
    const bool dash = i == 8 || i == 13 || i == 18 || i == 23;
    if (dash ? v[i] != '-' : std::isxdigit(static_cast<unsigned char>(v[i])) == 0) return false;
  }
  return true;
}

// E9: a scheme-less user@host, mapped as a sip: URI and written without the scheme.
Result<std::optional<std::string>> user_at_host(std::string_view v, sip::Context& ctx) {
  if (v.find('@') == std::string_view::npos || v.find(':') != std::string_view::npos) {
    return std::optional<std::string>{};
  }
  auto u = sip::rewrite_uri_text("sip:" + std::string(v), ctx);
  if (!u || !*u) return u;
  if (!(*u)->starts_with("sip:")) return std::optional<std::string>{};
  return std::optional<std::string>((*u)->substr(4));
}

// E1: by scheme: an instance URN, a SIP or tel URI, or an NCName (opaque).
Result<std::optional<std::string>> any_id(std::string_view v, sip::Context& ctx) {
  if (scheme_is(v, "urn:uuid:") || scheme_is(v, "urn:gsma:imei:")) return sip::map_instance(v, ctx);
  if (scheme_is(v, "sip:") || scheme_is(v, "sips:") || scheme_is(v, "tel:")) return sip::rewrite_uri_text(v, ctx);
  if (ncname(v)) return opaque(v, ctx);
  return std::optional<std::string>{};
}

// Feature 007: an http(s) URL. With a known AUID it is an XCAP selector (E.7.4); otherwise the
// host is mapped and each path segment is kept when the HTTP rule set keeps it in request lines,
// or mapped as opaque (escapes as written are not preserved: the segments are plain text).
Result<std::optional<std::string>> web_url(std::string_view v, sip::Context& ctx) {
  const auto map = [&ctx](XmlCategory c, std::string_view part) { return map_category(c, part, ctx); };
  const auto colon = v.find("://");
  std::string_view rest = v.substr(colon + 3);
  const auto slash = rest.find('/');
  std::string_view path = slash == std::string_view::npos ? std::string_view() : rest.substr(slash + 1);
  for (std::size_t start = 0; start <= path.size();) {
    const auto e = path.find('/', start);
    if (is_known_auid(path.substr(start, e == std::string_view::npos ? std::string_view::npos : e - start))) {
      return rewrite_xcap_selector(v, map);
    }
    if (e == std::string_view::npos) break;
    start = e + 1;
  }
  const auto authority = rest.substr(0, slash);
  if (authority.empty() || authority.find('@') != std::string_view::npos) return std::optional<std::string>{};
  std::string_view host = authority;
  std::string_view port;
  if (host.front() != '[') {
    if (const auto c = host.rfind(':'); c != std::string_view::npos) {
      port = host.substr(c);
      host = host.substr(0, c);
    }
  }
  auto h = sip::map_host(host, ctx);
  if (!h || !*h) return h;
  std::string out = std::string(v.substr(0, colon + 3)) + **h + std::string(port);
  if (slash == std::string_view::npos) return std::optional<std::string>(std::move(out));
  for (std::size_t start = 0;;) {
    const auto e = path.find('/', start);
    const auto seg = path.substr(start, e == std::string_view::npos ? std::string_view::npos : e - start);
    out.push_back('/');
    const bool kept = ctx.kept_path_segments != nullptr &&
                      std::find(ctx.kept_path_segments->begin(), ctx.kept_path_segments->end(), seg) !=
                          ctx.kept_path_segments->end();
    if (kept || seg.empty() || seg.find('%') != std::string_view::npos) {
      if (!kept && !seg.empty()) {
        auto o = opaque(seg, ctx);
        if (!o || !*o) return o;
        out += **o;
      } else {
        out += seg;
      }
    } else {
      auto o = opaque(seg, ctx);
      if (!o || !*o) return o;
      out += **o;
    }
    if (e == std::string_view::npos) break;
    start = e + 1;
  }
  return std::optional<std::string>(std::move(out));
}

}  // namespace

Result<std::optional<std::string>> map_category(XmlCategory category, std::string_view value, sip::Context& ctx) {
  // cid: the 002 Content-ID mapping through the cid: URI rule (I8), so a signed Reference@URI
  // names the same part as the pseudonymised Content-ID (FR-018a).
  if (category == XmlCategory::uri || category == XmlCategory::cid) return sip::rewrite_uri_text(value, ctx);
  if (category == XmlCategory::kms_uri) return kms_uri(value, ctx);
  if (category == XmlCategory::web_uri) {
    // Feature 007: server addresses of the CMS, GMS and KMS documents.
    if (scheme_is(value, "http://") || scheme_is(value, "https://")) {
      if (value.find_first_of("?#") != std::string_view::npos) return std::optional<std::string>{};
      return web_url(value, ctx);
    }
    return kms_uri(value, ctx);
  }
  if (category == XmlCategory::instance) {
    // X16: a bare UUID (the MCData client ID form) maps with the 002 UUID mapping, so it shares
    // its pseudonym with the urn:uuid: form.
    if (bare_uuid(value)) return sip::map_value(SipCategory::uuid, value, ctx);
    return sip::map_instance(value, ctx);
  }
  if (category == XmlCategory::opaque) return opaque(value, ctx);
  if (is_location_category(category)) return map_location(category, value, ctx.mapper);
  if (category == XmlCategory::any_id) return any_id(value, ctx);
  if (category == XmlCategory::user_at_host) return user_at_host(value, ctx);
  if (category == XmlCategory::xcap_node) {
    return rewrite_xcap_node(value, [&ctx](XmlCategory c, std::string_view part) { return map_category(c, part, ctx); });
  }
  if (category == XmlCategory::xcap_selector) {
    return rewrite_xcap_selector(value, [&ctx](XmlCategory c, std::string_view part) { return map_category(c, part, ctx); });
  }
  if (category == XmlCategory::replaces) return replaces(value, ctx);
  if (category == XmlCategory::xpk_id) {
    // Feature 005 (FR-016): the base64 of a 32-bit XPK-ID takes the key identifier
    // pseudonym, written back in the same base64 form; anything else does not fit (removed).
    auto d = base64::decode(value);
    if (!d || d->bytes.size() != 4) return std::optional<std::string>{};
    const std::uint32_t k = (std::uint32_t{d->bytes[0]} << 24) | (std::uint32_t{d->bytes[1]} << 16) |
                            (std::uint32_t{d->bytes[2]} << 8) | d->bytes[3];
    auto p = ctx.mikey != nullptr ? ctx.mikey->key_identifier(k, ctx) : ctx.mapper.key_id(k);
    if (!p) return std::unexpected(p.error());
    const Bytes out{static_cast<std::uint8_t>(*p >> 24), static_cast<std::uint8_t>(*p >> 16),
                    static_cast<std::uint8_t>(*p >> 8), static_cast<std::uint8_t>(*p)};
    return std::optional<std::string>(base64::encode(out, d->layout));
  }
  if (category == XmlCategory::mikey_hex) {
    // Feature 005: the MIKEY carrier rewrites the I_MESSAGE in place; nullopt
    // is its fallback (the caller removes the element as a credential, FR-020 c).
    if (ctx.mikey == nullptr) return std::optional<std::string>{};
    sip::MikeyOutcome outcome;
    return ctx.mikey->rewrite(sip::MikeyCarrierKind::gktp, value, {}, outcome, ctx);
  }
  if (const auto c = simple_category(category)) return sip::map_value(*c, value, ctx);
  return fail(ErrorCode::internal, "xml category '" + std::string(to_string(category)) + "' is not implemented");
}

}  // namespace mcxanon::xml
