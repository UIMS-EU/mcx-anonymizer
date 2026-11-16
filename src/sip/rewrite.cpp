// SPDX-License-Identifier: GPL-3.0-or-later
#include "sip/rewrite.hpp"

#include "bytes/base64.hpp"

#include "sip/header_values.hpp"
#include "sip/limits.hpp"
#include "sip/multipart.hpp"
#include "sip/render.hpp"
#include "sip/sdp.hpp"
#include "sip/uri.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <utility>

namespace mcxanon::sip {
namespace {

using Opt = Result<std::optional<std::string>>;
const auto kNone = std::optional<std::string>{};

bool iequal(std::string_view a, std::string_view b) {
  return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), [](char x, char y) {
           return std::tolower(static_cast<unsigned char>(x)) ==
                  std::tolower(static_cast<unsigned char>(y));
         });
}

std::string lower(std::string_view s) {
  std::string out(s);
  for (auto& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return out;
}

bool all_digits(std::string_view s) {
  return !s.empty() && std::all_of(s.begin(), s.end(), [](char c) { return c >= '0' && c <= '9'; });
}

// RFC 3261 §21: the default reason phrases.
constexpr std::array<std::pair<int, std::string_view>, 50> kReasons{{
    {100, "Trying"}, {180, "Ringing"}, {181, "Call Is Being Forwarded"}, {182, "Queued"},
    {183, "Session Progress"}, {200, "OK"}, {300, "Multiple Choices"}, {301, "Moved Permanently"},
    {302, "Moved Temporarily"}, {305, "Use Proxy"}, {380, "Alternative Service"},
    {400, "Bad Request"}, {401, "Unauthorized"}, {402, "Payment Required"}, {403, "Forbidden"},
    {404, "Not Found"}, {405, "Method Not Allowed"}, {406, "Not Acceptable"},
    {407, "Proxy Authentication Required"}, {408, "Request Timeout"}, {410, "Gone"},
    {413, "Request Entity Too Large"}, {414, "Request-URI Too Long"},
    {415, "Unsupported Media Type"}, {416, "Unsupported URI Scheme"}, {420, "Bad Extension"},
    {421, "Extension Required"}, {423, "Interval Too Brief"}, {480, "Temporarily Unavailable"},
    {481, "Call/Transaction Does Not Exist"}, {482, "Loop Detected"}, {483, "Too Many Hops"},
    {484, "Address Incomplete"}, {485, "Ambiguous"}, {486, "Busy Here"},
    {487, "Request Terminated"}, {488, "Not Acceptable Here"}, {491, "Request Pending"},
    {493, "Undecipherable"}, {500, "Server Internal Error"}, {501, "Not Implemented"},
    {502, "Bad Gateway"}, {503, "Service Unavailable"}, {504, "Server Time-out"},
    {505, "Version Not Supported"}, {513, "Message Too Large"}, {600, "Busy Everywhere"},
    {603, "Decline"}, {604, "Does Not Exist Anywhere"}, {606, "Not Acceptable"},
}};

// The headers whose failure makes the whole message malformed (FR-029).
bool dialog_defining(std::string_view rule_name) {
  for (std::string_view n : {"Via", "From", "To", "Call-ID", "CSeq", "Content-Length", "Content-Type"}) {
    if (iequal(n, rule_name)) return true;
  }
  return false;
}

std::string unwrap(std::string_view v, bool& angle) {
  angle = v.size() >= 2 && v.front() == '<' && v.back() == '>';
  return std::string(angle ? v.substr(1, v.size() - 2) : v);
}

struct Rewriter {
  explicit Rewriter(Context& c) : ctx(c) {}
  Context& ctx;
  // Feature 003 (FR-014a): a URI rewritten as a resource-lists entry may carry an
  // embedded body; outside that, URI headers are removed as in 002.
  bool embed = false;
  std::size_t embed_depth = 0;   // the embedding depth of the entry URI itself
  std::string embed_outcome;     // "" (no body), "rewritten", or why the body was removed
  std::size_t xml_depth = 0;     // the depth passed to the XML layer (1 inside an entry URI)
  std::string xml_reason;        // why the XML layer emptied the last body

  // --- instance identifiers (+sip.instance, gr; TS 23.003 §13.8, RFC 7254 §3) ---------------
  Opt instance(std::string_view v) {
    bool angle = false;
    const std::string inner = unwrap(v, angle);
    const auto wrap = [&](std::string s) -> Opt {
      return std::optional<std::string>(angle ? "<" + s + ">" : s);
    };
    constexpr std::string_view imei_prefix = "urn:gsma:imei:";
    constexpr std::string_view uuid_prefix = "urn:uuid:";
    if (inner.size() > imei_prefix.size() && iequal(std::string_view(inner).substr(0, imei_prefix.size()), imei_prefix)) {
      // imeival = tac "-" snr "-" spare, tac = 8DIGIT, snr = 6DIGIT, spare = DIGIT
      std::string_view rest = std::string_view(inner).substr(imei_prefix.size());
      const auto semi = rest.find(';');
      const auto val = rest.substr(0, semi);
      if (val.size() != 17 || val[8] != '-' || val[15] != '-' || !all_digits(val.substr(0, 8)) ||
          !all_digits(val.substr(9, 6)) || !all_digits(val.substr(16, 1))) {
        return kNone;
      }
      const std::string digits = std::string(val.substr(0, 8)) + std::string(val.substr(9, 6));
      auto p = map_value(SipCategory::imei, digits, ctx);
      if (!p || !*p) return p;
      // A check digit (TS 23.003 §B.2) is recomputed; a spare "0" (IMEISV form) stays "0".
      const char spare = val[16] == '0' ? '0' : (**p)[14];
      std::string out = std::string(inner.substr(0, imei_prefix.size())) + (**p).substr(0, 8) + "-" +
                        (**p).substr(8, 6) + "-" + spare;
      // The svn parameter (RFC 7254 §4.1) carries the software version, no identity.
      if (semi != std::string_view::npos) {
        for (auto prm : split_semis(rest.substr(semi + 1))) {
          if (prm.size() > 4 && iequal(prm.substr(0, 4), "svn=") && all_digits(prm.substr(4))) {
            out += ";" + std::string(prm);
          }
        }
      }
      return wrap(out);
    }
    if (inner.size() > uuid_prefix.size() && iequal(std::string_view(inner).substr(0, uuid_prefix.size()), uuid_prefix)) {
      auto p = map_value(SipCategory::uuid, std::string_view(inner).substr(uuid_prefix.size()), ctx);
      if (!p || !*p) return p;
      return wrap(std::string(inner.substr(0, uuid_prefix.size())) + **p);
    }
    return kNone;
  }

  static std::vector<std::string_view> split_semis(std::string_view s) {
    std::vector<std::string_view> out;
    std::size_t start = 0;
    for (;;) {
      const auto p = s.find(';', start);
      out.push_back(s.substr(start, p == std::string_view::npos ? p : p - start));
      if (p == std::string_view::npos) break;
      start = p + 1;
    }
    return out;
  }

  Opt category(SipCategory c, std::string_view v) {
    if (c == SipCategory::instance) return instance(v);
    return map_value(c, v, ctx);
  }

  // Feature 005 (TS 33.180 §9.3.4.3): the user part of an encrypted
  // URI attribute, "<b64 ciphertext>;iv=<b64>;key-id=<b64>;alg=128-aes-gcm", in this order, in the
  // standard or URL-safe base64 alphabet. The ciphertext token takes a sip-user pseudonym, the IV
  // the nonce mapping, the key-id (32 bits) the key identifier mapping, each written back in its
  // input form; alg is kept. nullopt: another form, which takes the whole-user-part mapping.
  Opt encrypted_user(std::string_view user) {
    const bool marked = user.find(";key-id=") != std::string_view::npos;
    const auto whole = [&]() -> Opt {
      if (marked && ctx.mikey != nullptr) ctx.mikey->encrypted_uri(false);
      return kNone;
    };
    std::vector<std::string_view> f;
    for (std::size_t start = 0;;) {
      const auto semi = user.find(';', start);
      f.push_back(user.substr(start, semi == std::string_view::npos ? std::string_view::npos : semi - start));
      if (semi == std::string_view::npos) break;
      start = semi + 1;
    }
    if (f.size() != 4 || f[0].empty() || !f[1].starts_with("iv=") || !f[2].starts_with("key-id=") ||
        !f[3].starts_with("alg=") || !iequal(f[3].substr(4), "128-aes-gcm")) {
      return whole();
    }
    // One alphabet for the whole URI: URL-safe when a field has '-' or '_', standard when one has
    // '+', '/' or padding, else URL-safe (the form of the TS 33.180 §9.3.4.3 example).
    const std::array<std::string_view, 3> vals{f[0], f[1].substr(3), f[2].substr(7)};
    const auto has = [&](std::string_view chars) {
      return std::any_of(vals.begin(), vals.end(), [&](std::string_view x) { return x.find_first_of(chars) != x.npos; });
    };
    const auto alphabet = has("-_") ? base64::Alphabet::url : has("+/=") ? base64::Alphabet::standard : base64::Alphabet::url;
    const auto decode = [&](std::string_view t) -> std::optional<std::pair<base64::Decoded, base64::Alphabet>> {
      if (auto d = base64::decode(t, alphabet); d && d->layout.line == 0) return std::pair{std::move(*d), alphabet};
      return std::nullopt;
    };
    const auto token = decode(vals[0]);
    const auto iv = decode(vals[1]);
    const auto kid = decode(vals[2]);
    if (!token || !iv || !kid || kid->first.bytes.size() != 4 || iv->first.bytes.empty()) return whole();
    auto t = map_value(SipCategory::sip_user, f[0], ctx);
    if (!t) return std::unexpected(t.error());
    if (!*t) return whole();
    auto n = ctx.mapper.bytes(Category::nonce, iv->first.bytes);
    if (!n) return std::unexpected(n.error());
    const auto& kb = kid->first.bytes;
    const std::uint32_t k = (std::uint32_t{kb[0]} << 24) | (std::uint32_t{kb[1]} << 16) | (std::uint32_t{kb[2]} << 8) | kb[3];
    auto p = ctx.mikey != nullptr ? ctx.mikey->key_identifier(k, ctx) : ctx.mapper.key_id(k);
    if (!p) return std::unexpected(p.error());
    const Bytes pk{static_cast<std::uint8_t>(*p >> 24), static_cast<std::uint8_t>(*p >> 16),
                   static_cast<std::uint8_t>(*p >> 8), static_cast<std::uint8_t>(*p)};
    if (ctx.mikey != nullptr) ctx.mikey->encrypted_uri(true);
    return std::optional<std::string>(**t + ";iv=" + base64::encode(*n, iv->first.layout, iv->second) +
                                      ";key-id=" + base64::encode(pk, kid->first.layout, kid->second) + ";" +
                                      std::string(f[3]));
  }

  // --- URIs (FR-009) -------------------------------------------------------------------------
  Result<std::optional<Uri>> uri(const Uri& in) {
    Uri u = in;
    if (u.kind == Scheme::other) {
      const std::string full = u.scheme + ":" + u.opaque;
      if (iequal(u.scheme, "cid")) {
        // cid: URIs use the Content-ID mapping, so references and parts stay consistent.
        auto p = map_value(SipCategory::call_id, percent_decode(u.opaque), ctx);
        if (!p) return std::unexpected(p.error());
        if (!*p) return std::optional<Uri>{};
        u.opaque = **p;
        return std::optional<Uri>(u);
      }
      if (ctx.rules.uri.kept(full)) return std::optional<Uri>(u);
      if (const auto* fv = ctx.rules.find_feature_value(full); fv != nullptr && fv->rule.action == SipAction::keep) {
        return std::optional<Uri>(u);
      }
      ctx.counters.count(ctx.counters.removed_unknown, "sip-param", lower(u.scheme));
      return std::optional<Uri>{};
    }
    u.had_password = false;
    if (u.headers && embed) {
      auto h = embedded_headers(*u.headers);
      if (!h) return std::unexpected(h.error());
      u.headers = std::move(*h);
    } else if (u.headers) {
      ctx.counters.count(ctx.counters.removed_unknown, "sip-param", "uri-headers");
      u.headers.reset();
    }
    const bool phone = std::any_of(u.params.begin(), u.params.end(), [](const Param& p) {
      return iequal(p.name, "user") && p.value && iequal(*p.value, "phone");
    });
    if (u.kind == Scheme::tel || (u.user && phone)) {
      // A telephone number (RFC 3966; user=phone, TS 23.003 §13.4): digits replaced, the same
      // number of digits. Parameters inside a SIP user part are removed.
      std::string_view number = *u.user;
      if (u.kind != Scheme::tel) {
        const auto semi = number.find(';');
        if (semi != std::string_view::npos) {
          ctx.counters.count(ctx.counters.removed_unknown, "sip-param", "user-params");
          number = number.substr(0, semi);
        }
      }
      auto t = map_value(SipCategory::tel, percent_decode(number), ctx);
      if (!t) return std::unexpected(t.error());
      if (!*t) return std::optional<Uri>{};
      u.user = **t;
    } else if (u.user) {
      auto e = encrypted_user(*u.user);
      if (!e) return std::unexpected(e.error());
      if (*e) {
        u.user = **e;
      } else {
        auto p = map_value(SipCategory::sip_user, *u.user, ctx);
        if (!p) return std::unexpected(p.error());
        if (!*p) return std::optional<Uri>{};
        u.user = **p;
      }
    }
    if (u.kind != Scheme::tel) {
      auto h = map_host(u.host, ctx);
      if (!h) return std::unexpected(h.error());
      if (!*h) return std::optional<Uri>{};
      u.host = **h;
      if (u.port) {
        auto p = map_value(SipCategory::port, *u.port, ctx);
        if (!p) return std::unexpected(p.error());
        if (!*p) return std::optional<Uri>{};
        u.port = **p;
      }
    }
    auto params = filter(u.params, nullptr, true);
    if (!params) return std::unexpected(params.error());
    u.params = std::move(*params);
    if (ctx.uris != nullptr) {
      // Feature 005: the identity ledger records the bare URI (no parameters, no
      // headers), original and pseudonym, for the resolution of hidden-identity UIDs.
      Uri a = in;
      Uri b = u;
      for (Uri* x : {&a, &b}) {
        x->params.clear();
        x->headers.reset();
        x->had_password = false;
      }
      ctx.uris->on_uri(render_uri(a), render_uri(b));
    }
    return std::optional<Uri>(u);
  }

  // --- bodies embedded in an entry URI (feature 003, FR-014a) ----------------
  // RFC 3261 §25.1: hvalue = *( hnv-unreserved / unreserved / escaped ).
  static std::string escape_hvalue(std::string_view v) {
    std::string out;
    const char* hex = "0123456789ABCDEF";
    for (const char ch : v) {
      const auto c = static_cast<unsigned char>(ch);
      if (std::isalnum(c) != 0 || std::string_view("-_.!~*'()[]/?:+$").find(ch) != std::string_view::npos) {
        out.push_back(ch);
      } else {
        out.push_back('%');
        out.push_back(hex[c >> 4]);
        out.push_back(hex[c & 15]);
      }
    }
    return out;
  }

  // Percent-decoding that fails on an incomplete or non-hex escape.
  static std::optional<std::string> strict_decode(std::string_view v) {
    std::string out;
    out.reserve(v.size());
    for (std::size_t i = 0; i < v.size(); ++i) {
      if (v[i] != '%') {
        out.push_back(v[i]);
        continue;
      }
      if (i + 2 >= v.size() || std::isxdigit(static_cast<unsigned char>(v[i + 1])) == 0 ||
          std::isxdigit(static_cast<unsigned char>(v[i + 2])) == 0) {
        return std::nullopt;
      }
      out.push_back(static_cast<char>(std::stoi(std::string(v.substr(i + 1, 2)), nullptr, 16)));
      i += 2;
    }
    return out;
  }

  // The URI headers of an entry URI: Content-Type and body are kept when the body rewrites;
  // every other header is removed as in 002; nullopt when nothing is left.
  Result<std::optional<std::string>> embedded_headers(std::string_view headers) {
    constexpr std::size_t kMaxEmbedded = 1024 * 1024;  // FR-003, after URL-decoding
    std::optional<std::string_view> ct_raw, body_raw;
    bool others = false;
    bool ct_first = true;
    for (std::size_t start = 0; start <= headers.size();) {
      const auto amp = headers.find('&', start);
      const auto item = headers.substr(start, amp == std::string_view::npos ? std::string_view::npos : amp - start);
      const auto eq = item.find('=');
      const auto name = item.substr(0, eq);
      const auto val = eq == std::string_view::npos ? std::string_view() : item.substr(eq + 1);
      if (iequal(name, "Content-Type") || iequal(name, "c")) {
        ct_raw = val;
        ct_first = !body_raw.has_value();
      } else if (iequal(name, "body")) {
        body_raw = val;
      } else if (!item.empty()) {
        others = true;
      }
      if (amp == std::string_view::npos) break;
      start = amp + 1;
    }
    if (others || (ct_raw && !body_raw)) ctx.counters.count(ctx.counters.removed_unknown, "sip-param", "uri-headers");
    if (!body_raw) return std::optional<std::string>{};
    const auto removed = [&](const char* why) -> Result<std::optional<std::string>> {
      embed_outcome = why;
      ctx.counters.removed(*body_raw);
      return std::optional<std::string>{};
    };
    if (embed_depth >= 1) return removed("nested");
    const auto data = strict_decode(*body_raw);
    if (!data) return removed("undecodable");
    if (!ct_raw) return removed("unknown-type");
    const auto ct = strict_decode(*ct_raw);
    if (!ct) return removed("undecodable");
    if (data->size() > kMaxEmbedded) return removed("limit");
    const auto mt = media_type(*ct);
    const auto* rule = mt ? ctx.rules.find_body(mt->first) : nullptr;
    if (rule == nullptr) return removed("unknown-type");
    if (rule->handling == BodyHandling::empty) return removed("emptied");
    const auto* ct_rule = ctx.rules.find_header("Content-Type");
    if (ct_rule == nullptr) return removed("unknown-type");
    auto new_ct = value(*ct_rule, *ct);
    if (!new_ct) return std::unexpected(new_ct.error());
    if (!*new_ct || (*new_ct)->empty()) return removed("malformed");
    const auto saved_depth = xml_depth;
    xml_depth = embed_depth + 1;
    xml_reason.clear();
    auto b = body(*ct, "", *data, 0);
    xml_depth = saved_depth;
    if (!b) return std::unexpected(b.error());
    if (b->malformed || b->bytes.empty()) return removed(xml_reason.empty() ? "malformed" : xml_reason.c_str());
    embed_outcome = "rewritten";
    const std::string c = "Content-Type=" + escape_hvalue(**new_ct);
    const std::string d = "body=" + escape_hvalue(b->bytes);
    return std::optional<std::string>(ct_first ? c + "&" + d : d + "&" + c);
  }

  // A URI written as a parameter value (quoted or not, with or without angle brackets).
  Opt uri_text(std::string_view v) {
    bool angle = false;
    const std::string inner = unwrap(v, angle);
    auto u = parse_uri(inner);
    if (!u) return kNone;
    auto r = uri(*u);
    if (!r) return std::unexpected(r.error());
    if (!*r) return kNone;
    const std::string s = render_uri(**r);
    return std::optional<std::string>(angle ? "<" + s + ">" : s);
  }

  // --- parameters (FR-007) and feature tags (FR-008) ----------------------------------------
  bool shape_ok(const SipParamRule& r, const Param& p) {
    switch (r.value) {
      case ParamValue::flag: return !p.value;
      case ParamValue::number: return p.value && !p.quoted && all_digits(*p.value);
      case ParamValue::quoted: return p.value && p.quoted;
      default: return true;
    }
  }

  // Header parameters filtered by `header` (or the URI parameter rules when `uri_params`).
  // Parameters without a rule are removed and counted; with `header`, a media feature tag rule
  // is consulted next (Contact, Accept-Contact, Reject-Contact, Feature-Caps).
  Result<std::vector<Param>> filter(const std::vector<Param>& in, const SipHeaderRule* header,
                                    bool uri_params) {
    std::vector<Param> out;
    for (const auto& p : in) {
      const SipParamRule* r = uri_params ? ctx.rules.uri.find_param(p.name)
                                         : (header != nullptr ? header->find_param(p.name) : nullptr);
      if (r == nullptr && !uri_params) {
        if (const auto* ft = ctx.rules.find_feature_tag(p.name)) {
          auto t = feature(p, *ft);
          if (!t) return std::unexpected(t.error());
          if (*t) out.push_back(std::move(**t));
          continue;
        }
      }
      if (r == nullptr) {
        ctx.counters.count(ctx.counters.removed_unknown, "sip-param", p.name);
        continue;
      }
      if (!shape_ok(*r, p) || r->rule.action == SipAction::remove || r->rule.action == SipAction::blank) {
        if (r->rule.action == SipAction::remove && p.value) ctx.counters.removed(*p.value);
        if (r->rule.action != SipAction::remove) {
          ctx.counters.count(ctx.counters.removed_unknown, "sip-param", p.name);
        }
        continue;
      }
      if (r->rule.action == SipAction::keep || !p.value) {
        out.push_back(p);  // a flag carries nothing to pseudonymise
        continue;
      }
      Opt v = kNone;
      if (r->rule.category == SipCategory::session_id && *p.value == std::string(32, '0')) {
        out.push_back(p);  // RFC 7989 §4.2: the nil UUID carries no identity
        continue;
      }
      if (r->rule.action == SipAction::uri) {
        v = uri_text(*p.value);
      } else if (r->rule.category) {
        if (uri_params && iequal(p.name, "phone-context") && !p.value->empty() &&
            ((*p.value)[0] == '+' || std::isdigit(static_cast<unsigned char>((*p.value)[0])) != 0)) {
          v = std::optional<std::string>(*p.value);  // a numeric context (a number prefix)
        } else {
          v = category(*r->rule.category, *p.value);
        }
      }
      if (!v) return std::unexpected(v.error());
      if (!*v) {
        ctx.counters.count(ctx.counters.removed_unknown, "sip-param", p.name);
        continue;
      }
      Param q = p;
      q.value = **v;
      out.push_back(std::move(q));
    }
    return out;
  }

  // One media feature tag or feature-capability indicator.
  Result<std::optional<Param>> feature(const Param& p, const FeatureTagRule& r) {
    const auto drop = [&]() -> Result<std::optional<Param>> {
      ctx.counters.count(ctx.counters.removed_unknown, "sip-param", p.name);
      return std::optional<Param>{};
    };
    if (r.rule.action == SipAction::remove) {
      // Removed by its rule: a scan token, but not unknown (FR-036), as for parameters.
      if (p.value) ctx.counters.removed(*p.value);
      return std::optional<Param>{};
    }
    switch (r.value_type) {
      case FeatureValue::none:
        if (p.value) return drop();
        return std::optional<Param>(p);
      case FeatureValue::boolean:
        if (p.value && !iequal(*p.value, "TRUE") && !iequal(*p.value, "FALSE")) return drop();
        return std::optional<Param>(p);
      case FeatureValue::token:
      case FeatureValue::token_list: {
        if (!p.value) return std::optional<Param>(p);
        for (auto t : split_list(*p.value).value_or(std::vector<std::string_view>{})) {
          const auto bare = t.starts_with('!') ? t.substr(1) : t;
          if (!is_token(bare)) return drop();
        }
        if (!split_list(*p.value)) return drop();
        return std::optional<Param>(p);
      }
      case FeatureValue::urn_list: {
        // tag-value-list of ICSI/IARI URNs, percent-encoded (TS 24.229 §7.2A.8.2): each value
        // must be on the allowlist; the received encoding is kept.
        if (!p.value || !p.quoted) return drop();
        std::vector<std::string> kept;
        auto items = split_list(*p.value);
        if (!items) return drop();
        for (auto v : *items) {
          const auto* fv = ctx.rules.find_feature_value(percent_decode(v));
          if (fv != nullptr && fv->rule.action == SipAction::keep) {
            kept.emplace_back(v);
          } else {
            ctx.counters.count(ctx.counters.removed_unknown, "sip-param", p.name);
          }
        }
        if (kept.empty()) return std::optional<Param>{};
        Param q = p;
        q.value.emplace();
        for (std::size_t i = 0; i < kept.size(); ++i) *q.value += (i ? "," : "") + kept[i];
        return std::optional<Param>(q);
      }
      case FeatureValue::uri: {
        if (!p.value) return std::optional<Param>(p);
        auto v = uri_text(*p.value);
        if (!v) return std::unexpected(v.error());
        if (!*v) return drop();
        Param q = p;
        q.value = **v;
        return std::optional<Param>(q);
      }
      case FeatureValue::string:
      case FeatureValue::identity: {
        if (!p.value) return drop();
        if (r.rule.action != SipAction::pseudonymise || !r.rule.category) return drop();
        bool angle = false;
        std::string inner = unwrap(*p.value, angle);
        Opt v = r.rule.category == SipCategory::instance ? instance(*p.value) : category(*r.rule.category, inner);
        if (!v) return std::unexpected(v.error());
        if (!*v) return drop();
        Param q = p;
        q.value = (angle && r.rule.category != SipCategory::instance) ? "<" + **v + ">" : **v;
        return std::optional<Param>(q);
      }
    }
    return drop();
  }

  // --- header values -------------------------------------------------------------------------
  const SipItemRule* comp(const SipHeaderRule& r, const char* name) {
    const auto it = r.components.find(name);
    return it == r.components.end() ? nullptr : &it->second;
  }

  // Applies a component rule; a header-level keep keeps a component without a rule.
  Opt component(const SipHeaderRule& r, const char* name, std::string_view v) {
    const SipItemRule* c = comp(r, name);
    if (c == nullptr) {
      if (r.action == SipAction::keep) return std::optional<std::string>(std::string(v));
      return kNone;
    }
    switch (c->action) {
      case SipAction::keep: return std::optional<std::string>(std::string(v));
      case SipAction::blank: return std::optional<std::string>(c->value);
      case SipAction::pseudonymise:
        if (c->category) return category(*c->category, v);
        return kNone;
      case SipAction::uri: return uri_text(v);
      case SipAction::remove: return kNone;
    }
    return kNone;
  }

  Opt name_addrs(const SipHeaderRule& r, std::string_view value) {
    auto list = parse_name_addr_list(value);
    if (!list || (!r.multi && list->size() != 1)) return kNone;
    std::vector<std::string> out;
    for (auto& na : *list) {
      if (na.uri.kind == Scheme::other && na.uri.opaque == "*" && !na.angle) {
        out.emplace_back("*");  // Contact: * (RFC 3261 §20.10)
        continue;
      }
      if (na.display) {
        const SipItemRule* d = comp(r, "display-name");
        if (d != nullptr && d->action == SipAction::pseudonymise && d->category) {
          auto p = category(*d->category, *na.display);
          if (!p) return std::unexpected(p.error());
          if (!*p) return kNone;
          na.display = **p;
          na.display_quoted = true;  // FR-010: always a quoted string
        } else if (d == nullptr || d->action != SipAction::keep) {
          na.display.reset();
        }
      }
      auto u = uri(na.uri);
      if (!u) return std::unexpected(u.error());
      if (!*u) continue;  // a URI that cannot be kept: this value is removed
      na.uri = std::move(**u);
      if (!na.angle && (!na.uri.params.empty() || na.uri.headers)) na.angle = true;
      auto params = filter(na.params, &r, false);
      if (!params) return std::unexpected(params.error());
      na.params = std::move(*params);
      out.push_back(render_name_addr(na));
    }
    if (out.empty()) return std::optional<std::string>(std::string());
    std::string s;
    for (std::size_t i = 0; i < out.size(); ++i) s += (i ? ", " : "") + out[i];
    return std::optional<std::string>(s);
  }

  Opt via(const SipHeaderRule& r, std::string_view value) {
    auto list = parse_via(value);
    if (!list) return kNone;
    std::vector<std::string> out;
    for (auto& v : *list) {
      auto host = component(r, "sent-by", v.host);
      if (!host) return host;
      if (!*host) return kNone;
      v.host = **host;
      if (v.port) {
        auto port = component(r, "port", *v.port);
        if (!port) return port;
        if (!*port) return kNone;
        v.port = **port;
      }
      auto params = filter(v.params, &r, false);
      if (!params) return std::unexpected(params.error());
      v.params = std::move(*params);
      out.push_back(render_via(v));
    }
    std::string s;
    for (std::size_t i = 0; i < out.size(); ++i) s += (i ? ", " : "") + out[i];
    return std::optional<std::string>(s);
  }

  Opt call_ids(const SipHeaderRule& r, std::string_view value) {
    std::vector<std::string_view> elems;
    if (r.multi) {
      auto l = split_list(value);
      if (!l) return kNone;
      elems = *l;
    } else {
      elems.push_back(trim_lws(value));
    }
    std::vector<std::string> out;
    for (auto e : elems) {
      // callid [*(SEMI param)]; a msg-id (Content-ID, RFC 8262 §3.2) is in angle brackets.
      const auto semi = e.find(';');
      bool angle = false;
      const std::string id = unwrap(trim_lws(e.substr(0, semi)), angle);
      if (!parse_call_id(id) || id.find(' ') != std::string::npos) return kNone;
      auto p = component(r, "value", id);
      if (!p) return p;
      if (!*p) return kNone;
      auto params = parse_params(semi == std::string_view::npos ? std::string_view() : e.substr(semi));
      if (!params) return kNone;
      auto f = filter(*params, &r, false);
      if (!f) return std::unexpected(f.error());
      out.push_back((angle ? "<" + **p + ">" : **p) + render_params(*f));
    }
    std::string s;
    for (std::size_t i = 0; i < out.size(); ++i) s += (i ? ", " : "") + out[i];
    return std::optional<std::string>(s);
  }

  Opt items(const SipHeaderRule& r, std::string_view value, HeadKind kind, const char* head_name) {
    auto list = parse_items(value, kind, r.multi);
    if (!list) return kNone;
    std::vector<std::string> out;
    for (auto& it : *list) {
      const bool nil = kind == HeadKind::session_id && it.value == std::string(32, '0');
      // Feature 005: a token header with a value list keeps only those values (the whole header
      // is malformed otherwise, FR-029).
      if (!r.values.empty() && std::find(r.values.begin(), r.values.end(), lower(it.value)) == r.values.end()) {
        return kNone;
      }
      if (!nil) {
        auto h = component(r, head_name, it.value);
        if (!h) return h;
        if (!*h) continue;
        it.value = **h;
      }
      auto params = filter(it.params, &r, false);
      if (!params) return std::unexpected(params.error());
      it.params = std::move(*params);
      out.push_back(render_item(it));
    }
    std::string s;
    for (std::size_t i = 0; i < out.size(); ++i) s += (i ? ", " : "") + out[i];
    return std::optional<std::string>(s);
  }

  Opt auth(const SipHeaderRule& r, std::string_view value, bool with_scheme) {
    AuthValue a;
    if (with_scheme) {
      auto parsed = parse_auth(value);
      if (!parsed) return kNone;
      a = std::move(*parsed);
      auto scheme = component(r, "scheme", a.scheme);
      if (!scheme) return scheme;
      if (!*scheme) return kNone;
      a.scheme = **scheme;
    } else {
      auto parts = split_list(value);
      if (!parts) return kNone;
      for (auto p : *parts) {
        auto params = parse_params(";" + std::string(p));
        if (!params || params->size() != 1 || !params->front().value) return kNone;
        a.params.push_back(std::move(params->front()));
      }
    }
    auto params = filter(a.params, &r, false);
    if (!params) return std::unexpected(params.error());
    a.params = std::move(*params);
    if (with_scheme) return std::optional<std::string>(render_auth(a));
    std::string s;
    for (std::size_t i = 0; i < a.params.size(); ++i) {
      const auto& p = a.params[i];
      s += (i ? ", " : "") + p.name + "=" + (p.quoted ? quote(*p.value) : *p.value);
    }
    return std::optional<std::string>(s);
  }

  Opt warnings(const SipHeaderRule& r, std::string_view value) {
    auto list = parse_warning(value);
    if (!list) return kNone;
    std::vector<std::string> out;
    for (auto& w : *list) {
      auto agent = component(r, "agent", w.agent);
      if (!agent) return agent;
      if (!*agent) continue;
      ctx.counters.removed(w.text);
      // Decision D2: a leading 3-digit MCX warn code (TS 24.379 §4.4.2) is kept.
      const bool mcx_code = w.text.size() >= 3 && all_digits(w.text.substr(0, 3)) &&
                            (w.text.size() == 3 || w.text[3] == ' ');
      auto text = component(r, "text", w.text);
      if (!text) return text;
      w.agent = **agent;
      w.text = mcx_code ? w.text.substr(0, 3) : text->value_or("");
      out.push_back(render_warning(w));
    }
    std::string s;
    for (std::size_t i = 0; i < out.size(); ++i) s += (i ? ", " : "") + out[i];
    return std::optional<std::string>(s);
  }

  // The rewritten value of one header field; nullopt when the value does not parse
  // (malformed), an empty string when every value of the field was removed.
  Opt value(const SipHeaderRule& r, std::string_view v) {
    switch (r.grammar) {
      case SipGrammar::name_addr:
      case SipGrammar::name_addr_list:
      case SipGrammar::uri_list: return name_addrs(r, v);
      case SipGrammar::via: return via(r, v);
      case SipGrammar::call_id: return call_ids(r, v);
      case SipGrammar::cseq: {
        auto c = parse_cseq(v);
        if (!c || !ctx.rules.known_method(c->method)) return kNone;
        return std::optional<std::string>(c->number + " " + c->method);
      }
      case SipGrammar::token:
      case SipGrammar::token_list:
      case SipGrammar::event: return items(r, v, HeadKind::token, "value");
      case SipGrammar::number: return items(r, v, HeadKind::number, "value");
      case SipGrammar::media_type: return items(r, v, HeadKind::media_type, "value");
      case SipGrammar::session_id: return items(r, v, HeadKind::session_id, "value");
      case SipGrammar::pani: return items(r, v, HeadKind::token, "access-type");
      case SipGrammar::reason: return items(r, v, HeadKind::token, "protocol");
      case SipGrammar::security_mech: return items(r, v, HeadKind::token, "mechanism");
      case SipGrammar::credentials:
      case SipGrammar::challenge: return auth(r, v, true);
      case SipGrammar::auth_params: return auth(r, v, false);
      case SipGrammar::param_list: {
        auto params = parse_params(";" + std::string(v));
        if (!params || params->empty()) return kNone;
        auto f = filter(*params, &r, false);
        if (!f) return std::unexpected(f.error());
        const std::string s = render_params(*f);
        return std::optional<std::string>(s.empty() ? s : s.substr(1));
      }
      case SipGrammar::warning: return warnings(r, v);
      case SipGrammar::date: {
        auto d = parse_date(v);
        if (!d) return kNone;
        return std::optional<std::string>(render_date(*d + ctx.options.time_shift_s.value_or(0)));
      }
      case SipGrammar::retry_after: {
        auto ra = parse_retry_after(v);
        if (!ra) return kNone;
        if (ra->comment) ctx.counters.removed(*ra->comment);
        ra->comment.reset();  // free text
        auto f = filter(ra->params, &r, false);
        if (!f) return std::unexpected(f.error());
        ra->params = std::move(*f);
        return std::optional<std::string>(render_retry_after(*ra));
      }
      case SipGrammar::quoted_text:
      case SipGrammar::opaque: return std::optional<std::string>(std::string(v));
      // HTTP grammars (feature 007) are rewritten by the HTTP layer; here they are removed.
      case SipGrammar::host:
      case SipGrammar::etag_list:
      case SipGrammar::http_uri:
      case SipGrammar::http_credentials:
      case SipGrammar::cookie:
      case SipGrammar::set_cookie:
      case SipGrammar::directives:
      case SipGrammar::range:
      case SipGrammar::identity: return kNone;
    }
    return kNone;
  }

  // --- bodies (FR-022, FR-023) ---------------------------------------------------------------
  struct BodyOut {
    std::string bytes;
    bool malformed = false;
  };

  std::optional<std::pair<std::string, std::vector<Param>>> media_type(std::string_view ct) {
    auto it = parse_items(ct, HeadKind::media_type, false);
    if (!it || it->size() != 1) return std::nullopt;
    return std::pair{lower(it->front().value), it->front().params};
  }

  Result<BodyOut> body(std::string_view ct, std::string_view encoding, std::string_view data, std::size_t depth,
                       std::string_view cte = {}) {
    if (data.empty()) return BodyOut{};
    if (ct.empty()) {
      ctx.counters.count(ctx.counters.removed_unknown, "content-type", "(none)");
      return BodyOut{};
    }
    const auto mt = media_type(ct);
    if (!mt) return BodyOut{{}, true};
    const auto* rule = ctx.rules.find_body(mt->first);
    if (rule == nullptr) {
      ctx.counters.count(ctx.counters.removed_unknown, "content-type", mt->first);
      return BodyOut{};
    }
    // R12: a Content-Encoding other than identity makes the body unknown.
    if (!encoding.empty() && !iequal(trim_lws(encoding), "identity")) {
      ctx.counters.count(ctx.counters.bodies, rule->content_type, "emptied");
      return BodyOut{};
    }
    switch (rule->handling) {
      case BodyHandling::empty:
        ctx.counters.count(ctx.counters.bodies, rule->content_type, "emptied");
        return BodyOut{};
      case BodyHandling::xml: {
        // Feature 003: rewritten by the attached XML layer, else emptied as in
        // 002. An emptied XML body never makes the message malformed.
        if (ctx.xml == nullptr) {
          ctx.counters.count(ctx.counters.bodies, rule->content_type, "emptied");
          return BodyOut{};
        }
        std::string charset;
        for (const auto& p : mt->second) {
          if (iequal(p.name, "charset") && p.value) charset = *p.value;
        }
        auto x = ctx.xml->rewrite(rule->content_type, charset, data, xml_depth, ctx);
        if (!x) return std::unexpected(x.error());
        if (!x->rewritten) {
          ctx.counters.count(ctx.counters.bodies, rule->content_type, "emptied");
          xml_reason = x->reason;
          return BodyOut{};
        }
        ctx.counters.count(ctx.counters.bodies, rule->content_type, "xml");
        return BodyOut{std::move(x->bytes), false};
      }
      case BodyHandling::sdp: {
        auto s = rewrite_sdp(data, ctx);
        if (!s) return std::unexpected(s.error());
        if (!*s) return BodyOut{{}, true};
        ctx.counters.count(ctx.counters.bodies, rule->content_type, "sdp");
        return BodyOut{**s, false};
      }
      case BodyHandling::multipart: return multipart(*rule, mt->second, data, depth);
      case BodyHandling::mikey: {
        // Feature 005: the I_MESSAGE is rewritten by the attached MIKEY layer;
        // without one, or on its fallback, the body is emptied as in 002 (FR-020 b). RFC 3830
        // §10.1: a version other than 1 is not this MIKEY.
        const auto emptied = [&] {
          ctx.counters.count(ctx.counters.bodies, rule->content_type, "emptied");
          return BodyOut{};
        };
        if (ctx.mikey == nullptr) return emptied();
        for (const auto& p : mt->second) {
          if (iequal(p.name, "version") && (!p.value || trim_lws(*p.value) != "1")) {
            ctx.mikey->fallback(MikeyCarrierKind::body, "not-sakke");
            return emptied();
          }
        }
        MikeyOutcome outcome;
        auto r = ctx.mikey->rewrite(MikeyCarrierKind::body, data, cte, outcome, ctx);
        if (!r) return std::unexpected(r.error());
        if (!*r) return emptied();
        ctx.counters.count(ctx.counters.bodies, rule->content_type, "mikey");
        return BodyOut{std::move(**r), false};
      }
    }
    return BodyOut{{}, true};
  }

  Result<BodyOut> multipart(const SipBodyRule& rule, const std::vector<Param>& params,
                            std::string_view data, std::size_t depth) {
    if (depth >= kMaxMultipartDepth) return BodyOut{{}, true};
    const auto b = std::find_if(params.begin(), params.end(),
                                [](const Param& p) { return iequal(p.name, "boundary") && p.value; });
    if (b == params.end()) return BodyOut{{}, true};
    auto parsed = parse_multipart(data, *b->value);
    if (!parsed) return BodyOut{{}, true};
    auto nb = map_value(SipCategory::boundary, *b->value, ctx);
    if (!nb) return std::unexpected(nb.error());
    if (!*nb) return BodyOut{{}, true};
    std::string out;
    for (const auto& part : parsed->parts) {
      std::string ct, enc, cte;
      for (const auto& h : part.headers) {
        const auto* hr = ctx.rules.find_header(data.substr(h.name.off, h.name.len));
        if (hr != nullptr && iequal(hr->name, "Content-Type")) ct = h.unfolded;
        if (hr != nullptr && iequal(hr->name, "Content-Encoding")) enc = h.unfolded;
        if (hr != nullptr && iequal(hr->name, "Content-Transfer-Encoding")) cte = h.unfolded;
      }
      auto pb = body(ct, enc, part.body, depth + 1, cte);
      if (!pb) return std::unexpected(pb.error());
      if (pb->malformed) return BodyOut{{}, true};
      // An emptied part keeps one CRLF of content: a zero-length XML part is reported as
      // malformed by analysers, a whitespace-only one is not (FR-023 with FR-040).
      if (pb->bytes.empty() && !part.body.empty()) pb->bytes = "\r\n";
      out += "--" + **nb + "\r\n";
      bool malformed = false;
      auto hdrs = headers(data, part.headers, pb->bytes.size(), malformed, nullptr);
      if (!hdrs) return std::unexpected(hdrs.error());
      if (malformed) return BodyOut{{}, true};
      out += *hdrs + "\r\n" + pb->bytes + "\r\n";
    }
    out += "--" + **nb + "--\r\n";
    // R12: the boundary pseudonym must not occur in any part: exactly one occurrence per
    // delimiter, the close delimiter included.
    std::size_t count = 0;
    for (std::size_t at = out.find(**nb); at != std::string::npos; at = out.find(**nb, at + 1)) ++count;
    if (count != parsed->parts.size() + 1) return BodyOut{{}, true};
    ctx.counters.count(ctx.counters.bodies, rule.content_type, "multipart");
    return BodyOut{out, false};
  }

  // Header fields of a message or part, rendered; `malformed` is set when a dialog-defining
  // header (Content-Type for parts) fails. With `spans`, each field's output is recorded.
  struct FieldOut {
    Span line;
    std::string text;
    bool verbatim = false;
  };
  Result<std::string> headers(std::string_view data, const std::vector<HeaderField>& fields,
                              std::size_t body_len, bool& malformed, std::vector<FieldOut>* spans,
                              bool* header_failed = nullptr) {
    std::string out;
    for (const auto& h : fields) {
      const auto name = data.substr(h.name.off, h.name.len);
      const auto line = data.substr(h.line.off, h.line.len);
      const auto prefix = data.substr(h.line.off, h.value.off - h.line.off);
      const auto* rule = ctx.rules.find_header(name);
      FieldOut fo{h.line, {}, false};
      if (rule == nullptr) {
        ctx.counters.count(ctx.counters.removed_unknown, "sip-header", std::string(name));
        if (spans) spans->push_back(fo);
        continue;
      }
      if (iequal(rule->name, "Content-Length")) {
        fo.text = std::string(prefix) + std::to_string(body_len) + "\r\n";
        fo.verbatim = fo.text == line;
        ctx.counters.count(ctx.counters.headers, rule->name, "keep");
      } else if (rule->action == SipAction::remove) {
        ctx.counters.count(ctx.counters.headers, rule->name, "remove");
        ctx.counters.removed(h.unfolded);
      } else if (rule->grammar == SipGrammar::opaque || rule->grammar == SipGrammar::quoted_text) {
        fo.text = std::string(line);
        fo.verbatim = true;
        ctx.counters.count(ctx.counters.headers, rule->name, "keep");
      } else {
        auto v = value(*rule, h.unfolded);
        if (!v) return std::unexpected(v.error());
        if (!*v) {
          if (dialog_defining(rule->name)) {
            malformed = true;
            return std::string();
          }
          ctx.counters.count(ctx.counters.headers, rule->name, "malformed");
          ++ctx.counters.malformed_headers[rule->name];
          if (header_failed) *header_failed = true;
        } else if ((*v)->empty()) {
          ctx.counters.count(ctx.counters.headers, rule->name, "remove");
        } else {
          fo.text = std::string(prefix) + **v + "\r\n";
          fo.verbatim = fo.text == line;
          ctx.counters.count(ctx.counters.headers, rule->name,
                             rule->action == SipAction::keep ? "keep" : "pseudonymise");
        }
      }
      out += fo.text;
      if (spans) spans->push_back(std::move(fo));
    }
    return out;
  }
};

class Writer {
 public:
  void emit(std::size_t orig, std::size_t orig_len, std::string_view text, bool verbatim) {
    map_.push_back({orig, orig_len, out_.size(), text.size(), verbatim});
    out_ += text;
  }
  std::string out_;
  std::vector<OffsetSpan> map_;
};

SipRewriteResult zeroed(std::string_view data, SipRewriteResult r) {
  r.bytes.assign(data.size(), '\0');
  r.offset_map = {{0, data.size(), 0, data.size(), false}};
  r.malformed = Malformed::message;
  return r;
}

}  // namespace

std::string_view default_reason(int code) {
  for (const auto& [c, phrase] : kReasons) {
    if (c == code) return phrase;
  }
  return "-";
}

std::size_t map_offset(const std::vector<OffsetSpan>& map, std::size_t orig) {
  for (const auto& s : map) {
    if (orig < s.orig || orig >= s.orig + s.orig_len) continue;
    if (s.verbatim) return s.out + (orig - s.orig);
    return orig == s.orig ? s.out : s.out + s.out_len;
  }
  return map.empty() ? orig : map.back().out + map.back().out_len;
}

Result<SipRewriteResult> rewrite_message(std::string_view data, Transport transport, Context& outer) {
  SipRewriteResult result;
  auto m = parse_message(data, transport);
  if (!m) return zeroed(data, result);
  // The message's items are counted apart and added when the message is rewritten. A zeroed
  // message counts each of its headers as zeroed instead (FR-036); its removed values stay
  // scan tokens.
  SipCounters local;
  // The media descriptions of the message's SDP bodies reach the outer sink only when the
  // message is rewritten, not when it is zeroed (feature 004).
  struct Collect : MediaSink {
    std::vector<SdpMedia> media;
    void announce(const SdpMedia& x) override { media.push_back(x); }
  } collect;
  Context ctx{outer.rules, outer.mapper, outer.options, local, outer.media != nullptr ? &collect : nullptr, outer.xml,
              outer.mikey, outer.uris, nullptr, {}};
  const auto zero_message = [&] {
    outer.counters.merge(std::move(local), false);
    for (const auto& h : m->headers) {
      const auto name = data.substr(h.name.off, h.name.len);
      if (const auto* rule = outer.rules.find_header(name)) {
        outer.counters.count(outer.counters.headers, rule->name, "zero");
      } else {
        outer.counters.count(outer.counters.removed_unknown, "sip-header", std::string(name));
      }
    }
    return zeroed(data, result);
  };
  result.request = m->kind == MessageKind::request;
  if (result.request) {
    result.method = std::string(data.substr(m->method.off, m->method.len));
    // An extension method is a token the rules do not know: the message is zeroed.
    if (!ctx.rules.known_method(result.method)) {
      ctx.counters.removed(result.method);
      result.method = "(invalid-name)";  // the report never shows the token
      return zero_message();
    }
  } else {
    result.status_code = m->status_code;
  }
  ctx.method = result.method;
  Rewriter rw{ctx};
  Writer w;

  // Start line (§7.1, §7.2): the Request-URI by the URI rules; the reason phrase replaced by
  // the default phrase of its code (FR-016).
  std::string start;
  if (result.request) {
    auto u = parse_uri(data.substr(m->request_uri.off, m->request_uri.len));
    if (!u) return zero_message();
    auto r = rw.uri(*u);
    if (!r) return std::unexpected(r.error());
    if (!*r) return zero_message();
    start = result.method + " " + render_uri(**r) + " " +
            std::string(data.substr(m->request_uri.end() + 1, m->start_line.len - m->request_uri.end() - 1));
  } else {
    const auto phrase = default_reason(m->status_code);
    const auto reason = data.substr(m->reason.off, m->reason.len);
    if (reason != phrase) ctx.counters.removed(reason);
    start = std::string(data.substr(0, 12)) + std::string(phrase);
  }
  w.emit(0, m->start_line.len, start, start == data.substr(0, m->start_line.len));
  w.emit(m->start_line.len, 2, "\r\n", true);

  // Feature 005: the identity URIs of this message, as written, for the MIKEY UID resolution of
  // its body (the headers are rewritten after the body).
  std::vector<std::string> message_uris;
  if (ctx.mikey != nullptr) {
    if (result.request) message_uris.emplace_back(data.substr(m->request_uri.off, m->request_uri.len));
    for (const auto& h : m->headers) {
      const auto name = lower(data.substr(h.name.off, h.name.len));
      if (name != "from" && name != "f" && name != "to" && name != "t" && name != "p-asserted-identity" &&
          name != "p-preferred-identity") {
        continue;
      }
      const std::string_view v = h.unfolded;
      for (std::size_t p = 0; p < v.size() && message_uris.size() < 32;) {
        std::size_t s = std::string_view::npos;
        for (std::string_view scheme : {"sip:", "sips:", "tel:"}) {
          const auto at = v.find(scheme, p);
          if (at != std::string_view::npos && (s == std::string_view::npos || at < s)) s = at;
        }
        if (s == std::string_view::npos) break;
        std::size_t e = s;
        while (e < v.size() && v[e] != '>' && v[e] != ';' && v[e] != ',' && v[e] != ' ' && v[e] != '"') ++e;
        message_uris.emplace_back(v.substr(s, e - s));
        p = e;
      }
    }
  }
  ctx.message_uris = &message_uris;

  // Body first: Content-Length is rendered when its header is reached.
  std::string ct, enc, cte;
  for (const auto& h : m->headers) {
    const auto* hr = ctx.rules.find_header(data.substr(h.name.off, h.name.len));
    if (hr != nullptr && iequal(hr->name, "Content-Type")) ct = h.unfolded;
    if (hr != nullptr && iequal(hr->name, "Content-Encoding")) enc = h.unfolded;
    if (hr != nullptr && iequal(hr->name, "Content-Transfer-Encoding")) cte = h.unfolded;
  }
  auto body = rw.body(ct, enc, data.substr(m->body.off, m->body.len), 0, cte);
  if (!body) return std::unexpected(body.error());
  if (body->malformed) return zero_message();

  bool malformed = false;
  bool header_failed = false;
  std::vector<Rewriter::FieldOut> spans;
  auto hdrs = rw.headers(data, m->headers, body->bytes.size(), malformed, &spans, &header_failed);
  if (!hdrs) return std::unexpected(hdrs.error());
  if (malformed) return zero_message();
  for (const auto& s : spans) w.emit(s.line.off, s.line.len, s.text, s.verbatim);
  w.emit(m->header_end - 2, 2, "\r\n", true);
  const auto orig_body = data.substr(m->body.off, m->body.len);
  w.emit(m->body.off, m->body.len, body->bytes, body->bytes == orig_body);
  if (m->trailing.len > 0) {
    // §18.3: bytes after the body "MUST be discarded": zeroed, with the same length.
    w.emit(m->trailing.off, m->trailing.len, std::string(m->trailing.len, '\0'), false);
    result.trailing_zeroed = m->trailing.len;
  }
  result.bytes = std::move(w.out_);
  result.offset_map = std::move(w.map_);
  result.malformed = header_failed ? Malformed::header : Malformed::none;
  outer.counters.merge(std::move(local));
  if (outer.media != nullptr) {
    for (const auto& x : collect.media) outer.media->announce(x);
  }
  return result;
}

Result<std::optional<std::string>> rewrite_header_value(const SipHeaderRule& rule, std::string_view value,
                                                        Context& ctx) {
  Rewriter rw{ctx};
  return rw.value(rule, value);
}

Result<std::optional<std::string>> rewrite_uri_text(std::string_view text, Context& ctx) {
  Rewriter rw{ctx};
  return rw.uri_text(text);
}

Result<EmbeddedUri> rewrite_entry_uri(std::string_view text, Context& ctx, std::size_t depth) {
  Rewriter rw{ctx};
  rw.embed = true;
  rw.embed_depth = depth;
  auto u = rw.uri_text(text);
  if (!u) return std::unexpected(u.error());
  if (!*u) {
    // The URI does not parse with its headers (for example an escape that is not %HH in the
    // body): without them it may, and the body is counted as undecodable.
    const auto q = text.find('?');
    if (q != std::string_view::npos) {
      std::string base(text.substr(0, q));
      const bool angle = !base.empty() && base.front() == '<';
      if (angle) base += '>';
      Rewriter plain(ctx);
      auto b = plain.uri_text(base);
      if (!b) return std::unexpected(b.error());
      if (*b) {
        ctx.counters.removed(text.substr(q + 1));
        const auto h = lower(std::string(text.substr(q + 1)));
        const bool body = h.starts_with("body=") || h.find("&body=") != std::string::npos;
        return EmbeddedUri{std::move(*b), body ? "undecodable" : ""};
      }
    }
  }
  return EmbeddedUri{std::move(*u), std::move(rw.embed_outcome)};
}

Result<std::optional<std::string>> map_instance(std::string_view text, Context& ctx) {
  Rewriter rw{ctx};
  return rw.instance(text);
}

}  // namespace mcxanon::sip
