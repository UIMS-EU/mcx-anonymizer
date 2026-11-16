// SPDX-License-Identifier: GPL-3.0-or-later
#include "tls/handshake.hpp"

#include "sip/rewrite.hpp"
#include "tls/der.hpp"
#include "tls/limits.hpp"
#include "tls/x509.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <optional>

namespace mcxanon::tls {

namespace {

struct In {
  std::string_view b;
  std::size_t p = 0;
  bool ok = true;
  [[nodiscard]] bool done() const { return ok && p == b.size(); }
  std::uint32_t num(std::size_t n) {
    if (!ok || p + n > b.size()) {
      ok = false;
      return 0;
    }
    std::uint32_t v = 0;
    for (std::size_t i = 0; i < n; ++i) v = (v << 8) | static_cast<unsigned char>(b[p++]);
    return v;
  }
  std::string_view take(std::size_t n) {
    if (!ok || p + n > b.size()) {
      ok = false;
      return {};
    }
    const auto s = b.substr(p, n);
    p += n;
    return s;
  }
  std::string_view vec(std::size_t width) { return take(num(width)); }
};

void put(std::string& o, std::uint32_t v, std::size_t n) {
  for (std::size_t i = n; i-- > 0;) o.push_back(static_cast<char>((v >> (8 * i)) & 0xFF));
}
void put_vec(std::string& o, std::string_view v, std::size_t width) {
  put(o, static_cast<std::uint32_t>(v.size()), width);
  o.append(v);
}
std::string zeros(std::size_t n) { return std::string(n, '\0'); }

// RFC 8446 §4.1.3.
constexpr std::array<std::uint8_t, 32> kHrr{0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C,
                                            0x02, 0x1E, 0x65, 0xB8, 0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB,
                                            0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C};

Result<std::string> nonce(std::string_view v, Env& env) {
  if (v.empty()) return std::string();
  if (v.size() > 255) return zeros(v.size());
  auto b = env.sip.mapper.bytes(Category::nonce, ByteView(reinterpret_cast<const std::uint8_t*>(v.data()), v.size()));
  if (!b) return std::unexpected(b.error());
  return std::string(b->begin(), b->end());
}

// R20: a printable identity is opaque, a B-TID (RAND@BSF domain, TS 33.220 §4.4.7) keeps its form
// with the domain mapped; a binary identity (a resumption ticket) is zeroed.
Result<std::string> psk_identity(std::string_view v, Env& env) {
  const bool printable = !v.empty() && std::all_of(v.begin(), v.end(), [](char c) {
    return static_cast<unsigned char>(c) >= 0x21 && static_cast<unsigned char>(c) < 0x7f;
  });
  if (!printable) {
    Counters::bump(env.counters.psk_identities, "zeroed");
    return zeros(v.size());
  }
  if (const auto at = v.rfind('@'); at != std::string_view::npos && at > 0 && at + 1 < v.size()) {
    auto r = map_opaque(v.substr(0, at), env);
    if (!r) return std::unexpected(r.error());
    auto h = sip::map_host(v.substr(at + 1), env.sip);
    if (!h) return std::unexpected(h.error());
    if (*r && *h) {
      Counters::bump(env.counters.psk_identities, "b-tid");
      return **r + "@" + **h;
    }
  }
  auto r = map_opaque(v, env);
  if (!r) return std::unexpected(r.error());
  Counters::bump(env.counters.psk_identities, "opaque");
  return r->value_or(zeros(v.size()));
}

std::string_view ext_name(const TlsExtensionRule* r) { return r != nullptr ? std::string_view(r->name) : "unknown"; }

// One extension's data by its rule; nullopt: zero it.
Result<std::optional<std::string>> extension(const TlsExtensionRule* rule, std::string_view d, bool client, bool hrr, Env& env) {
  const auto action = rule != nullptr ? rule->action : TlsExtensionAction::zero;
  In in{d};
  std::string out;
  switch (action) {
    case TlsExtensionAction::keep: return std::optional<std::string>(std::string(d));
    case TlsExtensionAction::zero: return std::optional<std::string>{};
    case TlsExtensionAction::server_name: {
      if (d.empty()) return std::optional<std::string>(std::string());  // ServerHello acknowledgement
      In list{in.vec(2)};
      std::string names;
      while (list.ok && list.p < list.b.size()) {
        const auto type = list.num(1);
        const auto name = list.vec(2);
        if (!list.ok) break;
        put(names, type, 1);
        if (type == 0) {
          auto h = sip::map_host(name, env.sip);
          if (!h) return std::unexpected(h.error());
          ++env.counters.server_names;
          put_vec(names, h->value_or(zeros(name.size())), 2);
        } else {
          put_vec(names, zeros(name.size()), 2);
        }
      }
      if (!list.done() || !in.done()) return std::optional<std::string>{};
      put_vec(out, names, 2);
      return std::optional<std::string>(out);
    }
    case TlsExtensionAction::alpn: {
      In list{in.vec(2)};
      std::string names;
      while (list.ok && list.p < list.b.size()) {
        const auto n = list.vec(1);
        const bool known = std::find(rule->values.begin(), rule->values.end(), n) != rule->values.end();
        put_vec(names, known ? std::string(n) : zeros(n.size()), 1);
      }
      if (!list.done() || !in.done()) return std::optional<std::string>{};
      put_vec(out, names, 2);
      return std::optional<std::string>(out);
    }
    case TlsExtensionAction::key_share: {
      const auto entry = [&](In& x, std::string& o) {
        put(o, x.num(2), 2);
        put_vec(o, zeros(x.vec(2).size()), 2);
      };
      if (hrr) return d.size() == 2 ? std::optional<std::string>(std::string(d)) : std::optional<std::string>{};
      if (client) {
        In list{in.vec(2)};
        std::string shares;
        while (list.ok && list.p < list.b.size()) entry(list, shares);
        if (!list.done() || !in.done()) return std::optional<std::string>{};
        put_vec(out, shares, 2);
      } else {
        entry(in, out);
        if (!in.done()) return std::optional<std::string>{};
      }
      return std::optional<std::string>(out);
    }
    case TlsExtensionAction::pre_shared_key: {
      if (!client) return d.size() == 2 ? std::optional<std::string>(std::string(d)) : std::optional<std::string>{};
      In ids{in.vec(2)};
      std::string list;
      while (ids.ok && ids.p < ids.b.size()) {
        const auto id = ids.vec(2);
        ids.num(4);
        if (!ids.ok) break;
        auto m = psk_identity(id, env);
        if (!m) return std::unexpected(m.error());
        put_vec(list, *m, 2);
        put(list, 0, 4);  // obfuscated_ticket_age zeroed
      }
      In bl{in.vec(2)};
      std::string binders;
      while (bl.ok && bl.p < bl.b.size()) put_vec(binders, zeros(bl.vec(1).size()), 1);  // binders zeroed
      if (!ids.done() || !bl.done() || !in.done()) return std::optional<std::string>{};
      put_vec(out, list, 2);
      put_vec(out, binders, 2);
      return std::optional<std::string>(out);
    }
    case TlsExtensionAction::renegotiation_info: {
      const auto rc = in.vec(1);
      if (!in.done()) return std::optional<std::string>{};
      put_vec(out, zeros(rc.size()), 1);
      return std::optional<std::string>(out);
    }
    case TlsExtensionAction::status_request: {
      if (d.empty()) return std::optional<std::string>(std::string());
      out.push_back(d[0]);
      out += zeros(d.size() - 1);
      return std::optional<std::string>(out);
    }
    case TlsExtensionAction::certificate_authorities: {
      In list{in.vec(2)};
      std::string names;
      while (list.ok && list.p < list.b.size()) {
        const auto dn = list.vec(2);
        auto n = der::parse(dn);
        std::string w = zeros(dn.size());
        if (n) {
          auto ok = rewrite_name(*n, env);
          if (!ok) return std::unexpected(ok.error());
          if (*ok) w = der::write(*n);
        }
        put_vec(names, w, 2);
      }
      if (!list.done() || !in.done()) return std::optional<std::string>{};
      put_vec(out, names, 2);
      return std::optional<std::string>(out);
    }
  }
  return std::optional<std::string>{};
}

std::optional<KexFamily> family(const stream::Connection& conn, Env& env) {
  if (!conn.tls_suite) return std::nullopt;
  const auto* s = env.rules.find_suite(*conn.tls_suite);
  if (s == nullptr) return std::nullopt;
  return s->family;
}

bool tls12(const stream::Connection& conn) { return conn.tls_version.value_or(0x0303) >= 0x0303; }

// ServerKeyExchange params, after an optional PSK hint: ECDHE or DHE public values zeroed.
bool kex_params(In& in, std::string& o, KexFamily f) {
  if (f == KexFamily::ecdhe || f == KexFamily::ecdhe_psk) {
    const auto curve_type = in.num(1);
    put(o, curve_type, 1);
    if (curve_type != 3) return false;  // named_curve only (RFC 8422 §5.4)
    put(o, in.num(2), 2);
    put_vec(o, zeros(in.vec(1).size()), 1);
    return in.ok;
  }
  if (f == KexFamily::dhe || f == KexFamily::dhe_psk) {
    for (int i = 0; i < 3; ++i) put_vec(o, zeros(in.vec(2).size()), 2);  // dh_p, dh_g, dh_Ys
    return in.ok;
  }
  return true;
}

}  // namespace

Result<std::string> rewrite_hello(std::string_view body, bool client, stream::Connection& conn, Env& env) {
  In in{body};
  std::string o;
  const auto version = in.num(2);
  put(o, version, 2);
  const auto random = in.take(32);
  const auto sid = in.vec(1);
  if (!in.ok) return zeros(body.size());
  const bool hrr = !client && std::equal(random.begin(), random.end(), kHrr.begin(), kHrr.end(),
                                         [](char a, std::uint8_t b) { return static_cast<std::uint8_t>(a) == b; });
  if (hrr) {
    o.append(random);
  } else {
    // RFC 8446 §4.1.3: the downgrade sentinels in the last 8 octets of a ServerHello random stay;
    // only the 24 octets before them take a pseudonym, so that the mapping holds what the output
    // shows (reveal).
    const bool sentinel = !client && (random.substr(24) == std::string_view("DOWNGRD\x01", 8) ||
                                      random.substr(24) == std::string_view("DOWNGRD\x00", 8));
    auto r = nonce(sentinel ? random.substr(0, 24) : random, env);
    if (!r) return std::unexpected(r.error());
    o += *r;
    if (sentinel) o.append(random.substr(24));
  }
  auto s = nonce(sid, env);
  if (!s) return std::unexpected(s.error());
  put_vec(o, *s, 1);
  if (client) {
    put_vec(o, in.vec(2), 2);  // cipher_suites
    put_vec(o, in.vec(1), 1);  // compression_methods
  } else {
    const auto suite = in.num(2);
    put(o, suite, 2);
    put(o, in.num(1), 1);
    conn.tls_suite = static_cast<std::uint16_t>(suite);
    conn.tls_version = static_cast<std::uint16_t>(version);
  }
  if (!in.ok) return zeros(body.size());
  if (in.p == body.size()) return o;  // no extensions
  In exts{in.vec(2)};
  if (!in.done()) return zeros(body.size());
  std::string list;
  std::size_t n = 0;
  while (exts.ok && exts.p < exts.b.size()) {
    const auto type = static_cast<std::uint16_t>(exts.num(2));
    const auto data = exts.vec(2);
    if (!exts.ok || ++n > 256) return zeros(body.size());
    const auto* rule = env.rules.find_extension(type);
    auto d = extension(rule, data, client, hrr, env);
    if (!d) return std::unexpected(d.error());
    Counters::bump(env.counters.extensions, ext_name(rule), !*d ? "zeroed" : **d == data ? "kept" : "rewritten");
    // supported_versions in a ServerHello selects the version (RFC 8446 §4.2.1).
    if (!client && type == 43 && data.size() == 2 && *d) {
      conn.tls_version = static_cast<std::uint16_t>((static_cast<unsigned char>(data[0]) << 8) | static_cast<unsigned char>(data[1]));
    }
    put(list, type, 2);
    put_vec(list, d->value_or(zeros(data.size())), 2);
  }
  if (!exts.done()) return zeros(body.size());
  put_vec(o, list, 2);
  return o;
}

Result<std::string> rewrite_handshake(std::uint8_t type, std::string_view body, stream::Connection& conn, Env& env) {
  const auto* rule = env.rules.find_handshake(type);
  Counters::bump(env.counters.handshakes, rule != nullptr ? rule->name : "unknown");
  const auto action = rule != nullptr ? rule->action : TlsHandshakeAction::zero_body;
  std::string b;
  In in{body};
  switch (action) {
    case TlsHandshakeAction::keep: b.assign(body); break;
    case TlsHandshakeAction::zero_body: b = zeros(body.size()); break;
    case TlsHandshakeAction::hello: {
      auto h = rewrite_hello(body, type == 1, conn, env);
      if (!h) return std::unexpected(h.error());
      b = std::move(*h);
      break;
    }
    case TlsHandshakeAction::certificate: {
      In list{in.vec(3)};
      std::string certs;
      std::size_t n = 0;
      while (list.ok && list.p < list.b.size() && ++n <= kMaxChain) {
        const auto c = list.vec(3);
        if (!list.ok) break;
        auto r = rewrite_certificate(c, env);
        if (!r) return std::unexpected(r.error());
        if (!*r) Counters::bump(env.counters.certificates_zeroed, "malformed");
        put_vec(certs, r->value_or(zeros(c.size())), 3);
      }
      if (!list.done() || !in.done()) {
        b = zeros(body.size());
        Counters::bump(env.counters.certificates_zeroed, "message");
        break;
      }
      put_vec(b, certs, 3);
      break;
    }
    case TlsHandshakeAction::certificate_request: {
      put_vec(b, in.vec(1), 1);  // certificate_types
      put_vec(b, in.vec(2), 2);  // supported_signature_algorithms (TLS 1.2)
      In names{in.vec(2)};
      std::string out;
      while (names.ok && names.p < names.b.size()) {
        const auto dn = names.vec(2);
        auto n = der::parse(dn);
        std::string w = zeros(dn.size());
        if (n) {
          auto ok = rewrite_name(*n, env);
          if (!ok) return std::unexpected(ok.error());
          if (*ok) w = der::write(*n);
        }
        put_vec(out, w, 2);
      }
      if (!names.done() || !in.done()) {
        b = zeros(body.size());
        break;
      }
      put_vec(b, out, 2);
      break;
    }
    case TlsHandshakeAction::server_key_exchange: {
      const auto f = family(conn, env);
      bool ok = f.has_value() && *f != KexFamily::rsa && *f != KexFamily::tls13;
      if (ok && (*f == KexFamily::psk || *f == KexFamily::ecdhe_psk || *f == KexFamily::dhe_psk || *f == KexFamily::rsa_psk)) {
        auto h = psk_identity(in.vec(2), env);  // psk_identity_hint (RFC 4279 §2)
        if (!h) return std::unexpected(h.error());
        put_vec(b, *h, 2);
      }
      ok = ok && in.ok && kex_params(in, b, *f);
      if (ok && (*f == KexFamily::ecdhe || *f == KexFamily::dhe) && in.p < body.size()) {
        if (tls12(conn)) put(b, in.num(2), 2);  // SignatureAndHashAlgorithm
        put_vec(b, zeros(in.vec(2).size()), 2);
      }
      if (!ok || !in.done()) b = zeros(body.size());
      break;
    }
    case TlsHandshakeAction::client_key_exchange: {
      const auto f = family(conn, env);
      bool ok = f.has_value() && *f != KexFamily::tls13;
      if (ok && (*f == KexFamily::psk || *f == KexFamily::ecdhe_psk || *f == KexFamily::dhe_psk || *f == KexFamily::rsa_psk)) {
        auto h = psk_identity(in.vec(2), env);  // psk_identity (RFC 4279 §2)
        if (!h) return std::unexpected(h.error());
        put_vec(b, *h, 2);
      }
      if (ok) {
        switch (*f) {
          case KexFamily::ecdhe:
          case KexFamily::ecdhe_psk: put_vec(b, zeros(in.vec(1).size()), 1); break;
          case KexFamily::dhe:
          case KexFamily::dhe_psk:
          case KexFamily::rsa:
          case KexFamily::rsa_psk: put_vec(b, zeros(in.vec(2).size()), 2); break;
          default: break;
        }
      }
      if (!ok || !in.done()) b = zeros(body.size());
      break;
    }
    case TlsHandshakeAction::certificate_verify: {
      if (tls12(conn)) put(b, in.num(2), 2);
      put_vec(b, zeros(in.vec(2).size()), 2);
      if (!in.done()) b = zeros(body.size());
      break;
    }
    case TlsHandshakeAction::new_session_ticket: {
      put(b, in.num(4), 4);
      put_vec(b, zeros(in.vec(2).size()), 2);
      if (!in.done()) b = zeros(body.size());
      break;
    }
  }
  std::string out;
  put(out, type, 1);
  put(out, static_cast<std::uint32_t>(b.size()), 3);
  return out + b;
}

}  // namespace mcxanon::tls
