// SPDX-License-Identifier: GPL-3.0-or-later
#include "scan/walker/web_harvest.hpp"

#include "scan/walker/hpack_strings.hpp"
#include "scan/walker/mikey_harvest.hpp"
#include "scan/walker/walker.hpp"

#include <algorithm>
#include <array>
#include <cctype>

namespace mcxanon::scan::detail {

namespace {

constexpr std::size_t kCarry = 4096;
constexpr std::size_t kMaxFrames = 1u << 20;
constexpr std::size_t kMaxValue = 16384;

// OAuth/OIDC parameter, JSON member and JWT claim names whose values identify or authenticate
// (RFC 6749, RFC 7636, RFC 7662, RFC 7519, TS 33.180 Annex B): the scanner's own list.
constexpr std::array<std::string_view, 26> kSecretNames{
    "password",      "code",         "code_verifier", "client_secret", "refresh_token", "access_token", "id_token",
    "token",         "subject_token", "assertion",    "client_id",     "username",      "state",        "sub",
    "mcptt_id",      "mcvideo_id",   "mcdata_id",     "mcrec_id",      "jti",           "nonce",        "code_challenge",
    "kid",           "azp",          "sid",           "redirect_uri",  "client_assertion"};

bool secret_name(std::string_view n) { return std::find(kSecretNames.begin(), kSecretNames.end(), n) != kSecretNames.end(); }

bool ieq(std::string_view a, std::string_view b) {
  return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), [](char x, char y) {
           return std::tolower(static_cast<unsigned char>(x)) == std::tolower(static_cast<unsigned char>(y));
         });
}

std::string_view trim(std::string_view s) {
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '"')) s.remove_prefix(1);
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '"' || s.back() == '\r')) s.remove_suffix(1);
  return s;
}

bool b64url_char(char c) { return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '-' || c == '_'; }

// "name": "value" pairs of a JSON text, for the listed names (no full parse: syntax only).
template <class F>
void json_strings(std::string_view t, F&& each) {
  std::size_t p = 0;
  while ((p = t.find('"', p)) != std::string_view::npos) {
    const auto e = t.find('"', p + 1);
    if (e == std::string_view::npos) return;
    const auto name = t.substr(p + 1, e - p - 1);
    std::size_t q = e + 1;
    while (q < t.size() && (t[q] == ' ' || t[q] == '\t' || t[q] == '\n' || t[q] == '\r')) ++q;
    if (q < t.size() && t[q] == ':') {
      ++q;
      while (q < t.size() && (t[q] == ' ' || t[q] == '\t' || t[q] == '\n' || t[q] == '\r')) ++q;
      if (q < t.size() && t[q] == '"') {
        std::string v;
        std::size_t r = q + 1;
        for (; r < t.size() && t[r] != '"' && v.size() < kMaxValue; ++r) {
          if (t[r] == '\\' && r + 1 < t.size()) ++r;
          v.push_back(t[r]);
        }
        each(name, std::string_view(v));
        p = r + 1;
        continue;
      }
    }
    p = e + 1;
  }
}

}  // namespace

std::optional<std::string> b64url_decode(std::string_view s) {
  std::string out;
  std::uint32_t acc = 0;
  int bits = 0;
  for (char c : s) {
    int v = 0;
    if (c >= 'A' && c <= 'Z') v = c - 'A';
    else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
    else if (c >= '0' && c <= '9') v = c - '0' + 52;
    else if (c == '-' || c == '+') v = 62;
    else if (c == '_' || c == '/') v = 63;
    else if (c == '=') break;
    else return std::nullopt;
    acc = (acc << 6) | static_cast<std::uint32_t>(v);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<char>((acc >> bits) & 0xFF));
    }
  }
  return out;
}

std::optional<std::string> pct_decode(std::string_view s) {
  std::string out;
  for (std::size_t i = 0; i < s.size(); ++i) {
    if (s[i] == '%' && i + 2 < s.size() && std::isxdigit(static_cast<unsigned char>(s[i + 1])) != 0 &&
        std::isxdigit(static_cast<unsigned char>(s[i + 2])) != 0) {
      out.push_back(static_cast<char>(std::stoi(std::string(s.substr(i + 1, 2)), nullptr, 16)));
      i += 2;
    } else {
      out.push_back(s[i] == '+' ? ' ' : s[i]);
    }
  }
  return out;
}

void WebHarvest::add(std::string_view v, const char* what) {
  v = trim(v);
  if (v.size() < 4 || v.size() > kMaxValue) return;
  // An IPv4 literal: a binary address token unless the anonymiser keeps it (loopback, ...).
  {
    std::array<std::uint8_t, 4> a{};
    int parts = 0;
    unsigned cur = 0;
    bool ok = !v.empty() && v.size() <= 15;
    std::size_t digits = 0;
    for (char c : v) {
      if (!ok) break;
      if (c >= '0' && c <= '9') {
        cur = cur * 10 + static_cast<unsigned>(c - '0');
        ok = ++digits <= 3 && cur <= 255;
      } else if (c == '.' && digits > 0 && parts < 3) {
        a[static_cast<std::size_t>(parts++)] = static_cast<std::uint8_t>(cur);
        cur = 0;
        digits = 0;
      } else {
        ok = false;
      }
    }
    if (ok && parts == 3 && digits > 0) {
      a[3] = static_cast<std::uint8_t>(cur);
      if (keeps_ipv4(a.data())) return;
      if (seen_.insert(std::string(v)).second) {
        tokens_.push_back(Token{TokenCategory::ipv4, std::vector<std::uint8_t>(a.begin(), a.end()),
                                std::string("input:web-ipv4#") + std::to_string(++n_)});
      }
      return;
    }
  }
  if (v.front() == '[' || std::count(v.begin(), v.end(), ':') >= 2) return;  // IPv6 literals: L3 harvest
  if (!seen_.insert(std::string(v)).second) return;
  tokens_.push_back(Token{TokenCategory::string, std::vector<std::uint8_t>(v.begin(), v.end()),
                          std::string("input:web-") + what + "#" + std::to_string(++n_)});
}

// sip:user@host;params, tel:+..., user@host, or a bare value.
void WebHarvest::identity(std::string_view v) {
  v = trim(v);
  if (const auto c = v.find(':'); c != std::string_view::npos && c < 6) v.remove_prefix(c + 1);
  v = v.substr(0, v.find_first_of(";?>"));
  if (const auto at = v.find('@'); at != std::string_view::npos) {
    add(v.substr(0, at), "user");
    add(v.substr(at + 1), "host");
    return;
  }
  add(v, "identity");
}

void WebHarvest::token(std::string_view t) {
  t = trim(t);
  add(t, "token");
  // A JWS compact JWT: its identity claims and its signature (RFC 7515 §7.1, RFC 7519).
  const auto d1 = t.find('.');
  const auto d2 = d1 == std::string_view::npos ? d1 : t.find('.', d1 + 1);
  if (d2 == std::string_view::npos) return;
  if (const auto claims = b64url_decode(t.substr(d1 + 1, d2 - d1 - 1))) {
    json_strings(*claims, [&](std::string_view n, std::string_view v) {
      if (secret_name(n)) identity(v);
    });
  }
  add(t.substr(d2 + 1), "jwt-signature");
}

void WebHarvest::params(std::string_view q) {
  std::size_t start = 0;
  while (start < q.size()) {
    const auto amp = q.find('&', start);
    const auto pair = q.substr(start, amp == std::string_view::npos ? std::string_view::npos : amp - start);
    start = amp == std::string_view::npos ? q.size() : amp + 1;
    const auto eq = pair.find('=');
    if (eq == std::string_view::npos) continue;
    const auto name = pct_decode(pair.substr(0, eq));
    const auto value = pct_decode(pair.substr(eq + 1));
    if (!name || !value || !secret_name(*name)) continue;
    if (*name == "access_token" || *name == "id_token" || *name == "token" || *name == "refresh_token" ||
        *name == "subject_token" || *name == "assertion") {
      token(*value);
    } else if (value->find("://") != std::string::npos) {
      target(*value);  // a URL: its host and identity segments
    } else {
      identity(*value);
      add(*value, "param");
    }
  }
}

void WebHarvest::target(std::string_view t) {
  if (const auto s = t.find("://"); s != std::string_view::npos) {
    t.remove_prefix(s + 3);
    const auto slash = t.find('/');
    const auto auth = t.substr(0, slash);
    const auto at = auth.rfind('@');
    if (at != std::string_view::npos) add(auth.substr(0, at), "userinfo");
    const auto host = at == std::string_view::npos ? auth : auth.substr(at + 1);
    add(host.substr(0, host.rfind(':') == std::string_view::npos ? host.size() : host.rfind(':')), "host");
    t = slash == std::string_view::npos ? std::string_view() : t.substr(slash);
  }
  const auto q = t.find('?');
  if (q != std::string_view::npos) params(t.substr(q + 1));
  std::string_view path = t.substr(0, q);
  std::size_t start = 0;
  while (start < path.size()) {
    const auto slash = path.find('/', start);
    const auto seg = path.substr(start, slash == std::string_view::npos ? std::string_view::npos : slash - start);
    start = slash == std::string_view::npos ? path.size() : slash + 1;
    const auto d = pct_decode(seg);
    if (d && (d->find('@') != std::string::npos || d->starts_with("sip:") || d->starts_with("tel:"))) identity(*d);
  }
}

void WebHarvest::header(std::string_view name, std::string_view value) {
  if (ieq(name, "host") || ieq(name, ":authority")) {
    const auto c = value.rfind(':');
    add(c != std::string_view::npos && value.find(']') == std::string_view::npos ? value.substr(0, c) : value, "host");
  } else if (ieq(name, ":path")) {
    target(value);
  } else if (ieq(name, "authorization") || ieq(name, "proxy-authorization")) {
    const auto sp = value.find(' ');
    const auto scheme = value.substr(0, sp);
    const auto rest = sp == std::string_view::npos ? std::string_view() : trim(value.substr(sp + 1));
    if (ieq(scheme, "basic")) {
      if (auto d = decode_base64(rest)) {
        const std::string up(d->begin(), d->end());
        const auto colon = up.find(':');
        add(up.substr(0, colon), "basic-user");
        if (colon != std::string::npos) add(up.substr(colon + 1), "basic-password");
      }
      add(rest, "basic");
    } else if (ieq(scheme, "bearer")) {
      token(rest);
    } else {
      for (std::string_view key : {"username=", "response=", "cnonce=", "nonce=", "opaque="}) {
        const auto k = rest.find(key);
        if (k == std::string_view::npos) continue;
        const auto v = rest.substr(k + key.size());
        add(v.substr(0, v.find(',')), "digest");
      }
    }
  } else if (ieq(name, "cookie") || ieq(name, "set-cookie")) {
    std::size_t start = 0;
    while (start < value.size()) {
      const auto semi = value.find(';', start);
      const auto pair = trim(value.substr(start, semi == std::string_view::npos ? std::string_view::npos : semi - start));
      start = semi == std::string_view::npos ? value.size() : semi + 1;
      const auto eq = pair.find('=');
      if (eq == std::string_view::npos) continue;
      if (ieq(pair.substr(0, eq), "domain")) add(trim(pair.substr(eq + 1)), "cookie-domain");
      else if (!ieq(pair.substr(0, eq), "path") && !ieq(pair.substr(0, eq), "expires") && !ieq(pair.substr(0, eq), "max-age")) add(pair.substr(eq + 1), "cookie");
      if (ieq(name, "set-cookie")) break;  // attributes after the pair carry no value of their own
    }
  } else if (ieq(name, "x-3gpp-asserted-identity") || ieq(name, "x-3gpp-intended-identity")) {
    identity(value);
  } else if (ieq(name, "location") || ieq(name, "content-location")) {
    target(value);
  }
}

void WebHarvest::text(std::string_view t) {
  std::size_t p = 0;
  while (p < t.size()) {
    auto e = t.find('\n', p);
    if (e == std::string_view::npos) e = t.size();
    std::string_view line = t.substr(p, e - p);
    p = e + 1;
    if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
    // A request line: METHOD SP target SP HTTP/x.y
    if (const auto sp1 = line.find(' '); sp1 != std::string_view::npos) {
      const auto sp2 = line.find(' ', sp1 + 1);
      if (sp2 != std::string_view::npos && line.substr(sp2 + 1).starts_with("HTTP/")) {
        target(line.substr(sp1 + 1, sp2 - sp1 - 1));
        continue;
      }
    }
    const auto colon = line.find(':');
    if (colon != std::string_view::npos && colon > 0 && line.find(' ') > colon) {
      header(line.substr(0, colon), trim(line.substr(colon + 1)));
    }
    if (line.find('=') != std::string_view::npos && line.find(' ') == std::string_view::npos) params(line);
  }
  json_strings(t, [&](std::string_view n, std::string_view v) {
    if (!secret_name(n)) return;
    if (n == "access_token" || n == "id_token" || n == "refresh_token" || n == "token") token(v);
    else identity(v);
  });
  // JWTs anywhere in the text.
  for (std::size_t q = t.find("eyJ"); q != std::string_view::npos; q = t.find("eyJ", q + 3)) {
    std::size_t r = q;
    int dots = 0;
    while (r < t.size() && (b64url_char(t[r]) || (t[r] == '.' && dots < 2))) {
      if (t[r] == '.') ++dots;
      ++r;
    }
    if (dots == 2) token(t.substr(q, r - q));
  }
}

void WebHarvest::h2_frames(Dir& d) {
  std::size_t p = 0;
  while (d.frames.size() >= p + 9) {
    const auto u = [&](std::size_t i) { return static_cast<std::size_t>(static_cast<unsigned char>(d.frames[i])); };
    const std::size_t len = (u(p) << 16) | (u(p + 1) << 8) | u(p + 2);
    if (len > kMaxFrames) {
      d.h2 = false;
      d.frames.clear();
      return;
    }
    if (d.frames.size() < p + 9 + len) break;
    const auto type = u(p + 3);
    const auto flags = u(p + 4);
    std::string_view pl = std::string_view(d.frames).substr(p + 9, len);
    if ((type == 0 || type == 1) && (flags & 0x8) != 0 && !pl.empty()) {
      const std::size_t pad = static_cast<unsigned char>(pl[0]);
      pl = pad + 1 <= pl.size() ? pl.substr(1, pl.size() - 1 - pad) : std::string_view();
    }
    if (type == 1 && (flags & 0x20) != 0) pl = pl.size() >= 5 ? pl.substr(5) : std::string_view();
    if (type == 0) text(pl);
    if (type == 1 || type == 9) {
      d.block.append(pl);
      if ((flags & 0x4) != 0) {
        for (const auto& l : hpack_literals(d.block)) {
          header(l.name, l.value);
          if (l.name.empty()) add(l.value, "hpack");  // a name from the dynamic table: harvested
        }
        d.block.clear();
      }
    }
    p += 9 + len;
  }
  d.frames.erase(0, p);
}

namespace {
std::size_t be16(std::string_view b, std::size_t p) {
  return (static_cast<std::size_t>(static_cast<unsigned char>(b[p])) << 8) | static_cast<unsigned char>(b[p + 1]);
}
std::size_t be24(std::string_view b, std::size_t p) {
  return (static_cast<std::size_t>(static_cast<unsigned char>(b[p])) << 16) | be16(b, p + 1);
}
}  // namespace

void WebHarvest::add_bytes(std::string_view v, const char* what) {
  if (v.size() < 4 || v.size() > kMaxValue) return;
  if (std::all_of(v.begin(), v.end(), [&](char c) { return c == v.front(); })) return;  // degenerate
  std::string key = "\x01" + std::string(v);
  if (!seen_.insert(key).second) return;
  tokens_.push_back(Token{TokenCategory::bytes, std::vector<std::uint8_t>(v.begin(), v.end()),
                          std::string("input:web-") + what + "#" + std::to_string(++n_)});
}

// Every string, name and value of a DER tree (X.690 TLV, definite lengths), bounded.
void WebHarvest::der_values(std::string_view b, int depth) {
  std::size_t p = 0;
  int first_integer = depth == 2 ? 1 : 0;  // the serial number is the first INTEGER of tbsCertificate
  while (p + 2 <= b.size() && depth < 32) {
    const auto tag = static_cast<unsigned char>(b[p++]);
    std::size_t len = static_cast<unsigned char>(b[p++]);
    if (len & 0x80) {
      const std::size_t k = len & 0x7F;
      if (k == 0 || k > 3 || p + k > b.size()) return;
      len = 0;
      for (std::size_t i = 0; i < k; ++i) len = (len << 8) | static_cast<unsigned char>(b[p++]);
    }
    if (p + len > b.size()) return;
    const auto v = b.substr(p, len);
    p += len;
    if (tag & 0x20) {
      der_values(v, depth + 1);
      continue;
    }
    switch (tag) {
      case 0x0c: case 0x13: case 0x14: case 0x16: case 0x1a:  // strings
      case 0x81: case 0x82: case 0x86:                         // rfc822Name, dNSName, URI
        identity(v);
        add(v, "x509");
        break;
      case 0x1e: {  // BMPString
        std::string a;
        for (std::size_t i = 1; i < v.size(); i += 2) a.push_back(v[i]);
        add(a, "x509");
        break;
      }
      case 0x87:  // iPAddress
        if (v.size() == 4 && !keeps_ipv4(reinterpret_cast<const std::uint8_t*>(v.data()))) {
          tokens_.push_back(Token{TokenCategory::ipv4, std::vector<std::uint8_t>(v.begin(), v.end()),
                                  std::string("input:web-x509-ip#") + std::to_string(++n_)});
        }
        break;
      case 0x02:
        if (first_integer-- == 1) add_bytes(v.size() > 1 && v[0] == 0 ? v.substr(1) : v, "x509-serial");
        break;
      case 0x04:
      case 0x80: {  // key identifiers; an OCTET STRING holding DER is an extension value (walked)
        const auto t0 = v.empty() ? 0 : static_cast<unsigned char>(v[0]);
        const bool nested = tag == 0x04 && (t0 == 0x30 || t0 == 0x04 || t0 == 0x03 || t0 == 0x02 || t0 == 0x06 ||
                                            t0 == 0x01 || (t0 & 0xE0) == 0xA0);
        if (nested) {
          der_values(v, depth + 1);
        } else if (v.size() >= 8 && v.size() <= 64) {
          add_bytes(v, "x509-key-id");
        }
        break;
      }
      case 0x03:  // public keys and signatures
        if (v.size() > 8) add_bytes(v.substr(1), "x509-bits");
        break;
      default: break;
    }
  }
}

void WebHarvest::tls_message(std::uint8_t type, std::string_view body) {
  if ((type == 1 || type == 2) && body.size() >= 35) {
    // The HelloRetryRequest random is a constant the output keeps (RFC 8446 §4.1.3).
    static constexpr std::string_view kHrr =
        "\xCF\x21\xAD\x74\xE5\x9A\x61\x11\xBE\x1D\x8C\x02\x1E\x65\xB8\x91"
        "\xC2\xA2\x11\x16\x7A\xBB\x8C\x5E\x07\x9E\x09\xE2\xC8\xA8\x33\x9C";
    if (body.substr(2, 32) != kHrr) add_bytes(body.substr(2, 32), "tls-random");
    const std::size_t sid = static_cast<unsigned char>(body[34]);
    if (35 + sid > body.size()) return;
    add_bytes(body.substr(35, sid), "tls-session-id");
    std::size_t p = 35 + sid;
    if (type == 1) {
      if (p + 2 > body.size()) return;
      p += 2 + be16(body, p);
      if (p + 1 > body.size()) return;
      p += 1 + std::size_t{static_cast<unsigned char>(body[p])};
    } else {
      p += 3;
    }
    if (p + 2 > body.size()) return;
    const std::size_t end = std::min(body.size(), p + 2 + be16(body, p));
    p += 2;
    while (p + 4 <= end) {
      const auto et = be16(body, p);
      const auto el = be16(body, p + 2);
      const auto ed = body.substr(p + 4, std::min(el, end - p - 4));
      p += 4 + el;
      if (et == 0 && ed.size() > 5) add(ed.substr(5), "tls-sni");
      if (et == 41 && type == 1 && ed.size() > 4) {
        const auto il = be16(ed, 2);
        if (4 + il <= ed.size()) {
          const auto id = ed.substr(4, il);
          identity(id);
          add(id, "tls-psk");
          add_bytes(id, "tls-psk");
        }
      }
      if (et == 51 && ed.size() > 8) add_bytes(ed.substr(type == 1 ? 6 : 4), "tls-key-share");
    }
    return;
  }
  if (type == 11 && body.size() > 6) {  // Certificate: 24-bit length-prefixed DER certificates
    std::size_t p = 3;
    while (p + 3 <= body.size()) {
      const std::size_t l = be24(body, p);
      if (p + 3 + l > body.size()) return;
      der_values(body.substr(p + 3, l), 0);
      p += 3 + l;
    }
    return;
  }
  if (type == 12 || type == 16) {  // key exchange: identities, hints and public values
    if (body.size() > 2) {
      const auto l = be16(body, 0);
      if (2 + l <= body.size()) {
        identity(body.substr(2, l));
        add(body.substr(2, l), "tls-psk");
      }
    }
    add_bytes(body, "tls-kex");
    return;
  }
  if (type == 13) der_values(body, 4);  // CertificateRequest names
}

void WebHarvest::tls_records(Dir& d) {
  std::size_t p = 0;
  while (d.records.size() >= p + 5) {
    const auto type = static_cast<unsigned char>(d.records[p]);
    const std::size_t len = be16(d.records, p + 3);
    if (type < 20 || type > 24 || d.records[p + 1] != 3 || len > 18432) {
      d.tls = 0;
      d.records.clear();
      return;
    }
    if (d.records.size() < p + 5 + len) break;
    if (type == 20) d.protected_ = true;  // a TLS 1.3 compatibility CCS ends the harvest too: fewer tokens, never more
    if (type == 22 && !d.protected_) d.hs.append(d.records, p + 5, len);
    p += 5 + len;
  }
  d.records.erase(0, p);
  std::size_t q = 0;
  while (d.hs.size() >= q + 4) {
    const std::size_t l = be24(d.hs, q + 1);
    if (d.hs.size() < q + 4 + l) break;
    tls_message(static_cast<std::uint8_t>(d.hs[q]), std::string_view(d.hs).substr(q + 4, l));
    q += 4 + l;
  }
  d.hs.erase(0, q);
  if (d.hs.size() > kMaxFrames) d.hs.clear();
}

void WebHarvest::feed(std::span<const std::uint8_t> payload, const std::vector<std::uint8_t>& direction) {
  if (payload.empty()) return;
  auto& d = dirs_[direction];
  const std::string_view bytes(reinterpret_cast<const char*>(payload.data()), payload.size());
  if (d.tls == -1) {
    const auto t = static_cast<unsigned char>(bytes[0]);
    d.tls = t >= 20 && t <= 23 && bytes.size() >= 3 && bytes[1] == 3 ? 1 : 0;
  }
  if (d.tls == 1) {
    d.records.append(bytes);
    if (d.records.size() > kMaxFrames) {
      d.records.clear();
      d.tls = 0;
      return;
    }
    tls_records(d);
    return;
  }
  if (!d.h2) {
    std::string all = d.carry + std::string(bytes);
    constexpr std::string_view kPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    if (const auto pre = all.find(kPreface); pre != std::string::npos) {
      text(std::string_view(all).substr(0, pre));
      d.h2 = true;
      d.frames = all.substr(pre + kPreface.size());
      d.carry.clear();
    } else if (const auto up = all.find("101 Switching Protocols"); up != std::string::npos &&
               all.find("h2c", up) != std::string::npos && all.find("\r\n\r\n", up) != std::string::npos) {
      const auto end = all.find("\r\n\r\n", up) + 4;
      text(std::string_view(all).substr(0, end));
      d.h2 = true;
      d.frames = all.substr(end);
      d.carry.clear();
    } else if (all.size() >= 9 && all[3] == 4 && all[0] == 0 && all[5] == 0 && all[6] == 0 && all[7] == 0 &&
               all[8] == 0 && d.carry.empty()) {
      d.h2 = true;  // the server side of a prior-knowledge h2c connection starts with SETTINGS
      d.frames = all;
    } else {
      text(all);
      d.carry = all.size() > kCarry ? all.substr(all.size() - kCarry) : all;
      return;
    }
  } else {
    d.frames.append(bytes);
  }
  if (d.frames.size() > kMaxFrames) {
    d.frames.clear();
    d.h2 = false;
    return;
  }
  h2_frames(d);
}

std::vector<Token> WebHarvest::take() { return std::exchange(tokens_, {}); }

}  // namespace mcxanon::scan::detail
