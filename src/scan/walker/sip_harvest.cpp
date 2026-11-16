// SPDX-License-Identifier: GPL-3.0-or-later
#include "scan/walker/sip_harvest.hpp"

#include "scan/walker/mikey_carriers.hpp"
#include "scan/walker/mikey_harvest.hpp"

#include "scan/walker/walker.hpp"
#include "scan/walker/xml_harvest.hpp"

#include <algorithm>
#include <array>
#include <optional>
#include <cctype>

namespace mcxanon::scan::detail {
namespace {

constexpr std::size_t kCarry = 4096;           // per TCP direction
constexpr std::size_t kMaxText = 1024 * 1024;  // per payload
constexpr std::size_t kMaxDirections = 65536;
constexpr std::size_t kMaxToken = 256;
constexpr std::size_t kMaxTokensPerPayload = 1024;

// Access-network information parameters that carry cell, node or location identities
// (RFC 7315 §5.4; TS 24.229 §7.2A.4.2).
constexpr std::array<std::string_view, 15> kAccessInfo{
    "cgi-3gpp", "utran-cell-id-3gpp", "utran-sai-3gpp", "i-wlan-node-id", "dsl-location", "eth-location",
    "fiber-location", "gstn-location", "ci-3gpp2", "ci-3gpp2-femto", "dvb-rcs2-node-id", "operator-specific-gi",
    "u2n-relay-id", "ue-local-ip-address", "epdg-ip-address"};

std::string lower(std::string_view s) {
  std::string o(s);
  for (auto& c : o) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return o;
}

bool is_digit(char c) { return c >= '0' && c <= '9'; }
bool is_hex(char c) { return std::isxdigit(static_cast<unsigned char>(c)) != 0; }

std::string_view trim(std::string_view s) {
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.remove_suffix(1);
  return s;
}

// End of a URI or parameter token: whitespace, quotes, brackets, separators.
std::size_t token_end(std::string_view s, std::size_t i, std::string_view stop) {
  while (i < s.size()) {
    const auto c = static_cast<unsigned char>(s[i]);
    if (c <= 0x20 || c >= 0x7F || stop.find(static_cast<char>(c)) != std::string_view::npos) break;
    ++i;
  }
  return i;
}

std::optional<std::array<std::uint8_t, 4>> v4(std::string_view s) {
  std::array<std::uint8_t, 4> a{};
  std::size_t i = 0;
  for (int part = 0; part < 4; ++part) {
    unsigned v = 0;
    std::size_t start = i;
    while (i < s.size() && is_digit(s[i]) && i - start < 3) v = v * 10 + static_cast<unsigned>(s[i++] - '0');
    if (i == start || v > 255) return std::nullopt;
    a[static_cast<std::size_t>(part)] = static_cast<std::uint8_t>(v);
    if (part < 3) {
      if (i >= s.size() || s[i] != '.') return std::nullopt;
      ++i;
    }
  }
  if (i != s.size()) return std::nullopt;
  return a;
}

// RFC 4291-style text: hex groups, one "::", an optional dotted IPv4 tail.
std::optional<std::array<std::uint8_t, 16>> v6(std::string_view s) {
  if (s.starts_with('[') && s.ends_with(']')) s = s.substr(1, s.size() - 2);
  if (s.find(':') == std::string_view::npos || s.size() > 45) return std::nullopt;
  std::vector<unsigned> head, tail;
  bool gap = false;
  std::size_t i = 0;
  if (s.starts_with("::")) {
    gap = true;
    i = 2;
  }
  while (i < s.size()) {
    std::size_t j = i;
    while (j < s.size() && s[j] != ':') ++j;
    const auto g = s.substr(i, j - i);
    auto& out = gap ? tail : head;
    if (g.find('.') != std::string_view::npos) {
      auto a = v4(g);
      if (!a || j != s.size()) return std::nullopt;
      out.push_back((unsigned{(*a)[0]} << 8) | (*a)[1]);
      out.push_back((unsigned{(*a)[2]} << 8) | (*a)[3]);
      i = j;
      break;
    }
    if (g.empty() || g.size() > 4 || !std::all_of(g.begin(), g.end(), is_hex)) return std::nullopt;
    out.push_back(static_cast<unsigned>(std::stoul(std::string(g), nullptr, 16)));
    if (j == s.size()) {
      i = j;
      break;
    }
    if (j + 1 < s.size() && s[j + 1] == ':') {
      if (gap) return std::nullopt;
      gap = true;
      i = j + 2;
    } else {
      i = j + 1;
    }
  }
  const std::size_t n = head.size() + tail.size();
  if (gap ? n > 7 : n != 8) return std::nullopt;
  std::array<unsigned, 8> g{};
  for (std::size_t k = 0; k < head.size(); ++k) g[k] = head[k];
  for (std::size_t k = 0; k < tail.size(); ++k) g[8 - tail.size() + k] = tail[k];
  std::array<std::uint8_t, 16> a{};
  for (std::size_t k = 0; k < 8; ++k) {
    a[2 * k] = static_cast<std::uint8_t>(g[k] >> 8);
    a[2 * k + 1] = static_cast<std::uint8_t>(g[k]);
  }
  return a;
}

}  // namespace

void SipHarvest::add(TokenCategory c, std::string_view v, const char* what) {
  v = trim(v);
  if (v.size() < 4 || v.size() > kMaxToken) return;
  add_bytes(c, std::vector<std::uint8_t>(v.begin(), v.end()), what);
}

void SipHarvest::add_bytes(TokenCategory c, const std::vector<std::uint8_t>& v, const char* what) {
  if (v.size() < 4) return;
  if (seen_.insert({static_cast<int>(c), v}).second) {
    tokens_.push_back(Token{c, v, std::string("input:") + what + "#" + std::to_string(++n_)});
  }
}

// A host as written: an IP literal becomes a binary address token (all its encodings are
// searched); a name becomes a string token. Kept values are not harvested: the special
// addresses and names under the reserved TLD .invalid (MBMS placeholders, TS 24.379 §14.2.2.2).
void SipHarvest::host(std::string_view h) {
  h = trim(h);
  if (h.empty() || h.size() > kMaxToken) return;
  if (auto a = v4(h)) {
    if (!keeps_ipv4(a->data())) add_bytes(TokenCategory::ipv4, {a->begin(), a->end()}, "ipv4");
    return;
  }
  if (auto a = v6(h)) {
    if (!keeps_ipv6(a->data())) add_bytes(TokenCategory::ipv6, {a->begin(), a->end()}, "ipv6");
    return;
  }
  const std::string l = lower(h.ends_with('.') ? h.substr(0, h.size() - 1) : h);
  if (l == "invalid" || l.ends_with(".invalid")) return;
  if (std::all_of(h.begin(), h.end(), [](char c) {
        return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '-' || c == '.' || c == '_';
      })) {
    add(TokenCategory::string, h, "domain");
  }
}

void SipHarvest::uris(std::string_view text) {
  const std::string low = lower(text);
  for (std::string_view scheme : {"sips:", "sip:", "tel:", "msrps://", "msrp://"}) {
    for (std::size_t at = low.find(scheme); at != std::string::npos && tokens_.size() < budget_;
         at = low.find(scheme, at + 1)) {
      if (at > 0 && (std::isalnum(static_cast<unsigned char>(low[at - 1])) != 0)) continue;  // "xsip:"
      if (scheme == "sip:" && at > 0 && low[at - 1] == 's') continue;
      const std::size_t start = at + scheme.size();
      const std::size_t end = token_end(text, start, "<>\",;?");
      std::string_view u = text.substr(start, end - start);
      if (scheme == "tel:") {
        std::string digits;
        for (char c : u) {
          if (is_digit(c)) digits.push_back(c);
        }
        add(TokenCategory::number, digits, "tel");
        continue;
      }
      const bool msrp = scheme.starts_with("msrp");
      if (msrp) {
        const auto slash = u.find('/');
        if (slash != std::string_view::npos) {
          add(TokenCategory::string, u.substr(slash + 1), "msrp-session");
          u = u.substr(0, slash);
        }
      }
      const auto atsign = u.rfind('@');
      std::string_view hostport = u;
      if (atsign != std::string_view::npos) {
        const auto user = u.substr(0, atsign);
        const auto colon = user.find(':');  // a password part
        const auto name = user.substr(0, colon);
        add(TokenCategory::string, name, "sip-user");
        if (!name.empty() && (name.front() == '+' || is_digit(name.front()))) {
          std::string digits;
          for (char c : name.substr(0, name.find(';'))) {
            if (is_digit(c)) digits.push_back(c);
          }
          add(TokenCategory::number, digits, "tel");
        }
        hostport = u.substr(atsign + 1);
      }
      if (hostport.starts_with('[')) {
        host(hostport.substr(0, hostport.find(']') + 1));
      } else {
        host(hostport.substr(0, hostport.find(':')));
      }
    }
  }
}

void SipHarvest::params(std::string_view text) {
  const std::string low = lower(text);
  const auto value_at = [&](std::size_t start) -> std::string_view {
    if (start < text.size() && text[start] == '"') {
      const auto close = text.find('"', start + 1);
      if (close == std::string_view::npos) return {};
      return text.substr(start + 1, close - start - 1);
    }
    return text.substr(start, token_end(text, start, ";,>\"") - start);
  };
  const auto each = [&](std::string_view name, const auto& f) {
    for (std::size_t at = low.find(name); at != std::string::npos && tokens_.size() < budget_;
         at = low.find(name, at + 1)) {
      if (at > 0 && (std::isalnum(static_cast<unsigned char>(low[at - 1])) != 0 || low[at - 1] == '-')) continue;
      std::size_t v = at + name.size();
      while (v < text.size() && (text[v] == ' ' || text[v] == '\t')) ++v;
      if (v >= text.size() || text[v] != '=') continue;
      ++v;
      while (v < text.size() && (text[v] == ' ' || text[v] == '\t')) ++v;
      f(value_at(v));
    }
  };
  each("tag", [&](std::string_view v) { add(TokenCategory::string, v, "tag"); });
  each("branch", [&](std::string_view v) { add(TokenCategory::string, v, "branch"); });
  each("realm", [&](std::string_view v) { add(TokenCategory::string, v, "domain"); });
  each("username", [&](std::string_view v) {
    add(TokenCategory::string, v, "sip-user");
    const auto atsign = v.rfind('@');
    if (atsign != std::string_view::npos) {
      add(TokenCategory::string, v.substr(0, atsign), "sip-user");
      host(v.substr(atsign + 1));
    }
  });
  each("+sip.instance", [&](std::string_view v) {
    if (v.starts_with('<') && v.ends_with('>')) v = v.substr(1, v.size() - 2);
    add(TokenCategory::string, v, "instance");
  });
  for (auto name : kAccessInfo) {
    each(name, [&](std::string_view v) {
      if (v4(v) || v6(v)) {
        host(v);
      } else {
        add(TokenCategory::string, v, "cell-id");
      }
    });
  }
}

void SipHarvest::display_names(std::string_view text) {
  for (std::size_t q = text.find('"'); q != std::string_view::npos && tokens_.size() < budget_;) {
    std::string name;
    std::size_t i = q + 1;
    for (; i < text.size() && text[i] != '"' && text[i] != '\r' && text[i] != '\n' && name.size() <= kMaxToken; ++i) {
      if (text[i] == '\\' && i + 1 < text.size()) ++i;
      name.push_back(text[i]);
    }
    if (i >= text.size() || text[i] != '"') break;
    std::size_t j = i + 1;
    while (j < text.size() && (text[j] == ' ' || text[j] == '\t')) ++j;
    if (j < text.size() && text[j] == '<') add(TokenCategory::string, name, "display-name");
    q = text.find('"', i + 1);
  }
}

void SipHarvest::header_line(std::string_view line) {
  const auto colon = line.find(':');
  if (colon == std::string_view::npos || colon == 0) return;
  const std::string name = lower(trim(line.substr(0, colon)));
  const auto value = trim(line.substr(colon + 1));
  if (name == "call-id" || name == "i") {
    add(TokenCategory::string, value, "call-id");
  } else if (name == "via" || name == "v") {
    // sent-protocol LWS sent-by, per comma-separated value
    std::size_t start = 0;
    while (start < value.size()) {
      auto end = value.find(',', start);
      if (end == std::string_view::npos) end = value.size();
      auto item = trim(value.substr(start, end - start));
      const auto sp = item.find_first_of(" \t");
      if (sp != std::string_view::npos) {
        auto sent_by = trim(item.substr(sp));
        sent_by = sent_by.substr(0, sent_by.find(';'));
        if (sent_by.starts_with('[')) {
          host(sent_by.substr(0, sent_by.find(']') + 1));
        } else {
          host(sent_by.substr(0, sent_by.find(':')));
        }
      }
      start = end + 1;
    }
  }
}

// Feature 005: key identifiers outside MIKEY. The base64 XPK-ID of
// <KeyName> (TS 33.180 §9.3.4.2, §9.3.5) and the key-id of an encrypted URI attribute (§9.3.4.3)
// are `key` tokens; the IV of the URI is a `bytes` token. Both alphabets of base64 are read.
void SipHarvest::key_references(std::string_view text) {
  const auto b64 = [](std::string_view v) {
    std::string t(v);
    for (auto& c : t) {
      if (c == '-') c = '+';
      if (c == '_') c = '/';
    }
    return decode_base64(t);
  };
  const auto value = [&](std::size_t from, std::string_view stops) {
    std::size_t e = from;
    while (e < text.size() && stops.find(text[e]) == std::string_view::npos) ++e;
    return text.substr(from, e - from);
  };
  for (std::size_t p = text.find("KeyName>"); p != std::string_view::npos && tokens_.size() < budget_;
       p = text.find("KeyName>", p + 1)) {
    if (p == 0 || (text[p - 1] != '<' && text[p - 1] != ':')) continue;
    if (auto d = b64(trim(value(p + 8, "<"))); d && d->size() == 4) add_bytes(TokenCategory::key, *d, "xpk-id");
  }
  for (std::size_t p = text.find(";key-id="); p != std::string_view::npos && tokens_.size() < budget_;
       p = text.find(";key-id=", p + 1)) {
    if (auto d = b64(value(p + 8, ";@\"'<> \r\n")); d && d->size() == 4) add_bytes(TokenCategory::key, *d, "uri-key-id");
  }
  for (std::size_t p = text.find(";iv="); p != std::string_view::npos && tokens_.size() < budget_;
       p = text.find(";iv=", p + 1)) {
    if (auto d = b64(value(p + 4, ";@\"'<> \r\n")); d && d->size() >= 8) add_bytes(TokenCategory::bytes, *d, "uri-iv");
  }
}

void SipHarvest::mikey(std::span<const std::uint8_t> message) {
  const auto v = walk_mikey(message);
  for (const auto& u : v.uris) {
    add(TokenCategory::string, u, "mikey");
    if (u.find(':') != std::string::npos) {
      uris(u);
    } else {
      host(u);
    }
  }
  for (const auto& k : v.keys) add_bytes(TokenCategory::key, k, "mikey-key");
  for (const auto& b : v.bytes) add_bytes(TokenCategory::bytes, b, "mikey");
}

void SipHarvest::sdp_line(std::string_view line) {
  if (line.size() < 2 || line[1] != '=') return;
  const auto v = line.substr(2);
  std::vector<std::string_view> f;
  std::size_t start = 0;
  while (start <= v.size()) {
    const auto sp = v.find(' ', start);
    f.push_back(v.substr(start, sp == std::string_view::npos ? std::string_view::npos : sp - start));
    if (sp == std::string_view::npos) break;
    start = sp + 1;
  }
  if (line[0] == 'a' && v.starts_with("key-mgmt:")) {
    // Feature 005: a=key-mgmt:mikey <base64> (RFC 4567 §3.1).
    auto rest = v.substr(9);
    if (!rest.empty() && rest.front() == ' ') rest.remove_prefix(1);
    if (rest.starts_with("mikey ")) {
      if (auto d = decode_base64(trim(rest.substr(6)))) mikey(*d);
    }
    return;
  }
  if (line[0] == 'o' && f.size() == 6) {
    if (f[0] != "-") add(TokenCategory::string, f[0], "sip-user");
    if (!f[1].empty() && std::all_of(f[1].begin(), f[1].end(), is_digit)) add(TokenCategory::number, f[1], "sdp-sess");
    host(f[5]);
  } else if (line[0] == 'c' && f.size() == 3) {
    host(f[2].substr(0, f[2].find('/')));
  } else if (line.starts_with("a=rtcp:") && f.size() == 4) {
    host(f[3]);
  }
}

void SipHarvest::scan(std::string_view text) {
  // Feature 005: application/mikey bodies and <GKTP> elements; a=key-mgmt is read
  // per SDP line below.
  for (const auto& c : find_mikey_carriers({reinterpret_cast<const std::uint8_t*>(text.data()), text.size()})) {
    if (c.carrier != "sdp") mikey(c.decoded);
  }
  key_references(text);
  uris(text);
  params(text);
  display_names(text);
  // XML bodies (feature 003): every value and unknown name, and the URIs inside
  // the unescaped values (a URI written with character references is found only here).
  // Only SIP messages: XML in HTTP (XCAP, OIDC pages) belongs to a later feature and is zeroed.
  std::vector<std::string> embedded;
  const bool sip = text.find("SIP/2.0") != std::string_view::npos;
  const auto xml = sip ? harvest_xml(text, nested_ ? nullptr : &embedded, tcp_ && !nested_) : std::vector<std::string>{};
  for (const auto& v : xml) {
    if (tokens_.size() >= budget_) break;
    add(TokenCategory::string, v, "xml");
    uris(v);
  }
  // Bodies embedded in entry URIs (R12 item 4): harvested as a SIP body, one level deep.
  for (const auto& b : embedded) {
    if (tokens_.size() >= budget_) break;
    nested_ = true;
    scan("SIP/2.0 embedded\r\n\r\n" + b);
    nested_ = false;
  }
  std::size_t start = 0;
  while (start < text.size() && tokens_.size() < budget_) {
    auto end = text.find('\n', start);
    if (end == std::string_view::npos) end = text.size();
    auto line = text.substr(start, end - start);
    if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
    if (line.size() >= 2 && line[1] == '=') {
      sdp_line(line);
    } else {
      header_line(line);
    }
    start = end + 1;
  }
}

void SipHarvest::text_value(std::string_view v, const char* what) {
  if (v.empty() || v.size() > kMaxToken) return;
  const bool printable = std::all_of(v.begin(), v.end(), [](char c) {
    const auto u = static_cast<unsigned char>(c);
    return u >= 0x20 && u < 0x7F;
  });
  if (!printable) return;
  budget_ = tokens_.size() + kMaxTokensPerPayload;
  add(TokenCategory::string, v, what);
  uris(v);
}

void SipHarvest::ssrc(std::uint32_t v) {
  add_bytes(TokenCategory::binary,
            {static_cast<std::uint8_t>(v >> 24), static_cast<std::uint8_t>(v >> 16), static_cast<std::uint8_t>(v >> 8),
             static_cast<std::uint8_t>(v)},
            "ssrc");
}

void SipHarvest::feed(std::span<const std::uint8_t> payload, const std::vector<std::uint8_t>& direction,
                      bool tcp) {
  const auto n = std::min(payload.size(), kMaxText);
  std::string text(reinterpret_cast<const char*>(payload.data()), n);
  if (tcp) {
    if (carry_.size() >= kMaxDirections && !carry_.contains(direction)) carry_.clear();
    auto& c = carry_[direction];
    text = c + text;
    c = text.size() > kCarry ? text.substr(text.size() - kCarry) : text;
  }
  budget_ = tokens_.size() + kMaxTokensPerPayload;
  tcp_ = tcp;
  scan(text);
  tcp_ = false;
}

std::vector<Token> SipHarvest::take() {
  carry_.clear();
  seen_.clear();
  return std::move(tokens_);
}

}  // namespace mcxanon::scan::detail
