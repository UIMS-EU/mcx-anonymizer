// SPDX-License-Identifier: GPL-3.0-or-later
#include "xml/xcap.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <map>
#include <vector>

namespace mcxanon::xml {
namespace {

// AUIDs kept as written (§E.7.4 step 3).
constexpr std::array<std::string_view, 16> kAuids{
    "org.3gpp.mcptt.ue-init-config", "org.3gpp.mcptt.ue-config",      "org.3gpp.mcptt.user-profile",
    "org.3gpp.mcptt.service-config", "org.3gpp.mcvideo.ue-config",     "org.3gpp.mcvideo.user-profile",
    "org.3gpp.mcvideo.service-config", "org.3gpp.mcdata.ue-config",    "org.3gpp.mcdata.user-profile",
    "org.3gpp.mcdata.service-config", "org.3gpp.MCPTT-GKTP",           "org.openmobilealliance.groups",
    "resource-lists",                 "rls-services",                  "pidf-manipulation",
    // Feature 007: the location user configuration document (TS 24.484 §7.4.2.2).
    "org.3gpp.mcs.location-user-config"};

using Opt = Result<std::optional<std::string>>;
const auto kNone = std::optional<std::string>{};

bool starts_with_ci(std::string_view s, std::string_view p) {
  if (s.size() < p.size()) return false;
  for (std::size_t i = 0; i < p.size(); ++i) {
    if (std::tolower(static_cast<unsigned char>(s[i])) != p[i]) return false;
  }
  return true;
}

// Fixed document names (TS 24.484 §8.3.2.8, §7.4.2.8) and the RLS index (RFC 5875 §4.4).
bool kept_document(std::string_view s) {
  if (s == "index") return true;
  for (std::string_view p : {std::string_view("mcptt-user-profile-"), std::string_view("location-user-config-")}) {
    if (s.starts_with(p) && s.ends_with(".xml")) {
      const auto d = s.substr(p.size(), s.size() - p.size() - 4);
      if (!d.empty() && std::all_of(d.begin(), d.end(), [](char c) { return c >= '0' && c <= '9'; })) return true;
    }
  }
  return false;
}

class Splitter {
 public:
  Splitter(std::string_view v, const PartMapper& map) : v_(v), map_(map) {
    // The escapes as written in the input: the same octets are escaped again in the output.
    for (std::size_t i = 0; i + 2 < v.size(); ++i) {
      if (v[i] == '%' && std::isxdigit(static_cast<unsigned char>(v[i + 1])) != 0 &&
          std::isxdigit(static_cast<unsigned char>(v[i + 2])) != 0) {
        const auto c = static_cast<char>(std::stoi(std::string(v.substr(i + 1, 2)), nullptr, 16));
        escapes_.try_emplace(c, std::string(v.substr(i, 3)));
      }
    }
  }

  Opt run() {
    if (v_.empty()) return kNone;
    std::string out;
    std::string_view rest = v_;
    bool absolute = false;
    // Step 1: scheme "://" authority.
    const auto colon = rest.find("://");
    if (colon != std::string_view::npos && colon > 0 && std::isalpha(static_cast<unsigned char>(rest[0])) != 0 &&
        std::all_of(rest.begin(), rest.begin() + static_cast<std::ptrdiff_t>(colon), [](char c) {
          return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '+' || c == '-' || c == '.';
        })) {
      absolute = true;
      out.append(rest.substr(0, colon + 3));
      rest.remove_prefix(colon + 3);
      const auto slash = rest.find('/');
      const auto authority = rest.substr(0, slash);
      rest = slash == std::string_view::npos ? std::string_view() : rest.substr(slash);
      if (authority.empty() || authority.find('@') != std::string_view::npos) return kNone;
      std::string_view host = authority;
      std::string_view port;
      if (host.front() == '[') {
        const auto close = host.find(']');
        if (close == std::string_view::npos) return kNone;
        port = host.substr(close + 1);
        host = host.substr(0, close + 1);
      } else if (const auto c = host.rfind(':'); c != std::string_view::npos) {
        port = host.substr(c);
        host = host.substr(0, c);
      }
      if (!port.empty() && (port.front() != ':' || port.size() == 1 ||
                            !std::all_of(port.begin() + 1, port.end(), [](char c) { return c >= '0' && c <= '9'; }))) {
        return kNone;
      }
      auto h = map_(XmlCategory::host, host);
      if (!h) return std::unexpected(h.error());
      if (!*h) return kNone;
      out += **h;
      out.append(port);
      if (rest.empty()) return std::optional<std::string>(out);
      out.push_back('/');
      rest.remove_prefix(1);
    }
    // Step 2: document selector and node selector.
    std::string_view doc = rest;
    std::optional<std::string_view> node;
    if (const auto t = rest.find("/~~/"); t != std::string_view::npos) {
      doc = rest.substr(0, t);
      node = rest.substr(t + 4);
    }
    std::vector<std::string_view> segs;
    for (std::size_t start = 0;;) {
      const auto slash = doc.find('/', start);
      segs.push_back(doc.substr(start, slash == std::string_view::npos ? std::string_view::npos : slash - start));
      if (slash == std::string_view::npos) break;
      start = slash + 1;
    }
    std::vector<std::string> decoded;
    for (const auto s : segs) {
      auto d = decode(s);
      if (!d) return kNone;
      decoded.push_back(std::move(*d));
    }
    // The AUID: the first segment, or in an absolute selector the segment before users/global.
    std::size_t auid = 0;
    if (absolute) {
      auid = segs.size();
      for (std::size_t k = 0; k + 1 < segs.size(); ++k) {
        if (decoded[k + 1] == "users" || decoded[k + 1] == "global") {
          auid = k;
          break;
        }
      }
      // Feature 005: the directory of an application usage under the XCAP root
      // (the GMS identity of TS 24.481 §7.4.2, "http://<xcap-root>/org.3gpp.MCPTT-GKTP/"): a known
      // AUID followed only by an empty segment keeps the AUID.
      if (auid == segs.size() && !node) {
        for (std::size_t k = 0; k < segs.size(); ++k) {
          const bool rest_empty = std::all_of(decoded.begin() + static_cast<std::ptrdiff_t>(k) + 1, decoded.end(),
                                              [](const std::string& x) { return x.empty(); });
          if (rest_empty && std::find(kAuids.begin(), kAuids.end(), decoded[k]) != kAuids.end()) {
            auid = k;
            break;
          }
        }
      }
      if (auid == segs.size() && node) return kNone;  // an XCAP root has no node selector
    }
    std::vector<std::string> parts(segs.size());
    for (std::size_t k = 0; k < segs.size(); ++k) {
      Opt p = std::optional<std::string>(std::string(segs[k]));
      const auto& d = decoded[k];
      if (d.empty()) {
        p = std::optional<std::string>(std::string());
      } else if (k < auid || auid == segs.size()) {
        p = opaque(d);  // XCAP root path
      } else if (k == auid) {
        const bool known = std::find(kAuids.begin(), kAuids.end(), d) != kAuids.end();
        p = known ? std::optional<std::string>(std::string(segs[k])) : opaque(d);
      } else if (k == auid + 1 && (d == "users" || d == "global")) {
        // kept as written
      } else if (k > auid + 1 && k - auid >= 2 && decoded[auid + 1] == "users" && k == auid + 2) {
        p = identity(d);
      } else if (decoded.size() > auid + 1 && decoded[auid + 1] == "global" && k == auid + 2 && d == "byGroupID") {
        // kept as written
      } else if (decoded.size() > auid + 2 && decoded[auid + 1] == "global" && decoded[auid + 2] == "byGroupID" &&
                 k == auid + 3) {
        p = identity(d);
      } else if (k > auid + 1 && kept_document(d) &&
                 (decoded[auid + 1] == "users" || decoded[auid + 1] == "global")) {
        // kept as written
      } else {
        p = opaque(d);
      }
      if (!p) return std::unexpected(p.error());
      if (!*p) return kNone;
      parts[k] = std::move(**p);
    }
    for (std::size_t k = 0; k < parts.size(); ++k) {
      if (k > 0) out.push_back('/');
      out += parts[k];
    }
    if (node) {
      auto n = node_selector(*node);
      if (!n) return std::unexpected(n.error());
      if (!*n) return kNone;
      out += "/~~/" + **n;
    }
    return std::optional<std::string>(std::move(out));
  }

 private:
  static std::optional<std::string> decode(std::string_view s) {
    std::string out;
    for (std::size_t i = 0; i < s.size(); ++i) {
      if (s[i] != '%') {
        out.push_back(s[i]);
        continue;
      }
      if (i + 2 >= s.size() || std::isxdigit(static_cast<unsigned char>(s[i + 1])) == 0 ||
          std::isxdigit(static_cast<unsigned char>(s[i + 2])) == 0) {
        return std::nullopt;
      }
      out.push_back(static_cast<char>(std::stoi(std::string(s.substr(i + 1, 2)), nullptr, 16)));
      i += 2;
    }
    return out;
  }

  // A mapped part, escaped as the input escaped those octets, plus what a path segment needs.
  std::string encode(std::string_view s, bool node) const {
    std::string out;
    const char* hex = "0123456789ABCDEF";
    for (const char ch : s) {
      if (const auto it = escapes_.find(ch); it != escapes_.end()) {
        out += it->second;
        continue;
      }
      const auto c = static_cast<unsigned char>(ch);
      const bool pchar = std::isalnum(c) != 0 || std::string_view("-._~!$&'()*+,;=:@").find(ch) != std::string_view::npos ||
                         (node && std::string_view("[]\"/").find(ch) != std::string_view::npos);
      if (pchar && c < 0x80) {
        out.push_back(ch);
      } else {
        out.push_back('%');
        out.push_back(hex[c >> 4]);
        out.push_back(hex[c & 15]);
      }
    }
    return out;
  }

  Opt mapped(XmlCategory c, std::string_view d, bool node = false) {
    auto p = map_(c, d);
    if (!p || !*p) return p;
    return std::optional<std::string>(encode(**p, node));
  }

  Opt opaque(std::string_view d, bool node = false) { return mapped(XmlCategory::opaque, d, node); }

  // An XUI or a group ID: a URI, a scheme-less user@host (E9), or an instance URN.
  Opt identity(std::string_view d, bool node = false) {
    if (starts_with_ci(d, "sip:") || starts_with_ci(d, "sips:") || starts_with_ci(d, "tel:")) {
      return mapped(XmlCategory::uri, d, node);
    }
    if (starts_with_ci(d, "urn:")) return mapped(XmlCategory::any_id, d, node);
    if (d.find('@') != std::string_view::npos) return mapped(XmlCategory::user_at_host, d, node);
    return opaque(d, node);
  }

  // Step 4: steps, operators and names kept; each quoted literal mapped by kind. The namespace
  // names of an "?xmlns(p=ns)" query of a 3GPP, IETF or OMA namespace are kept.
  Opt node_selector(std::string_view raw) {
    auto d = decode(raw);
    if (!d) return kNone;
    const std::string_view s = *d;
    std::string out;
    std::size_t i = 0;
    while (i < s.size()) {
      const char c = s[i];
      if (c == '\'' || c == '"') {
        const auto close = s.find(c, i + 1);
        if (close == std::string_view::npos) return kNone;
        const auto lit = s.substr(i + 1, close - i - 1);
        std::string q = encode(std::string(1, c), true);
        out += q;
        if (!lit.empty()) {
          auto m = identity_or_opaque(lit);
          if (!m) return std::unexpected(m.error());
          if (!*m) return kNone;
          out += **m;
        }
        out += q;
        i = close + 1;
        continue;
      }
      if (s.substr(i).starts_with("?xmlns(")) {
        const auto end = s.find(')', i);
        if (end == std::string_view::npos) return kNone;
        const auto inner = s.substr(i + 7, end - i - 7);
        const auto eq = inner.find('=');
        if (eq == std::string_view::npos) return kNone;
        const auto ns = inner.substr(eq + 1);
        out += encode(std::string(s.substr(i, 7)) + std::string(inner.substr(0, eq + 1)), true);
        if (starts_with_ci(ns, "urn:3gpp:") || starts_with_ci(ns, "urn:ietf:params:xml:ns:") ||
            starts_with_ci(ns, "urn:oma:")) {
          out += encode(ns, true);
        } else {
          auto m = opaque(ns, true);
          if (!m) return std::unexpected(m.error());
          if (!*m) return kNone;
          out += **m;
        }
        out += encode(")", true);
        i = end + 1;
        continue;
      }
      out += encode(std::string(1, c), true);
      ++i;
    }
    return std::optional<std::string>(std::move(out));
  }

  Opt identity_or_opaque(std::string_view lit) { return identity(lit, true); }

 public:
  Opt node_only() { return node_selector(v_); }

 private:

  std::string_view v_;
  const PartMapper& map_;
  std::map<char, std::string> escapes_;
};

}  // namespace

bool is_known_auid(std::string_view s) { return std::find(kAuids.begin(), kAuids.end(), s) != kAuids.end(); }

Result<std::optional<std::string>> rewrite_xcap_selector(std::string_view value, const PartMapper& map) {
  return Splitter(value, map).run();
}

Result<std::optional<std::string>> rewrite_xcap_node(std::string_view value, const PartMapper& map) {
  if (value.empty() || value.find('%') != std::string_view::npos) return std::optional<std::string>{};
  return Splitter(value, map).node_only();
}

}  // namespace mcxanon::xml
