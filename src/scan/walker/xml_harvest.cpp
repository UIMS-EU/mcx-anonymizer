// SPDX-License-Identifier: GPL-3.0-or-later
#include "scan/walker/xml_harvest.hpp"
#include "scan/walker/mikey_harvest.hpp"

#include "scan/walker/xml_vocabulary.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <set>

namespace mcxanon::scan::detail {
namespace {

constexpr std::size_t kMaxValues = 4096;  // per payload; SipHarvest caps the tokens again

bool is_space(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }
bool is_digit(char c) { return c >= '0' && c <= '9'; }

bool is_name_char(char c) {
  const auto u = static_cast<unsigned char>(c);
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || is_digit(c) || c == '_' || c == ':' || c == '-' ||
         c == '.' || u >= 0x80;
}

std::string_view trim(std::string_view s) {
  while (!s.empty() && is_space(s.front())) s.remove_prefix(1);
  while (!s.empty() && is_space(s.back())) s.remove_suffix(1);
  return s;
}

void utf8(std::string& out, std::uint32_t cp) {
  if (cp < 0x80) {
    out.push_back(static_cast<char>(cp));
  } else if (cp < 0x800) {
    out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
    out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
  } else if (cp < 0x10000) {
    out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
    out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
    out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
  } else {
    out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
    out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
    out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
    out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
  }
}

// The five predefined entities and character references; anything else stays as written.
std::string unescape(std::string_view s) {
  std::string out;
  out.reserve(s.size());
  for (std::size_t i = 0; i < s.size(); ++i) {
    if (s[i] != '&') {
      out.push_back(s[i]);
      continue;
    }
    const auto semi = s.find(';', i);
    if (semi == std::string_view::npos || semi - i > 12) {
      out.push_back('&');
      continue;
    }
    const auto ent = s.substr(i + 1, semi - i - 1);
    if (ent == "amp") out.push_back('&');
    else if (ent == "lt") out.push_back('<');
    else if (ent == "gt") out.push_back('>');
    else if (ent == "quot") out.push_back('"');
    else if (ent == "apos") out.push_back('\'');
    else if (ent.size() >= 2 && ent[0] == '#') {
      const bool hex = ent[1] == 'x' || ent[1] == 'X';
      std::uint32_t cp = 0;
      bool ok = ent.size() > (hex ? 2u : 1u);
      for (std::size_t k = hex ? 2 : 1; k < ent.size() && ok; ++k) {
        const char c = ent[k];
        const int d = is_digit(c) ? c - '0'
                      : hex && c >= 'a' && c <= 'f' ? c - 'a' + 10
                      : hex && c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
        ok = d >= 0 && cp <= 0x10FFFF;
        cp = cp * (hex ? 16u : 10u) + static_cast<std::uint32_t>(d < 0 ? 0 : d);
      }
      if (!ok || cp > 0x10FFFF || cp == 0) {
        out.push_back('&');
        continue;
      }
      utf8(out, cp);
    } else {
      out.push_back('&');
      continue;
    }
    i = semi;
  }
  return out;
}

// Exactly n digits at s[i], advancing i.
bool digits(std::string_view s, std::size_t& i, std::size_t n) {
  for (std::size_t k = 0; k < n; ++k, ++i) {
    if (i >= s.size() || !is_digit(s[i])) return false;
  }
  return true;
}

bool lit(std::string_view s, std::size_t& i, char c) {
  if (i < s.size() && s[i] == c) {
    ++i;
    return true;
  }
  return false;
}

// Optional time zone: Z or (+|-)hh:mm, then the end.
bool tz_end(std::string_view s, std::size_t i) {
  if (i == s.size()) return true;
  if (s[i] == 'Z') return i + 1 == s.size();
  if (s[i] != '+' && s[i] != '-') return false;
  ++i;
  return digits(s, i, 2) && lit(s, i, ':') && digits(s, i, 2) && i == s.size();
}

// hh:mm:ss(.s+)? at i.
bool clock(std::string_view s, std::size_t& i) {
  if (!(digits(s, i, 2) && lit(s, i, ':') && digits(s, i, 2) && lit(s, i, ':') && digits(s, i, 2))) return false;
  if (lit(s, i, '.')) {
    const auto start = i;
    while (i < s.size() && is_digit(s[i])) ++i;
    if (i == start) return false;
  }
  return true;
}

// XSD date, dateTime, time and duration lexical forms (XML Schema Part 2 §3.2.6-§3.2.9).
bool xsd_temporal(std::string_view s) {
  std::size_t i = 0;
  if (!s.empty() && s[0] == '-') ++i;
  if (i < s.size() && s[i] == 'P') {
    ++i;
    bool any = false;
    bool time = false;
    while (i < s.size()) {
      if (s[i] == 'T' && !time) {
        time = true;
        ++i;
        continue;
      }
      const auto start = i;
      while (i < s.size() && (is_digit(s[i]) || s[i] == '.')) ++i;
      if (i == start || i >= s.size()) return false;
      const char u = s[i++];
      if (std::string_view(time ? "HMS" : "YMD").find(u) == std::string_view::npos) return false;
      any = true;
    }
    return any;
  }
  std::size_t j = 0;
  if (clock(s, j) && tz_end(s, j)) return true;  // time
  i = s.starts_with('-') ? 1 : 0;
  if (!(digits(s, i, 4) && lit(s, i, '-') && digits(s, i, 2) && lit(s, i, '-') && digits(s, i, 2))) return false;
  if (i < s.size() && s[i] == 'T') {
    ++i;
    if (!clock(s, i)) return false;
  }
  return tz_end(s, i);
}

// A Resource-Priority r-value (RFC 4412 §3.1: namespace "." r-priority), kept by the XML rules
// (TS 24.379 `ric-app-level-priority`, A13) as 002 keeps Resource-Priority: the priority is a
// number of at most 3 digits or a priority word of the RFC 4412 §12.6 registry (proposal N4).
// "alice.nowak" is not one, so identities of that shape are still harvested.
bool r_value(std::string_view v) {
  const auto dot = v.find('.');
  if (dot == std::string_view::npos || dot == 0 || dot > 32 || v.find('.', dot + 1) != std::string_view::npos) {
    return false;
  }
  for (const char c : v.substr(0, dot)) {
    if (std::isalnum(static_cast<unsigned char>(c)) == 0 && c != '-') return false;
  }
  const auto prio = v.substr(dot + 1);
  if (!prio.empty() && prio.size() <= 3 && std::all_of(prio.begin(), prio.end(), is_digit)) return true;
  for (std::string_view w : {"routine", "priority", "immediate", "flash", "flash-override", "flash-override-override"}) {
    if (prio == w) return true;
  }
  return false;
}

// An XCAP selector made only of segments the output keeps (proposal N9): the AUIDs of the
// rewrite's allowlist, the tree names and
// the fixed document names. The scanner's own copy of that list.
bool standard_xcap(std::string_view v) {
  static constexpr std::string_view kKept[] = {
      "org.3gpp.mcptt.ue-init-config", "org.3gpp.mcptt.ue-config",     "org.3gpp.mcptt.user-profile",
      "org.3gpp.mcptt.service-config", "org.3gpp.mcvideo.ue-config",    "org.3gpp.mcvideo.user-profile",
      "org.3gpp.mcvideo.service-config", "org.3gpp.mcdata.ue-config",   "org.3gpp.mcdata.user-profile",
      "org.3gpp.mcdata.service-config", "org.3gpp.MCPTT-GKTP",          "org.openmobilealliance.groups",
      "resource-lists", "rls-services", "pidf-manipulation", "users", "global", "byGroupID", "index", ""};
  if (v.find('/') == std::string_view::npos) return false;
  for (std::size_t start = 0;;) {
    const auto slash = v.find('/', start);
    const auto seg = v.substr(start, slash == std::string_view::npos ? std::string_view::npos : slash - start);
    if (std::find(std::begin(kKept), std::end(kKept), seg) == std::end(kKept)) return false;
    if (slash == std::string_view::npos) return true;
    start = slash + 1;
  }
}

std::string_view local_name(std::string_view qname) {
  const auto colon = qname.rfind(':');
  return colon == std::string_view::npos ? qname : qname.substr(colon + 1);
}

// A field whose value the rules keep on purpose (proposal N13, xml_kept_value_fields()).
bool kept_token_field(std::string_view qname) {
  const auto colon = qname.rfind(':');
  return xml_kept_value_field(colon == std::string_view::npos ? qname : qname.substr(colon + 1));
}

bool skipped_value(std::string_view v) {
  if (v.empty() || within_xml_vocabulary(v)) return true;
  if (v == "true" || v == "false") return true;
  std::string_view d = v;
  if (d.starts_with('-') || d.starts_with('+')) d.remove_prefix(1);
  if (!d.empty() && d.size() < 7 && std::all_of(d.begin(), d.end(), is_digit)) return true;
  // Hex values of at most 24 bits (SAI, TAC, FSA): the output writes the pseudonyms of such values
  // as hex of the same width, which a short input value would match by chance (proposal N17).
  if (v.size() <= 6 && std::all_of(v.begin(), v.end(), [](char c) { return std::isxdigit(static_cast<unsigned char>(c)) != 0; })) {
    return true;
  }
  return xsd_temporal(v) || r_value(v) || standard_xcap(v);
}

class Harvester {
 public:
  Harvester(std::string_view t, std::vector<std::string>* embedded, bool cut)
      : t_(t), embedded_(embedded), cut_(cut) {}

  std::vector<std::string> run() {
    std::set<std::size_t> starts;
    for (std::size_t p = t_.find("\n\r\n"); p != std::string_view::npos; p = t_.find("\n\r\n", p + 1)) {
      starts.insert(p + 3);
    }
    for (std::size_t p = t_.find("\n\n"); p != std::string_view::npos; p = t_.find("\n\n", p + 1)) {
      starts.insert(p + 2);
    }
    for (std::size_t p = t_.find("<?xml"); p != std::string_view::npos; p = t_.find("<?xml", p + 1)) {
      starts.insert(p);
    }
    for (auto s : starts) {
      if (t_.substr(s).starts_with("\xEF\xBB\xBF")) s += 3;
      if (s < t_.size() && t_[s] == '<' && s >= done_) region(s);
    }
    return std::move(out_);
  }

 private:
  void add(std::string_view v) {
    if (out_.size() >= kMaxValues || v.empty()) return;
    if (seen_.insert(std::string(v)).second) out_.emplace_back(v);
  }

  void value(std::string_view raw) {
    raw = trim(raw);
    if (raw.empty()) return;
    const std::string u = unescape(raw);
    const auto core = trim(u);
    if (skipped_value(core)) return;
    add(raw);
    if (core != raw) add(core);
    if (embedded_ != nullptr) embedded_body(core);
  }

  // The `body` URI header of a URI value, URL-decoded (RFC 3261 §19.1.1), leniently.
  void embedded_body(std::string_view v) {
    const auto q = v.find('?');
    if (q == std::string_view::npos || embedded_->size() >= 64) return;
    for (std::string_view h = v.substr(q + 1); !h.empty();) {
      const auto amp = h.find('&');
      const auto item = h.substr(0, amp);
      if (item.size() > 5 && (item.substr(0, 5) == "body=" || item.substr(0, 5) == "Body=" || item.substr(0, 5) == "BODY=")) {
        std::string out;
        const auto b = item.substr(5);
        for (std::size_t i = 0; i < b.size(); ++i) {
          const auto hx = [](char c) { return std::isxdigit(static_cast<unsigned char>(c)) != 0; };
          if (b[i] == '%' && i + 2 < b.size() && hx(b[i + 1]) && hx(b[i + 2])) {
            out.push_back(static_cast<char>(std::stoi(std::string(b.substr(i + 1, 2)), nullptr, 16)));
            i += 2;
          } else {
            out.push_back(b[i]);
          }
        }
        embedded_->push_back(std::move(out));
      }
      if (amp == std::string_view::npos) break;
      h.remove_prefix(amp + 1);
    }
  }

  // An element name outside the vocabulary, in the forms a surviving tag would take: "<name"
  // (unprefixed start or empty tag) and ":name>", ":name ", ":name/" (prefixed tags). Bare names
  // are common words ("status", "Report") that kept SIP and MSRP headers contain (proposal N2).
  void element_name(std::string_view qname) {
    const auto colon = qname.rfind(':');
    const auto local = colon == std::string_view::npos ? qname : qname.substr(colon + 1);
    if (local.empty() || within_xml_vocabulary(local)) return;
    const std::string l(local);
    add("<" + l);
    for (const char* end : {">", " ", "/"}) add(":" + l + end);
  }

  void ns_name(std::string_view raw) {
    const std::string u = unescape(trim(raw));
    if (!u.empty() && !within_xml_vocabulary(u)) {
      add(trim(raw));
      add(u);
    }
  }

  // Index after `what`, or the end of the text when it is missing.
  std::size_t after(std::size_t from, std::string_view what) const {
    const auto p = t_.find(what, from);
    return p == std::string_view::npos ? t_.size() : p + what.size();
  }

  // A markup declaration (<!DOCTYPE ...>, possibly with an internal subset): its quoted
  // literals are values (entity replacement texts, system identifiers).
  std::size_t declaration(std::size_t i) {
    int brackets = 0;
    for (++i; i < t_.size(); ++i) {
      const char c = t_[i];
      if (c == '"' || c == '\'') {
        const auto close = t_.find(c, i + 1);
        if (close == std::string_view::npos) {
          value(t_.substr(i + 1));
          return t_.size();
        }
        value(t_.substr(i + 1, close - i - 1));
        i = close;
      } else if (c == '[') {
        ++brackets;
      } else if (c == ']') {
        --brackets;
      } else if (c == '>' && brackets <= 0) {
        return i + 1;
      }
    }
    return t_.size();
  }

  // One body from `i` until its root element closes (or the text ends).
  void region(std::size_t i) {
    int depth = 0;
    bool root = false;
    while (i < t_.size()) {
      if (t_[i] != '<') {
        const auto next = std::min(t_.find('<', i), t_.size());
        if (cut_ && next == t_.size()) break;  // a value cut at the end of a TCP segment
        const auto text = t_.substr(i, next - i);
        if (depth > 0) {
          // Feature 005: <GKTP> text is an I_MESSAGE, read by the MIKEY harvester.
          // Feature 005 (P8): a cipher value is kept ciphertext, not a value; a KeyName holding a
          // 32-bit XPK-ID is a `key` token of the SIP harvester.
          const auto local = names_.empty() ? std::string_view() : local_name(names_.back());
          const auto xpk = local == "KeyName" ? decode_base64(trim(text)) : std::nullopt;
          const bool gktp = local == "GKTP" || local == "CipherValue" || (xpk && xpk->size() == 4);
          if (!gktp && !(names_.empty() ? false : kept_token_field(names_.back()))) value(text);
        } else if (!trim(text).empty()) {
          break;  // character data outside the root: not (or no longer) XML
        }
        i = next;
        continue;
      }
      const auto rest = t_.substr(i);
      if (rest.starts_with("<!--")) {
        const auto end = t_.find("-->", i + 4);
        if (cut_ && end == std::string_view::npos) break;
        value(t_.substr(i + 4, (end == std::string_view::npos ? t_.size() : end) - i - 4));
        i = after(i + 4, "-->");
      } else if (rest.starts_with("<![CDATA[")) {
        const auto end = t_.find("]]>", i + 9);
        if (cut_ && end == std::string_view::npos) break;
        value(t_.substr(i + 9, (end == std::string_view::npos ? t_.size() : end) - i - 9));
        i = after(i + 9, "]]>");
      } else if (rest.starts_with("<!")) {
        i = declaration(i + 1);
      } else if (rest.starts_with("<?")) {
        const auto end = t_.find("?>", i + 2);
        const auto body = t_.substr(i + 2, (end == std::string_view::npos ? t_.size() : end) - i - 2);
        std::size_t n = 0;
        while (n < body.size() && is_name_char(body[n])) ++n;
        if (body.substr(0, n) != "xml") value(body.substr(n));
        i = after(i + 2, "?>");
      } else if (rest.starts_with("</")) {
        i = after(i + 2, ">");
        --depth;
        if (!names_.empty()) names_.pop_back();
        if (root && depth <= 0) break;
      } else {
        bool empty = false;
        const auto next = start_tag(i, empty);
        if (next == i) {  // '<' not followed by a name: character data
          if (depth == 0) break;
          ++i;
          continue;
        }
        i = next;
        root = true;
        if (!empty) {
          ++depth;
          names_.push_back(last_name_);
        }
        if (depth <= 0) break;
      }
    }
    done_ = std::max(done_, i);
  }

  // A start or empty-element tag at i; returns the index after it (i when it is not one).
  std::size_t start_tag(std::size_t i, bool& empty) {
    std::size_t n = i + 1;
    while (n < t_.size() && is_name_char(t_[n])) ++n;
    if (n == i + 1) return i;
    // A tag cut at the end of a TCP segment: its name and values may be partial; the next
    // segment, which carries this one's tail, sees the whole tag.
    if (cut_ && t_.find('>', n) == std::string_view::npos) return t_.size();
    last_name_ = std::string(t_.substr(i + 1, n - i - 1));
    element_name(last_name_);
    while (n < t_.size()) {
      while (n < t_.size() && is_space(t_[n])) ++n;
      if (n >= t_.size()) return n;
      if (t_[n] == '>') return n + 1;
      if (t_[n] == '/') {
        empty = true;
        return after(n, ">");
      }
      const auto an = n;
      while (n < t_.size() && is_name_char(t_[n])) ++n;
      if (n == an) return after(n, ">");  // garbage inside the tag
      const auto attr = t_.substr(an, n - an);
      while (n < t_.size() && is_space(t_[n])) ++n;
      if (n >= t_.size() || t_[n] != '=') continue;
      ++n;
      while (n < t_.size() && is_space(t_[n])) ++n;
      if (n >= t_.size() || (t_[n] != '"' && t_[n] != '\'')) continue;
      const char q = t_[n];
      const auto close = std::min(t_.find(q, n + 1), t_.size());
      const auto v = t_.substr(n + 1, close - n - 1);
      // Attribute names are not harvested: their only surviving form, name="...", is also the
      // form of quoted SIP header parameters (uri="...", realm="...") (proposal N2).
      if (attr == "xmlns" || attr.starts_with("xmlns:")) {
        ns_name(v);
      } else {
        if (!kept_token_field(attr)) value(v);
      }
      n = close + 1;
    }
    return n;
  }

  std::string_view t_;
  std::vector<std::string>* embedded_;
  bool cut_;  // the text may end inside a value (TCP): unterminated items are not harvested
  std::vector<std::string> names_;  // open elements of the current region
  std::string last_name_;
  std::vector<std::string> out_;
  std::set<std::string> seen_;
  std::size_t done_ = 0;
};

}  // namespace

std::vector<std::string> harvest_xml(std::string_view text, std::vector<std::string>* embedded, bool cut) {
  return Harvester(text, embedded, cut).run();
}

}  // namespace mcxanon::scan::detail
