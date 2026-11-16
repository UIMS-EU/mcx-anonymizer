// SPDX-License-Identifier: GPL-3.0-or-later
//
// The XML reader. Productions are those of W3C XML 1.0 (Fifth Edition),
// cited as [n], and of Namespaces in XML 1.0 (Third Edition).
#include "xml/reader.hpp"

#include "xml/escape.hpp"
#include "xml/limits.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>

namespace mcxanon::xml {
namespace {

constexpr std::string_view kXmlNs = "http://www.w3.org/XML/1998/namespace";
constexpr std::string_view kXmlnsNs = "http://www.w3.org/2000/xmlns/";

bool is_space(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }  // [3]

bool iequal(std::string_view a, std::string_view b) {
  return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), [](char x, char y) {
           return (x | 0x20) == (y | 0x20);
         });
}

// Decodes the code point at i of already validated UTF-8; returns its length.
std::size_t decode(std::string_view s, std::size_t i, char32_t& cp) {
  const auto b = static_cast<unsigned char>(s[i]);
  if (b < 0x80) {
    cp = b;
    return 1;
  }
  const std::size_t n = b >= 0xF0 ? 4 : b >= 0xE0 ? 3 : 2;
  cp = b & (n == 2 ? 0x1F : n == 3 ? 0x0F : 0x07);
  for (std::size_t k = 1; k < n; ++k) cp = (cp << 6) | (static_cast<unsigned char>(s[i + k]) & 0x3F);
  return n;
}

// Strict UTF-8 (no overlong forms, no surrogates, at most U+10FFFF). Returns false on an
// invalid sequence; sets `non_char` when a decoded code point is not an XML Char ([2]).
bool valid_utf8(std::string_view s, bool& non_char, std::size_t& at) {
  non_char = false;
  for (std::size_t i = 0; i < s.size();) {
    const auto b = static_cast<unsigned char>(s[i]);
    char32_t cp = 0;
    std::size_t n = 0;
    if (b < 0x80) {
      cp = b;
      n = 1;
    } else if (b >= 0xC2 && b <= 0xDF) {
      n = 2;
      cp = b & 0x1F;
    } else if (b >= 0xE0 && b <= 0xEF) {
      n = 3;
      cp = b & 0x0F;
    } else if (b >= 0xF0 && b <= 0xF4) {
      n = 4;
      cp = b & 0x07;
    } else {
      at = i;
      return false;
    }
    if (i + n > s.size()) {
      at = i;
      return false;
    }
    for (std::size_t k = 1; k < n; ++k) {
      const auto c = static_cast<unsigned char>(s[i + k]);
      if ((c & 0xC0) != 0x80) {
        at = i;
        return false;
      }
      cp = (cp << 6) | (c & 0x3F);
    }
    if ((n == 3 && (cp < 0x800 || (cp >= 0xD800 && cp <= 0xDFFF))) || (n == 4 && (cp < 0x10000 || cp > 0x10FFFF))) {
      at = i;
      return false;
    }
    if (!non_char && !is_xml_char(cp)) {
      non_char = true;
      at = i;
    }
    i += n;
  }
  return true;
}

bool name_start(char32_t c) {  // [4] without ':' (Namespaces NCName)
  return (c >= 'A' && c <= 'Z') || c == '_' || (c >= 'a' && c <= 'z') || (c >= 0xC0 && c <= 0xD6) ||
         (c >= 0xD8 && c <= 0xF6) || (c >= 0xF8 && c <= 0x2FF) || (c >= 0x370 && c <= 0x37D) ||
         (c >= 0x37F && c <= 0x1FFF) || (c >= 0x200C && c <= 0x200D) || (c >= 0x2070 && c <= 0x218F) ||
         (c >= 0x2C00 && c <= 0x2FEF) || (c >= 0x3001 && c <= 0xD7FF) || (c >= 0xF900 && c <= 0xFDCF) ||
         (c >= 0xFDF0 && c <= 0xFFFD) || (c >= 0x10000 && c <= 0xEFFFF);
}

bool name_char(char32_t c) {  // [4a] without ':'
  return name_start(c) || c == '-' || c == '.' || (c >= '0' && c <= '9') || c == 0xB7 ||
         (c >= 0x300 && c <= 0x36F) || (c >= 0x203F && c <= 0x2040);
}

struct Fail {
  ReadError e;
};

class Parser {
 public:
  Parser(std::string_view s, Document& d, std::vector<std::pair<std::string, std::string>>& scope,
         std::vector<std::size_t>& marks, std::vector<std::uint32_t>& open)
      : s_(s), d_(d), scope_(scope), marks_(marks), open_(open) {}

  std::optional<ReadError> run() {
    if (s_.size() > kMaxBodyBytes) return err(Reject::limit, 0, "body too large");
    if (s_.size() >= 2 && ((s_[0] == '\xFE' && s_[1] == '\xFF') || (s_[0] == '\xFF' && s_[1] == '\xFE'))) {
      return err(Reject::encoding, 0, "UTF-16 byte order mark");
    }
    if (std::memchr(s_.data(), 0, std::min<std::size_t>(4, s_.size())) != nullptr) {
      return err(Reject::encoding, 0, "NUL in the first four bytes");
    }
    bool non_char = false;
    std::size_t at = 0;
    if (!valid_utf8(s_, non_char, at)) return err(Reject::encoding, at, "invalid UTF-8");
    if (non_char) return err(Reject::malformed, at, "character outside the Char production");
    if (s_.starts_with("\xEF\xBB\xBF")) {
      d_.bom = true;
      p_ = 3;
    }
    if (auto e = decl()) return e;
    while (p_ < s_.size()) {
      if (s_[p_] == '<') {
        if (auto e = markup()) return e;
      } else {
        if (auto e = text()) return e;
      }
    }
    if (!open_.empty()) return err(Reject::malformed, s_.size(), "unclosed element");
    if (d_.elements.empty()) return err(Reject::malformed, s_.size(), "no root element");
    return std::nullopt;
  }

 private:
  std::optional<ReadError> err(Reject r, std::size_t at, const char* what) { return ReadError{r, at, what}; }
  bool at(std::string_view lit) const { return s_.substr(p_).starts_with(lit); }
  void skip_space() {
    while (p_ < s_.size() && is_space(s_[p_])) ++p_;
  }
  std::uint32_t current() const { return open_.empty() ? kNoElement : open_.back(); }
  void item(ItemKind k, std::size_t from, std::uint32_t el, bool ws = false) {
    d_.items.push_back(Item{k, Span{from, p_ - from}, el, ws});
  }

  // An NCName at p_ ([4], [5] without ':'); its length, 0 if none.
  std::size_t ncname(std::size_t i) const {
    std::size_t j = i;
    char32_t cp = 0;
    while (j < s_.size()) {
      const std::size_t n = decode(s_, j, cp);
      if (j == i ? !name_start(cp) : !name_char(cp)) break;
      j += n;
    }
    return j - i;
  }

  // A QName at p_: prefix and local part. Advances p_.
  std::optional<ReadError> qname(std::string_view& prefix, std::string_view& local, Span& span) {
    const std::size_t start = p_;
    const std::size_t a = ncname(p_);
    if (a == 0) return err(Reject::malformed, p_, "name expected");
    p_ += a;
    prefix = {};
    local = s_.substr(start, a);
    if (p_ < s_.size() && s_[p_] == ':') {
      const std::size_t b = ncname(p_ + 1);
      if (b == 0) return err(Reject::malformed, p_, "bad qualified name");
      prefix = local;
      local = s_.substr(p_ + 1, b);
      p_ += 1 + b;
      if (p_ < s_.size() && s_[p_] == ':') return err(Reject::malformed, p_, "bad qualified name");
    }
    span = Span{start, p_ - start};
    if (span.len > kMaxNameBytes) return err(Reject::limit, start, "name too long");
    return std::nullopt;
  }

  // [23]-[26], [32], [80], [81]
  std::optional<ReadError> decl() {
    if (!at("<?xml") || p_ + 5 >= s_.size() || !is_space(s_[p_ + 5])) return std::nullopt;
    const std::size_t from = p_;
    p_ += 5;
    auto pseudo_attr = [&](std::string_view name, std::string_view& value) -> int {
      const std::size_t save = p_;
      skip_space();
      if (p_ == save || !at(name)) {
        p_ = save;
        return 0;
      }
      p_ += name.size();
      skip_space();
      if (p_ >= s_.size() || s_[p_] != '=') return -1;
      ++p_;
      skip_space();
      if (p_ >= s_.size() || (s_[p_] != '"' && s_[p_] != '\'')) return -1;
      const char q = s_[p_++];
      const auto end = s_.find(q, p_);
      if (end == std::string_view::npos) return -1;
      value = s_.substr(p_, end - p_);
      p_ = end + 1;
      return 1;
    };
    std::string_view version, encoding, standalone;
    if (pseudo_attr("version", version) != 1) return err(Reject::malformed, from, "XML declaration without version");
    if (version.size() < 3 || !version.starts_with("1.") ||
        !std::all_of(version.begin() + 2, version.end(), [](char c) { return c >= '0' && c <= '9'; })) {
      return err(Reject::malformed, from, "unsupported XML version");
    }
    const int e = pseudo_attr("encoding", encoding);
    if (e < 0) return err(Reject::malformed, from, "bad encoding declaration");
    if (e == 1) {
      const bool name_ok = !encoding.empty() && std::isalpha(static_cast<unsigned char>(encoding[0])) &&
                           std::all_of(encoding.begin(), encoding.end(), [](char c) {
                             return std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '_' || c == '-';
                           });
      if (!name_ok) return err(Reject::malformed, from, "bad encoding name");
      if (!iequal(encoding, "UTF-8") && !iequal(encoding, "US-ASCII")) {
        return err(Reject::encoding, from, "encoding other than UTF-8");
      }
    }
    const int sd = pseudo_attr("standalone", standalone);
    if (sd < 0 || (sd == 1 && standalone != "yes" && standalone != "no")) {
      return err(Reject::malformed, from, "bad standalone declaration");
    }
    skip_space();
    if (!at("?>")) return err(Reject::malformed, from, "bad XML declaration");
    p_ += 2;
    d_.decl = Span{from, p_ - from};
    item(ItemKind::decl, from, kNoElement);
    return std::nullopt;
  }

  std::optional<ReadError> markup() {
    if (at("<!--")) return comment();
    if (at("<![CDATA[")) return cdata();
    if (at("<!DOCTYPE")) return err(Reject::dtd, p_, "document type declaration");
    if (at("<!")) return err(Reject::malformed, p_, "unexpected markup declaration");
    if (at("<?")) return pi();
    if (at("</")) return end_tag();
    return start_tag();
  }

  std::optional<ReadError> comment() {  // [15]
    const std::size_t from = p_;
    const auto dd = s_.find("--", p_ + 4);
    if (dd == std::string_view::npos) return err(Reject::malformed, from, "unterminated comment");
    if (dd + 2 >= s_.size() || s_[dd + 2] != '>') return err(Reject::malformed, dd, "'--' inside a comment");
    p_ = dd + 3;
    item(ItemKind::comment, from, current());
    return std::nullopt;
  }

  std::optional<ReadError> cdata() {  // [18]-[21]
    const std::size_t from = p_;
    if (open_.empty()) return err(Reject::malformed, from, "CDATA outside the root element");
    const auto end = s_.find("]]>", p_ + 9);
    if (end == std::string_view::npos) return err(Reject::malformed, from, "unterminated CDATA section");
    if (end - (p_ + 9) > kMaxValueBytes) return err(Reject::limit, from, "CDATA section too long");
    p_ = end + 3;
    item(ItemKind::cdata, from, current());
    return std::nullopt;
  }

  std::optional<ReadError> pi() {  // [16], [17]
    const std::size_t from = p_;
    p_ += 2;
    const std::size_t n = ncname(p_);
    if (n == 0) return err(Reject::malformed, from, "processing instruction without a target");
    if (iequal(s_.substr(p_, n), "xml")) return err(Reject::malformed, from, "reserved processing instruction target");
    p_ += n;
    if (!at("?>") && (p_ >= s_.size() || !is_space(s_[p_]))) return err(Reject::malformed, from, "bad processing instruction");
    const auto end = s_.find("?>", p_);
    if (end == std::string_view::npos) return err(Reject::malformed, from, "unterminated processing instruction");
    if (end - from > kMaxValueBytes) return err(Reject::limit, from, "processing instruction too long");
    p_ = end + 2;
    item(ItemKind::pi, from, current());
    return std::nullopt;
  }

  std::optional<ReadError> text() {  // [14]
    const std::size_t from = p_;
    auto end = s_.find('<', p_);
    if (end == std::string_view::npos) end = s_.size();
    const std::string_view t = s_.substr(p_, end - p_);
    p_ = end;
    const bool ws = std::all_of(t.begin(), t.end(), is_space);
    if (open_.empty()) {
      if (!ws) return err(Reject::malformed, from, "character data outside the root element");
      item(ItemKind::text, from, kNoElement, true);
      return std::nullopt;
    }
    if (t.size() > kMaxValueBytes) return err(Reject::limit, from, "text too long");
    if (!ws) {
      if (t.find("]]>") != std::string_view::npos) return err(Reject::malformed, from, "']]>' in character data");
      if (t.find('&') != std::string_view::npos && !unescape(t, false)) {
        return err(Reject::malformed, from, "bad reference in character data");
      }
    }
    item(ItemKind::text, from, current(), ws);
    return std::nullopt;
  }

  std::optional<ReadError> end_tag() {  // [42]
    const std::size_t from = p_;
    p_ += 2;
    std::string_view prefix, local;
    Span name;
    if (auto e = qname(prefix, local, name)) return e;
    skip_space();
    if (p_ >= s_.size() || s_[p_] != '>') return err(Reject::malformed, from, "bad end tag");
    ++p_;
    if (open_.empty()) return err(Reject::malformed, from, "end tag without start tag");
    auto& el = d_.elements[open_.back()];
    if (s_.substr(name.off, name.len) != s_.substr(el.name_span.off, el.name_span.len)) {
      return err(Reject::malformed, from, "end tag does not match the start tag");
    }
    el.end_tag = Span{from, p_ - from};
    el.content = Span{el.start_tag.end(), from - el.start_tag.end()};
    item(ItemKind::end, from, open_.back());
    open_.pop_back();
    pop_scope();
    return std::nullopt;
  }

  void pop_scope() {
    scope_.resize(marks_.back());
    marks_.pop_back();
  }

  std::optional<std::string_view> lookup(std::string_view prefix) const {
    for (auto it = scope_.rbegin(); it != scope_.rend(); ++it) {
      if (it->first == prefix) return std::string_view(it->second);
    }
    return std::nullopt;
  }

  std::optional<ReadError> start_tag() {  // [40], [44], [41]
    const std::size_t from = p_;
    ++p_;
    if (!open_.empty() || d_.elements.empty()) {
      // ok: a child, or the first root
    } else {
      return err(Reject::malformed, from, "more than one root element");
    }
    if (d_.elements.size() >= kMaxElements) return err(Reject::limit, from, "too many elements");
    if (open_.size() >= kMaxDepth) return err(Reject::limit, from, "nesting too deep");
    std::string_view prefix, local;
    Span name;
    if (auto e = qname(prefix, local, name)) return e;

    const auto first_attr = static_cast<std::uint32_t>(d_.attributes.size());
    std::vector<std::pair<std::string_view, std::string_view>> raw_names;  // (prefix, local)
    bool empty = false;
    for (;;) {
      const std::size_t ws_from = p_;
      skip_space();
      if (p_ >= s_.size()) return err(Reject::malformed, from, "unterminated start tag");
      if (s_[p_] == '>') {
        ++p_;
        break;
      }
      if (at("/>")) {
        p_ += 2;
        empty = true;
        break;
      }
      if (p_ == ws_from) return err(Reject::malformed, p_, "whitespace expected before an attribute");
      std::string_view ap, al;
      Span an;
      if (auto e = qname(ap, al, an)) return e;
      skip_space();
      if (p_ >= s_.size() || s_[p_] != '=') return err(Reject::malformed, p_, "'=' expected");
      ++p_;
      skip_space();
      if (p_ >= s_.size() || (s_[p_] != '"' && s_[p_] != '\'')) return err(Reject::malformed, p_, "quoted value expected");
      const char q = s_[p_];
      const auto close = s_.find(q, p_ + 1);
      if (close == std::string_view::npos) return err(Reject::malformed, p_, "unterminated attribute value");
      const Span vs{p_ + 1, close - p_ - 1};
      if (vs.len > kMaxValueBytes) return err(Reject::limit, p_, "attribute value too long");
      const std::string_view raw = s_.substr(vs.off, vs.len);
      if (raw.find('<') != std::string_view::npos) return err(Reject::malformed, vs.off, "'<' in an attribute value");
      auto value = unescape(raw, true);
      if (!value) return err(Reject::malformed, vs.off, "bad reference in an attribute value");
      p_ = close + 1;
      if (d_.attributes.size() - first_attr >= kMaxAttributes) return err(Reject::limit, an.off, "too many attributes");
      for (const auto& [rp, rl] : raw_names) {
        if (rp == ap && rl == al) return err(Reject::malformed, an.off, "duplicate attribute");
      }
      raw_names.emplace_back(ap, al);
      Attribute a;
      a.span = Span{ws_from, p_ - ws_from};
      a.name_span = an;
      a.value_span = vs;
      a.quote = q;
      a.value = std::move(*value);
      if ((ap.empty() && al == "xmlns") || ap == "xmlns") {
        a.ns_decl = true;
        a.declared_prefix = ap.empty() ? std::string() : std::string(al);
      }
      a.name.local = std::string(al);
      a.name.ns = std::string(ap);  // the prefix for now; resolved below
      d_.attributes.push_back(std::move(a));
    }

    // Namespace declarations of this element (Namespaces §3, §5).
    marks_.push_back(scope_.size());
    for (std::uint32_t i = first_attr; i < d_.attributes.size(); ++i) {
      auto& a = d_.attributes[i];
      if (!a.ns_decl) continue;
      const std::string& pfx = a.declared_prefix;
      if (pfx == "xmlns") return err(Reject::malformed, a.name_span.off, "the xmlns prefix cannot be declared");
      if (pfx == "xml" && a.value != kXmlNs) return err(Reject::malformed, a.name_span.off, "the xml prefix cannot be rebound");
      if (pfx != "xml" && (a.value == kXmlNs || a.value == kXmlnsNs)) {
        return err(Reject::malformed, a.name_span.off, "reserved namespace name bound");
      }
      if (!pfx.empty() && a.value.empty()) return err(Reject::malformed, a.name_span.off, "empty namespace name for a prefix");
      scope_.emplace_back(pfx, a.value);
    }

    Element el;
    if (prefix.empty()) {
      el.name.ns = std::string(lookup("").value_or(""));
    } else {
      auto ns = lookup(prefix);
      if (!ns) return err(Reject::malformed, name.off, "undeclared prefix");
      el.name.ns = std::string(*ns);
    }
    el.name.local = std::string(local);
    for (std::uint32_t i = first_attr; i < d_.attributes.size(); ++i) {
      auto& a = d_.attributes[i];
      if (a.ns_decl) {
        a.name.ns = std::string(kXmlnsNs);
        continue;
      }
      const std::string pfx = std::move(a.name.ns);
      if (pfx.empty()) {
        a.name.ns.clear();
      } else {
        auto ns = lookup(pfx);
        if (!ns) return err(Reject::malformed, a.name_span.off, "undeclared attribute prefix");
        a.name.ns = std::string(*ns);
      }
      for (std::uint32_t j = first_attr; j < i; ++j) {
        if (!d_.attributes[j].ns_decl && d_.attributes[j].name == a.name) {
          return err(Reject::malformed, a.name_span.off, "duplicate attribute after namespace expansion");
        }
      }
    }
    el.name_span = name;
    el.start_tag = Span{from, p_ - from};
    el.parent = current();
    el.depth = static_cast<std::uint32_t>(open_.size() + 1);
    el.attr_first = first_attr;
    el.attr_count = static_cast<std::uint32_t>(d_.attributes.size() - first_attr);
    el.empty_tag = empty;
    if (empty) el.content = Span{p_, 0};
    if (!open_.empty()) d_.elements[open_.back()].simple = false;
    const auto id = static_cast<std::uint32_t>(d_.elements.size());
    d_.elements.push_back(std::move(el));
    item(empty ? ItemKind::empty : ItemKind::start, from, id);
    if (empty) {
      pop_scope();
    } else {
      open_.push_back(id);
    }
    return std::nullopt;
  }

  std::string_view s_;
  Document& d_;
  std::vector<std::pair<std::string, std::string>>& scope_;
  std::vector<std::size_t>& marks_;
  std::vector<std::uint32_t>& open_;
  std::size_t p_ = 0;
};

}  // namespace

std::string_view to_string(Reject r) {
  switch (r) {
    case Reject::malformed: return "malformed";
    case Reject::encoding: return "encoding";
    case Reject::limit: return "limit";
    case Reject::dtd: return "dtd";
  }
  return "malformed";
}

std::expected<const Document*, ReadError> Reader::read(std::string_view body) {
  doc_.bom = false;
  doc_.decl.reset();
  doc_.items.clear();
  doc_.elements.clear();
  doc_.attributes.clear();
  scope_.clear();
  scope_.emplace_back("xml", std::string(kXmlNs));
  scope_marks_.clear();
  open_.clear();
  Parser p(body, doc_, scope_, scope_marks_, open_);
  if (auto e = p.run()) return std::unexpected(*e);
  return &doc_;
}

}  // namespace mcxanon::xml
