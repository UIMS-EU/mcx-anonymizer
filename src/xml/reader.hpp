// SPDX-License-Identifier: GPL-3.0-or-later
//
// A minimal, non-validating XML 1.0 + Namespaces reader that keeps the byte span of every item
// It never processes a document type declaration, recognises only the five
// predefined entities and character references, accepts UTF-8 (and its US-ASCII subset) only,
// and enforces the bounds of xml/limits.hpp. One pass, linear in the body size.
//
// Grammar references are productions of W3C XML 1.0 (Fifth Edition) and Namespaces in XML 1.0
// (Third Edition), cited by number; neither document is in the local index (plan P8).
#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace mcxanon::xml {

struct Span {
  std::size_t off = 0;
  std::size_t len = 0;
  std::size_t end() const { return off + len; }
  friend bool operator==(const Span&, const Span&) = default;
};

// An expanded name (Namespaces §3): the namespace name ("" for none) and the local part.
struct QName {
  std::string ns;
  std::string local;
  friend bool operator==(const QName&, const QName&) = default;
};

inline constexpr std::uint32_t kNoElement = 0xFFFFFFFFu;

struct Attribute {
  QName name;              // unprefixed attributes have no namespace (Namespaces §6.2)
  Span span;               // from the whitespace before the name to the closing quote
  Span name_span;
  Span value_span;         // between the quotes, raw
  char quote = '"';
  std::string value;       // the normalised, unescaped value (XML 1.0 §3.3.3)
  bool ns_decl = false;    // xmlns or xmlns:prefix
  std::string declared_prefix;  // for ns_decl: "" for the default namespace
};

struct Element {
  QName name;
  Span name_span;          // the raw (prefixed) name in the start tag
  Span start_tag;          // '<' to '>' of the start tag, or of the empty-element tag
  std::optional<Span> end_tag;
  Span content;            // between the tags; empty (len 0) for an empty-element tag
  std::uint32_t parent = kNoElement;
  std::uint32_t depth = 1; // the root is 1
  std::uint32_t attr_first = 0;
  std::uint32_t attr_count = 0;
  bool simple = true;      // content is character data, CDATA, comments and PIs only
  bool empty_tag = false;  // written as <x/>
};

enum class ItemKind : std::uint8_t {
  decl,     // the XML declaration
  start,    // a start tag (element = its element)
  end,      // an end tag (element = its element)
  empty,    // an empty-element tag (element = its element)
  text,     // character data (element = the enclosing element, kNoElement outside the root)
  cdata,    // a CDATA section, the whole markup (element = the enclosing element)
  comment,  // a comment (element = the enclosing element or kNoElement)
  pi,       // a processing instruction other than the XML declaration
};

struct Item {
  ItemKind kind = ItemKind::text;
  Span span;
  std::uint32_t element = kNoElement;
  bool whitespace = false;  // text made of S characters only (XML 1.0 [3])
};

struct Document {
  bool bom = false;
  std::optional<Span> decl;
  std::vector<Item> items;        // document order
  std::vector<Element> elements;  // element id = index; elements[0] is the root
  std::vector<Attribute> attributes;

  const Attribute* attrs(const Element& e) const { return attributes.data() + e.attr_first; }
};

enum class Reject : std::uint8_t {
  malformed,  // not well-formed XML 1.0 + Namespaces
  encoding,   // not UTF-8 / US-ASCII, or invalid UTF-8
  limit,      // a bound of xml/limits.hpp exceeded
  dtd,        // a document type declaration is present (FR-004)
};

struct ReadError {
  Reject reason = Reject::malformed;
  std::size_t offset = 0;
  const char* what = "";  // a fixed English description, never input text
};

std::string_view to_string(Reject r);

// Reads one body. The buffers of the previous call are reused; the returned document stays
// valid until the next call.
class Reader {
 public:
  std::expected<const Document*, ReadError> read(std::string_view body);

 private:
  Document doc_;
  std::vector<std::pair<std::string, std::string>> scope_;  // prefix -> namespace name
  std::vector<std::size_t> scope_marks_;
  std::vector<std::uint32_t> open_;
};

}  // namespace mcxanon::xml
