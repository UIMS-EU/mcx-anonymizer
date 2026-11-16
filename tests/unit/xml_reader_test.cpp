// SPDX-License-Identifier: GPL-3.0-or-later
//
// The XML reader (feature 003, FR-003, FR-004, FR-005).
#include "xml/limits.hpp"
#include "xml/reader.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace mcxanon::xml;

namespace {

std::string_view sub(std::string_view body, Span s) { return body.substr(s.off, s.len); }

Reject reason_of(std::string_view body) {
  Reader r;
  auto d = r.read(body);
  REQUIRE_FALSE(d.has_value());
  return d.error().reason;
}

const Document& ok(Reader& r, std::string_view body) {
  auto d = r.read(body);
  if (!d) FAIL("rejected: " << d.error().what << " at " << d.error().offset);
  return **d;
}

constexpr const char* kNs = "urn:3gpp:ns:mcpttInfo:1.0";

}  // namespace

TEST_CASE("xml reader: spans of names, values, text and markup") {
  const std::string body =
      "\xEF\xBB\xBF<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
      "<!-- head -->\r\n"
      "<m:mcpttinfo xmlns:m='urn:3gpp:ns:mcpttInfo:1.0'>\r\n"
      "  <m:mcptt-Params><m:session-type>prearranged</m:session-type>"
      "<m:x a=\"1&amp;2\" b = 'q'/><?pi data?><![CDATA[a<b]]></m:mcptt-Params>\r\n"
      "</m:mcpttinfo>\r\n";
  Reader r;
  const auto& d = ok(r, body);
  CHECK(d.bom);
  REQUIRE(d.decl);
  CHECK(sub(body, *d.decl) == "<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
  REQUIRE(d.elements.size() == 4);
  const auto& root = d.elements[0];
  CHECK(root.name == QName{kNs, "mcpttinfo"});
  CHECK(sub(body, root.name_span) == "m:mcpttinfo");
  CHECK(root.parent == kNoElement);
  CHECK(root.depth == 1);
  CHECK_FALSE(root.simple);
  REQUIRE(root.attr_count == 1);
  CHECK(d.attrs(root)[0].ns_decl);
  CHECK(d.attrs(root)[0].declared_prefix == "m");
  CHECK(d.attrs(root)[0].value == kNs);
  CHECK(d.attrs(root)[0].quote == '\'');
  CHECK(sub(body, d.attrs(root)[0].span) == " xmlns:m='urn:3gpp:ns:mcpttInfo:1.0'");

  const auto& st = d.elements[2];
  CHECK(st.name.local == "session-type");
  CHECK(st.parent == 1);
  CHECK(st.depth == 3);
  CHECK(st.simple);
  CHECK(sub(body, st.content) == "prearranged");
  CHECK(sub(body, st.start_tag) == "<m:session-type>");
  REQUIRE(st.end_tag);
  CHECK(sub(body, *st.end_tag) == "</m:session-type>");

  const auto& x = d.elements[3];
  CHECK(x.empty_tag);
  CHECK(x.content.len == 0);
  CHECK_FALSE(x.end_tag);
  REQUIRE(x.attr_count == 2);
  const auto* xa = d.attrs(x);
  CHECK(xa[0].name == QName{"", "a"});  // unprefixed attribute: no namespace
  CHECK(sub(body, xa[0].value_span) == "1&amp;2");
  CHECK(xa[0].value == "1&2");
  CHECK(sub(body, xa[0].span) == " a=\"1&amp;2\"");
  CHECK(sub(body, xa[1].span) == " b = 'q'");
  CHECK(sub(body, xa[1].name_span) == "b");

  bool saw_pi = false, saw_cdata = false, saw_comment = false;
  for (const auto& it : d.items) {
    if (it.kind == ItemKind::pi) {
      saw_pi = true;
      CHECK(sub(body, it.span) == "<?pi data?>");
      CHECK(it.element == 1);
    }
    if (it.kind == ItemKind::cdata) {
      saw_cdata = true;
      CHECK(sub(body, it.span) == "<![CDATA[a<b]]>");
    }
    if (it.kind == ItemKind::comment) {
      saw_comment = true;
      CHECK(it.element == kNoElement);
    }
  }
  CHECK(saw_pi);
  CHECK(saw_cdata);
  CHECK(saw_comment);
  CHECK(d.elements[1].simple == false);
}

TEST_CASE("xml reader: every byte is covered by the items in order") {
  const std::string body = "<?xml version='1.0'?>\n<a xmlns='urn:x'>\n <b c='d'>t</b>\n <e/>\n</a>\n";
  Reader r;
  const auto& d = ok(r, body);
  std::size_t at = 0;
  for (const auto& it : d.items) {
    CHECK(it.span.off == at);
    at = it.span.end();
  }
  CHECK(at == body.size());
}

TEST_CASE("xml reader: namespace resolution") {
  Reader r;
  SECTION("default namespace and redeclaration in a child") {
    const auto& d = ok(r, "<a xmlns='urn:one'><b xmlns='urn:two'><c/></b><d/></a>");
    CHECK(d.elements[0].name.ns == "urn:one");
    CHECK(d.elements[1].name.ns == "urn:two");
    CHECK(d.elements[2].name.ns == "urn:two");
    CHECK(d.elements[3].name.ns == "urn:one");
  }
  SECTION("undeclaring the default namespace") {
    const auto& d = ok(r, "<a xmlns='urn:one'><b xmlns=''/></a>");
    CHECK(d.elements[1].name.ns.empty());
  }
  SECTION("the same namespace under two prefixes") {
    const auto& d = ok(r, "<p:a xmlns:p='urn:x' xmlns:q='urn:x'><q:b/></p:a>");
    CHECK(d.elements[1].name == QName{"urn:x", "b"});
  }
  SECTION("prefixed attributes and the implicit xml prefix") {
    const auto& d = ok(r, "<a xmlns:p='urn:x' p:k='1' xml:lang='en'/>");
    const auto* at = d.attrs(d.elements[0]);
    CHECK(at[1].name == QName{"urn:x", "k"});
    CHECK(at[2].name == QName{"http://www.w3.org/XML/1998/namespace", "lang"});
  }
  SECTION("xml prefix bound to its own namespace is accepted") {
    ok(r, "<a xmlns:xml='http://www.w3.org/XML/1998/namespace'/>");
  }
}

TEST_CASE("xml reader: not well-formed documents are malformed") {
  for (const char* body : {
           "<a>",                                  // unclosed
           "<a></b>",                              // mismatched end tag
           "<a/><b/>",                             // two roots
           "text<a/>",                             // text before the root
           "<a/>text",                             // text after the root
           "",                                     // no root
           "<a b='1' b='2'/>",                     // duplicate attribute
           "<a xmlns:p='urn:x' xmlns:q='urn:x' p:k='1' q:k='2'/>",  // duplicate after expansion
           "<a b='<'/>",                           // '<' in a value
           "<a b='1'c='2'/>",                      // no space between attributes
           "<a b=1/>",                             // unquoted value
           "<a>x]]>y</a>",                         // ']]>' in character data
           "<a><!-- x -- y --></a>",               // '--' in a comment
           "<a><!-- x ---></a>",                   // comment ending in '-'
           "<1a/>",                                // bad name start
           "<a:b/>",                               // undeclared prefix
           "<a p:k='1'/>",                         // undeclared attribute prefix
           "<a xmlns:p=''/>",                      // empty prefixed namespace
           "<a xmlns:xml='urn:other'/>",           // rebinding xml
           "<a xmlns:xmlns='urn:x'/>",             // declaring xmlns
           "<a xmlns:p='http://www.w3.org/XML/1998/namespace'/>",  // another prefix for xml
           "<a>&nbsp;</a>",                        // unknown entity
           "<a>&#1;</a>",                          // reference to a non-Char
           "<a>a & b</a>",                         // bare ampersand
           "<a>\x01</a>",                          // a control character
           "<a><?xml version='1.0'?></a>",         // the declaration not at the start
           "<a><?XmL x?></a>",                     // a reserved PI target
           "<![CDATA[x]]><a/>",                    // CDATA outside the root
           "<a b='1' / >",                         // broken empty-element tag
           "<?xml version='2.0'?><a/>",            // unknown version
           "<?xml encoding='UTF-8'?><a/>",         // version missing
       }) {
    INFO(body);
    CHECK(reason_of(body) == Reject::malformed);
  }
}

TEST_CASE("xml reader: encodings other than UTF-8 are rejected as encoding") {
  for (const std::string& body : {
           std::string("<a>\xC3</a>"),                       // truncated sequence
           std::string("<a>\xC0\xAF</a>"),                   // overlong
           std::string("<a>\xED\xA0\x80</a>"),               // surrogate
           std::string("<a>\xF4\x90\x80\x80</a>"),           // beyond U+10FFFF
           std::string("\xFF\xFE<\0a\0/\0>\0", 10),          // UTF-16LE BOM
           std::string("\xFE\xFF\0<\0a\0/\0>", 10),          // UTF-16BE BOM
           std::string("\0<\0a\0/\0>", 8),                   // UTF-16BE without BOM
           std::string("<?xml version='1.0' encoding='ISO-8859-1'?><a/>"),
           std::string("<?xml version='1.0' encoding='UTF-16'?><a/>"),
       }) {
    CHECK(reason_of(body) == Reject::encoding);
  }
  Reader r;
  ok(r, "<?xml version='1.0' encoding='utf-8'?><a/>");
  ok(r, "<?xml version='1.0' encoding='US-ASCII' standalone='yes'?><a/>");
  ok(r, "<a>\xE2\x82\xAC \xF0\x9F\x98\x80</a>");
}

TEST_CASE("xml reader: a document type declaration is never processed") {
  CHECK(reason_of("<!DOCTYPE a [<!ENTITY x 'y'>]><a>&x;</a>") == Reject::dtd);
  CHECK(reason_of("<?xml version='1.0'?><!DOCTYPE a SYSTEM 'http://example.net/a.dtd'><a/>") == Reject::dtd);
  std::string laughs = "<?xml version='1.0'?><!DOCTYPE l [<!ENTITY l0 'ha'>";
  for (int i = 1; i < 10; ++i) {
    laughs += "<!ENTITY l" + std::to_string(i) + " '";
    for (int j = 0; j < 10; ++j) laughs += "&l" + std::to_string(i - 1) + ";";
    laughs += "'>";
  }
  laughs += "]><l>&l9;</l>";
  CHECK(reason_of(laughs) == Reject::dtd);
}

TEST_CASE("xml reader: bounds") {
  auto nested = [](std::size_t depth) {
    std::string s;
    for (std::size_t i = 0; i < depth; ++i) s += "<a>";
    for (std::size_t i = 0; i < depth; ++i) s += "</a>";
    return s;
  };
  Reader r;
  ok(r, nested(kMaxDepth));
  CHECK(reason_of(nested(kMaxDepth + 1)) == Reject::limit);

  auto many = [](std::size_t n) {
    std::string s = "<r>";
    for (std::size_t i = 1; i < n; ++i) s += "<e/>";
    return s + "</r>";
  };
  ok(r, many(kMaxElements));
  CHECK(reason_of(many(kMaxElements + 1)) == Reject::limit);

  auto attrs = [](std::size_t n) {
    std::string s = "<r";
    for (std::size_t i = 0; i < n; ++i) s += " a" + std::to_string(i) + "='v'";
    return s + "/>";
  };
  ok(r, attrs(kMaxAttributes));
  CHECK(reason_of(attrs(kMaxAttributes + 1)) == Reject::limit);

  ok(r, "<" + std::string(kMaxNameBytes, 'n') + "/>");
  CHECK(reason_of("<" + std::string(kMaxNameBytes + 1, 'n') + "/>") == Reject::limit);

  ok(r, "<r a='" + std::string(kMaxValueBytes, 'v') + "'/>");
  CHECK(reason_of("<r a='" + std::string(kMaxValueBytes + 1, 'v') + "'/>") == Reject::limit);
  ok(r, "<r>" + std::string(kMaxValueBytes, 't') + "</r>");
  CHECK(reason_of("<r>" + std::string(kMaxValueBytes + 1, 't') + "</r>") == Reject::limit);

  CHECK(reason_of("<r>" + std::string(kMaxBodyBytes, ' ') + "</r>") == Reject::limit);
}

TEST_CASE("xml reader: a large body is read in one pass and buffers are reused") {
  std::string body = "<r xmlns='urn:x'>";
  const std::string text(90, 't');
  for (int i = 0; i < 9000; ++i) body += "<e k='v'>" + text + "</e>";  // about 950 KiB
  body += "</r>";
  Reader r;
  const auto& d = ok(r, body);
  CHECK(d.elements.size() > 1000);
  CHECK(d.elements.size() <= kMaxElements);
  const auto& d2 = ok(r, "<a/>");
  CHECK(d2.elements.size() == 1);
  CHECK(d2.attributes.empty());
}
