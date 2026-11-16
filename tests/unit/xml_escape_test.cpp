// SPDX-License-Identifier: GPL-3.0-or-later
//
// XML references and escaping (feature 003, FR-011).
#include "xml/escape.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace mcxanon::xml;

TEST_CASE("xml unescape: the five predefined entities and character references") {
  CHECK(unescape("a&amp;b&lt;c&gt;d&quot;e&apos;f", false) == "a&b<c>d\"e'f");
  CHECK(unescape("user&#64;host", false) == "user@host");
  CHECK(unescape("user&#x40;host&#X41;", false) == std::nullopt);  // 'X' is not allowed ([66])
  CHECK(unescape("&#x40;&#x1F600;", false) == "@\xF0\x9F\x98\x80");
  CHECK(unescape("plain", false) == "plain");
  CHECK(unescape("", false) == "");
}

TEST_CASE("xml unescape: anything else is rejected") {
  CHECK(unescape("&nbsp;", false) == std::nullopt);       // not predefined
  CHECK(unescape("&amp", false) == std::nullopt);         // unterminated
  CHECK(unescape("a & b", false) == std::nullopt);        // bare ampersand
  CHECK(unescape("&#0;", false) == std::nullopt);         // not a Char
  CHECK(unescape("&#x1;", false) == std::nullopt);        // C0 control
  CHECK(unescape("&#xD800;", false) == std::nullopt);     // surrogate
  CHECK(unescape("&#xFFFE;", false) == std::nullopt);     // not a Char
  CHECK(unescape("&#x110000;", false) == std::nullopt);   // beyond Unicode
  CHECK(unescape("&#;", false) == std::nullopt);
  CHECK(unescape("&#x;", false) == std::nullopt);
  CHECK(unescape("&#99999999999999999999;", false) == std::nullopt);
}

TEST_CASE("xml unescape: attribute value normalisation") {
  CHECK(unescape("a\tb\nc\r\nd\re", true) == "a b c d e");
  CHECK(unescape("a&#9;b&#10;c", true) == "a\tb\nc");  // references are not normalised
  CHECK(unescape("a\tb", false) == "a\tb");            // character data keeps them
}

TEST_CASE("xml escape: text and both quote styles") {
  CHECK(escape_text("a&b<c>d\"e'f") == "a&amp;b&lt;c&gt;d\"e'f");
  CHECK(escape_attr("a&b<c\"d'e", '"') == "a&amp;b&lt;c&quot;d'e");
  CHECK(escape_attr("a&b<c\"d'e", '\'') == "a&amp;b&lt;c\"d&apos;e");
  CHECK(escape_attr("a\tb\nc\rd", '"') == "a&#9;b&#10;c&#13;d");
}

TEST_CASE("xml escape: a round trip keeps the value") {
  for (std::string_view v : {"sip:a&b@example.net;x=\"1\"", "t<u@v", "plain", "x\ty", "]]>"}) {
    CHECK(unescape(escape_text(v), false) == std::string(v));
    CHECK(unescape(escape_attr(v, '"'), true) == std::string(v));
    CHECK(unescape(escape_attr(v, '\''), true) == std::string(v));
  }
  CHECK(escape_text("]]>").find("]]>") == std::string::npos);
}

TEST_CASE("xml Char production") {
  CHECK(is_xml_char(0x9));
  CHECK(is_xml_char(0xA));
  CHECK(is_xml_char(0xD));
  CHECK(is_xml_char(0x20));
  CHECK(is_xml_char(0xD7FF));
  CHECK(is_xml_char(0xE000));
  CHECK(is_xml_char(0xFFFD));
  CHECK(is_xml_char(0x10000));
  CHECK(is_xml_char(0x10FFFF));
  CHECK_FALSE(is_xml_char(0x0));
  CHECK_FALSE(is_xml_char(0x1F));
  CHECK_FALSE(is_xml_char(0xD800));
  CHECK_FALSE(is_xml_char(0xFFFE));
  CHECK_FALSE(is_xml_char(0x110000));
}
