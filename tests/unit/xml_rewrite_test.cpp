// SPDX-License-Identifier: GPL-3.0-or-later
//
// The XML edit engine (feature 003, FR-006 to FR-011,
// FR-018, SC-004).
#include "policy/xml_rules.hpp"
#include "xml/reader.hpp"
#include "xml/rewrite.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using namespace mcxanon;
using namespace mcxanon::xml;

namespace {

constexpr const char* kCt = "application/vnd.3gpp.mcptt-info+xml";
constexpr const char* kNs = "urn:3gpp:ns:mcpttInfo:1.0";
const std::string kS = R"(source: {spec: TS 24.379, version: "19.6.0", clause: "F.1.3"})";

const XmlRuleSet& rules() {
  static const XmlRuleSet rs = [] {
    const std::string text =
        "ruleset: mcxanon-xml\nversion: 1.0.0\n"
        "documents:\n"
        "  - content_type: application/vnd.3gpp.mcptt-info+xml\n"
        "    roots: [{ns: \"urn:3gpp:ns:mcpttInfo:1.0\", name: mcpttinfo}]\n"
        "    source: {spec: TS 24.379, version: \"19.6.0\", clause: \"F.1.4\"}\n"
        "namespaces:\n"
        "  - name: \"urn:3gpp:ns:mcpttInfo:1.0\"\n"
        "    source: {spec: TS 24.379, version: \"19.6.0\", clause: \"F.1.2\"}\n"
        "    elements:\n"
        "      - {name: mcpttinfo, action: container, " + kS + "}\n"
        "      - {name: mcptt-Params, action: container, " + kS + "}\n"
        "      - {name: session-type, action: keep, value: {enum: [private, prearranged]}, " + kS + "}\n"
        "      - {name: mcptt-request-uri, action: container, encryptable: true, " + kS + "}\n"
        "      - {name: mcpttURI, action: pseudonymise, category: uri, " + kS + "}\n"
        "      - {name: alert-text, action: remove, reason: free-text, " + kS + "}\n"
        "      - {name: coord, action: fixed, constant: \"0\", " + kS + "}\n"
        "      - {name: sig, action: empty, " + kS + "}\n"
        "    attributes:\n"
        "      - {element: \"*\", name: type, action: keep, value: {enum: [Normal, Encrypted]}, " + kS + "}\n"
        "      - {element: mcptt-Params, name: who, action: pseudonymise, category: uri, " + kS + "}\n"
        "      - {element: mcptt-Params, name: note, action: remove, reason: free-text, " + kS + "}\n"
        "  - name: \"http://www.w3.org/XML/1998/namespace\"\n"
        "    source: {spec: TS 37.579-5, version: \"19.1.0\", clause: \"XSD xml\"}\n"
        "    attributes:\n"
        "      - {element: \"*\", ns: \"http://www.w3.org/XML/1998/namespace\", name: lang, action: keep, value: lang, " + kS + "}\n"
        "  - name: \"http://www.w3.org/2001/04/xmlenc#\"\n"
        "    disposition: remove_encrypted\n"
        "    source: {spec: TS 33.180, version: \"20.0.0\", clause: \"9.3.4.2\"}\n";
    std::vector<RuleFile> files{RuleFile{"xml-test.yaml", text}};
    auto r = load_xml_ruleset(files);
    if (!r) throw std::runtime_error(r.error().message);
    return *r;
  }();
  return rs;
}

// Maps a URI to "sip:p-<user>@example.org"; a value containing "bad" does not fit.
struct FakeMapper : ValueMapper {
  std::vector<std::string> removed_values;
  Result<std::optional<std::string>> map(XmlCategory, std::string_view v) override {
    if (v.find("bad") != std::string_view::npos) return std::optional<std::string>{};
    const auto colon = v.find(':');
    const auto at = v.find('@');
    if (colon == std::string_view::npos || at == std::string_view::npos) return std::optional<std::string>{};
    return std::optional<std::string>("sip:p-" + std::string(v.substr(colon + 1, at - colon - 1)) + "&x@example.org");
  }
  void removed(std::string_view v) override { removed_values.emplace_back(v); }
};

struct Run {
  Counters counters;
  FakeMapper mapper;
  Outcome out;
};

Run run(const std::string& body, std::string_view charset = "") {
  Run r;
  BodyRewriter rw(rules(), r.counters, RewriteOptions{true});
  auto o = rw.rewrite(kCt, charset, body, r.mapper);
  REQUIRE(o.has_value());
  r.out = std::move(*o);
  return r;
}

std::string doc(const std::string& inner, const std::string& root_attrs = "") {
  return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n<mcpttinfo xmlns=\"urn:3gpp:ns:mcpttInfo:1.0\"" + root_attrs +
         ">\r\n  <mcptt-Params>" + inner + "</mcptt-Params>\r\n</mcpttinfo>\r\n";
}

std::uint64_t count(const Counters& c, const std::string& local, const std::string& action) {
  auto it = c.elements.find({kNs, local});
  if (it == c.elements.end()) return 0;
  auto a = it->second.find(action);
  return a == it->second.end() ? 0 : a->second;
}

bool well_formed(const std::string& s) {
  Reader r;
  return r.read(s).has_value();
}

}  // namespace

TEST_CASE("xml rewrite: kept bytes are the input's; values are replaced in place") {
  const std::string in = doc("<session-type>prearranged</session-type>"
                             "<mcptt-request-uri type='Normal'><mcpttURI>sip:alice@example.net</mcpttURI></mcptt-request-uri>");
  auto r = run(in);
  REQUIRE(r.out.rewritten);
  const std::string expect = doc("<session-type>prearranged</session-type>"
                                 "<mcptt-request-uri type='Normal'><mcpttURI>sip:p-alice&amp;x@example.org</mcpttURI></mcptt-request-uri>");
  CHECK(r.out.bytes == expect);
  CHECK(count(r.counters, "session-type", "keep") == 1);
  CHECK(count(r.counters, "mcpttURI", "pseudonymise") == 1);
  CHECK(count(r.counters, "mcptt-Params", "container") == 1);
  CHECK(r.counters.bodies.at(kCt).at("rewritten") == 1);
}

TEST_CASE("xml rewrite: a URI written with character references maps to the same pseudonym") {
  auto a = run(doc("<mcptt-request-uri><mcpttURI>sip:alice@example.net</mcpttURI></mcptt-request-uri>"));
  auto b = run(doc("<mcptt-request-uri><mcpttURI>sip:alice&#x40;example.net</mcpttURI></mcptt-request-uri>"));
  CHECK(a.out.bytes == b.out.bytes);
}

TEST_CASE("xml rewrite: whitespace around a replaced value stays") {
  auto r = run(doc("<mcptt-request-uri><mcpttURI>\r\n  sip:alice@example.net\r\n</mcpttURI></mcptt-request-uri>"));
  CHECK(r.out.bytes.find("<mcpttURI>\r\n  sip:p-alice&amp;x@example.org\r\n</mcpttURI>") != std::string::npos);
}

TEST_CASE("xml rewrite: CDATA input is written as escaped text") {
  auto r = run(doc("<mcptt-request-uri><mcpttURI><![CDATA[sip:alice@example.net]]></mcpttURI></mcptt-request-uri>"));
  CHECK(r.out.bytes.find("<mcpttURI>sip:p-alice&amp;x@example.org</mcpttURI>") != std::string::npos);
  CHECK(r.out.bytes.find("CDATA") == std::string::npos);
}

TEST_CASE("xml rewrite: removal of elements, attributes, comments and processing instructions") {
  const std::string in = doc("<alert-text>Hello CANARY-1</alert-text>"
                             "<!-- CANARY-2 --><?vendor CANARY-3?>"
                             "<unknown-thing a='CANARY-4'><x>CANARY-5</x></unknown-thing>"
                             "<v:ext xmlns:v='urn:vendor:acme'>CANARY-6</v:ext><alert-text/>",
                             " xmlns:w='urn:vendor:other'");
  auto r = run(in);
  REQUIRE(r.out.rewritten);
  CHECK(r.out.bytes.find("CANARY") == std::string::npos);
  CHECK(r.out.bytes.find("urn:vendor") == std::string::npos);
  CHECK(r.out.bytes.find("<mcptt-Params></mcptt-Params>") != std::string::npos);
  CHECK(r.counters.comments == 1);
  CHECK(r.counters.processing_instructions == 1);
  CHECK(count(r.counters, "alert-text", "remove") == 2);
  CHECK(count(r.counters, "unknown-thing", "unknown") == 1);
  CHECK(r.counters.removed_namespaces.at("urn:vendor:acme") == 1);
  // The free text removed by a rule is a scan token; unknown content is not.
  REQUIRE(r.mapper.removed_values.size() == 1);
  CHECK(r.mapper.removed_values[0] == "Hello CANARY-1");
  CHECK(well_formed(r.out.bytes));
}

TEST_CASE("xml rewrite: attributes by rule") {
  auto r = run("<mcpttinfo xmlns='urn:3gpp:ns:mcpttInfo:1.0' xml:lang='en'><mcptt-Params who=\"sip:bob@example.net\" "
               "note='CANARY-7' extra='CANARY-8' type='Bogus'/></mcpttinfo>");
  REQUIRE(r.out.rewritten);
  CHECK(r.out.bytes == "<mcpttinfo xmlns='urn:3gpp:ns:mcpttInfo:1.0' xml:lang='en'>"
                       "<mcptt-Params who=\"sip:p-bob&amp;x@example.org\"/></mcpttinfo>");
  CHECK(r.counters.attributes.at({kNs, "mcptt-Params", "", "extra"}).at("unknown") == 1);
  CHECK(r.counters.attributes.at({kNs, "mcptt-Params", "", "type"}).at("malformed") == 1);
}

TEST_CASE("xml rewrite: a value that fails its type is removed, the element stays") {
  auto r = run(doc("<session-type>free text here</session-type>"
                   "<mcptt-request-uri><mcpttURI>sip:bad@example.net</mcpttURI></mcptt-request-uri>"));
  REQUIRE(r.out.rewritten);
  CHECK(r.out.bytes.find("<session-type></session-type>") != std::string::npos);
  CHECK(r.out.bytes.find("<mcpttURI></mcpttURI>") != std::string::npos);
  CHECK(count(r.counters, "session-type", "malformed") == 1);
  CHECK(count(r.counters, "mcpttURI", "malformed") == 1);
}

TEST_CASE("xml rewrite: stray text in a container is removed") {
  auto r = run(doc("CANARY-9<session-type>private</session-type>"));
  CHECK(r.out.bytes.find("CANARY") == std::string::npos);
  CHECK(count(r.counters, "mcptt-Params", "malformed") == 1);
}

TEST_CASE("xml rewrite: fixed and empty") {
  auto r = run(doc("<coord>123456</coord><sig>c2lnbmF0dXJl</sig>"));
  CHECK(r.out.bytes.find("<coord>0</coord>") != std::string::npos);
  CHECK(r.out.bytes.find("<sig></sig>") != std::string::npos);
  CHECK(count(r.counters, "coord", "fixed") == 1);
  CHECK(count(r.counters, "sig", "empty") == 1);
}

TEST_CASE("xml rewrite: encrypted content is removed at element level") {
  auto r = run(doc("<mcptt-request-uri type=\"Encrypted\"><xenc:EncryptedData xmlns:xenc='http://www.w3.org/2001/04/xmlenc#'>"
                   "<xenc:CipherData><xenc:CipherValue>Q0FOQVJZ</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>"
                   "</mcptt-request-uri><session-type>private</session-type>"));
  REQUIRE(r.out.rewritten);
  CHECK(r.out.bytes.find("<mcptt-request-uri type=\"Encrypted\"></mcptt-request-uri>") != std::string::npos);
  CHECK(r.out.bytes.find("Q0FOQVJZ") == std::string::npos);
  CHECK(r.out.bytes.find("<session-type>private</session-type>") != std::string::npos);
  CHECK(r.counters.encrypted == 1);
  CHECK(r.counters.removed_namespaces.empty());
}

TEST_CASE("xml rewrite: whole bodies are emptied with a reason") {
  auto reason = [](const std::string& body, std::string_view charset = "") {
    auto r = run(body, charset);
    CHECK_FALSE(r.out.rewritten);
    return r.out.reason;
  };
  CHECK(reason("<mcpttinfo xmlns='urn:3gpp:ns:mcpttInfo:1.0'>") == EmptyReason::malformed);
  CHECK(reason("<!DOCTYPE a><mcpttinfo/>") == EmptyReason::dtd);
  CHECK(reason("<mcpttinfo xmlns='urn:3gpp:ns:mcpttInfo:1.0'/>", "iso-8859-1") == EmptyReason::encoding);
  CHECK(reason("<other xmlns='urn:3gpp:ns:mcpttInfo:1.0'/>") == EmptyReason::root);
  CHECK(reason("<mcpttinfo xmlns='urn:vendor'/>") == EmptyReason::root);
  CHECK(reason("<xenc:EncryptedData xmlns:xenc='http://www.w3.org/2001/04/xmlenc#'/>") == EmptyReason::encrypted);
  auto ok = run("<mcpttinfo xmlns='urn:3gpp:ns:mcpttInfo:1.0'/>", "UTF-8");
  CHECK(ok.out.rewritten);
}

TEST_CASE("xml rewrite: the output does not depend on the order of the rules") {
  const std::string in = doc("<alert-text>x</alert-text><session-type>private</session-type>"
                             "<mcptt-request-uri><mcpttURI>sip:a@b.c</mcpttURI></mcptt-request-uri>");
  auto a = run(in);
  auto b = run(in);
  CHECK(a.out.bytes == b.out.bytes);
  CHECK(well_formed(a.out.bytes));
}
