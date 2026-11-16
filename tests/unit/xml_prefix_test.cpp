// SPDX-License-Identifier: GPL-3.0-or-later
//
// Feature 008 (FR-003, FR-004): namespace prefixes. A prefix that a normative schema of the
// namespace declares (rule data `prefixes`) is standard vocabulary and stays; any other prefix
// is identity-capable free text and is renamed to a neutral `ns<k>` in the whole body. The output
// stays well-formed and every kept element and attribute keeps its expanded name.
#include "policy/xml_rules.hpp"
#include "xml/reader.hpp"
#include "xml/rewrite.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <tuple>
#include <vector>

using namespace mcxanon;
using namespace mcxanon::xml;

namespace {

constexpr const char* kCt = "application/pidf+xml";
constexpr const char* kPidf = "urn:ietf:params:xml:ns:pidf";
constexpr const char* kPi = "urn:3gpp:ns:mcpttPresInfo:1.0";
const std::string kS = R"(source: {spec: TS 24.379, version: "19.6.0", clause: "9.3.1.2"})";
const std::string kX = R"(source: {spec: TS 37.579-5, version: "19.1.0", clause: "XSD RFC3863_pdif"})";

const XmlRuleSet& rules() {
  static const XmlRuleSet rs = [] {
    const std::string text =
        "ruleset: mcxanon-xml\nversion: 1.0.0\n"
        "documents:\n"
        "  - content_type: application/pidf+xml\n"
        "    roots: [{ns: \"urn:ietf:params:xml:ns:pidf\", name: presence}]\n"
        "    " + kX + "\n"
        "namespaces:\n"
        "  - name: \"urn:ietf:params:xml:ns:pidf\"\n"
        "    " + kX + "\n"
        "    prefixes:\n"
        "      - {name: tns, " + kX + "}\n"
        "    elements:\n"
        "      - {name: presence, action: container, " + kX + "}\n"
        "      - {name: tuple, action: container, " + kX + "}\n"
        "      - {name: status, action: container, " + kX + "}\n"
        "    attributes:\n"
        "      - {element: presence, name: entity, action: pseudonymise, category: uri, " + kX + "}\n"
        "      - {element: tuple, name: id, action: keep, value: {enum: [t1, t2]}, " + kX + "}\n"
        "  - name: \"urn:3gpp:ns:mcpttPresInfo:1.0\"\n"
        "    " + kS + "\n"
        "    prefixes:\n"
        "      - {name: mcpttPI10, " + kS + "}\n"
        "    elements:\n"
        "      - {name: affiliation, action: container, " + kS + "}\n"
        "      - {name: p-id, action: keep, value: {enum: [p1]}, " + kS + "}\n"
        "    attributes:\n"
        "      - {element: affiliation, name: group, action: pseudonymise, category: uri, " + kS + "}\n"
        "      - {element: affiliation, name: status, action: keep, value: {enum: [affiliated, deaffiliated]}, " + kS + "}\n"
        "      - {element: tuple, ns: \"urn:3gpp:ns:mcpttPresInfo:1.0\", name: flag, action: keep, value: boolean, " + kS + "}\n";
    std::vector<RuleFile> files{RuleFile{"xml-test.yaml", text}};
    auto r = load_xml_ruleset(files);
    if (!r) throw std::runtime_error(r.error().message);
    return *r;
  }();
  return rs;
}

struct FakeMapper : ValueMapper {
  Result<std::optional<std::string>> map(XmlCategory, std::string_view) override {
    return std::optional<std::string>("sip:u-1@d-1.invalid");
  }
  void removed(std::string_view) override {}
};

struct Run {
  Counters counters;
  FakeMapper mapper;
  Outcome out;
};

Run run(const std::string& body) {
  Run r;
  BodyRewriter rw(rules(), r.counters, RewriteOptions{true});
  auto o = rw.rewrite(kCt, "", body, r.mapper);
  REQUIRE(o.has_value());
  r.out = std::move(*o);
  return r;
}

// Element and attribute expanded names in document order (namespace declarations excluded).
std::vector<std::tuple<std::string, std::string, std::string, std::string>> names(const std::string& body) {
  Reader rd;
  auto d = rd.read(body);
  REQUIRE(d.has_value());
  std::vector<std::tuple<std::string, std::string, std::string, std::string>> out;
  for (const auto& e : (*d)->elements) {
    out.emplace_back(e.name.ns, e.name.local, "", "");
    const auto* a = (*d)->attrs(e);
    for (std::uint32_t i = 0; i < e.attr_count; ++i) {
      if (!a[i].ns_decl) out.emplace_back(e.name.ns, e.name.local, a[i].name.ns, a[i].name.local);
    }
  }
  return out;
}

std::uint64_t renamed(const Run& r, const std::string& ns) {
  const auto it = r.counters.prefixes_rewritten.find(ns);
  return it == r.counters.prefixes_rewritten.end() ? 0 : it->second;
}

std::string body(const std::string& decls, const std::string& p) {
  return "<?xml version=\"1.0\"?><presence xmlns=\"urn:ietf:params:xml:ns:pidf\"" + decls +
         " entity=\"sip:alice@example.net\"><tuple id=\"t1\"><status><" + p +
         ":affiliation group=\"sip:ops@example.net\" status=\"affiliated\"/></status></tuple><" + p + ":p-id>p1</" + p +
         ":p-id></presence>";
}

}  // namespace

TEST_CASE("a standard prefix of the namespace stays as written", "[xml][prefix]") {
  const auto in = body(" xmlns:mcpttPI10=\"urn:3gpp:ns:mcpttPresInfo:1.0\"", "mcpttPI10");
  auto r = run(in);
  REQUIRE(r.out.rewritten);
  CHECK(r.out.bytes.find("xmlns:mcpttPI10=\"urn:3gpp:ns:mcpttPresInfo:1.0\"") != std::string::npos);
  CHECK(r.out.bytes.find("<mcpttPI10:affiliation ") != std::string::npos);
  CHECK(r.out.bytes.find("</mcpttPI10:p-id>") != std::string::npos);
  CHECK(r.counters.prefixes_rewritten.empty());
}

TEST_CASE("a vendor prefix is renamed in the declaration, the tags and the attribute names", "[xml][prefix]") {
  const std::string vendor = "acmeCANARY77";
  const auto in = "<?xml version=\"1.0\"?><presence xmlns=\"urn:ietf:params:xml:ns:pidf\" xmlns:" + vendor +
                  "=\"urn:3gpp:ns:mcpttPresInfo:1.0\" entity=\"sip:alice@example.net\"><tuple id=\"t1\" " + vendor +
                  ":flag=\"true\"><status><" + vendor + ":affiliation group=\"sip:ops@example.net\"/></status></tuple><" +
                  vendor + ":p-id>p1</" + vendor + ":p-id></presence>";
  auto r = run(in);
  REQUIRE(r.out.rewritten);
  CHECK(r.out.bytes.find(vendor) == std::string::npos);
  CHECK(r.out.bytes.find("xmlns:ns1=\"urn:3gpp:ns:mcpttPresInfo:1.0\"") != std::string::npos);
  CHECK(r.out.bytes.find(" ns1:flag=\"true\"") != std::string::npos);
  CHECK(r.out.bytes.find("<ns1:affiliation ") != std::string::npos);
  CHECK(r.out.bytes.find("<ns1:p-id>p1</ns1:p-id>") != std::string::npos);
  CHECK(names(r.out.bytes) == names(in));
  CHECK(renamed(r, kPi) == 1);
}

TEST_CASE("a standard prefix name bound to another namespace is renamed", "[xml][prefix]") {
  const auto in = "<?xml version=\"1.0\"?><mcpttPI10:presence xmlns:mcpttPI10=\"urn:ietf:params:xml:ns:pidf\" "
                  "entity=\"sip:alice@example.net\"><mcpttPI10:tuple id=\"t2\"/></mcpttPI10:presence>";
  auto r = run(in);
  REQUIRE(r.out.rewritten);
  CHECK(r.out.bytes.find("mcpttPI10") == std::string::npos);
  CHECK(r.out.bytes.find("<ns1:presence xmlns:ns1=\"urn:ietf:params:xml:ns:pidf\"") != std::string::npos);
  CHECK(r.out.bytes.find("</ns1:presence>") != std::string::npos);
  CHECK(names(r.out.bytes) == names(in));
  CHECK(renamed(r, kPidf) == 1);
}

TEST_CASE("one namespace under a standard and a vendor prefix: only the vendor one changes", "[xml][prefix]") {
  const auto in = "<?xml version=\"1.0\"?><presence xmlns=\"urn:ietf:params:xml:ns:pidf\" "
                  "xmlns:mcpttPI10=\"urn:3gpp:ns:mcpttPresInfo:1.0\" xmlns:v=\"urn:3gpp:ns:mcpttPresInfo:1.0\" "
                  "entity=\"sip:a@example.net\"><tuple id=\"t1\"><status><mcpttPI10:affiliation/><v:affiliation/>"
                  "</status></tuple></presence>";
  auto r = run(in);
  REQUIRE(r.out.rewritten);
  CHECK(r.out.bytes.find("<mcpttPI10:affiliation/><ns1:affiliation/>") != std::string::npos);
  CHECK(r.out.bytes.find("xmlns:v=") == std::string::npos);
  CHECK(names(r.out.bytes) == names(in));
  CHECK(renamed(r, kPi) == 1);
}

TEST_CASE("a vendor prefix declared twice is renamed alike; a declared ns<k> is skipped", "[xml][prefix]") {
  const auto in = "<?xml version=\"1.0\"?><presence xmlns=\"urn:ietf:params:xml:ns:pidf\" xmlns:ns1=\"urn:example:vendor\" "
                  "entity=\"sip:a@example.net\"><tuple id=\"t1\" xmlns:x=\"urn:3gpp:ns:mcpttPresInfo:1.0\"><status>"
                  "<x:affiliation/></status></tuple><tuple id=\"t2\"><status xmlns:x=\"urn:3gpp:ns:mcpttPresInfo:1.0\">"
                  "<x:affiliation status=\"deaffiliated\"/><ns1:secret>CANARY</ns1:secret></status></tuple></presence>";
  auto r = run(in);
  REQUIRE(r.out.rewritten);
  CHECK(r.out.bytes.find("xmlns:x=") == std::string::npos);
  CHECK(r.out.bytes.find("<ns2:affiliation/>") != std::string::npos);
  CHECK(r.out.bytes.find("<ns2:affiliation status=\"deaffiliated\"/>") != std::string::npos);
  CHECK(r.out.bytes.find("xmlns:ns2=\"urn:3gpp:ns:mcpttPresInfo:1.0\"") != std::string::npos);
  CHECK(r.out.bytes.find("ns1") == std::string::npos);  // the unknown namespace and its element are removed
  CHECK(r.out.bytes.find("CANARY") == std::string::npos);
  CHECK(renamed(r, kPi) == 2);
}

TEST_CASE("the default namespace and the xml prefix are unchanged", "[xml][prefix]") {
  const auto in = "<?xml version=\"1.0\"?><presence xmlns=\"urn:ietf:params:xml:ns:pidf\" entity=\"sip:a@example.net\">"
                  "<tuple id=\"t1\"><status><affiliation xmlns=\"urn:3gpp:ns:mcpttPresInfo:1.0\"/></status></tuple></presence>";
  auto r = run(in);
  REQUIRE(r.out.rewritten);
  CHECK(r.out.bytes.find("<affiliation xmlns=\"urn:3gpp:ns:mcpttPresInfo:1.0\"/>") != std::string::npos);
  CHECK(r.counters.prefixes_rewritten.empty());
}

TEST_CASE("a QName in a value the rules do not model removes that attribute", "[xml][prefix]") {
  const auto in = "<?xml version=\"1.0\"?><presence xmlns=\"urn:ietf:params:xml:ns:pidf\" "
                  "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:vnd=\"urn:3gpp:ns:mcpttPresInfo:1.0\" "
                  "entity=\"sip:a@example.net\"><tuple id=\"t1\" xsi:type=\"vnd:T\"><status><vnd:affiliation "
                  "status=\"vnd:affiliated\"/></status></tuple></presence>";
  auto r = run(in);
  REQUIRE(r.out.rewritten);
  CHECK(r.out.bytes.find("vnd") == std::string::npos);
  CHECK(r.out.bytes.find("xsi") == std::string::npos);
  CHECK(r.out.bytes.find("<ns1:affiliation/>") != std::string::npos);
}

TEST_CASE("prefixes of removed elements and attributes are not edited twice", "[xml][prefix]") {
  const auto in = "<?xml version=\"1.0\"?><presence xmlns=\"urn:ietf:params:xml:ns:pidf\" xmlns:q=\"urn:3gpp:ns:mcpttPresInfo:1.0\" "
                  "entity=\"sip:a@example.net\"><tuple id=\"t1\" q:unknown=\"1\"><status><q:unknown-element><q:p-id>p1</q:p-id>"
                  "</q:unknown-element><q:p-id>CANARY-bad</q:p-id></status></tuple></presence>";
  auto r = run(in);
  REQUIRE(r.out.rewritten);
  CHECK(r.out.bytes.find("q:") == std::string::npos);
  CHECK(r.out.bytes.find("CANARY") == std::string::npos);
  CHECK(r.out.bytes.find("<ns1:p-id></ns1:p-id>") != std::string::npos);
  CHECK(renamed(r, kPi) == 1);
}

TEST_CASE("the prefixes rule data is validated", "[xml][prefix][rules]") {
  const auto load = [](const std::string& prefixes) {
    const std::string text =
        "ruleset: mcxanon-xml\nversion: 1.0.0\n"
        "namespaces:\n"
        "  - name: \"urn:3gpp:ns:mcpttPresInfo:1.0\"\n"
        "    " + kS + "\n"
        "    prefixes:\n" + prefixes +
        "    elements:\n"
        "      - {name: affiliation, action: container, " + kS + "}\n";
    std::vector<RuleFile> files{RuleFile{"xml-test.yaml", text}};
    return load_xml_ruleset(files);
  };
  auto ok = load("      - {name: mcpttPI10, " + kS + "}\n");
  REQUIRE(ok.has_value());
  const auto* ns = ok->ns(kPi);
  REQUIRE(ns != nullptr);
  CHECK(ns->standard_prefix("mcpttPI10"));
  CHECK_FALSE(ns->standard_prefix("mcpttPI1"));
  CHECK_FALSE(load("      - {name: mcpttPI10}\n").has_value());                                    // no source
  CHECK_FALSE(load("      - {name: \"a:b\", " + kS + "}\n").has_value());                          // not an NCName
  CHECK_FALSE(load("      - {name: xml, " + kS + "}\n").has_value());                              // reserved
  CHECK_FALSE(load("      - {name: xmlns, " + kS + "}\n").has_value());                            // reserved
  CHECK_FALSE(load("      - {name: p, " + kS + "}\n      - {name: p, " + kS + "}\n").has_value());  // duplicate
  CHECK_FALSE(load("      - {name: p, bogus: 1, " + kS + "}\n").has_value());                      // unknown key
}
