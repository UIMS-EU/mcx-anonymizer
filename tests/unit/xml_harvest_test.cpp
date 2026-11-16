// SPDX-License-Identifier: GPL-3.0-or-later
//
// The scanner's own XML harvester (FR-019): a lenient tokenizer that finds the XML
// bodies of a SIP payload and harvests their values and unknown names, in raw and unescaped form,
// except the vocabulary of the XML rule set, short decimal numbers, booleans and XSD date and
// time forms (P7).
#include "mcxanon/scan.hpp"
#include "scan/walker/sip_harvest.hpp"
#include "scan/walker/xml_harvest.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <set>
#include <string>
#include <vector>

using namespace mcxanon::scan;
using namespace mcxanon::scan::detail;

namespace {

std::set<std::string> harvest(std::string_view body) {
  const std::string payload = "MESSAGE sip:b@example.net SIP/2.0\r\nContent-Type: application/x+xml\r\n\r\n" +
                              std::string(body);
  auto v = harvest_xml(payload);
  return {v.begin(), v.end()};
}

std::set<std::string> sip_tokens(std::string_view payload) {
  SipHarvest h;
  const std::vector<std::uint8_t> dir{1};
  h.feed({reinterpret_cast<const std::uint8_t*>(payload.data()), payload.size()}, dir, false);
  std::set<std::string> out;
  for (const auto& t : h.take()) out.emplace(t.value.begin(), t.value.end());
  return out;
}

constexpr std::string_view kNs = "urn:3gpp:ns:mcpttInfo:1.0";

}  // namespace

TEST_CASE("xml harvest: attribute and text values, raw and unescaped", "[scan][xml]") {
  const auto h = harvest(std::string("<mcpttinfo xmlns=\"") + std::string(kNs) +
                         "\"><a x=\"tok&amp;en-one\" y='quote&apos;d-two'>text&lt;three</a>"
                         "<b><![CDATA[cdata-four]]></b></mcpttinfo>");
  CHECK(h.contains("tok&amp;en-one"));
  CHECK(h.contains("tok&en-one"));
  CHECK(h.contains("quote&apos;d-two"));
  CHECK(h.contains("quote'd-two"));
  CHECK(h.contains("text&lt;three"));
  CHECK(h.contains("text<three"));
  CHECK(h.contains("cdata-four"));
}

TEST_CASE("xml harvest: URIs and their parts, also behind character references", "[scan][xml]") {
  const std::string payload =
      "MESSAGE sip:b@example.net SIP/2.0\r\nContent-Type: application/vnd.3gpp.mcptt-info+xml\r\n\r\n"
      "<mcpttinfo xmlns=\"urn:3gpp:ns:mcpttInfo:1.0\"><u>sip:alice.nowak&#x40;fire.example.net</u>"
      "<v uri=\"sip:bob.kowal&#64;police.example.net\"/></mcpttinfo>";
  const auto t = sip_tokens(payload);
  CHECK(t.contains("alice.nowak"));
  CHECK(t.contains("fire.example.net"));
  CHECK(t.contains("bob.kowal"));
  CHECK(t.contains("police.example.net"));
  CHECK(t.contains("sip:alice.nowak&#x40;fire.example.net"));
}

TEST_CASE("xml harvest: vocabulary, short numbers, booleans and XSD date/time forms are not harvested",
          "[scan][xml]") {
  const auto h = harvest(std::string("<mcpttinfo xmlns=\"") + std::string(kNs) +
                         "\" type=\"Encrypted\"><n>123456</n><m>1234567</m><f>true</f><g>false</g>"
                         "<d>2026-11-14T10:00:00Z</d><e>2026-11-14</e><t>10:00:00.5+01:00</t><p>PT5M30S</p>"
                         "<q>-P1Y2M</q></mcpttinfo>");
  CHECK_FALSE(h.contains("mcpttinfo"));
  CHECK_FALSE(h.contains(std::string(kNs)));
  CHECK_FALSE(h.contains("Encrypted"));
  CHECK_FALSE(h.contains("type"));
  CHECK_FALSE(h.contains("123456"));
  CHECK(h.contains("1234567"));
  CHECK_FALSE(h.contains("true"));
  CHECK_FALSE(h.contains("false"));
  CHECK_FALSE(h.contains("2026-11-14T10:00:00Z"));
  CHECK_FALSE(h.contains("2026-11-14"));
  CHECK_FALSE(h.contains("10:00:00.5+01:00"));
  CHECK_FALSE(h.contains("PT5M30S"));
  CHECK_FALSE(h.contains("-P1Y2M"));
}

TEST_CASE("xml harvest: XCAP selectors of kept segments only are not harvested (N9)", "[scan][xml]") {
  const auto h = harvest("<resource-lists xmlns=\"urn:ietf:params:xml:ns:resource-lists\"><list>"
                         "<entry uri=\"org.3gpp.mcptt.ue-config/\"/>"
                         "<entry uri=\"org.3gpp.mcptt.service-config/global/\"/>"
                         "<entry uri=\"org.3gpp.mcptt.ue-config/users/sip:alice@example.net/\"/>"
                         "</list></resource-lists>");
  CHECK_FALSE(h.contains("org.3gpp.mcptt.ue-config/"));
  CHECK_FALSE(h.contains("org.3gpp.mcptt.service-config/global/"));
  CHECK(h.contains("org.3gpp.mcptt.ue-config/users/sip:alice@example.net/"));
}

TEST_CASE("xml harvest: Resource-Priority r-values are not harvested, look-alike identities are",
          "[scan][xml]") {
  const auto h = harvest(std::string("<mcpttinfo xmlns=\"") + std::string(kNs) +
                         "\"><a>mcpttp.5</a><b>dsn.flash-override</b><c>alice.nowak</c><d>mcpttq.1234</d>"
                         "</mcpttinfo>");
  CHECK_FALSE(h.contains("mcpttp.5"));
  CHECK_FALSE(h.contains("dsn.flash-override"));
  CHECK(h.contains("alice.nowak"));
  CHECK(h.contains("mcpttq.1234"));
}

TEST_CASE("xml harvest: unknown namespace names, and unknown element names in tag form", "[scan][xml]") {
  const auto h = harvest(std::string("<mcpttinfo xmlns=\"") + std::string(kNs) +
                         "\" xmlns:v=\"urn:vendor:secret-ns\"><v:secretelement v:secretattr=\"1\"/>"
                         "<other-unknown-name/><zebra/></mcpttinfo>");
  CHECK(h.contains("urn:vendor:secret-ns"));
  CHECK(h.contains("<secretelement"));
  CHECK(h.contains(":secretelement>"));
  CHECK(h.contains(":secretelement "));
  CHECK(h.contains(":secretelement/"));
  CHECK(h.contains("<other-unknown-name"));
  CHECK(h.contains("<zebra"));
  // Bare names are common words that kept SIP and MSRP headers contain ("Status:", "REPORT").
  CHECK_FALSE(h.contains("status"));
  CHECK_FALSE(h.contains("secretelement"));
  CHECK_FALSE(h.contains("v:secretelement"));  // prefixes are not harvested
  // Attribute names are not harvested (uri="..." is also a quoted SIP header parameter).
  CHECK_FALSE(h.contains("secretattr"));
  CHECK_FALSE(h.contains("secretattr=\""));
}

TEST_CASE("xml harvest: lenient on malformed markup, DTDs, comments and PIs", "[scan][xml]") {
  const auto h = harvest(
      "<?xml version=\"1.0\"?><!DOCTYPE a [<!ENTITY e \"entity-value\">]>"
      "<a><!-- comment-value --><?target pi-value?><b>unclosed-value");
  CHECK(h.contains("entity-value"));
  CHECK(h.contains("comment-value"));
  CHECK(h.contains("pi-value"));
  CHECK(h.contains("unclosed-value"));
  CHECK_FALSE(h.contains("1.0"));
}

TEST_CASE("xml harvest: only bodies; SIP and multipart headers are not markup", "[scan][xml]") {
  const std::string payload =
      "INVITE sip:b@example.net SIP/2.0\r\nContact: <urn:uuid:4f3c2a10-0000-4000-8000-000000000001>\r\n"
      "Content-Type: multipart/mixed;boundary=bnd\r\n\r\n--bnd\r\nContent-Type: application/sdp\r\n"
      "Content-ID: <part1.example>\r\n\r\nv=0\r\n--bnd\r\nContent-Type: application/x+xml\r\n\r\n"
      "<r xmlns=\"urn:x:y\"><i>inner-value</i></r>\r\n--bnd--\r\n";
  const auto v = harvest_xml(payload);
  const std::set<std::string> h(v.begin(), v.end());
  CHECK(h.contains("inner-value"));
  CHECK(h.contains("urn:x:y"));
  for (const auto& s : h) {
    INFO(s);
    CHECK(s.find("Content-") == std::string::npos);
    CHECK(s.find("part1.example") == std::string::npos);
    CHECK(s.find("urn:uuid") == std::string::npos);
  }
}

TEST_CASE("xml harvest: bodies embedded in entry URIs are decoded and harvested, one level deep",
          "[scan][xml]") {
  // R12 item 4: the URL-decoded body of a resource-lists entry URI (mcptt-info and SDP).
  const std::string info = "%3Cmcpttinfo%20xmlns%3D%22urn%3A3gpp%3Ans%3AmcpttInfo%3A1.0%22%3E%3CmcpttURI%3E"
                           "sip%3Aembedded.user%40fire.example.net%3C%2FmcpttURI%3E%3C%2Fmcpttinfo%3E";
  const std::string sdp = "v%3D0%0D%0Ao%3Dsdp.embedded.user%202890844526%201%20IN%20IP4%2010.1.2.3%0D%0A";
  const std::string payload =
      "REFER sip:b@example.net SIP/2.0\r\nContent-Type: application/resource-lists+xml\r\n\r\n"
      "<resource-lists xmlns=\"urn:ietf:params:xml:ns:resource-lists\"><list>"
      "<entry uri=\"sip:g@example.net?Content-Type=application%2Fvnd.3gpp.mcptt-info%2Bxml&amp;body=" + info + "\"/>"
      "<entry uri=\"sip:g@example.net?Content-Type=application%2Fsdp&amp;body=" + sdp + "\"/>"
      "</list></resource-lists>";
  const auto t = sip_tokens(payload);
  CHECK(t.contains("embedded.user"));
  CHECK(t.contains("sdp.embedded.user"));
}

TEST_CASE("xml harvest: TriggerId and AreaIdentifier values, kept by the rules, are not harvested (N13)",
          "[scan][xml]") {
  const auto h = harvest("<location-info xmlns=\"urn:3gpp:ns:mcpttLocationInfo:1.0\"><Configuration><TriggeringCriteria>"
                         "<CellChange><AnyCellChange TriggerId=\"cell-trigger-1\"/></CellChange></TriggeringCriteria>"
                         "</Configuration><Report><TriggerId>cell-trigger-1</TriggerId><Other>other-value-1</Other>"
                         "</Report><Request><anyExt><LocationFilter><AreaIdentifier>area-west-1</AreaIdentifier>"
                         "</LocationFilter></anyExt></Request></location-info>");
  CHECK_FALSE(h.contains("cell-trigger-1"));
  CHECK_FALSE(h.contains("area-west-1"));
  CHECK(h.contains("other-value-1"));
}

TEST_CASE("xml harvest: hex values of at most 6 digits are not harvested (N17)", "[scan][xml]") {
  const auto h = harvest("<mcptt-mbms-usage-info xmlns=\"urn:3gpp:ns:mcpttMbmsUsage:1.0\"><a>a1B2</a><b>00ff10</b>"
                         "<c>0a1b2c3</c><d>sai-a1b2</d></mcptt-mbms-usage-info>");
  CHECK_FALSE(h.contains("a1B2"));
  CHECK_FALSE(h.contains("00ff10"));
  CHECK(h.contains("0a1b2c3"));
  CHECK(h.contains("sai-a1b2"));
}

TEST_CASE("xml harvest: on a TCP segment, items cut at its end are not harvested", "[scan][xml]") {
  const std::string text = "MESSAGE sip:b@example.net SIP/2.0\r\n\r\n<mcpttinfo xmlns=\"urn:x\"><a>whole-value</a>"
                           "<b>cut-val";
  const auto cut = harvest_xml(text, nullptr, true);
  const std::set<std::string> h(cut.begin(), cut.end());
  CHECK(h.contains("whole-value"));
  CHECK_FALSE(h.contains("cut-val"));
  const auto tag = harvest_xml("MESSAGE sip:b@example.net SIP/2.0\r\n\r\n<mcpttinfo xmlns=\"urn:x\"><mcptt-Par", nullptr, true);
  CHECK(std::find(tag.begin(), tag.end(), "<mcptt-Par") == tag.end());
  const auto udp = harvest_xml(text, nullptr, false);  // a whole message: lenient
  CHECK(std::find(udp.begin(), udp.end(), "cut-val") != udp.end());
}

TEST_CASE("xml harvest: standard prefixes are vocabulary, declared vendor prefixes are searched in tag form",
          "[scan][xml][prefix]") {
  // Feature 008 (FR-003, FR-004): the anonymiser keeps the prefixes of the normative schemas and
  // renames every other one; the scanner's own lists agree.
  const auto pidf = harvest(
      "<presence xmlns=\"urn:ietf:params:xml:ns:pidf\" xmlns:mcpttPI10=\"urn:3gpp:ns:mcpttPresInfo:1.0\" "
      "xmlns:acmeVendor7=\"urn:3gpp:ns:mcpttPresInfo:1.0\"><mcpttPI10:p-id>p1</mcpttPI10:p-id></presence>");
  CHECK(pidf.contains("xmlns:acmeVendor7="));
  CHECK(pidf.contains("<acmeVendor7:"));
  CHECK(pidf.contains("</acmeVendor7:"));
  for (const auto& v : pidf) CHECK(v.find("mcpttPI10") == std::string::npos);
  // The pilot's source of the tokens: prefix names as attribute values of a filter body.
  const auto filter = harvest(
      "<filter-set xmlns=\"urn:ietf:params:xml:ns:simple-filter\"><ns-bindings>"
      "<ns-binding prefix=\"mcpttPI10\" urn=\"urn:3gpp:ns:mcpttPresInfo:1.0\"/>"
      "<ns-binding prefix=\"mcdataPI10\" urn=\"urn:3gpp:ns:mcdataPresInfo:1.0\"/>"
      "<ns-binding prefix=\"mcvideoPI10\" urn=\"urn:3gpp:ns:mcvideoPresInfo:1.0\"/>"
      "<ns-binding prefix=\"mcs10Set\" urn=\"urn:3gpp:mcsSettings:1.0\"/></ns-bindings></filter-set>");
  for (const char* p : {"mcpttPI10", "mcdataPI10", "mcvideoPI10", "mcs10Set"}) {
    INFO(p);
    CHECK_FALSE(filter.contains(p));
  }
}

TEST_CASE("xml harvest: decimal values are numbers, matched on digit boundaries only", "[scan][xml]") {
  // A coordinate of a location report (threebytes) is zeroed in the output. Its 7 digits used to
  // be searched as a string, so the run failed whenever a cell identity pseudonym (6 decimal
  // digits of PLMN and 36 binary ones) began with them: a few project keys in a hundred.
  const std::string payload =
      "MESSAGE sip:b@example.net SIP/2.0\r\nContent-Type: application/vnd.3gpp.mcptt-location-info+xml\r\n\r\n"
      "<location-info xmlns=\"urn:3gpp:ns:mcpttLocationInfo:1.0\"><Report><CurrentLocation><CurrentCoordinate>"
      "<longitude type=\"Normal\"><threebytes>4057871</threebytes></longitude></CurrentCoordinate>"
      "</CurrentLocation></Report></location-info>";
  SipHarvest h;
  const std::vector<std::uint8_t> dir{1};
  h.feed({reinterpret_cast<const std::uint8_t*>(payload.data()), payload.size()}, dir, false);
  std::vector<Token> tokens = h.take();
  const auto coord = std::find_if(tokens.begin(), tokens.end(), [](const Token& t) {
    return std::string(t.value.begin(), t.value.end()) == "4057871";
  });
  REQUIRE(coord != tokens.end());
  CHECK(coord->category == TokenCategory::number);
  const Index ix(std::move(tokens));
  const auto scan = [&ix](std::string_view out) {
    return scan_bytes({reinterpret_cast<const std::uint8_t*>(out.data()), out.size()}, ix).hits.size();
  };
  CHECK(scan("<Ncgi>405787101110101110100110011011010000100100</Ncgi>") == 0);
  CHECK(scan("<threebytes>4057871</threebytes>") == 1);
  CHECK(scan("tel:+4057871;phone-context=x") == 1);
}
