// SPDX-License-Identifier: GPL-3.0-or-later
//
// Loader of the SIP rule set: load-time validation and the
// fail-closed defaults.
#include "mcxanon/error.hpp"

#include "policy/sip_rules.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <string_view>

using namespace mcxanon;

namespace {

const char* const kHead = "ruleset: mcxanon-sip\nversion: 1.0.0\n";
const char* const kSrc = "source: {spec: RFC 3261, version: \"2002-06\", clause: \"20.20\"}";

std::string from_rule(const std::string& extra_param = "") {
  return std::string(kHead) +
         "headers:\n"
         "  - name: From\n"
         "    compact: f\n"
         "    grammar: name-addr\n"
         "    components:\n"
         "      display-name: {action: pseudonymise, category: display-name}\n"
         "      uri: {action: uri}\n"
         "    params:\n"
         "      - {name: tag, action: pseudonymise, category: tag, value: token,\n"
         "         source: {spec: RFC 3261, version: \"2002-06\", clause: \"19.3\"}}\n" +
         extra_param + "    " + kSrc + "\n";
}

Result<SipRuleSet> load(const std::string& text, const std::string& name = "sip-a.yaml") {
  const RuleFile f{name, text};
  return load_sip_ruleset({&f, 1});
}

void expect_error(const std::string& text, const char* needle) {
  auto rs = load(text);
  REQUIRE_FALSE(rs.has_value());
  CHECK(rs.error().code == ErrorCode::internal);
  INFO(rs.error().message);
  CHECK(rs.error().message.find(needle) != std::string::npos);
}

}  // namespace

TEST_CASE("a valid SIP rule file loads", "[sip-rules]") {
  auto rs = load(from_rule() +
                 "  - {name: User-Agent, grammar: opaque, action: remove,\n"
                 "     source: {spec: RFC 3261, version: \"2002-06\", clause: \"20.41\"}}\n"
                 "uri:\n"
                 "  schemes: [sip, sips, tel]\n"
                 "  params:\n"
                 "    - {name: maddr, action: pseudonymise, category: host, value: host,\n"
                 "       source: {spec: RFC 3261, version: \"2002-06\", clause: \"19.1.1\"}}\n"
                 "sdp:\n"
                 "  lines:\n"
                 "    - {type: s, action: blank, value: \"-\",\n"
                 "       source: {spec: RFC 8866, version: \"2021-01\", clause: \"5\"}}\n"
                 "  attributes:\n"
                 "    - name: fmtp\n"
                 "      format: MCPTT\n"
                 "      grammar: fmtp-params\n"
                 "      fmtp_params:\n"
                 "        - {name: mc_ssrc, action: pseudonymise, category: ssrc, value: number,\n"
                 "           source: {spec: TS 24.380, version: \"19.1.0\", clause: \"12.1.2.3\"}}\n"
                 "      separators: [\";\", \":\"]\n"
                 "      source: {spec: TS 24.380, version: \"19.1.0\", clause: \"12.1.2.3\"}\n"
                 "bodies:\n"
                 "  - {content_type: application/SDP, handling: sdp,\n"
                 "     source: {spec: RFC 8866, version: \"2021-01\", clause: \"8\"}}\n"
                 "feature_tags:\n"
                 "  - {tag: \"+g.3gpp.mcptt\", value_type: boolean, action: keep,\n"
                 "     source: {spec: TS 24.379, version: \"19.6.0\", clause: \"D.2\"}}\n");
  REQUIRE(rs.has_value());
  CHECK(rs->name == "mcxanon-sip");
  CHECK(rs->version == "1.0.0");
  CHECK_FALSE(rs->digest.empty());
  const auto* from = rs->find_header("FROM");
  REQUIRE(from != nullptr);
  CHECK(rs->find_header("f") == from);  // compact form, case-insensitive
  CHECK(rs->find_header("F") == from);
  CHECK(from->grammar == SipGrammar::name_addr);
  CHECK(from->components.at("display-name").category == SipCategory::display_name);
  CHECK(from->components.at("uri").action == SipAction::uri);
  REQUIRE(from->find_param("TAG") != nullptr);
  CHECK(from->find_param("tag")->rule.category == SipCategory::tag);
  CHECK(from->source.clause == "20.20");
  CHECK(rs->find_header("User-Agent")->action == SipAction::remove);
  CHECK(rs->uri.find_param("maddr")->rule.category == SipCategory::host);
  CHECK(rs->find_sdp_line('s')->value == "-");
  const auto* fmtp = rs->find_sdp_attribute("fmtp", "mcptt");
  REQUIRE(fmtp != nullptr);
  CHECK(fmtp->separators.size() == 2);
  CHECK(rs->find_body("application/sdp")->handling == BodyHandling::sdp);
  CHECK(rs->find_feature_tag("+g.3gpp.mcptt")->rule.action == SipAction::keep);
}

TEST_CASE("fail-closed defaults: what has no rule is not found", "[sip-rules]") {
  auto rs = load(from_rule());
  REQUIRE(rs.has_value());
  CHECK(rs->find_header("X-Vendor-Thing") == nullptr);
  CHECK(rs->find_header("From")->find_param("x-unknown") == nullptr);
  CHECK(rs->uri.find_param("transport") == nullptr);
  CHECK(rs->find_sdp_line('k') == nullptr);
  CHECK(rs->find_sdp_attribute("crypto") == nullptr);
  CHECK(rs->find_sdp_attribute("fmtp", "MCVideo") == nullptr);
  CHECK(rs->find_body("application/pidf+xml") == nullptr);
  CHECK(rs->find_feature_tag("+g.vendor.x") == nullptr);
}

TEST_CASE("duplicate header names and compact forms are rejected", "[sip-rules]") {
  expect_error(from_rule() + "  - {name: from, grammar: name-addr, " + kSrc + "}\n", "duplicate");
  expect_error(from_rule() + "  - {name: Foo, compact: F, grammar: token, action: keep, " + kSrc +
                   "}\n",
               "duplicate");
}

TEST_CASE("unknown grammar, category or action is rejected", "[sip-rules]") {
  expect_error(std::string(kHead) + "headers:\n  - {name: X, grammar: nonsense, action: keep, " +
                   kSrc + "}\n",
               "grammar");
  expect_error(from_rule("      - {name: x, action: pseudonymise, category: bogus, value: token, " +
                         std::string(kSrc) + "}\n"),
               "category");
  expect_error(from_rule("      - {name: x, action: obliterate, value: token, " +
                         std::string(kSrc) + "}\n"),
               "action");
}

TEST_CASE("a rule without a valid source is rejected", "[sip-rules]") {
  expect_error(std::string(kHead) + "headers:\n  - {name: X, grammar: token, action: keep}\n",
               "source");
  // A document outside the index list.
  expect_error(std::string(kHead) +
                   "headers:\n  - {name: X, grammar: token, action: keep,\n"
                   "     source: {spec: RFC 9999, version: \"2099-01\", clause: \"1\"}}\n",
               "source");
  expect_error(std::string(kHead) +
                   "headers:\n  - {name: X, grammar: token, action: keep,\n"
                   "     source: {spec: TS 33.203, version: \"19.0.0\", clause: \"7\"}}\n",
               "source");
}

TEST_CASE("pseudonymise needs a category and blank needs a value", "[sip-rules]") {
  expect_error(from_rule("      - {name: x, action: pseudonymise, value: token, " +
                         std::string(kSrc) + "}\n"),
               "category");
  expect_error(std::string(kHead) +
                   "sdp:\n  lines:\n    - {type: s, action: blank,\n"
                   "       source: {spec: RFC 8866, version: \"2021-01\", clause: \"5\"}}\n",
               "value");
}

TEST_CASE("files of one rule set must agree on name and version", "[sip-rules]") {
  const RuleFile a{"sip-a.yaml", from_rule()};
  const RuleFile b{"sip-b.yaml", "ruleset: mcxanon-sip\nversion: 2.0.0\nheaders: []\n"};
  const RuleFile files[] = {a, b};
  auto rs = load_sip_ruleset(files);
  REQUIRE_FALSE(rs.has_value());
  CHECK(rs.error().message.find("version") != std::string::npos);
  auto wrong = load("ruleset: mcxanon-l2l4\nversion: 1.0.0\nheaders: []\n");
  REQUIRE_FALSE(wrong.has_value());
}

TEST_CASE("corrupt YAML yields an error value, never a crash", "[sip-rules]") {
  for (const char* text : {
           "ruleset: mcxanon-sip\nversion: 1.0.0\nheaders: [\n",                 // unclosed list
           "ruleset: mcxanon-sip\nversion: 1.0.0\nheaders:\n - name: A\n  grammar: token\n",
           "ruleset: mcxanon-sip\nversion: 1.0.0\nheaders:\n  - {name: [1, 2], grammar: token}\n",
           "ruleset: mcxanon-sip\nversion: 1.0.0\nheaders:\n  - 42\n",
           "ruleset: mcxanon-sip\nversion: 1.0.0\nheaders: {a: b}\n",
           "ruleset: mcxanon-sip\nversion: 1.0.0\nunknown_section: []\n",
           "",
           "- just\n- a\n- list\n",
           "ruleset: mcxanon-sip\nversion: 1.0.0\nsdp:\n  lines:\n    - {type: ss, action: keep,\n"
           "       source: {spec: RFC 8866, version: \"2021-01\", clause: \"5\"}}\n",
       }) {
    auto rs = load(text);
    CHECK_FALSE(rs.has_value());
  }
}

TEST_CASE("the embedded SIP rule set loads", "[sip-rules]") {
  auto rs = load_embedded_sip_ruleset();
  INFO((rs ? std::string() : rs.error().message));
  REQUIRE(rs.has_value());
  CHECK(rs->name == "mcxanon-sip");
  CHECK(rs->digest == embedded_sip_ruleset_digest());
}

TEST_CASE("request methods: listed with a source, upper case, no duplicates", "[sip-rules]") {
  const std::string m = "methods:\n  - {name: INVITE, " + std::string(kSrc) + "}\n  - {name: ACK, " + kSrc + "}\n";
  auto rs = load(from_rule() + m);
  REQUIRE(rs.has_value());
  CHECK(rs->known_method("INVITE"));
  CHECK(rs->known_method("ACK"));
  CHECK_FALSE(rs->known_method("invite"));  // case-sensitive (RFC 3261 §7.1)
  CHECK_FALSE(rs->known_method("XFOO"));
  // Without a list (a test rule set), every method is accepted.
  CHECK(load(from_rule())->known_method("XFOO"));
  expect_error(from_rule() + "methods:\n  - {name: invite, " + kSrc + "}\n", "upper-case");
  expect_error(from_rule() + m + "  - {name: ACK, " + kSrc + "}\n", "duplicate");
  expect_error(from_rule() + "methods:\n  - {name: INVITE}\n", "source");
  // The embedded rule set lists the 14 methods of TS 24.229 annex A.2.1.4.
  CHECK(load_embedded_sip_ruleset()->methods.size() == 14);
}

// FR-004, FR-019: every header of the SIP inventory and every SDP attribute whose proposed
// action is not "remove" has a rule in the embedded rule set; the three MCX fmtp formats too. A rule
// may still remove an entry when a later decision says so (I5, I8). The lists are copied from
// the inventory of 2026-11-12; a new inventory entry is added here together with its rule.
namespace {
constexpr std::string_view kInventoryHeaders[] = {
    "Accept", "Accept-Contact", "Accept-Encoding", "Accept-Language", "Accept-Resource-Priority",
    "Additional-Identity", "Alert-Info", "Allow", "Allow-Events", "Answer-Mode", "Attestation-Info",
    "Authentication-Info", "Authorization", "Call-ID", "Call-Info", "Cellular-Network-Info",
    "Contact", "Content-Disposition", "Content-Encoding", "Content-ID", "Content-Language",
    "Content-Length", "Content-Type", "CSeq", "Date", "DC-Info", "Error-Info", "Event", "Expires",
    "Feature-Caps", "Flow-Timer", "From", "Geolocation", "Geolocation-Error", "Geolocation-Routing",
    "Handover-Info", "History-Info", "In-Reply-To", "Info-Package", "Join", "Max-Breadth",
    "Max-Forwards", "MIME-Version", "Min-Expires", "Min-SE", "Origination-Id",
    "P-Access-Network-Info", "P-Answer-State", "P-Asserted-Identity", "P-Asserted-Service",
    "P-Associated-URI", "P-Called-Party-ID", "P-Charging-Function-Addresses", "P-Charging-Vector",
    "P-Early-Media", "P-Preferred-Identity", "P-Preferred-Service", "P-Private-Network-Indication",
    "P-Profile-Key", "P-Refused-URI-List", "P-Served-User", "P-User-Database",
    "P-Visited-Network-ID", "Path", "Permission-Missing", "Priority", "Priority-Share",
    "Priority-Verstat", "Priv-Answer-Mode", "Privacy", "Proxy-Authenticate", "Proxy-Authorization",
    "Proxy-Require", "RAck", "Reason", "Record-Route", "Recv-Info", "Refer-Sub", "Refer-To",
    "Referred-By", "Reject-Contact", "Relayed-Charge", "Replaces", "Reply-To",
    "Request-Disposition", "Require", "Resource-Priority", "Resource-Share", "Response-Source",
    "Restoration-Info", "Retry-After", "Route", "RSeq", "Security-Client", "Security-Server",
    "Security-Verify", "Service-Interact-Info", "Service-Route", "Session-Expires", "Session-ID",
    "SIP-Etag", "SIP-If-Match", "Subscription-State", "Supported", "Target-Dialog", "Timestamp",
    "To", "Trigger-Consent", "Unsupported", "Via", "Warning", "WWW-Authenticate"};
constexpr std::string_view kInventoryAttributes[] = {
    "3ge2ae", "accept-types", "accept-wrapped-types", "candidate", "charset", "conf", "connection",
    "content", "curr", "des", "ecn-capable-rtp", "extmap", "fmtp", "framerate", "group", "ice-lite",
    "ice-mismatch", "ice-options", "ice-pacing", "imageattr", "inactive", "label", "lang",
    "max-size", "maxprate", "maxptime", "mid", "msrp-cema", "orient", "path", "ptime", "quality",
    "recvonly", "remote-candidates", "rtcp", "rtcp-fb", "rtcp-mux", "rtcp-mux-only", "rtcp-rsize",
    "rtcp-xr", "rtpmap", "sdplang", "sendonly", "sendrecv", "setup", "ssrc", "ssrc-group", "type"};
}  // namespace

TEST_CASE("every inventory header and SDP attribute that is not removed has a rule", "[sip-rules][inventory]") {
  auto rs = load_embedded_sip_ruleset();
  REQUIRE(rs.has_value());
  for (const auto name : kInventoryHeaders) {
    INFO("header " << name);
    CHECK(rs->find_header(name) != nullptr);
  }
  for (const auto name : kInventoryAttributes) {
    INFO("a=" << name);
    CHECK(rs->find_sdp_attribute(name) != nullptr);
  }
  for (const auto format : {"MCPTT", "MCVideo", "MCDATA"}) {
    INFO("a=fmtp:" << format);
    const auto* r = rs->find_sdp_attribute("fmtp", format);
    REQUIRE(r != nullptr);
    CHECK(r->format.has_value());
  }
}
