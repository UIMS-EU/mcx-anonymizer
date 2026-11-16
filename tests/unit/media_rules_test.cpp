// SPDX-License-Identifier: GPL-3.0-or-later
//
// Loader of the media rule set: load-time validation.
#include "mcxanon/error.hpp"

#include "policy/media_rules.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using namespace mcxanon;

namespace {

const char* const kHead = "ruleset: mcxanon-media\nversion: 1.0.0\n";
const char* const kSrc380 = "source: {spec: TS 24.380, version: \"V19.1.0\", clause: \"8.2.5\"}";

std::string mcpt(const std::string& fields, const std::string& names = "[MCPT]",
                 const std::string& id = "mcpt") {
  return std::string(kHead) +
         "app:\n"
         "  - family: " + id + "\n"
         "    names: " + names + "\n"
         "    " + kSrc380 + "\n"
         "    messages:\n"
         "      - {name: Floor Granted, subtype: 1, ack_variant: true, " + kSrc380 + "}\n"
         "      - {name: Floor Request, subtype: 0, " + kSrc380 + "}\n"
         "    fields:\n" + fields;
}

const std::string kGranted =
    "      - {id: 4, name: Granted Party's Identity, encoding: uri, action: pseudonymise,\n"
    "         source: {spec: TS 24.380, version: \"V19.1.0\", clause: \"8.2.3.6\"}}\n"
    "      - {id: 0, name: Floor Priority, encoding: u8+spare, action: keep,\n"
    "         source: {spec: TS 24.380, version: \"V19.1.0\", clause: \"8.2.3.2\"}}\n";

Result<MediaRuleSet> load(const std::vector<std::string>& texts) {
  std::vector<RuleFile> files;
  for (std::size_t i = 0; i < texts.size(); ++i) files.push_back({"m" + std::to_string(i) + ".yaml", texts[i]});
  return load_media_ruleset(files);
}

void rejects(const std::string& text, const std::string& needle) {
  auto r = load({text});
  REQUIRE_FALSE(r.has_value());
  INFO(r.error().message);
  CHECK(r.error().message.find(needle) != std::string::npos);
}

}  // namespace

TEST_CASE("an APP family loads with messages, ack variants and fields", "[media][rules]") {
  auto r = load({mcpt(kGranted)});
  REQUIRE(r.has_value());
  const auto* f = r->family_by_name("MCPT");
  REQUIRE(f != nullptr);
  CHECK(f->id == "mcpt");
  REQUIRE(f->message(1) != nullptr);
  REQUIRE(f->message(17) != nullptr);  // x bit: subtype + 16 (TS 24.380 §8.2.2.1)
  CHECK(f->message(17)->name == "Floor Granted");
  CHECK(f->message(16) == nullptr);    // Floor Request has no ack variant
  REQUIRE(f->field(4) != nullptr);
  CHECK(f->field(4)->encoding == AppEncoding::uri);
  CHECK(f->field(4)->action == MediaAction::pseudonymise);
  CHECK(f->field(4)->source.clause == "8.2.3.6");
  CHECK(f->field(5) == nullptr);
  CHECK(r->digest.size() == 64);
}

TEST_CASE("the ruleset name, top-level keys and version are checked", "[media][rules]") {
  rejects("ruleset: mcxanon-sip\nversion: 1.0.0\n", "ruleset must be 'mcxanon-media'");
  rejects(std::string(kHead) + "headers: []\n", "unknown key 'headers'");
  rejects("ruleset: mcxanon-media\n", "'ruleset' and 'version' are required");
  auto two = load({mcpt(kGranted), "ruleset: mcxanon-media\nversion: 2.0.0\n"});
  REQUIRE_FALSE(two.has_value());
  CHECK(two.error().message.find("version differs") != std::string::npos);
}

TEST_CASE("every rule needs a source from the media documents", "[media][rules]") {
  rejects(mcpt("      - {id: 6, name: User ID, encoding: uri, action: pseudonymise}\n"), "rule without source");
  rejects(mcpt("      - {id: 6, name: User ID, encoding: uri, action: pseudonymise,\n"
               "         source: {spec: TS 24.008, version: \"V19.0.0\", clause: \"10.5.6.13\"}}\n"),
          "not in the list of indexed documents");
  rejects(mcpt("      - {id: 6, name: User ID, encoding: uri, action: pseudonymise,\n"
               "         source: {spec: RFC 4976, version: \"2007-09\", clause: \"5\"}}\n"),
          "not in the list of indexed documents");
}

TEST_CASE("an action must be allowed for the encoding", "[media][rules]") {
  // A URI is an identity: it cannot be kept.
  rejects(mcpt("      - {id: 6, name: User ID, encoding: uri, action: keep, " + std::string(kSrc380) + "}\n"),
          "not allowed");
  // Opaque values are not understood: zero or remove only.
  rejects(mcpt("      - {id: 192, name: PCK I_MESSAGE, encoding: opaque, action: keep, " + std::string(kSrc380) + "}\n"),
          "not allowed");
  // An SSRC field is always pseudonymised (FR-005).
  rejects(mcpt("      - {id: 14, name: Audio SSRC, encoding: ssrc+spare, action: keep, " + std::string(kSrc380) + "}\n"),
          "not allowed");
  rejects(mcpt("      - {id: 6, name: User ID, encoding: utf8, action: remove, " + std::string(kSrc380) + "}\n"),
          "unknown encoding");
  auto ok = load({mcpt("      - {id: 192, name: PCK I_MESSAGE, encoding: opaque, action: zero, " + std::string(kSrc380) + "}\n")});
  CHECK(ok.has_value());
}

TEST_CASE("duplicates and bad identifiers are load errors", "[media][rules]") {
  rejects(mcpt(kGranted + "      - {id: 4, name: Again, encoding: uri, action: remove, " + kSrc380 + "}\n"),
          "duplicate field ID 4");
  rejects(mcpt(kGranted, "[MCP]"), "APP name 'MCP' must be 4 characters");
  rejects(mcpt("      - {id: 256, name: X, encoding: u8, action: keep, " + std::string(kSrc380) + "}\n"),
          "from 0 to 255");
  rejects(std::string(kHead) + "app:\n  - family: x\n    names: [ABCD]\n    " + kSrc380 +
              "\n    messages:\n      - {name: A, subtype: 32, " + kSrc380 + "}\n    fields: []\n",
          "subtype");
  // An acknowledgement variant needs a subtype below 16.
  rejects(std::string(kHead) + "app:\n  - family: x\n    names: [ABCD]\n    " + kSrc380 +
              "\n    messages:\n      - {name: A, subtype: 17, ack_variant: true, " + kSrc380 + "}\n    fields: []\n",
          "subtype");
}

TEST_CASE("two families may not share an APP name or an id", "[media][rules]") {
  auto r = load({mcpt(kGranted), mcpt(kGranted, "[MCPT]", "other")});
  REQUIRE_FALSE(r.has_value());
  CHECK(r.error().message.find("APP name 'MCPT'") != std::string::npos);
  auto s = load({mcpt(kGranted), mcpt(kGranted, "[MCPC]", "mcpt")});
  REQUIRE_FALSE(s.has_value());
  CHECK(s.error().message.find("duplicate family 'mcpt'") != std::string::npos);
}

TEST_CASE("rtp elements must all be classified with their only allowed action", "[media][rules]") {
  std::string rtp = std::string(kHead) + "rtp:\n";
  for (const auto& [name, action] : rtp_elements()) {
    rtp += "  - {name: " + std::string(name) + ", action: " + std::string(to_string(action)) +
           ", source: {spec: RFC 3550, version: \"2003-07\", clause: \"5.1\"}}\n";
  }
  auto r = load({rtp});
  REQUIRE(r.has_value());
  CHECK(r->rtp.size() == rtp_elements().size());
  CHECK(r->rtp.at("payload").action == MediaAction::zero);
  // The payload can never be kept.
  std::string bad = rtp;
  const auto pos = bad.find("{name: payload, action: zero");
  REQUIRE(pos != std::string::npos);
  bad.replace(pos, std::string("{name: payload, action: zero").size(), "{name: payload, action: keep");
  rejects(bad, "not allowed");
  // A missing element is a load error (fail-closed by construction).
  std::string missing = std::string(kHead) +
                        "rtp:\n  - {name: payload, action: zero, source: {spec: RFC 3550, version: \"2003-07\", clause: \"5.1\"}}\n";
  rejects(missing, "RTP element");
  rejects(std::string(kHead) +
              "rtp:\n  - {name: colour, action: keep, source: {spec: RFC 3550, version: \"2003-07\", clause: \"5.1\"}}\n",
          "unknown RTP element");
}

TEST_CASE("rtcp and msrp sections load", "[media][rules]") {
  const std::string text = std::string(kHead) +
                           "rtcp:\n"
                           "  packet_types:\n"
                           "    - {pt: 202, name: SDES, action: keep, source: {spec: RFC 3550, version: \"2003-07\", clause: \"6.5\"}}\n"
                           "  sdes_items:\n"
                           "    - {type: 1, name: CNAME, action: pseudonymise, source: {spec: RFC 3550, version: \"2003-07\", clause: \"6.5.1\"}}\n"
                           "    - {type: 2, name: NAME, action: remove, source: {spec: RFC 3550, version: \"2003-07\", clause: \"6.5.2\"}}\n"
                           "  feedback:\n"
                           "    - {pt: 205, fmt: 1, name: Generic NACK, action: keep, source: {spec: RFC 4585, version: \"2006-07\", clause: \"6.2.1\"}}\n"
                           "  xr_blocks:\n"
                           "    - {bt: 7, name: VoIP Metrics, action: keep, source: {spec: RFC 3611, version: \"2003-11\", clause: \"4.7\"}}\n"
                           "  bye_reason: {action: remove, source: {spec: RFC 3550, version: \"2003-07\", clause: \"6.6\"}}\n"
                           "msrp:\n"
                           "  methods:\n"
                           "    - {name: SEND, action: keep, source: {spec: RFC 4975, version: \"2007-09\", clause: \"7.1\"}}\n"
                           "  headers:\n"
                           "    - {name: To-Path, action: pseudonymise, source: {spec: RFC 4975, version: \"2007-09\", clause: \"9\"}}\n"
                           "    - {name: Content-ID, action: remove, source: {spec: RFC 4975, version: \"2007-09\", clause: \"9\"}}\n"
                           "  elements:\n"
                           "    - {name: content, action: zero, source: {spec: RFC 4975, version: \"2007-09\", clause: \"7.1\"}}\n";
  auto r = load({text});
  REQUIRE(r.has_value());
  CHECK(r->rtcp.packet_types.at(202).action == MediaAction::keep);
  CHECK(r->rtcp.sdes_items.at(2).action == MediaAction::remove);
  CHECK(r->rtcp.feedback.at({205, 1}).name == "Generic NACK");
  CHECK(r->rtcp.xr_blocks.at(7).action == MediaAction::keep);
  REQUIRE(r->rtcp.bye_reason.has_value());
  CHECK(r->msrp.headers.at("to-path").action == MediaAction::pseudonymise);
  CHECK(r->msrp.methods.at("SEND").action == MediaAction::keep);
  CHECK(r->msrp.elements.at("content").action == MediaAction::zero);
  // SDES CNAME may only be pseudonymised; other items only removed (FR-010).
  std::string bad = text;
  bad.replace(bad.find("CNAME, action: pseudonymise"), std::string("CNAME, action: pseudonymise").size(),
              "CNAME, action: keep");
  rejects(bad, "not allowed");
  // MSRP content can never be kept (FR-028).
  std::string keep_content = text;
  keep_content.replace(keep_content.find("content, action: zero"), std::string("content, action: zero").size(),
                       "content, action: keep");
  rejects(keep_content, "not allowed");
}

TEST_CASE("the embedded media rule set loads", "[media][rules]") {
  auto r = load_embedded_media_ruleset();
  REQUIRE(r.has_value());
  CHECK(r->name == "mcxanon-media");
  CHECK(r->digest == embedded_media_ruleset_digest());
}
