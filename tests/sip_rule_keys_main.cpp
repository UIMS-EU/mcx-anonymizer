// SPDX-License-Identifier: GPL-3.0-or-later
//
// Prints the key of every rule of the embedded SIP rule set that changes a value (any action
// but keep), one per line, in the canary key format of tools/fixturegen/canary.py. Used by
// test_rule_canary_coverage.py (every such rule has a canary).
//
// Items of category `port` follow the transport port policy: kept by default, pseudonymised
// with --pseudonymise-ephemeral-ports (FR-020). Like the transport port fields of feature 001
// (action keep), they have no canary; the sip-consistency test checks them under the option.
#include "policy/sip_rules.hpp"

#include <cstdio>
#include <set>
#include <string>

using namespace mcxanon;

int main() {
  auto rs = load_embedded_sip_ruleset();
  if (!rs) {
    std::fprintf(stderr, "%s\n", rs.error().message.c_str());
    return 1;
  }
  std::set<std::string> keys;
  const auto changes = [](const SipItemRule& r) {
    return r.action != SipAction::keep && r.category != SipCategory::port;
  };
  for (const auto& h : rs->headers) {
    if (h.action == SipAction::remove) {
      keys.insert("sip:" + h.name);
      continue;
    }
    for (const auto& [component, rule] : h.components) {
      if (changes(rule)) keys.insert("sip:" + h.name + "." + component);
    }
    for (const auto& p : h.params) {
      if (changes(p.rule)) keys.insert("sip-param:" + h.name + ";" + p.name);
    }
  }
  for (const auto& p : rs->uri.params) {
    if (changes(p.rule)) keys.insert("uri-param:" + p.name);
  }
  for (const auto& l : rs->sdp_lines) {
    const std::string line = std::string(1, l.type) + "=";
    if (l.action == SipAction::remove || l.action == SipAction::blank) keys.insert("sdp:" + line);
    for (const auto& [field, rule] : l.fields) {
      if (changes(rule)) keys.insert("sdp:" + line + "." + field);
    }
  }
  for (const auto& a : rs->sdp_attributes) {
    const std::string attr = "a=" + a.name + (a.format ? ":" + *a.format : "");
    if (a.action == SipAction::remove) keys.insert("sdp:" + attr);
    for (const auto& [field, rule] : a.fields) {
      if (changes(rule)) keys.insert("sdp:" + attr + "." + field);
    }
    for (const auto& p : a.fmtp_params) {
      if (changes(p.rule)) keys.insert("sdp:" + attr + "." + p.name);
    }
  }
  for (const auto& t : rs->feature_tags) {
    if (changes(t.rule)) keys.insert("tag:" + t.name);
  }
  for (const auto& b : rs->bodies) {
    if (b.handling == BodyHandling::empty) keys.insert("body:" + b.content_type);
  }
  for (const auto& k : keys) std::printf("%s\n", k.c_str());
  return 0;
}
