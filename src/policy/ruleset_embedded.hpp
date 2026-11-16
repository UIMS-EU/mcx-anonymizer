// SPDX-License-Identifier: GPL-3.0-or-later
// Rule files embedded at build time (generated: ruleset_embedded.cpp).
#pragma once

#include <span>
#include <string_view>

namespace mcxanon {

struct EmbeddedRuleFile {
  std::string_view name;
  std::string_view text;
};

std::span<const EmbeddedRuleFile> embedded_rule_files();      // mcxanon-l2l4
std::span<const EmbeddedRuleFile> embedded_sip_rule_files();  // mcxanon-sip
std::span<const EmbeddedRuleFile> embedded_media_rule_files();  // mcxanon-media
std::span<const EmbeddedRuleFile> embedded_xml_rule_files();    // mcxanon-xml
std::span<const EmbeddedRuleFile> embedded_mikey_rule_files();  // mcxanon-mikey
std::span<const EmbeddedRuleFile> embedded_http_rule_files();   // mcxanon-http (feature 007)
std::span<const EmbeddedRuleFile> embedded_tls_rule_files();    // mcxanon-tls (feature 007)

}  // namespace mcxanon
