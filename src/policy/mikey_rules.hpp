// SPDX-License-Identifier: GPL-3.0-or-later
//
// The MIKEY rule set (`ruleset: mcxanon-mikey`, feature 005): the MIKEY-SAKKE message
// constraints, the payload allowlist, the timestamp types, the identity role x type table, the
// general extension types, the security policy parameters, the CS IDs, the purpose tags and the
// default SRTP trailer profiles. Every entry cites its source; the loader accepts only the
// documents of the "MIKEY rule set" section of rules/SOURCES.md.
#pragma once

#include "mcxanon/error.hpp"

#include "policy/ruleset.hpp"

#include <cstddef>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace mcxanon {

enum class MikeyAction {
  keep,            // the field or payload is copied
  rewrite,         // a payload with its own handler (HDR, SP)
  shift,           // a timestamp follows --time-shift
  identity,        // IDR data: the 002 URI / NAI mapping (http(s): the 003 xcap-selector)
  kms,             // IDR data: the 003 kms-uri handling
  uid,             // IDR data: a hidden identity (TS 33.180 §E.7)
  nonce,           // RAND: same-length pseudonym
  key_id,          // a key identifier (TS 33.180 Annex G)
  zero,            // data zeroed, length kept
  sakke,           // SAKKE payload (kept in ciphertext mode)
  key_parameters,  // the protected payload of extension 7
  fallback,        // the whole message falls back to the carrier's previous handling
};

struct MikeyRule {
  std::string name;
  MikeyAction action = MikeyAction::fallback;
  Source source;
};

struct MikeyMessageRules {
  unsigned data_type = 26;
  unsigned version = 1;
  unsigned v_flag = 0;
  unsigned sign_s_type = 2;  // ECCSI
  std::vector<std::string> mandatory;
  std::size_t max_size = 65535;
  std::size_t max_payloads = 64;
  std::size_t max_id_data = 1024;
  std::vector<Source> sources;
};

struct MikeyRuleSet {
  std::string name;
  std::string version;
  std::string digest;
  MikeyMessageRules message;
  std::map<unsigned, MikeyRule> payloads;                      // next-payload value
  std::map<unsigned, MikeyRule> ts_types;                      // T payload TS type
  std::map<std::pair<unsigned, unsigned>, MikeyRule> id_roles;  // (ID role, ID type)
  std::map<unsigned, MikeyRule> extensions;                    // general extension type
  std::map<unsigned, std::map<unsigned, MikeyRule>> sp;        // prot type -> parameter type
  std::map<unsigned, MikeyRule> cs_ids;                        // name = the CS use
  std::map<unsigned, MikeyRule> purpose_tags;                  // name = the key type
  std::map<std::string, std::pair<std::size_t, Source>> default_trailer;  // key type -> SRTP tag octets after the MKI
  std::map<std::string, Source> body_methods;  // requests that carry application/mikey (FR-004 b)

  [[nodiscard]] const MikeyRule* payload(unsigned next) const;
  [[nodiscard]] const MikeyRule* id_role(unsigned role, unsigned id_type) const;
};

std::string_view to_string(MikeyAction a);

Result<MikeyRuleSet> load_mikey_ruleset(std::span<const RuleFile> files);
Result<MikeyRuleSet> load_embedded_mikey_ruleset();
std::string_view embedded_mikey_ruleset_digest();

}  // namespace mcxanon
