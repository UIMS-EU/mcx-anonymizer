// SPDX-License-Identifier: GPL-3.0-or-later
//
// The SIP rule set (`ruleset: mcxanon-sip`): rules per
// header and component, per header and URI parameter, per SDP line and attribute, per body
// type and per media feature tag. Everything without a rule is removed (or, for bodies,
// emptied). Every rule cites its normative source.
#pragma once

#include "mcxanon/error.hpp"

#include "policy/ruleset.hpp"

#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace mcxanon {

// What happens to a header, component, parameter, SDP item or feature tag.
enum class SipAction {
  keep,
  pseudonymise,  // needs a category
  uri,           // apply the URI rules to a nested URI
  blank,         // replace by a fixed neutral value
  remove,
};

// Header value grammars (closed set; each has a parser in src/sip/header_values.*).
enum class SipGrammar {
  name_addr,
  name_addr_list,
  uri_list,
  via,
  call_id,
  cseq,
  token,
  token_list,
  number,
  date,
  credentials,
  challenge,
  security_mech,
  pani,
  quoted_text,
  warning,
  reason,
  retry_after,
  event,
  media_type,
  session_id,
  opaque,
  auth_params,  // comma-separated auth-params without a scheme (Authentication-Info)
  param_list,   // semicolon-separated parameters without a head (P-Charging-Vector)
  // HTTP grammars (feature 007, rules/http.yaml only; the SIP rewriter removes such a value):
  host,              // host [":" port] (RFC 9110 §7.2)
  etag_list,         // "*" / #entity-tag (RFC 9110 §8.8.3, §13.1.1)
  http_uri,          // a URI reference (Location, Content-Location; RFC 9110 §10.2.2)
  http_credentials,  // Basic, Bearer, Digest and other schemes (RFC 9110 §11.6.2)
  cookie,            // RFC 6265 §4.2.1
  set_cookie,        // RFC 6265 §4.1.1
  directives,        // #( token [ "=" ( token / quoted-string ) ] ) (RFC 9111 §5.2)
  range,             // ranges and content ranges (RFC 9110 §14)
  identity,          // a quoted or bare URI naming a user (X-3GPP-Intended-Identity)
};

// True for the grammars of the HTTP rule set (feature 007).
bool is_http_grammar(SipGrammar g);

// Value grammars of header and URI parameters.
enum class ParamValue { token, quoted, host, uri, number, flag, any };

// Value grammars of SDP attributes.
enum class SdpGrammar {
  flag,        // a=<name> without a value
  opaque,      // any value; only with keep
  token,       // one token value
  rtcp,        // RFC 3605 §2.1
  ssrc,        // RFC 5576 §4.1
  ssrc_group,  // RFC 5576 §4.2
  candidate,   // RFC 8839 §5.1
  remote_candidates,  // RFC 8839 §5.2
  path,        // RFC 4975 §8.2
  fmtp_params, // a=fmtp:<format> with a parameter list (TS 24.380 §12.1.2.3 and alike)
  key_mgmt,    // RFC 4567 §3.1: prtcl-id SP base64 data; "mikey" goes to the MIKEY rewriter (feature 005)
};

// Mapping categories a SIP rule may name: the text categories of plus the
// address and port mappings of feature 001.
enum class SipCategory {
  sip_user,
  domain,
  display_name,
  tel,
  call_id,
  tag,
  branch,
  entity_tag,
  charging_id,
  session_id,
  imei,
  uuid,
  cell_id,
  spi,
  ssrc,
  digest,
  sdp_sess,
  boundary,
  msrp_session,
  reg_token,
  cname,
  host,      // a domain name or an IP address literal, whichever it is
  ip,        // an IP address literal (feature-001 address mapping)
  port,      // the transport port policy (001/FR-015)
  instance,  // an instance URN: urn:gsma:imei:… (imei) or urn:uuid:… (uuid)
};

// xml: an MCX XML body, rewritten by feature 003 through sip::XmlBodies (rules/xml-*.yaml).
enum class BodyHandling { sdp, multipart, empty, xml, mikey };

enum class FeatureValue { none, boolean, token, string, token_list, urn_list, uri, identity };

struct SipItemRule {
  SipAction action = SipAction::remove;
  std::optional<SipCategory> category;
  std::string value;  // replacement for blank
};

struct SipParamRule {
  std::string name;  // lowercase comparison key; spelling kept from the input
  SipItemRule rule;
  ParamValue value = ParamValue::token;
  Source source;
};

struct SipHeaderRule {
  std::string name;
  std::optional<char> compact;
  SipGrammar grammar = SipGrammar::opaque;
  bool multi = false;  // comma-separated values allowed
  // Header-level action: keep (unchanged), remove, or pseudonymise (per components).
  SipAction action = SipAction::pseudonymise;
  std::map<std::string, SipItemRule> components;
  std::vector<SipParamRule> params;
  std::vector<std::string> aliases;
  std::vector<std::string> values;  // token grammars: the only values kept (lowercase); empty = any token
  Source source;
  std::string note;
  [[nodiscard]] const SipParamRule* find_param(std::string_view name) const;
};

// A URI of another scheme that is kept as it is: an exact value, or a prefix when the value ends
// in ":" (for example "urn:alert:", RFC 7462 §7).
struct SipKeptUri {
  std::string value;
  Source source;
};

struct SipUriRules {
  std::vector<std::string> schemes;
  std::vector<SipParamRule> params;
  std::vector<SipKeptUri> keep;
  [[nodiscard]] bool kept(std::string_view uri) const;
  [[nodiscard]] const SipParamRule* find_param(std::string_view name) const;
};

struct SdpLineRule {
  char type = '?';
  SipAction action = SipAction::remove;
  std::string value;                         // replacement for blank
  std::vector<std::string> keep_values;      // exact values kept
  std::map<std::string, SipItemRule> fields;
  Source source;
};

struct SdpAttributeRule {
  std::string name;
  std::optional<std::string> format;  // for fmtp: the format token (MCPTT, MCVideo, MCDATA)
  SdpGrammar grammar = SdpGrammar::opaque;
  SipAction action = SipAction::keep;
  std::map<std::string, SipItemRule> fields;
  std::vector<SipParamRule> fmtp_params;
  std::vector<std::string> separators;
  Source source;
};

struct SipBodyRule {
  std::string content_type;  // lowercase type/subtype
  BodyHandling handling = BodyHandling::empty;
  std::vector<std::string> params;  // allowed Content-Type parameters (lowercase)
  Source source;
};

struct FeatureTagRule {
  std::string name;         // tag name as written (with "+" for non-base tags), or a value
  bool is_value = false;    // an ICSI/IARI value rather than a tag
  FeatureValue value_type = FeatureValue::none;
  SipItemRule rule;
  Source source;
};

// A request method the output keeps (TS 24.229 annex A.2.1.4: the 14 methods of the UA role).
// A message with any other method is zeroed (fail-closed: an extension method token is text the
// rules do not understand).
struct SipMethodRule {
  std::string name;  // case-sensitive (RFC 3261 §7.1)
  Source source;
};

struct SipRuleSet {
  std::string name;
  std::string version;
  std::string digest;
  std::vector<SipHeaderRule> headers;
  SipUriRules uri;
  std::vector<SdpLineRule> sdp_lines;
  std::vector<SdpAttributeRule> sdp_attributes;
  std::vector<SipBodyRule> bodies;
  std::vector<FeatureTagRule> feature_tags;
  std::vector<SipMethodRule> methods;

  // True when the method is listed (or when the rule set lists no methods: a test seam).
  [[nodiscard]] bool known_method(std::string_view method) const;
  // Full name, alias or compact form, compared case-insensitively.
  [[nodiscard]] const SipHeaderRule* find_header(std::string_view name) const;
  [[nodiscard]] const SdpLineRule* find_sdp_line(char type) const;
  // For fmtp, `format` selects the rule of that format (case-insensitive).
  [[nodiscard]] const SdpAttributeRule* find_sdp_attribute(std::string_view name,
                                                           std::string_view format = {}) const;
  [[nodiscard]] const SipBodyRule* find_body(std::string_view content_type) const;
  [[nodiscard]] const FeatureTagRule* find_feature_tag(std::string_view name) const;
  [[nodiscard]] const FeatureTagRule* find_feature_value(std::string_view value) const;
};

std::string_view to_string(SipAction a);
std::string_view to_string(SipCategory c);

// Loads and validates the files of the SIP rule set ("Load-time
// validation"). Errors are values (ErrorCode::internal), never exceptions.
Result<SipRuleSet> load_sip_ruleset(std::span<const RuleFile> files);

// Feature 007: the header and method rules of the HTTP rule set (`ruleset: mcxanon-http`), in the
// 002 header format with the HTTP grammars; the other keys of those files are read by
// load_http_ruleset (policy/http_rules.hpp).
Result<SipRuleSet> load_http_header_rules(std::span<const RuleFile> files);

// The SIP rule set embedded at build time from rules/sip-*.yaml and rules/sdp.yaml.
Result<SipRuleSet> load_embedded_sip_ruleset();
std::string_view embedded_sip_ruleset_digest();

}  // namespace mcxanon
