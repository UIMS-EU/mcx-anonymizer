// SPDX-License-Identifier: GPL-3.0-or-later
//
// The XML rule set (`ruleset: mcxanon-xml`, feature 003): which XML documents are rewritten
// (Content-Type -> allowed roots), and per namespace name the rules of its elements and
// attributes. Rules are keyed by namespace name and local name, never by prefix (FR-006), with
// an optional parent qualifier. Every entry cites its
// source; the loader accepts only the documents of the "MCX XML bodies" section of
// rules/SOURCES.md.
#pragma once

#include "mcxanon/error.hpp"

#include "policy/ruleset.hpp"

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace mcxanon {

struct SipRuleSet;

// Closed grammars of `token` values (X4, A13).
enum class XmlTokenGrammar : std::uint8_t {
  trigger_id,   // 1*64(ALPHA / DIGIT / "-" / "_" / "." / ":")
  hex_counter,  // 1*8HEXDIG
  r_value,      // RFC 4412 §3.1 r-value = namespace "." r-priority, both token-nodot
  ncname,       // an XML NCName of at most 64 characters
  qvalue,       // RFC 3863 XSD qvalue: 0(\.[0-9]{0,3})? | 1(\.0{0,3})? (pidf contact@priority)
  rfc_token,    // RFC 3261 §25.1 token of at most 64 characters (RFC 4574 media labels)
};

// The value type of a `keep` (or `fixed`) rule.
struct XmlValueType {
  enum class Kind : std::uint8_t {
    boolean, enumeration, integer, datetime, date, time, duration, hex, token, std_uri, lang, empty,
    base64,  // xs:base64Binary (feature 005: xenc CipherValue)
    datetime_shifted,  // feature 007: an xs:dateTime kept after adding --time-shift (KMS, FR-015)
  };
  Kind kind = Kind::empty;
  std::vector<std::string> values;   // enumeration, std_uri
  std::int64_t min = 0;              // integer
  std::uint64_t max = 0;             // integer
  std::vector<std::size_t> lengths;  // hex: allowed digit counts
  XmlTokenGrammar grammar = XmlTokenGrammar::trigger_id;
};

// zero (feature 007): the text is replaced by as many "0" (hexBinary) or "A"
// (base64) characters, so the element keeps its type and length (public KMS keys, signatures).
enum class XmlAction : std::uint8_t { container, keep, pseudonymise, fixed, empty, remove, zero };

enum class XmlRemoveReason : std::uint8_t { free_text, credential, tmgi, structure };

// What a namespace with no element rules does with its elements.
enum class XmlDisposition : std::uint8_t {
  rules,              // its elements follow their rules; an element without a rule is unknown
  remove_encrypted,   // xenc: every element is removed and counted `encrypted` (FR-018)
  remove_credential,  // the GKTP namespaces: removed as credentials (A12, D3)
  // xenc (feature 005, FR-016): EncryptedData under an encryptable element, or as the whole body,
  // follows the element rules in ciphertext mode and is copied as it is in passthrough mode;
  // anywhere else it is removed and counted as remove_encrypted does.
  encrypted_content,
};

// Mapping categories an XML rule may name.
enum class XmlCategory : std::uint8_t {
  uri, display_name, uuid, imei, instance, call_id, tag, entity_tag, cid, host, ip, port,
  ssrc, fc_ref, plmn, eci, tac, mbms_sai, mbsfn_area,
  opaque, nci, nr_tac, mbs_fsa,
  mbms_sai_hex,  // an MBMS SAI written as exactly 4 hex digits (usage documents, X4)
  xcap_node,     // an RFC 5261 patch-operation selector: node selector only (E.7.4 step 5)
  // composites: split a value and map its parts
  ecgi, ncgi, tai, tac_bin, any_id, kms_uri, replaces, xcap_selector, user_at_host,
  mikey_hex,  // feature 005: a <GKTP> hexBinary I_MESSAGE, rewritten by the MIKEY carrier
  xpk_id,     // feature 005: the base64 of a 32-bit key identifier (XPK-ID, TS 33.180 §9.3.4.2)
  web_uri,    // feature 007: an http(s) URL (host mapped, path as an XCAP selector), a SIP or tel URI, or a host
};

struct XmlItemRule {
  XmlAction action = XmlAction::remove;
  std::optional<XmlValueType> value;  // keep (required), fixed (optional)
  std::optional<XmlCategory> category;
  std::string constant;               // fixed
  std::optional<XmlRemoveReason> reason;
  bool encryptable = false;           // may carry type="Encrypted" + xenc:EncryptedData
  bool embeds_body = false;           // resource-lists entry@uri (FR-014a)
  Source source;
};

struct XmlElementRule {
  std::string local;
  std::vector<std::string> parents;  // local names of the parent in the same namespace; empty = any
  XmlItemRule rule;
};

struct XmlAttributeRule {
  std::string element;  // local name of the element, or "*"
  std::string ns;       // namespace name of the attribute, "" for unprefixed
  std::string local;
  XmlItemRule rule;
};

struct XmlNamespaceRules {
  std::string name;
  XmlDisposition disposition = XmlDisposition::rules;
  std::map<std::string, std::vector<XmlElementRule>, std::less<>> elements;  // by local name
  std::vector<XmlAttributeRule> attributes;
  Source source;

  // The rule whose parent list contains `parent_local`, else the rule without parents.
  [[nodiscard]] const XmlElementRule* element(std::string_view local, std::string_view parent_local) const;
  // The rule for (element, attribute), else for ("*", attribute).
  [[nodiscard]] const XmlAttributeRule* attribute(std::string_view element_local, std::string_view attr_ns,
                                                  std::string_view attr_local) const;
};

struct XmlRoot {
  std::string ns;
  std::string local;
};

struct XmlDocumentRule {
  std::string content_type;  // lower case
  std::vector<XmlRoot> roots;
  Source source;
};

struct XmlRuleSet {
  std::string name;
  std::string version;
  std::string digest;
  std::map<std::string, XmlDocumentRule, std::less<>> documents;    // by Content-Type
  std::map<std::string, XmlNamespaceRules, std::less<>> namespaces;  // by namespace name

  [[nodiscard]] const XmlDocumentRule* document(std::string_view content_type) const;
  [[nodiscard]] const XmlNamespaceRules* ns(std::string_view namespace_name) const;
};

std::string_view to_string(XmlAction a);
std::string_view to_string(XmlCategory c);
std::string_view to_string(XmlRemoveReason r);
std::optional<XmlTokenGrammar> xml_token_grammar(std::string_view name);

Result<XmlRuleSet> load_xml_ruleset(std::span<const RuleFile> files);
Result<XmlRuleSet> load_embedded_xml_ruleset();
std::string_view embedded_xml_ruleset_digest();

// Cross-check with the SIP body rules: every Content-Type with handling `xml` has a document
// rule, and every document rule names a Content-Type the SIP rules know. With `complete`, every
// document rule's Content-Type must also have handling `xml` (all types switched on).
// Feature 007: `http_xml` lists the content types the HTTP rule set sends to the XML engine; a
// document needs a SIP body rule or an HTTP one, and every HTTP xml type needs a document.
Result<void> check_xml_bodies(const SipRuleSet& sip, const XmlRuleSet& xml, bool complete,
                              const std::vector<std::string>& http_xml = {});

}  // namespace mcxanon
