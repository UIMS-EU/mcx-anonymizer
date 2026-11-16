// SPDX-License-Identifier: GPL-3.0-or-later
//
// The TLS rule set (`ruleset: mcxanon-tls`, feature 007):
// protocol versions, record content types, handshake message types, hello
// extensions, the key exchange family of each cipher suite, and the X.509 name attributes,
// certificate extensions and public key algorithms. Everything without a rule is zeroed. Every
// entry cites its normative source.
#pragma once

#include "mcxanon/error.hpp"

#include "policy/ruleset.hpp"

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace mcxanon {

enum class TlsRecordAction { parse, keep, zero };

enum class TlsHandshakeAction {
  hello,                // ClientHello, ServerHello (R17)
  certificate,          // TLS 1.2 Certificate (R18)
  certificate_request,  // types and algorithms kept, names by the X.509 name rules
  server_key_exchange,  // R19
  client_key_exchange,  // R19
  certificate_verify,   // algorithm kept, signature zeroed
  new_session_ticket,   // lifetime kept, ticket zeroed
  zero_body,            // type and length kept, body zeroed
  keep,                 // an empty or constant body (HelloRequest, ServerHelloDone)
};

enum class TlsExtensionAction {
  keep,                // protocol values only (versions, groups, algorithms, flags)
  zero,                // content zeroed, type and length kept
  server_name,         // host names mapped as domains, other name types zeroed
  alpn,                // protocol names in `values` kept, others zeroed
  key_share,           // groups and lengths kept, key exchange values zeroed
  pre_shared_key,      // identities (R20), ages and binders zeroed
  renegotiation_info,  // verify data zeroed
  status_request,      // status type kept, responder ids and extensions zeroed
  certificate_authorities,  // distinguished names by the X.509 name rules
};

enum class KexFamily { ecdhe, dhe, rsa, psk, ecdhe_psk, dhe_psk, rsa_psk, tls13 };

enum class X509AttributeAction { keep, identity, opaque, email, domain_label };

enum class X509ExtensionAction {
  keep,
  general_names,             // subjectAltName, issuerAltName
  uri_access,                // authorityInfoAccess, cRLDistributionPoints
  key_identifier,            // subjectKeyIdentifier
  authority_key_identifier,  // keyIdentifier, authorityCertIssuer, authorityCertSerialNumber
  policies,                  // policy OIDs kept, CPS URIs mapped, user notices zeroed
  zero,
};

enum class PublicKeyAction { rsa, ec, zero };

struct TlsVersionRule {
  std::uint16_t value = 0;
  std::string name;
  Source source;
};
struct TlsRecordRule {
  std::uint8_t type = 0;
  std::string name;
  TlsRecordAction action = TlsRecordAction::zero;
  Source source;
};
struct TlsHandshakeRule {
  std::uint8_t type = 0;
  std::string name;
  TlsHandshakeAction action = TlsHandshakeAction::zero_body;
  Source source;
};
struct TlsExtensionRule {
  std::uint16_t type = 0;
  std::string name;
  TlsExtensionAction action = TlsExtensionAction::zero;
  std::vector<std::string> values;  // alpn: protocol names kept
  Source source;
};
struct TlsSuiteRule {
  std::uint16_t suite = 0;
  KexFamily family = KexFamily::ecdhe;
  Source source;
};
struct X509AttributeRule {
  std::string oid;  // dotted decimal
  std::string name;
  X509AttributeAction action = X509AttributeAction::opaque;
  Source source;
};
struct X509ExtensionRule {
  std::string oid;
  std::string name;
  X509ExtensionAction action = X509ExtensionAction::zero;
  Source source;
};
struct X509PublicKeyRule {
  std::string oid;
  std::string name;
  PublicKeyAction action = PublicKeyAction::zero;
  Source source;
};

struct TlsRuleSet {
  std::string name;
  std::string version;
  std::string digest;
  std::vector<TlsVersionRule> versions;
  std::vector<TlsRecordRule> records;
  std::vector<TlsHandshakeRule> handshakes;
  std::vector<TlsExtensionRule> extensions;
  std::vector<TlsSuiteRule> suites;
  std::vector<X509AttributeRule> attributes;
  std::vector<X509ExtensionRule> x509_extensions;
  std::vector<X509PublicKeyRule> public_keys;

  [[nodiscard]] bool known_version(std::uint16_t v) const;
  [[nodiscard]] const TlsRecordRule* find_record(std::uint8_t type) const;
  [[nodiscard]] const TlsHandshakeRule* find_handshake(std::uint8_t type) const;
  [[nodiscard]] const TlsExtensionRule* find_extension(std::uint16_t type) const;
  [[nodiscard]] const TlsSuiteRule* find_suite(std::uint16_t suite) const;
  [[nodiscard]] const X509AttributeRule* find_attribute(std::string_view oid) const;
  [[nodiscard]] const X509ExtensionRule* find_x509_extension(std::string_view oid) const;
  [[nodiscard]] const X509PublicKeyRule* find_public_key(std::string_view oid) const;
};

std::string_view to_string(TlsExtensionAction a);

Result<TlsRuleSet> load_tls_ruleset(std::span<const RuleFile> files);
Result<TlsRuleSet> load_embedded_tls_ruleset();

}  // namespace mcxanon
