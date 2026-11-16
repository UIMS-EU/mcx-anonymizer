// SPDX-License-Identifier: GPL-3.0-or-later
//
// Prints the key of every rule of the embedded TLS rule set that changes a value, one per line,
// in the canary key format of tools/fixturegen/web.py. Used by
// test_rule_canary_coverage.py.
//   tls:<record, handshake or extension name>   a record, message or extension rule that zeroes
//                                               or pseudonymises
//   x509:<attribute, extension or key name>     X.509 rules that pseudonymise or zero
// and the fixed keys of the values every hello and certificate carries.
#include "policy/tls_rules.hpp"

#include <cstdio>
#include <set>
#include <string>

using namespace mcxanon;

int main() {
  auto rs = load_embedded_tls_ruleset();
  if (!rs) {
    std::fprintf(stderr, "%s\n", rs.error().message.c_str());
    return 1;
  }
  std::set<std::string> keys{"tls:random",        "tls:session-id",          "tls:extension-unknown",
                             "x509:serial",       "x509:signature",          "x509:unknown-attribute",
                             "x509:unknown-extension"};
  for (const auto& r : rs->records) {
    if (r.action == TlsRecordAction::zero) keys.insert("tls:" + r.name);
  }
  for (const auto& h : rs->handshakes) {
    if (h.action != TlsHandshakeAction::keep && h.action != TlsHandshakeAction::hello &&
        h.action != TlsHandshakeAction::certificate && h.action != TlsHandshakeAction::certificate_request) {
      keys.insert("tls:" + h.name);
    }
  }
  for (const auto& e : rs->extensions) {
    if (e.action != TlsExtensionAction::keep) keys.insert("tls:" + e.name);
  }
  for (const auto& a : rs->attributes) {
    if (a.action != X509AttributeAction::keep) keys.insert("x509:" + a.name);
  }
  for (const auto& e : rs->x509_extensions) {
    if (e.action != X509ExtensionAction::keep) keys.insert("x509:" + e.name);
  }
  for (const auto& k : rs->public_keys) keys.insert("x509:" + k.name);
  for (const auto& k : keys) std::printf("%s\n", k.c_str());
  return 0;
}
