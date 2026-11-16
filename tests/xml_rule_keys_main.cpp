// SPDX-License-Identifier: GPL-3.0-or-later
//
// Prints the key of every rule of the embedded XML rule set whose action is not keep or
// container, and of every namespace removed as a whole, one per line, in the canary key format of
// tools/fixturegen/xmlbodies.py. Used by test_rule_canary_coverage.py (every such
// rule has a canary).
//   xml:<namespace name>|<parent local or ->|<local>                     an element
//   xml:<namespace name>|<element local>|@<attr namespace or ->|<local>  an attribute
//   xml-ns:<namespace name>                                              a namespace
// An element rule with a parent list gives one key per parent.
#include "policy/xml_rules.hpp"

#include <cstdio>
#include <set>
#include <string>

using namespace mcxanon;

int main() {
  auto rs = load_embedded_xml_ruleset();
  if (!rs) {
    std::fprintf(stderr, "%s\n", rs.error().message.c_str());
    return 1;
  }
  std::set<std::string> keys;
  const auto changes = [](const XmlItemRule& r) {
    return r.action != XmlAction::keep && r.action != XmlAction::container;
  };
  for (const auto& [name, ns] : rs->namespaces) {
    if (ns.disposition != XmlDisposition::rules) {
      keys.insert("xml-ns:" + name);
      continue;
    }
    for (const auto& [local, rules] : ns.elements) {
      for (const auto& e : rules) {
        if (!changes(e.rule)) continue;
        if (e.parents.empty()) keys.insert("xml:" + name + "|-|" + local);
        for (const auto& p : e.parents) keys.insert("xml:" + name + "|" + p + "|" + local);
      }
    }
    for (const auto& a : ns.attributes) {
      if (changes(a.rule)) {
        keys.insert("xml:" + name + "|" + a.element + "|@" + (a.ns.empty() ? "-" : a.ns) + "|" + a.local);
      }
    }
  }
  for (const auto& k : keys) std::printf("%s\n", k.c_str());
  return 0;
}
