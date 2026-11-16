// SPDX-License-Identifier: GPL-3.0-or-later
#include "policy/ruleset.hpp"

#include "bytes/hex.hpp"
#include "mcxanon/version.hpp"
#include "policy/ruleset_embedded.hpp"
#include "policy/yaml_util.hpp"

#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <set>
#include <stdexcept>

namespace mcxanon {
namespace {

using yaml::key;
using yaml::str;
using yaml::YamlError;
using ScopedYamlCallbacks = yaml::ScopedCallbacks;

std::optional<Action> parse_action(std::string_view s) {
  if (s == "keep") return Action::keep;
  if (s == "pseudonymise") return Action::pseudonymise;
  if (s == "zero") return Action::zero;
  if (s == "pad") return Action::pad;
  if (s == "remove") return Action::remove;
  if (s == "recompute") return Action::recompute;
  if (s == "l7") return Action::l7;
  return std::nullopt;
}

bool action_allowed(FieldKind k, Action a) {
  switch (k) {
    case FieldKind::address_mac:
    case FieldKind::address_ipv4:
    case FieldKind::address_ipv6:
      return a == Action::keep || a == Action::pseudonymise || a == Action::zero;
    case FieldKind::vlan:
    case FieldKind::port:
      return a == Action::keep || a == Action::pseudonymise;
    case FieldKind::numeric:
      return a == Action::keep || a == Action::zero || a == Action::pseudonymise;
    case FieldKind::opaque:
      return a == Action::keep || a == Action::zero;
    case FieldKind::length:
    case FieldKind::checksum:
      return a == Action::recompute;
    case FieldKind::option:
      return a == Action::keep || a == Action::pad || a == Action::zero;
    case FieldKind::payload:
      return a == Action::zero;
    case FieldKind::pcapng_block:
    case FieldKind::pcapng_option:
      return a == Action::keep || a == Action::remove;
  }
  return false;
}

bool category_allowed(FieldKind k, std::string_view c) {
  switch (k) {
    case FieldKind::address_mac: return c == "mac";
    case FieldKind::address_ipv4: return c == "ipv4";
    case FieldKind::address_ipv6: return c == "ipv6";
    case FieldKind::vlan: return c == "vlan";
    case FieldKind::port: return c == "port-eph";
    case FieldKind::numeric: return c == "spi";  // 32-bit SPIs (feature 002)
    default: return false;
  }
}

std::string sha256_hex(std::string_view data) {
  std::array<unsigned char, SHA256_DIGEST_LENGTH> md{};
  SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), md.data());
  return to_hex(ByteView(md.data(), md.size()));
}

Result<void> load_file(const RuleFile& f, const Catalogue& cat, RuleSet& rs,
                       std::set<std::string>& seen, bool first) {
  const auto where = [&](const std::string& msg) {
    return fail(ErrorCode::internal, "rule file " + f.name + ": " + msg);
  };
  ryml::Tree tree = ryml::parse_in_arena(ryml::to_csubstr(f.name), ryml::to_csubstr(f.text));
  const ryml::ConstNodeRef root = tree.crootref();
  if (!root.is_map()) return where("top level must be a mapping");
  for (const auto child : root.children()) {
    const std::string k = key(child);
    if (k != "ruleset" && k != "version" && k != "rules") return where("unknown key '" + k + "'");
  }
  if (!root.has_child("ruleset") || !root.has_child("version") || !root.has_child("rules")) {
    return where("'ruleset', 'version' and 'rules' are required");
  }
  const std::string name = str(root["ruleset"]);
  const std::string version = str(root["version"]);
  if (name.empty() || version.empty()) return where("'ruleset' and 'version' must be non-empty");
  if (first) {
    rs.name = name;
    rs.version = version;
  } else if (name != rs.name || version != rs.version) {
    return where("rule set name/version differ from the other rule files");
  }
  const ryml::ConstNodeRef rules = root["rules"];
  if (!rules.is_seq()) return where("'rules' must be a sequence");
  for (const auto r : rules.children()) {
    if (!r.is_map()) return where("each rule must be a mapping");
    for (const auto c : r.children()) {
      const std::string k = key(c);
      if (k != "field" && k != "action" && k != "category" && k != "source" && k != "note") {
        return where("unknown rule key '" + k + "'");
      }
    }
    Rule rule;
    if (!r.has_child("field") || !r.has_child("action")) return where("rule without field/action");
    rule.field = str(r["field"]);
    const FieldDecl* decl = cat.find(rule.field);
    if (decl == nullptr) return where("unknown FieldId '" + rule.field + "'");
    if (!seen.insert(rule.field).second) return where("duplicate rule for '" + rule.field + "'");
    const auto action = parse_action(str(r["action"]));
    if (!action) return where("unknown action '" + str(r["action"]) + "' for " + rule.field);
    rule.action = *action;
    // payload.sip delegates to the SIP layer (feature 002) and payload.media to the
    // media layer (feature 004): they take l7 and only l7, and no other field may
    // take l7, so the coverage test stays exact.
    const bool sip_field = rule.field == "payload.sip" || rule.field == "payload.media";
    if ((rule.action == Action::l7) != sip_field) {
      return where("action '" + std::string(to_string(rule.action)) + "' not allowed for " +
                   rule.field + (sip_field ? " (" + rule.field + " takes l7 only)" : ""));
    }
    if (!sip_field && !action_allowed(decl->kind, rule.action)) {
      return where("action '" + std::string(to_string(rule.action)) + "' not allowed for " +
                   rule.field);
    }
    if (r.has_child("category")) rule.category = str(r["category"]);
    if (rule.action == Action::pseudonymise && rule.category == "spi" && rule.field != "ah.spi" &&
        rule.field != "esp.spi") {
      return where("category spi is for ah.spi and esp.spi only: " + rule.field);
    }
    if (rule.action == Action::pseudonymise &&
        (!rule.category || !category_allowed(decl->kind, *rule.category))) {
      return where("pseudonymise needs a category matching the field kind: " + rule.field);
    }
    if (rule.action != Action::pseudonymise && rule.category) {
      return where("category given for a non-pseudonymise rule: " + rule.field);
    }
    if (!r.has_child("source") || !r["source"].is_map()) {
      return where("rule without source: " + rule.field);
    }
    const auto src = r["source"];
    for (const auto c : src.children()) {
      const std::string k = key(c);
      if (k != "spec" && k != "version" && k != "clause") return where("unknown source key " + k);
    }
    if (!src.has_child("spec") || !src.has_child("version") || !src.has_child("clause")) {
      return where("source needs spec, version and clause: " + rule.field);
    }
    rule.source = {str(src["spec"]), str(src["version"]), str(src["clause"])};
    if (rule.source.spec.empty() || rule.source.version.empty() || rule.source.clause.empty()) {
      return where("empty source fields: " + rule.field);
    }
    if (r.has_child("note")) rule.note = str(r["note"]);
    rs.rules.push_back(std::move(rule));
  }
  return {};
}

}  // namespace

std::string_view to_string(Action a) {
  switch (a) {
    case Action::keep: return "keep";
    case Action::pseudonymise: return "pseudonymise";
    case Action::zero: return "zero";
    case Action::pad: return "pad";
    case Action::remove: return "remove";
    case Action::recompute: return "recompute";
    case Action::l7: return "l7";
  }
  return "?";
}

const Rule* RuleSet::find(std::string_view field) const {
  const auto it = std::find_if(rules.begin(), rules.end(),
                               [&](const Rule& r) { return r.field == field; });
  return it == rules.end() ? nullptr : &*it;
}

Result<RuleSet> load_ruleset(std::span<const RuleFile> files, const Catalogue& catalogue) {
  if (files.empty()) return fail(ErrorCode::internal, "rule set has no files");
  std::vector<const RuleFile*> ordered;
  for (const auto& f : files) ordered.push_back(&f);
  std::sort(ordered.begin(), ordered.end(),
            [](const RuleFile* a, const RuleFile* b) { return a->name < b->name; });
  RuleSet rs;
  std::set<std::string> seen;
  std::string combined;
  ScopedYamlCallbacks callbacks;
  for (std::size_t i = 0; i < ordered.size(); ++i) {
    combined += ordered[i]->text;
    try {
      if (auto r = load_file(*ordered[i], catalogue, rs, seen, i == 0); !r) {
        return std::unexpected(r.error());
      }
    } catch (const YamlError& e) {
      return fail(ErrorCode::internal, "rule file " + ordered[i]->name + ": " + e.what());
    }
  }
  rs.digest = sha256_hex(combined);
  return rs;
}

Result<RuleSet> load_embedded_ruleset() {
  std::vector<RuleFile> files;
  for (const auto& f : embedded_rule_files()) {
    files.push_back(RuleFile{std::string(f.name), std::string(f.text)});
  }
  return load_ruleset(files, Catalogue::builtin());
}

std::string_view embedded_ruleset_name() { return ruleset_name; }
std::string_view embedded_ruleset_digest() { return ruleset_digest; }

}  // namespace mcxanon
