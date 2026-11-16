// SPDX-License-Identifier: GPL-3.0-or-later
#include "policy/mikey_rules.hpp"

#include "bytes/hex.hpp"
#include "mcxanon/version.hpp"
#include "policy/ruleset_embedded.hpp"
#include "policy/yaml_util.hpp"

#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <initializer_list>

namespace mcxanon {

namespace {

using yaml::key;
using yaml::str;

// The documents the MIKEY rule set may cite: the "MIKEY rule set" section of rules/SOURCES.md.
// Keep both lists in sync.
constexpr std::array<std::string_view, 8> kDocuments{"RFC 3830",  "RFC 6043",  "RFC 6509",  "TS 33.180",
                                                      "TS 24.481", "TS 24.380", "TS 24.379", "TS 24.282"};

constexpr std::array<std::pair<MikeyAction, std::string_view>, 12> kActions{{
    {MikeyAction::keep, "keep"},
    {MikeyAction::rewrite, "rewrite"},
    {MikeyAction::shift, "shift"},
    {MikeyAction::identity, "identity"},
    {MikeyAction::kms, "kms"},
    {MikeyAction::uid, "uid"},
    {MikeyAction::nonce, "nonce"},
    {MikeyAction::key_id, "key-id"},
    {MikeyAction::zero, "zero"},
    {MikeyAction::sakke, "sakke"},
    {MikeyAction::key_parameters, "key-parameters"},
    {MikeyAction::fallback, "fallback"},
}};

std::string sha256_hex(const std::string& data) {
  std::array<unsigned char, SHA256_DIGEST_LENGTH> d{};
  SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), d.data());
  return to_hex(ByteView(d.data(), d.size()));
}

class Loader {
 public:
  explicit Loader(MikeyRuleSet& rs) : rs_(rs) {}

  Result<void> file(const RuleFile& f, bool first) {
    file_ = &f;
    ryml::Tree tree = ryml::parse_in_arena(ryml::to_csubstr(f.name), ryml::to_csubstr(f.text));
    const auto root = tree.crootref();
    if (!root.is_map()) return err("top level must be a mapping");
    if (auto r = only_keys(root, {"ruleset", "version", "message", "payloads", "ts_types", "id_roles", "extensions",
                                  "sp", "cs_ids", "purpose_tags", "default_trailer", "body_methods"},
                           "the rule file");
        !r) {
      return r;
    }
    if (!root.has_child("ruleset") || !root.has_child("version")) return err("'ruleset' and 'version' are required");
    const std::string name = scalar(root["ruleset"]);
    const std::string version = scalar(root["version"]);
    if (name != "mcxanon-mikey") return err("ruleset must be 'mcxanon-mikey'");
    if (version.empty()) return err("'version' must be non-empty");
    if (first) {
      rs_.name = name;
      rs_.version = version;
    } else if (version != rs_.version) {
      return err("rule set version differs from the other rule files");
    }
    if (root.has_child("message")) {
      if (auto r = message(root["message"]); !r) return r;
    }
    if (root.has_child("payloads")) {
      if (auto r = keyed(root["payloads"], "next", "payload rule", {"name"},
                         {MikeyAction::shift, MikeyAction::nonce, MikeyAction::rewrite, MikeyAction::sakke,
                          MikeyAction::zero, MikeyAction::fallback},
                         rs_.payloads);
          !r) {
        return r;
      }
    }
    if (root.has_child("ts_types")) {
      if (auto r = keyed(root["ts_types"], "value", "TS type rule", {"name"}, {MikeyAction::shift, MikeyAction::keep},
                         rs_.ts_types);
          !r) {
        return r;
      }
    }
    if (root.has_child("id_roles")) {
      if (auto r = id_roles(root["id_roles"]); !r) return r;
    }
    if (root.has_child("extensions")) {
      if (auto r = keyed(root["extensions"], "type", "extension rule", {"name"},
                         {MikeyAction::sakke, MikeyAction::key_parameters, MikeyAction::zero}, rs_.extensions);
          !r) {
        return r;
      }
    }
    if (root.has_child("sp")) {
      if (auto r = sp(root["sp"]); !r) return r;
    }
    if (root.has_child("cs_ids")) {
      if (auto r = named(root["cs_ids"], "cs_id", "CS ID", rs_.cs_ids); !r) return r;
    }
    if (root.has_child("purpose_tags")) {
      if (auto r = named(root["purpose_tags"], "tag", "purpose tag", rs_.purpose_tags); !r) return r;
    }
    if (root.has_child("default_trailer")) {
      if (auto r = trailer(root["default_trailer"]); !r) return r;
    }
    if (root.has_child("body_methods")) {
      if (auto r = body_methods(root["body_methods"]); !r) return r;
    }
    return {};
  }

  // The inventory of must be complete.
  Result<void> finish() const {
    const auto missing = [](const std::string& what) {
      return std::unexpected(Error{ErrorCode::internal, "MIKEY rule set: " + what + " has no rule"});
    };
    if (!saw_message_) return missing("the message section");
    for (unsigned n : {4u, 5u, 10u, 11u, 14u, 21u, 26u}) {
      const auto* r = rs_.payload(n);
      if (r == nullptr || r->action == MikeyAction::fallback) return missing("payload " + std::to_string(n));
    }
    for (unsigned t : {0u, 1u, 2u}) {
      if (!rs_.ts_types.contains(t)) return missing("TS type " + std::to_string(t));
    }
    for (unsigned role : {1u, 2u, 3u, 6u, 7u, 8u, 9u, 240u, 241u}) {
      if (std::none_of(rs_.id_roles.begin(), rs_.id_roles.end(), [&](const auto& e) { return e.first.first == role; })) {
        return missing("ID role " + std::to_string(role));
      }
    }
    for (unsigned t : {6u, 7u}) {
      if (!rs_.extensions.contains(t)) return missing("extension type " + std::to_string(t));
    }
    const auto srtp = rs_.sp.find(0);
    if (srtp == rs_.sp.end()) return missing("SP protocol type 0 (SRTP)");
    for (unsigned t : {0u, 1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u, 9u, 10u, 11u, 12u, 13u, 18u, 19u, 20u}) {
      if (!srtp->second.contains(t)) return missing("SRTP policy parameter " + std::to_string(t));
    }
    for (unsigned c = 0; c <= 9; ++c) {
      if (!rs_.cs_ids.contains(c)) return missing("CS ID " + std::to_string(c));
    }
    for (unsigned t = 0; t <= 6; ++t) {
      if (!rs_.purpose_tags.contains(t)) return missing("purpose tag " + std::to_string(t));
    }
    for (const char* k : {"GMK", "PCK", "CSK", "MuSiK"}) {
      if (!rs_.default_trailer.contains(k)) return missing(std::string("the default trailer of ") + k);
    }
    if (rs_.body_methods.empty()) return missing("the application/mikey body methods");
    for (const auto& m : rs_.message.mandatory) {
      if (std::none_of(rs_.payloads.begin(), rs_.payloads.end(), [&](const auto& e) { return e.second.name == m; })) {
        return std::unexpected(Error{ErrorCode::internal, "MIKEY rule set: mandatory payload '" + m + "' is unknown"});
      }
    }
    return {};
  }

 private:
  std::unexpected<Error> err(const std::string& msg) const {
    return std::unexpected(Error{ErrorCode::internal, "rule file " + file_->name + ": " + msg});
  }

  static std::string scalar(ryml::ConstNodeRef n) { return n.is_keyval() || n.is_val() ? str(n) : ""; }

  Result<void> only_keys(ryml::ConstNodeRef n, std::initializer_list<std::string_view> keys,
                         const std::string& what) const {
    if (!n.is_map()) return err(what + " must be a mapping");
    for (const auto c : n.children()) {
      const auto k = key(c);
      if (std::find(keys.begin(), keys.end(), k) == keys.end()) return err("unknown key '" + k + "' in " + what);
    }
    return {};
  }

  Result<std::string> text(ryml::ConstNodeRef n, std::string_view k, const std::string& what) const {
    if (!n.has_child(ryml::to_csubstr(std::string(k)))) return err(what + " needs '" + std::string(k) + "'");
    const auto c = n[ryml::to_csubstr(std::string(k))];
    if (!c.is_keyval()) return err("'" + std::string(k) + "' of " + what + " must be a scalar");
    return str(c);
  }

  Result<unsigned> number_of(const std::string& t, const std::string& what, unsigned max) const {
    unsigned v = 0;
    const auto* end = t.data() + t.size();
    const auto [p, ec] = std::from_chars(t.data(), end, v);
    if (t.empty() || ec != std::errc{} || p != end || v > max) {
      return err(what + " must be a number from 0 to " + std::to_string(max));
    }
    return v;
  }

  Result<unsigned> number(ryml::ConstNodeRef n, std::string_view k, const std::string& what, unsigned max) const {
    auto t = text(n, k, what);
    if (!t) return std::unexpected(t.error());
    return number_of(*t, "'" + std::string(k) + "' of " + what, max);
  }

  Result<Source> source(ryml::ConstNodeRef n, const std::string& what) const {
    if (!n.has_child("source") || !n["source"].is_map()) return err(what + ": rule without source");
    const auto s = n["source"];
    if (auto r = only_keys(s, {"spec", "version", "clause"}, what + " source"); !r) return std::unexpected(r.error());
    Source src;
    for (auto [k, dst] : {std::pair{"spec", &src.spec}, std::pair{"version", &src.version},
                          std::pair{"clause", &src.clause}}) {
      auto v = text(s, k, what + " source");
      if (!v) return std::unexpected(v.error());
      if (v->empty()) return err(what + ": empty source field '" + std::string(k) + "'");
      *dst = *v;
    }
    if (std::find(kDocuments.begin(), kDocuments.end(), src.spec) == kDocuments.end()) {
      return err(what + ": source '" + src.spec + "' is not in the list of indexed documents");
    }
    return src;
  }

  Result<MikeyAction> action(ryml::ConstNodeRef n, const std::string& what,
                             std::initializer_list<MikeyAction> allowed) const {
    auto a = text(n, "action", what);
    if (!a) return std::unexpected(a.error());
    const auto it = std::find_if(kActions.begin(), kActions.end(), [&](const auto& e) { return e.second == *a; });
    if (it == kActions.end()) return err("unknown action '" + *a + "' for " + what);
    if (std::find(allowed.begin(), allowed.end(), it->first) == allowed.end()) {
      return err("action '" + *a + "' not allowed for " + what);
    }
    return it->first;
  }

  // {value: N, source}; the value is returned through `out`.
  Result<void> valued(ryml::ConstNodeRef n, std::string_view k, unsigned max, unsigned& out) {
    const std::string what = "message " + std::string(k);
    if (!n.has_child(ryml::to_csubstr(std::string(k)))) return err(what + " is required");
    const auto c = n[ryml::to_csubstr(std::string(k))];
    if (auto r = only_keys(c, {"value", "source"}, what); !r) return r;
    auto v = number(c, "value", what, max);
    if (!v) return std::unexpected(v.error());
    auto s = source(c, what);
    if (!s) return std::unexpected(s.error());
    out = *v;
    rs_.message.sources.push_back(*s);
    return {};
  }

  Result<void> message(ryml::ConstNodeRef n) {
    if (auto r = only_keys(n, {"data_type", "version", "v_flag", "sign_s_type", "mandatory", "limits"}, "message"); !r) {
      return r;
    }
    auto& m = rs_.message;
    if (auto r = valued(n, "data_type", 255, m.data_type); !r) return r;
    if (auto r = valued(n, "version", 255, m.version); !r) return r;
    if (auto r = valued(n, "v_flag", 1, m.v_flag); !r) return r;
    if (auto r = valued(n, "sign_s_type", 15, m.sign_s_type); !r) return r;
    if (!n.has_child("mandatory")) return err("message mandatory is required");
    const auto md = n["mandatory"];
    if (auto r = only_keys(md, {"payloads", "source"}, "message mandatory"); !r) return r;
    if (!md.has_child("payloads") || !md["payloads"].is_seq()) return err("message mandatory needs a payloads list");
    m.mandatory.clear();
    for (const auto p : md["payloads"].children()) m.mandatory.push_back(str(p));
    if (auto s = source(md, "message mandatory"); !s) return std::unexpected(s.error());
    if (!n.has_child("limits")) return err("message limits are required");
    const auto l = n["limits"];
    if (auto r = only_keys(l, {"size", "payloads", "id_data", "source"}, "message limits"); !r) return r;
    auto size = number(l, "size", "message limits", 65535);
    auto pl = number(l, "payloads", "message limits", 255);
    auto id = number(l, "id_data", "message limits", 65535);
    if (!size) return std::unexpected(size.error());
    if (!pl) return std::unexpected(pl.error());
    if (!id) return std::unexpected(id.error());
    if (auto s = source(l, "message limits"); !s) return std::unexpected(s.error());
    m.max_size = *size;
    m.max_payloads = *pl;
    m.max_id_data = *id;
    saw_message_ = true;
    return {};
  }

  // A list of {<key>: N, name, action, source} rules keyed on N.
  Result<void> keyed(ryml::ConstNodeRef n, std::string_view key_name, const std::string& what,
                     std::initializer_list<std::string_view> extra, std::initializer_list<MikeyAction> allowed,
                     std::map<unsigned, MikeyRule>& out) {
    if (!n.is_seq()) return err(what + "s must be a sequence");
    for (const auto e : n.children()) {
      std::vector<std::string_view> keys{key_name, "action", "source"};
      keys.insert(keys.end(), extra.begin(), extra.end());
      if (!e.is_map()) return err(what + " must be a mapping");
      for (const auto c : e.children()) {
        if (std::find(keys.begin(), keys.end(), key(c)) == keys.end()) return err("unknown key '" + key(c) + "' in " + what);
      }
      auto k = number(e, key_name, what, 255);
      if (!k) return std::unexpected(k.error());
      MikeyRule r;
      if (e.has_child("name")) r.name = str(e["name"]);
      auto a = action(e, what + " " + std::to_string(*k), allowed);
      if (!a) return std::unexpected(a.error());
      r.action = *a;
      auto s = source(e, what + " " + std::to_string(*k));
      if (!s) return std::unexpected(s.error());
      r.source = *s;
      if (!out.emplace(*k, r).second) return err("duplicate " + what + " " + std::to_string(*k));
    }
    return {};
  }

  Result<void> id_roles(ryml::ConstNodeRef n) {
    if (!n.is_seq()) return err("id_roles must be a sequence");
    for (const auto e : n.children()) {
      if (auto r = only_keys(e, {"role", "name", "types", "action", "source"}, "ID role rule"); !r) return r;
      auto role = number(e, "role", "ID role rule", 255);
      if (!role) return std::unexpected(role.error());
      const std::string what = "ID role " + std::to_string(*role);
      if (!e.has_child("types") || !e["types"].is_seq()) return err(what + " needs a types list");
      MikeyRule r;
      if (e.has_child("name")) r.name = str(e["name"]);
      auto a = action(e, what, {MikeyAction::identity, MikeyAction::kms, MikeyAction::uid, MikeyAction::fallback});
      if (!a) return std::unexpected(a.error());
      r.action = *a;
      auto s = source(e, what);
      if (!s) return std::unexpected(s.error());
      r.source = *s;
      for (const auto t : e["types"].children()) {
        auto ty = number_of(str(t), what + " type", 255);
        if (!ty) return std::unexpected(ty.error());
        if (!rs_.id_roles.emplace(std::pair{*role, *ty}, r).second) return err("duplicate " + what);
      }
    }
    return {};
  }

  Result<void> sp(ryml::ConstNodeRef n) {
    if (!n.is_seq()) return err("sp must be a sequence");
    for (const auto e : n.children()) {
      if (auto r = only_keys(e, {"prot_type", "name", "source", "params"}, "SP rule"); !r) return r;
      auto prot = number(e, "prot_type", "SP rule", 255);
      if (!prot) return std::unexpected(prot.error());
      if (auto s = source(e, "SP protocol type " + std::to_string(*prot)); !s) return std::unexpected(s.error());
      if (!e.has_child("params")) return err("SP rule needs params");
      auto& table = rs_.sp[*prot];
      if (auto r = keyed(e["params"], "type", "SP parameter", {"name"}, {MikeyAction::keep}, table); !r) return r;
    }
    return {};
  }

  Result<void> named(ryml::ConstNodeRef n, std::string_view key_name, const std::string& what,
                     std::map<unsigned, MikeyRule>& out) {
    if (!n.is_seq()) return err(what + "s must be a sequence");
    for (const auto e : n.children()) {
      if (auto r = only_keys(e, {key_name, "name", "source"}, what); !r) return r;
      auto k = number(e, key_name, what, 255);
      if (!k) return std::unexpected(k.error());
      MikeyRule r;
      auto nm = text(e, "name", what);
      if (!nm) return std::unexpected(nm.error());
      r.name = *nm;
      r.action = MikeyAction::keep;
      auto s = source(e, what + " " + std::to_string(*k));
      if (!s) return std::unexpected(s.error());
      r.source = *s;
      if (!out.emplace(*k, r).second) return err("duplicate " + what + " " + std::to_string(*k));
    }
    return {};
  }

  Result<void> trailer(ryml::ConstNodeRef n) {
    if (!n.is_seq()) return err("default_trailer must be a sequence");
    for (const auto e : n.children()) {
      if (auto r = only_keys(e, {"key", "tag_octets", "source"}, "default trailer"); !r) return r;
      auto k = text(e, "key", "default trailer");
      if (!k) return std::unexpected(k.error());
      auto octets = number(e, "tag_octets", "default trailer", 32);
      if (!octets) return std::unexpected(octets.error());
      auto s = source(e, "default trailer " + *k);
      if (!s) return std::unexpected(s.error());
      if (!rs_.default_trailer.emplace(*k, std::pair{std::size_t{*octets}, *s}).second) {
        return err("duplicate default trailer " + *k);
      }
    }
    return {};
  }

  Result<void> body_methods(ryml::ConstNodeRef n) {
    if (!n.is_seq()) return err("body_methods must be a sequence");
    for (const auto e : n.children()) {
      if (auto r = only_keys(e, {"method", "source"}, "body method"); !r) return r;
      auto m = text(e, "method", "body method");
      if (!m) return std::unexpected(m.error());
      auto s = source(e, "body method " + *m);
      if (!s) return std::unexpected(s.error());
      if (!rs_.body_methods.emplace(*m, *s).second) return err("duplicate body method " + *m);
    }
    return {};
  }

  MikeyRuleSet& rs_;
  const RuleFile* file_ = nullptr;
  bool saw_message_ = false;
};

}  // namespace

const MikeyRule* MikeyRuleSet::payload(unsigned next) const {
  const auto it = payloads.find(next);
  return it == payloads.end() ? nullptr : &it->second;
}

const MikeyRule* MikeyRuleSet::id_role(unsigned role, unsigned id_type) const {
  const auto it = id_roles.find({role, id_type});
  return it == id_roles.end() ? nullptr : &it->second;
}

std::string_view to_string(MikeyAction a) {
  for (const auto& [v, n] : kActions) {
    if (v == a) return n;
  }
  return "?";
}

Result<MikeyRuleSet> load_mikey_ruleset(std::span<const RuleFile> files) {
  if (files.empty()) return fail(ErrorCode::internal, "MIKEY rule set has no files");
  std::vector<const RuleFile*> ordered;
  for (const auto& f : files) ordered.push_back(&f);
  std::sort(ordered.begin(), ordered.end(), [](const RuleFile* a, const RuleFile* b) { return a->name < b->name; });
  MikeyRuleSet rs;
  Loader loader(rs);
  std::string combined;
  yaml::ScopedCallbacks callbacks;
  for (std::size_t i = 0; i < ordered.size(); ++i) {
    combined += ordered[i]->text;
    try {
      if (auto r = loader.file(*ordered[i], i == 0); !r) return std::unexpected(r.error());
    } catch (const yaml::YamlError& e) {
      return fail(ErrorCode::internal, "rule file " + ordered[i]->name + ": " + e.what());
    }
  }
  if (auto r = loader.finish(); !r) return std::unexpected(r.error());
  rs.digest = sha256_hex(combined);
  return rs;
}

Result<MikeyRuleSet> load_embedded_mikey_ruleset() {
  std::vector<RuleFile> files;
  for (const auto& f : embedded_mikey_rule_files()) files.push_back(RuleFile{std::string(f.name), std::string(f.text)});
  return load_mikey_ruleset(files);
}

std::string_view embedded_mikey_ruleset_digest() { return mikey_ruleset_digest; }

}  // namespace mcxanon
