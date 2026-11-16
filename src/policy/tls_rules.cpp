// SPDX-License-Identifier: GPL-3.0-or-later
#include "policy/tls_rules.hpp"

#include "policy/http_rules.hpp"
#include "policy/rule_loader.hpp"
#include "policy/ruleset_embedded.hpp"

#include <algorithm>
#include <charconv>
#include <optional>
#include <utility>

namespace mcxanon {

namespace {

template <class E>
using Names = std::vector<std::pair<std::string_view, E>>;

template <class E>
std::optional<E> lookup(const Names<E>& names, std::string_view s) {
  for (const auto& [n, v] : names) {
    if (n == s) return v;
  }
  return std::nullopt;
}

const Names<TlsRecordAction> kRecordActions{
    {"parse", TlsRecordAction::parse}, {"keep", TlsRecordAction::keep}, {"zero", TlsRecordAction::zero}};

const Names<TlsHandshakeAction> kHandshakeActions{
    {"hello", TlsHandshakeAction::hello},
    {"certificate", TlsHandshakeAction::certificate},
    {"certificate-request", TlsHandshakeAction::certificate_request},
    {"server-key-exchange", TlsHandshakeAction::server_key_exchange},
    {"client-key-exchange", TlsHandshakeAction::client_key_exchange},
    {"certificate-verify", TlsHandshakeAction::certificate_verify},
    {"new-session-ticket", TlsHandshakeAction::new_session_ticket},
    {"zero-body", TlsHandshakeAction::zero_body},
    {"keep", TlsHandshakeAction::keep}};

const Names<TlsExtensionAction> kExtensionActions{
    {"keep", TlsExtensionAction::keep},
    {"zero", TlsExtensionAction::zero},
    {"server-name", TlsExtensionAction::server_name},
    {"alpn", TlsExtensionAction::alpn},
    {"key-share", TlsExtensionAction::key_share},
    {"pre-shared-key", TlsExtensionAction::pre_shared_key},
    {"renegotiation-info", TlsExtensionAction::renegotiation_info},
    {"status-request", TlsExtensionAction::status_request},
    {"certificate-authorities", TlsExtensionAction::certificate_authorities}};

const Names<KexFamily> kFamilies{{"ecdhe", KexFamily::ecdhe},       {"dhe", KexFamily::dhe},
                                 {"rsa", KexFamily::rsa},           {"psk", KexFamily::psk},
                                 {"ecdhe-psk", KexFamily::ecdhe_psk}, {"dhe-psk", KexFamily::dhe_psk},
                                 {"rsa-psk", KexFamily::rsa_psk},   {"tls13", KexFamily::tls13}};

const Names<X509AttributeAction> kAttributeActions{{"keep", X509AttributeAction::keep},
                                                   {"identity", X509AttributeAction::identity},
                                                   {"opaque", X509AttributeAction::opaque},
                                                   {"email", X509AttributeAction::email},
                                                   {"domain-label", X509AttributeAction::domain_label}};

const Names<X509ExtensionAction> kX509Actions{
    {"keep", X509ExtensionAction::keep},
    {"general-names", X509ExtensionAction::general_names},
    {"uri-access", X509ExtensionAction::uri_access},
    {"key-identifier", X509ExtensionAction::key_identifier},
    {"authority-key-identifier", X509ExtensionAction::authority_key_identifier},
    {"policies", X509ExtensionAction::policies},
    {"zero", X509ExtensionAction::zero}};

const Names<PublicKeyAction> kKeyActions{
    {"rsa", PublicKeyAction::rsa}, {"ec", PublicKeyAction::ec}, {"zero", PublicKeyAction::zero}};

// "0x0303" or "771".
std::optional<unsigned long> number(std::string_view s) {
  int base = 10;
  if (s.starts_with("0x") || s.starts_with("0X")) {
    s.remove_prefix(2);
    base = 16;
  }
  if (s.empty()) return std::nullopt;
  unsigned long v = 0;
  const auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v, base);
  if (ec != std::errc() || p != s.data() + s.size()) return std::nullopt;
  return v;
}

bool dotted_oid(std::string_view s) {
  if (s.empty() || s.front() == '.' || s.back() == '.') return false;
  bool dot = false;
  int arcs = 1;
  for (char c : s) {
    if (c == '.') {
      if (dot) return false;
      dot = true;
      ++arcs;
    } else if (c < '0' || c > '9') {
      return false;
    } else {
      dot = false;
    }
  }
  return arcs >= 2;
}

class Loader : public rules::LoaderBase {
 public:
  explicit Loader(TlsRuleSet& rs) : LoaderBase(http_source_allowed), rs_(rs) {}

  Result<void> file(const RuleFile& f, bool first) {
    file_ = &f;
    ryml::Tree tree = ryml::parse_in_arena(ryml::to_csubstr(f.name), ryml::to_csubstr(f.text));
    const auto root = tree.crootref();
    if (!root.is_map()) return err("top level must be a mapping");
    for (const auto c : root.children()) {
      const auto k = yaml::key(c);
      if (k != "ruleset" && k != "version" && k != "versions" && k != "records" && k != "handshakes" &&
          k != "extensions" && k != "key_exchange" && k != "x509") {
        return err("unknown key '" + k + "'");
      }
    }
    if (auto r = header(root, "mcxanon-tls", first, rs_.name, rs_.version); !r) return r;
    if (root.has_child("versions")) {
      if (auto r = list(root["versions"], "version", [&](ryml::ConstNodeRef n, std::string w) -> Result<void> {
            TlsVersionRule v;
            auto x = num(n, "value", w, 0xFFFF);
            if (!x) return std::unexpected(x.error());
            v.value = static_cast<std::uint16_t>(*x);
            if (rs_.known_version(v.value)) return err("duplicate " + w);
            return named(n, w, v, rs_.versions);
          });
          !r) {
        return r;
      }
    }
    if (root.has_child("records")) {
      if (auto r = list(root["records"], "record", [&](ryml::ConstNodeRef n, std::string w) -> Result<void> {
            TlsRecordRule v;
            auto x = num(n, "type", w, 0xFF);
            if (!x) return std::unexpected(x.error());
            v.type = static_cast<std::uint8_t>(*x);
            if (rs_.find_record(v.type) != nullptr) return err("duplicate " + w);
            auto a = action(n, w, kRecordActions);
            if (!a) return std::unexpected(a.error());
            v.action = *a;
            return named(n, w, v, rs_.records);
          });
          !r) {
        return r;
      }
    }
    if (root.has_child("handshakes")) {
      if (auto r = list(root["handshakes"], "handshake", [&](ryml::ConstNodeRef n, std::string w) -> Result<void> {
            TlsHandshakeRule v;
            auto x = num(n, "type", w, 0xFF);
            if (!x) return std::unexpected(x.error());
            v.type = static_cast<std::uint8_t>(*x);
            if (rs_.find_handshake(v.type) != nullptr) return err("duplicate " + w);
            auto a = action(n, w, kHandshakeActions);
            if (!a) return std::unexpected(a.error());
            v.action = *a;
            return named(n, w, v, rs_.handshakes);
          });
          !r) {
        return r;
      }
    }
    if (root.has_child("extensions")) {
      if (auto r = list(root["extensions"], "extension", [&](ryml::ConstNodeRef n, std::string w) -> Result<void> {
            TlsExtensionRule v;
            auto x = num(n, "type", w, 0xFFFF);
            if (!x) return std::unexpected(x.error());
            v.type = static_cast<std::uint16_t>(*x);
            if (rs_.find_extension(v.type) != nullptr) return err("duplicate " + w);
            auto a = action(n, w, kExtensionActions);
            if (!a) return std::unexpected(a.error());
            v.action = *a;
            if (n.has_child("values")) {
              if (v.action != TlsExtensionAction::alpn) return err("values only for alpn (" + w + ")");
              auto vals = strings(n["values"], "values of " + w);
              if (!vals) return std::unexpected(vals.error());
              v.values = std::move(*vals);
            }
            return named(n, w, v, rs_.extensions);
          });
          !r) {
        return r;
      }
    }
    if (root.has_child("key_exchange")) {
      if (auto r = list(root["key_exchange"], "suite", [&](ryml::ConstNodeRef n, std::string w) -> Result<void> {
            TlsSuiteRule v;
            auto x = num(n, "suite", w, 0xFFFF);
            if (!x) return std::unexpected(x.error());
            v.suite = static_cast<std::uint16_t>(*x);
            if (rs_.find_suite(v.suite) != nullptr) return err("duplicate " + w);
            auto fam = text(n, "family", w);
            if (!fam) return std::unexpected(fam.error());
            const auto f2 = lookup(kFamilies, *fam);
            if (!f2) return err("unknown family '" + *fam + "' for " + w);
            v.family = *f2;
            auto s = source(n, w);
            if (!s) return std::unexpected(s.error());
            v.source = *s;
            rs_.suites.push_back(std::move(v));
            return {};
          });
          !r) {
        return r;
      }
    }
    if (root.has_child("x509")) {
      const auto x = root["x509"];
      if (auto r = only_keys(x, {"attributes", "extensions", "public_keys"}, "x509"); !r) return r;
      if (x.has_child("attributes")) {
        if (auto r = oids(x["attributes"], "attribute", kAttributeActions, rs_.attributes); !r) return r;
      }
      if (x.has_child("extensions")) {
        if (auto r = oids(x["extensions"], "x509 extension", kX509Actions, rs_.x509_extensions); !r) return r;
      }
      if (x.has_child("public_keys")) {
        if (auto r = oids(x["public_keys"], "public key", kKeyActions, rs_.public_keys); !r) return r;
      }
    }
    return {};
  }

 private:
  template <class F>
  Result<void> list(ryml::ConstNodeRef n, const std::string& kind, F&& each) {
    if (!n.is_seq()) return err(kind + " rules must be a sequence");
    for (const auto c : n.children()) {
      if (auto r = only_keys(c, {"value", "type", "suite", "name", "action", "family", "values", "source"},
                             kind + " rule");
          !r) {
        return r;
      }
      if (auto r = each(c, kind); !r) return r;
    }
    return {};
  }

  Result<unsigned long> num(ryml::ConstNodeRef n, std::string_view k, std::string& w, unsigned long max) const {
    auto t = text(n, k, w);
    if (!t) return std::unexpected(t.error());
    const auto v = number(*t);
    if (!v || *v > max) return err("invalid " + std::string(k) + " '" + *t + "' in " + w);
    w += " " + *t;
    return *v;
  }

  template <class E>
  Result<E> action(ryml::ConstNodeRef n, const std::string& w, const Names<E>& names) const {
    auto a = text(n, "action", w);
    if (!a) return std::unexpected(a.error());
    const auto v = lookup(names, *a);
    if (!v) return err("unknown action '" + *a + "' for " + w);
    return *v;
  }

  template <class R>
  Result<void> named(ryml::ConstNodeRef n, const std::string& w, R& v, std::vector<R>& out) {
    auto name = text(n, "name", w);
    if (!name) return std::unexpected(name.error());
    v.name = *name;
    auto s = source(n, w);
    if (!s) return std::unexpected(s.error());
    v.source = *s;
    out.push_back(std::move(v));
    return {};
  }

  template <class E, class R>
  Result<void> oids(ryml::ConstNodeRef n, const std::string& kind, const Names<E>& names, std::vector<R>& out) {
    if (!n.is_seq()) return err(kind + " rules must be a sequence");
    for (const auto c : n.children()) {
      if (auto r = only_keys(c, {"oid", "name", "action", "source"}, kind + " rule"); !r) return r;
      R v;
      auto oid = text(c, "oid", kind + " rule");
      if (!oid) return std::unexpected(oid.error());
      if (!dotted_oid(*oid)) return err("invalid OID '" + *oid + "' in " + kind + " rule");
      v.oid = *oid;
      const std::string w = kind + " " + v.oid;
      for (const auto& x : out) {
        if (x.oid == v.oid) return err("duplicate " + w);
      }
      auto a = action(c, w, names);
      if (!a) return std::unexpected(a.error());
      v.action = *a;
      if (auto r = named(c, w, v, out); !r) return r;
    }
    return {};
  }

  TlsRuleSet& rs_;
};

template <class R, class K>
const R* find_by(const std::vector<R>& v, K R::*field, const K& key) {
  for (const auto& r : v) {
    if (r.*field == key) return &r;
  }
  return nullptr;
}

}  // namespace

bool TlsRuleSet::known_version(std::uint16_t v) const {
  return std::any_of(versions.begin(), versions.end(), [&](const TlsVersionRule& r) { return r.value == v; });
}
const TlsRecordRule* TlsRuleSet::find_record(std::uint8_t t) const { return find_by(records, &TlsRecordRule::type, t); }
const TlsHandshakeRule* TlsRuleSet::find_handshake(std::uint8_t t) const {
  return find_by(handshakes, &TlsHandshakeRule::type, t);
}
const TlsExtensionRule* TlsRuleSet::find_extension(std::uint16_t t) const {
  return find_by(extensions, &TlsExtensionRule::type, t);
}
const TlsSuiteRule* TlsRuleSet::find_suite(std::uint16_t s) const { return find_by(suites, &TlsSuiteRule::suite, s); }
const X509AttributeRule* TlsRuleSet::find_attribute(std::string_view oid) const {
  for (const auto& r : attributes) {
    if (r.oid == oid) return &r;
  }
  return nullptr;
}
const X509ExtensionRule* TlsRuleSet::find_x509_extension(std::string_view oid) const {
  for (const auto& r : x509_extensions) {
    if (r.oid == oid) return &r;
  }
  return nullptr;
}
const X509PublicKeyRule* TlsRuleSet::find_public_key(std::string_view oid) const {
  for (const auto& r : public_keys) {
    if (r.oid == oid) return &r;
  }
  return nullptr;
}

std::string_view to_string(TlsExtensionAction a) {
  for (const auto& [n, v] : kExtensionActions) {
    if (v == a) return n;
  }
  return "?";
}

Result<TlsRuleSet> load_tls_ruleset(std::span<const RuleFile> files) {
  if (files.empty()) return fail(ErrorCode::internal, "TLS rule set has no files");
  std::vector<const RuleFile*> ordered;
  for (const auto& f : files) ordered.push_back(&f);
  std::sort(ordered.begin(), ordered.end(), [](const RuleFile* a, const RuleFile* b) { return a->name < b->name; });
  TlsRuleSet rs;
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
  rs.digest = rules::sha256_hex(combined);
  return rs;
}

Result<TlsRuleSet> load_embedded_tls_ruleset() {
  std::vector<RuleFile> files;
  for (const auto& f : embedded_tls_rule_files()) files.push_back(RuleFile{std::string(f.name), std::string(f.text)});
  return load_tls_ruleset(files);
}

}  // namespace mcxanon
