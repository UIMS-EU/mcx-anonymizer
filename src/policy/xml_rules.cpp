// SPDX-License-Identifier: GPL-3.0-or-later
#include "policy/xml_rules.hpp"

#include "bytes/hex.hpp"
#include "mcxanon/version.hpp"
#include "policy/ruleset_embedded.hpp"
#include "policy/sip_rules.hpp"
#include "policy/yaml_util.hpp"

#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <initializer_list>
#include <set>

namespace mcxanon {
namespace {

using yaml::key;
using yaml::str;

// The documents the XML rule set may cite: the "MCX XML bodies" section of rules/SOURCES.md.
// Keep both lists in sync.
constexpr std::array<std::string_view, 12> kDocuments{
    "TS 24.379", "TS 24.282", "TS 24.281", "TS 33.180", "TS 37.579-5", "RFC 5875",
    "RFC 5627",  "RFC 3261",  "TS 24.229", "TS 23.003", "TS 24.484",   "TS 24.481"};

template <typename T>
using Names = std::initializer_list<std::pair<std::string_view, T>>;

// Namespaces in XML 1.0 [4] NCName, ASCII subset (the prefixes of the standards are ASCII).
bool ncname(std::string_view v) {
  if (v.empty() || v.size() > 64) return false;
  const auto c0 = static_cast<unsigned char>(v[0]);
  if (std::isalpha(c0) == 0 && v[0] != '_') return false;
  return std::all_of(v.begin(), v.end(), [](char ch) {
    return std::isalnum(static_cast<unsigned char>(ch)) != 0 || ch == '_' || ch == '-' || ch == '.';
  });
}

const Names<XmlAction> kActions{{"container", XmlAction::container}, {"keep", XmlAction::keep},
                                {"pseudonymise", XmlAction::pseudonymise}, {"fixed", XmlAction::fixed},
                                {"empty", XmlAction::empty}, {"remove", XmlAction::remove},
                                {"zero", XmlAction::zero}};

const Names<XmlRemoveReason> kReasons{{"free-text", XmlRemoveReason::free_text},
                                      {"credential", XmlRemoveReason::credential},
                                      {"tmgi", XmlRemoveReason::tmgi},
                                      {"structure", XmlRemoveReason::structure}};

const Names<XmlDisposition> kDispositions{{"rules", XmlDisposition::rules},
                                          {"remove_encrypted", XmlDisposition::remove_encrypted},
                                          {"remove_credential", XmlDisposition::remove_credential},
                                          {"encrypted_content", XmlDisposition::encrypted_content}};

const Names<XmlCategory> kCategories{
    {"uri", XmlCategory::uri},           {"display-name", XmlCategory::display_name},
    {"uuid", XmlCategory::uuid},         {"imei", XmlCategory::imei},
    {"instance", XmlCategory::instance}, {"call-id", XmlCategory::call_id},
    {"tag", XmlCategory::tag},           {"entity-tag", XmlCategory::entity_tag},
    {"cid", XmlCategory::cid},           {"host", XmlCategory::host},
    {"ip", XmlCategory::ip},             {"port", XmlCategory::port},
    {"ssrc", XmlCategory::ssrc},         {"fc-ref", XmlCategory::fc_ref},
    {"plmn", XmlCategory::plmn},         {"eci", XmlCategory::eci},
    {"tac", XmlCategory::tac},           {"mbms-sai", XmlCategory::mbms_sai},
    {"mbsfn-area", XmlCategory::mbsfn_area}, {"opaque", XmlCategory::opaque},
    {"mbms-sai-hex", XmlCategory::mbms_sai_hex}, {"xcap-node", XmlCategory::xcap_node},
    {"web-uri", XmlCategory::web_uri},
    {"nci", XmlCategory::nci},           {"nr-tac", XmlCategory::nr_tac},
    {"mbs-fsa", XmlCategory::mbs_fsa},   {"ecgi", XmlCategory::ecgi},
    {"ncgi", XmlCategory::ncgi},         {"tai", XmlCategory::tai},
    {"tac-bin", XmlCategory::tac_bin},   {"any-id", XmlCategory::any_id},
    {"kms-uri", XmlCategory::kms_uri},   {"replaces", XmlCategory::replaces},
    {"xcap-selector", XmlCategory::xcap_selector}, {"user-at-host", XmlCategory::user_at_host},
    {"mikey-hex", XmlCategory::mikey_hex}, {"xpk-id", XmlCategory::xpk_id}};

const Names<XmlTokenGrammar> kGrammars{{"trigger-id", XmlTokenGrammar::trigger_id},
                                       {"hex-counter", XmlTokenGrammar::hex_counter},
                                       {"r-value", XmlTokenGrammar::r_value},
                                       {"ncname", XmlTokenGrammar::ncname},
                                       {"qvalue", XmlTokenGrammar::qvalue},
                                       {"rfc-token", XmlTokenGrammar::rfc_token}};

const Names<XmlValueType::Kind> kSimpleValues{{"boolean", XmlValueType::Kind::boolean},
                                              {"datetime", XmlValueType::Kind::datetime},
                                              {"date", XmlValueType::Kind::date},
                                              {"time", XmlValueType::Kind::time},
                                              {"duration", XmlValueType::Kind::duration},
                                              {"lang", XmlValueType::Kind::lang},
                                              {"empty", XmlValueType::Kind::empty},
                                              {"base64", XmlValueType::Kind::base64},
                                              {"datetime-shifted", XmlValueType::Kind::datetime_shifted}};

template <typename T>
std::optional<T> lookup(const Names<T>& names, std::string_view n) {
  for (const auto& [k, v] : names) {
    if (k == n) return v;
  }
  return std::nullopt;
}

template <typename T>
std::string_view name_of(const Names<T>& names, T v) {
  for (const auto& [k, x] : names) {
    if (x == v) return k;
  }
  return "?";
}

std::string lower(std::string_view s) {
  std::string out(s);
  for (auto& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return out;
}

std::string sha256_hex(const std::string& data) {
  std::array<unsigned char, SHA256_DIGEST_LENGTH> d{};
  SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), d.data());
  return to_hex(ByteView(d.data(), d.size()));
}

// A minimal value matcher for the load-time check of `fixed` constants. The full matcher lives
// in src/xml/values.cpp (the policy module cannot depend on it); a constant is always one of a
// few simple forms, so the check here accepts integers, hex, enumerations and tokens only.
bool constant_fits(const XmlValueType& t, const std::string& c) {
  using K = XmlValueType::Kind;
  switch (t.kind) {
    case K::integer: {
      if (c.empty()) return false;
      std::int64_t v = 0;
      const auto [p, ec] = std::from_chars(c.data(), c.data() + c.size(), v);
      if (ec != std::errc{} || p != c.data() + c.size()) return false;
      return v >= t.min && (v < 0 || static_cast<std::uint64_t>(v) <= t.max);
    }
    case K::hex:
      return std::find(t.lengths.begin(), t.lengths.end(), c.size()) != t.lengths.end() &&
             std::all_of(c.begin(), c.end(), [](char x) { return std::isxdigit(static_cast<unsigned char>(x)) != 0; });
    case K::enumeration: return std::find(t.values.begin(), t.values.end(), c) != t.values.end();
    case K::token: return !c.empty();
    default: return false;
  }
}

class Loader {
 public:
  explicit Loader(XmlRuleSet& rs) : rs_(rs) {}

  Result<void> file(const RuleFile& f, bool first) {
    file_ = &f;
    ryml::Tree tree = ryml::parse_in_arena(ryml::to_csubstr(f.name), ryml::to_csubstr(f.text));
    const auto root = tree.crootref();
    if (!root.is_map()) return err("top level must be a mapping");
    for (const auto c : root.children()) {
      const auto k = key(c);
      if (k != "ruleset" && k != "version" && k != "documents" && k != "namespaces") {
        return err("unknown key '" + k + "'");
      }
    }
    if (!root.has_child("ruleset") || !root.has_child("version")) return err("'ruleset' and 'version' are required");
    const std::string name = scalar(root["ruleset"]);
    const std::string version = scalar(root["version"]);
    if (name != "mcxanon-xml") return err("ruleset must be 'mcxanon-xml'");
    if (version.empty()) return err("'version' must be non-empty");
    if (first) {
      rs_.name = name;
      rs_.version = version;
    } else if (version != rs_.version) {
      return err("rule set version differs from the other rule files");
    }
    if (root.has_child("documents")) {
      if (auto r = documents(root["documents"]); !r) return r;
    }
    if (root.has_child("namespaces")) {
      if (auto r = namespaces(root["namespaces"]); !r) return r;
    }
    return {};
  }

  // Every document root names a container rule of its namespace.
  Result<void> finish() const {
    for (const auto& [ct, doc] : rs_.documents) {
      for (const auto& r : doc.roots) {
        const auto* ns = rs_.ns(r.ns);
        const XmlElementRule* el = nullptr;
        if (ns != nullptr) {
          auto it = ns->elements.find(r.local);
          if (it != ns->elements.end()) {
            for (const auto& e : it->second) {
              if (e.parents.empty()) el = &e;
            }
          }
        }
        if (el == nullptr || el->rule.action != XmlAction::container) {
          return fail(ErrorCode::internal, "xml rule set: the root " + r.local + " of " + ct +
                                               " has no container rule in " + r.ns);
        }
      }
    }
    return {};
  }

 private:
  std::unexpected<Error> err(const std::string& msg) const {
    return std::unexpected(Error{ErrorCode::internal, "rule file " + file_->name + ": " + msg});
  }

  static std::string scalar(ryml::ConstNodeRef n) { return n.is_keyval() || n.is_val() ? str(n) : ""; }

  static bool has(ryml::ConstNodeRef n, std::string_view k) { return n.has_child(ryml::to_csubstr(std::string(k))); }
  static ryml::ConstNodeRef child(ryml::ConstNodeRef n, std::string_view k) { return n[ryml::to_csubstr(std::string(k))]; }

  Result<void> only_keys(ryml::ConstNodeRef n, std::initializer_list<std::string_view> keys,
                         const std::string& what) const {
    if (!n.is_map()) return err(what + " must be a mapping");
    for (const auto c : n.children()) {
      const auto k = key(c);
      if (std::find(keys.begin(), keys.end(), k) == keys.end()) return err("unknown key '" + k + "' in " + what);
    }
    return {};
  }

  Result<std::string> text(ryml::ConstNodeRef n, std::string_view k, const std::string& what, bool required = true) const {
    if (!has(n, k)) {
      if (required) return err(what + " needs '" + std::string(k) + "'");
      return std::string();
    }
    const auto c = child(n, k);
    if (!c.is_keyval()) return err("'" + std::string(k) + "' of " + what + " must be a scalar");
    return str(c);
  }

  Result<std::vector<std::string>> list(ryml::ConstNodeRef n, std::string_view k, const std::string& what) const {
    std::vector<std::string> out;
    if (!has(n, k)) return out;
    const auto c = child(n, k);
    if (!c.is_seq()) return err("'" + std::string(k) + "' of " + what + " must be a list");
    for (const auto v : c.children()) {
      if (!v.is_val()) return err("'" + std::string(k) + "' of " + what + " must list scalars");
      out.push_back(str(v));
    }
    return out;
  }

  Result<bool> flag(ryml::ConstNodeRef n, std::string_view k, const std::string& what) const {
    auto t = text(n, k, what, false);
    if (!t) return std::unexpected(t.error());
    if (t->empty() || *t == "false") return false;
    if (*t == "true") return true;
    return err("'" + std::string(k) + "' of " + what + " must be true or false");
  }

  Result<Source> source(ryml::ConstNodeRef n, const std::string& what) const {
    if (!has(n, "source") || !child(n, "source").is_map()) return err(what + ": rule without source");
    const auto s = child(n, "source");
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

  Result<XmlValueType> value(ryml::ConstNodeRef n, const std::string& what) const {
    using K = XmlValueType::Kind;
    XmlValueType t;
    if (n.is_keyval()) {
      const auto k = lookup(kSimpleValues, str(n));
      if (!k) return err("unknown value type '" + str(n) + "' of " + what);
      t.kind = *k;
      return t;
    }
    if (!n.is_map() || n.num_children() != 1) return err("value of " + what + " must be a type name or a one-key mapping");
    const auto c = n.first_child();
    const auto k = key(c);
    auto items = [&]() -> Result<std::vector<std::string>> {
      std::vector<std::string> out;
      if (!c.is_seq()) return err("'" + k + "' of " + what + " must be a list");
      for (const auto v : c.children()) {
        if (!v.is_val()) return err("'" + k + "' of " + what + " must list scalars");
        out.push_back(str(v));
      }
      return out;
    };
    if (k == "enum" || k == "std-uri") {
      auto v = items();
      if (!v) return std::unexpected(v.error());
      if (v->empty()) return err("'" + k + "' of " + what + " is empty");
      t.kind = k == "enum" ? K::enumeration : K::std_uri;
      t.values = std::move(*v);
      return t;
    }
    if (k == "int") {
      auto v = items();
      if (!v) return std::unexpected(v.error());
      if (v->size() != 2) return err("'int' of " + what + " needs [min, max]");
      const auto& a = (*v)[0];
      const auto& b = (*v)[1];
      const auto [pa, ea] = std::from_chars(a.data(), a.data() + a.size(), t.min);
      const auto [pb, eb] = std::from_chars(b.data(), b.data() + b.size(), t.max);
      if (ea != std::errc{} || eb != std::errc{} || pa != a.data() + a.size() || pb != b.data() + b.size() ||
          (t.min >= 0 && static_cast<std::uint64_t>(t.min) > t.max)) {
        return err("'int' of " + what + " needs integers min <= max");
      }
      t.kind = K::integer;
      return t;
    }
    if (k == "hex") {
      auto v = items();
      if (!v) return std::unexpected(v.error());
      for (const auto& s : *v) {
        std::size_t len = 0;
        const auto [p, e] = std::from_chars(s.data(), s.data() + s.size(), len);
        if (e != std::errc{} || p != s.data() + s.size() || len == 0) return err("'hex' of " + what + " needs lengths");
        t.lengths.push_back(len);
      }
      if (t.lengths.empty()) return err("'hex' of " + what + " needs lengths");
      t.kind = K::hex;
      return t;
    }
    if (k == "token") {
      const auto g = lookup(kGrammars, str(c));
      if (!g) return err("unknown token grammar '" + str(c) + "' of " + what);
      t.kind = K::token;
      t.grammar = *g;
      return t;
    }
    return err("unknown value type '" + k + "' of " + what);
  }

  Result<XmlItemRule> item(ryml::ConstNodeRef n, const std::string& what) const {
    XmlItemRule r;
    auto src = source(n, what);
    if (!src) return std::unexpected(src.error());
    r.source = *src;
    auto a = text(n, "action", what);
    if (!a) return std::unexpected(a.error());
    const auto action = lookup(kActions, *a);
    if (!action) return err("unknown action '" + *a + "' of " + what);
    r.action = *action;
    if (has(n, "value")) {
      auto v = value(child(n, "value"), what);
      if (!v) return std::unexpected(v.error());
      r.value = std::move(*v);
    }
    if (has(n, "category")) {
      auto c = text(n, "category", what);
      if (!c) return std::unexpected(c.error());
      const auto cat = lookup(kCategories, *c);
      if (!cat) return err("unknown category '" + *c + "' of " + what);
      r.category = *cat;
    }
    if (has(n, "reason")) {
      auto c = text(n, "reason", what);
      if (!c) return std::unexpected(c.error());
      const auto reason = lookup(kReasons, *c);
      if (!reason) return err("unknown reason '" + *c + "' of " + what);
      r.reason = *reason;
    }
    auto constant = text(n, "constant", what, false);
    if (!constant) return std::unexpected(constant.error());
    r.constant = *constant;
    auto enc = flag(n, "encryptable", what);
    if (!enc) return std::unexpected(enc.error());
    r.encryptable = *enc;
    auto emb = flag(n, "embeds_body", what);
    if (!emb) return std::unexpected(emb.error());
    r.embeds_body = *emb;

    switch (r.action) {
      case XmlAction::keep:
        if (!r.value) return err(what + ": keep needs a value type");
        break;
      case XmlAction::pseudonymise:
        if (!r.category) return err(what + ": pseudonymise needs a category");
        break;
      case XmlAction::fixed:
        if (!has(n, "constant")) return err(what + ": fixed needs a constant");
        if (r.value && !constant_fits(*r.value, r.constant)) return err(what + ": the fixed constant does not match its value type");
        break;
      case XmlAction::remove:
        if (!r.reason) return err(what + ": remove needs a reason");
        break;
      case XmlAction::container:
      case XmlAction::empty:
      case XmlAction::zero:
        break;
    }
    if (r.category && r.action != XmlAction::pseudonymise) return err(what + ": category without pseudonymise");
    if (r.reason && r.action != XmlAction::remove) return err(what + ": reason without remove");
    if (r.value && r.action != XmlAction::keep && r.action != XmlAction::fixed) return err(what + ": value type without keep or fixed");
    return r;
  }

  Result<void> documents(ryml::ConstNodeRef n) {
    if (!n.is_seq()) return err("'documents' must be a list");
    for (const auto d : n.children()) {
      if (auto r = only_keys(d, {"content_type", "roots", "source"}, "document"); !r) return r;
      auto ct = text(d, "content_type", "document");
      if (!ct) return std::unexpected(ct.error());
      const std::string w = "document " + *ct;
      XmlDocumentRule doc;
      doc.content_type = lower(*ct);
      auto src = source(d, w);
      if (!src) return std::unexpected(src.error());
      doc.source = *src;
      if (!has(d, "roots") || !child(d, "roots").is_seq()) return err(w + " needs a list of roots");
      for (const auto r : child(d, "roots").children()) {
        if (auto k = only_keys(r, {"ns", "name"}, w + " root"); !k) return k;
        auto ns = text(r, "ns", w + " root");
        auto local = text(r, "name", w + " root");
        if (!ns || !local) return std::unexpected(!ns ? ns.error() : local.error());
        doc.roots.push_back(XmlRoot{*ns, *local});
      }
      if (doc.roots.empty()) return err(w + " needs a root");
      if (rs_.documents.contains(doc.content_type)) return err(w + " is defined more than once");
      rs_.documents.emplace(doc.content_type, std::move(doc));
    }
    return {};
  }

  Result<void> namespaces(ryml::ConstNodeRef n) {
    if (!n.is_seq()) return err("'namespaces' must be a list");
    for (const auto s : n.children()) {
      if (auto r = only_keys(s, {"name", "disposition", "source", "prefixes", "elements", "attributes"}, "namespace"); !r) {
        return r;
      }
      auto name = text(s, "name", "namespace");
      if (!name) return std::unexpected(name.error());
      const std::string w = "namespace " + *name;
      XmlNamespaceRules ns;
      ns.name = *name;
      auto src = source(s, w);
      if (!src) return std::unexpected(src.error());
      ns.source = *src;
      auto disp = text(s, "disposition", w, false);
      if (!disp) return std::unexpected(disp.error());
      if (!disp->empty()) {
        const auto d = lookup(kDispositions, *disp);
        if (!d) return err("unknown disposition '" + *disp + "' of " + w);
        ns.disposition = *d;
      }
      if (has(s, "prefixes")) {
        // Feature 008 (FR-003): NCNames (Namespaces in XML), never the reserved xml and xmlns.
        if (!child(s, "prefixes").is_seq()) return err("'prefixes' of " + w + " must be a list");
        for (const auto p : child(s, "prefixes").children()) {
          if (auto r = only_keys(p, {"name", "source"}, "prefix rule"); !r) return r;
          auto pname = text(p, "name", "prefix rule of " + w);
          if (!pname) return std::unexpected(pname.error());
          const std::string pw = "prefix " + *pname + " of " + w;
          if (!ncname(*pname) || *pname == "xml" || *pname == "xmlns") return err(pw + ": not a usable NCName");
          for (const auto& other : ns.prefixes) {
            if (other.name == *pname) return err(pw + ": duplicate");
          }
          auto psrc = source(p, pw);
          if (!psrc) return std::unexpected(psrc.error());
          ns.prefixes.push_back(XmlPrefixRule{*pname, *psrc});
        }
      }
      if (has(s, "elements")) {
        if (!child(s, "elements").is_seq()) return err("'elements' of " + w + " must be a list");
        for (const auto e : child(s, "elements").children()) {
          if (auto r = only_keys(e, {"name", "parent", "action", "value", "category", "constant", "reason",
                                     "encryptable", "embeds_body", "source"},
                                 "element rule");
              !r) {
            return r;
          }
          auto local = text(e, "name", "element rule of " + w);
          if (!local) return std::unexpected(local.error());
          const std::string ew = "element " + *local + " of " + w;
          auto parents = list(e, "parent", ew);
          if (!parents) return std::unexpected(parents.error());
          auto r = item(e, ew);
          if (!r) return std::unexpected(r.error());
          auto& slot = ns.elements[*local];
          for (const auto& other : slot) {
            if (other.parents.empty() && parents->empty()) return err(ew + ": duplicate rule without parent");
            for (const auto& p : *parents) {
              if (std::find(other.parents.begin(), other.parents.end(), p) != other.parents.end()) {
                return err(ew + ": parent '" + p + "' in more than one rule");
              }
            }
          }
          slot.push_back(XmlElementRule{*local, std::move(*parents), std::move(*r)});
        }
      }
      if (has(s, "attributes")) {
        if (!child(s, "attributes").is_seq()) return err("'attributes' of " + w + " must be a list");
        for (const auto a : child(s, "attributes").children()) {
          if (auto r = only_keys(a, {"element", "ns", "name", "action", "value", "category", "constant", "reason",
                                     "encryptable", "embeds_body", "source"},
                                 "attribute rule");
              !r) {
            return r;
          }
          auto el = text(a, "element", "attribute rule of " + w);
          auto local = text(a, "name", "attribute rule of " + w);
          auto ans = text(a, "ns", "attribute rule of " + w, false);
          if (!el || !local || !ans) return std::unexpected(!el ? el.error() : !local ? local.error() : ans.error());
          const std::string aw = "attribute " + *el + "@" + *local + " of " + w;
          auto r = item(a, aw);
          if (!r) return std::unexpected(r.error());
          for (const auto& other : ns.attributes) {
            if (other.element == *el && other.ns == *ans && other.local == *local) return err(aw + ": duplicate rule");
          }
          ns.attributes.push_back(XmlAttributeRule{*el, *ans, *local, std::move(*r)});
        }
      }
      if (rs_.namespaces.contains(ns.name)) return err(w + " is defined more than once");
      rs_.namespaces.emplace(ns.name, std::move(ns));
    }
    return {};
  }

  XmlRuleSet& rs_;
  const RuleFile* file_ = nullptr;
};

}  // namespace

bool XmlNamespaceRules::standard_prefix(std::string_view prefix) const {
  return std::any_of(prefixes.begin(), prefixes.end(), [&](const XmlPrefixRule& p) { return p.name == prefix; });
}

const XmlElementRule* XmlNamespaceRules::element(std::string_view local, std::string_view parent_local) const {
  const auto it = elements.find(local);
  if (it == elements.end()) return nullptr;
  const XmlElementRule* fallback = nullptr;
  for (const auto& r : it->second) {
    if (r.parents.empty()) {
      fallback = &r;
    } else if (std::find(r.parents.begin(), r.parents.end(), parent_local) != r.parents.end()) {
      return &r;
    }
  }
  return fallback;
}

const XmlAttributeRule* XmlNamespaceRules::attribute(std::string_view element_local, std::string_view attr_ns,
                                                     std::string_view attr_local) const {
  const XmlAttributeRule* any = nullptr;
  for (const auto& a : attributes) {
    if (a.ns != attr_ns || a.local != attr_local) continue;
    if (a.element == element_local) return &a;
    if (a.element == "*") any = &a;
  }
  return any;
}

const XmlDocumentRule* XmlRuleSet::document(std::string_view content_type) const {
  const auto it = documents.find(lower(content_type));
  return it == documents.end() ? nullptr : &it->second;
}

const XmlNamespaceRules* XmlRuleSet::ns(std::string_view namespace_name) const {
  const auto it = namespaces.find(namespace_name);
  return it == namespaces.end() ? nullptr : &it->second;
}

std::string_view to_string(XmlAction a) { return name_of(kActions, a); }
std::string_view to_string(XmlCategory c) { return name_of(kCategories, c); }
std::string_view to_string(XmlRemoveReason r) { return name_of(kReasons, r); }
std::optional<XmlTokenGrammar> xml_token_grammar(std::string_view name) { return lookup(kGrammars, name); }

Result<XmlRuleSet> load_xml_ruleset(std::span<const RuleFile> files) {
  if (files.empty()) return fail(ErrorCode::internal, "xml rule set has no files");
  std::vector<const RuleFile*> ordered;
  for (const auto& f : files) ordered.push_back(&f);
  std::sort(ordered.begin(), ordered.end(), [](const RuleFile* a, const RuleFile* b) { return a->name < b->name; });
  XmlRuleSet rs;
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

Result<XmlRuleSet> load_embedded_xml_ruleset() {
  std::vector<RuleFile> files;
  for (const auto& f : embedded_xml_rule_files()) files.push_back(RuleFile{std::string(f.name), std::string(f.text)});
  return load_xml_ruleset(files);
}

std::string_view embedded_xml_ruleset_digest() { return xml_ruleset_digest; }

Result<void> check_xml_bodies(const SipRuleSet& sip, const XmlRuleSet& xml, bool complete,
                              const std::vector<std::string>& http_xml) {
  for (const auto& ct : http_xml) {
    if (xml.document(ct) == nullptr) return fail(ErrorCode::internal, "rule sets: HTTP body " + ct + " has handling xml but no XML document rule");
  }
  for (const auto& b : sip.bodies) {
    if (b.handling == BodyHandling::xml && xml.document(b.content_type) == nullptr) {
      return fail(ErrorCode::internal, "rule sets: " + b.content_type + " has handling xml but no XML document rule");
    }
  }
  for (const auto& [ct, doc] : xml.documents) {
    const auto* b = sip.find_body(ct);
    if (b == nullptr && std::find(http_xml.begin(), http_xml.end(), ct) != http_xml.end()) continue;
    if (b == nullptr) return fail(ErrorCode::internal, "rule sets: the XML document " + ct + " has no SIP body rule");
    if (complete && b->handling != BodyHandling::xml) {
      return fail(ErrorCode::internal, "rule sets: the XML document " + ct + " is not switched to handling xml");
    }
  }
  return {};
}

}  // namespace mcxanon
