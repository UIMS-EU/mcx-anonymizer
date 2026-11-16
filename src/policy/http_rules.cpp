// SPDX-License-Identifier: GPL-3.0-or-later
#include "policy/http_rules.hpp"

#include "bytes/hex.hpp"
#include "policy/rule_loader.hpp"
#include "policy/ruleset_embedded.hpp"

#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <set>
#include <utility>

namespace mcxanon {

namespace rules {

std::string sha256_hex(std::string_view data) {
  std::array<std::uint8_t, SHA256_DIGEST_LENGTH> md{};
  SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), md.data());
  return to_hex(ByteView(md.data(), md.size()));
}

}  // namespace rules

namespace {

// rules/SOURCES.md, "HTTP rule set" and "TLS rule set": the documents of the standards corpus
// that HTTP-1 rules may cite.
constexpr std::array<std::string_view, 9> kWeb3gpp{"TS 23.280", "TS 24.481", "TS 24.482", "TS 24.484", "TS 33.180",
                                                   "TS 33.220", "TS 24.282", "TS 24.379", "TS 37.579-5"};
constexpr int kWebRfcs[] = {2045, 2046, 2617, 3279, 3986, 4279, 4492, 4648, 4825, 4826, 5077, 5246, 5280, 5288,
                            5289, 5480, 5489, 5746, 5874, 5875, 6066, 6265, 6455, 6520, 6749, 6750, 7009, 7301,
                            7366, 7515, 7516, 7519, 7541, 7616, 7617, 7627, 7636, 7662, 7685, 7905, 7919, 8259,
                            8422, 8446, 8449, 8996, 9110, 9111, 9112, 9113};

std::string lower(std::string_view s) {
  std::string o(s);
  for (auto& c : o) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return o;
}

template <class E>
using Names = std::vector<std::pair<std::string_view, E>>;

template <class E>
std::optional<E> lookup(const Names<E>& names, std::string_view s) {
  for (const auto& [n, v] : names) {
    if (n == s) return v;
  }
  return std::nullopt;
}

template <class E>
std::string_view name_of(const Names<E>& names, E e) {
  for (const auto& [n, v] : names) {
    if (v == e) return n;
  }
  return "?";
}

const Names<HttpBodyHandling> kHandlings{{"xml", HttpBodyHandling::xml},
                                         {"form", HttpBodyHandling::form},
                                         {"json", HttpBodyHandling::json},
                                         {"jwt", HttpBodyHandling::jwt},
                                         {"multipart", HttpBodyHandling::multipart}};

const Names<HttpParamAction> kActions{{"keep", HttpParamAction::keep},   {"pseudonymise", HttpParamAction::pseudonymise},
                                      {"uri", HttpParamAction::uri},     {"token", HttpParamAction::token},
                                      {"shift", HttpParamAction::shift}, {"remove", HttpParamAction::remove}};

const Names<HttpValueGrammar> kGrammars{{"token", HttpValueGrammar::token},
                                        {"number", HttpValueGrammar::number},
                                        {"boolean", HttpValueGrammar::boolean}};

const Names<HttpCategory> kCategories{
    {"identity", HttpCategory::identity}, {"opaque", HttpCategory::opaque}, {"host", HttpCategory::host}};

const Names<CookieAttrAction> kCookieActions{{"keep", CookieAttrAction::keep},
                                             {"number", CookieAttrAction::number},
                                             {"date", CookieAttrAction::date},
                                             {"path", CookieAttrAction::path},
                                             {"domain", CookieAttrAction::domain}};

bool media_type_ok(std::string_view s) {
  const auto slash = s.find('/');
  if (slash == std::string_view::npos || slash == 0 || slash + 1 == s.size()) return false;
  return std::all_of(s.begin(), s.end(), [](char c) {
    return std::isalnum(static_cast<unsigned char>(c)) != 0 || std::string_view("!#$&-^_.+/").find(c) != std::string_view::npos;
  });
}

class Loader : public rules::LoaderBase {
 public:
  explicit Loader(HttpRuleSet& rs) : LoaderBase(http_source_allowed), rs_(rs) {}

  Result<void> file(const RuleFile& f, bool first) {
    file_ = &f;
    ryml::Tree tree = ryml::parse_in_arena(ryml::to_csubstr(f.name), ryml::to_csubstr(f.text));
    const auto root = tree.crootref();
    if (!root.is_map()) return err("top level must be a mapping");
    if (auto r = header(root, "mcxanon-http", first, rs_.name, rs_.version); !r) return r;
    if (root.has_child("bodies")) {
      if (auto r = bodies(root["bodies"]); !r) return r;
    }
    if (root.has_child("paths")) {
      if (auto r = paths(root["paths"]); !r) return r;
    }
    if (root.has_child("cookies")) {
      if (auto r = cookies(root["cookies"]); !r) return r;
    }
    if (root.has_child("params")) {
      if (auto r = params(root["params"], rs_.params, "param", false); !r) return r;
    }
    if (root.has_child("jwt")) {
      const auto j = root["jwt"];
      if (auto r = only_keys(j, {"header", "claims"}, "jwt"); !r) return r;
      if (j.has_child("header")) {
        if (auto r = params(j["header"], rs_.jwt_header, "jwt header member", true); !r) return r;
      }
      if (j.has_child("claims")) {
        if (auto r = params(j["claims"], rs_.jwt_claims, "jwt claim", true); !r) return r;
      }
    }
    return {};
  }

 private:
  Result<void> bodies(ryml::ConstNodeRef n) {
    if (!n.is_seq()) return err("'bodies' must be a sequence");
    for (const auto b : n.children()) {
      if (auto r = only_keys(b, {"content_type", "handling", "params", "source"}, "body rule"); !r) return r;
      HttpBodyRule br;
      auto ct = text(b, "content_type", "body rule");
      if (!ct) return std::unexpected(ct.error());
      br.content_type = lower(*ct);
      const std::string w = "body " + br.content_type;
      if (!media_type_ok(br.content_type)) return err("invalid content type: " + w);
      if (rs_.find_body(br.content_type) != nullptr) return err("duplicate " + w);
      auto h = text(b, "handling", w);
      if (!h) return std::unexpected(h.error());
      const auto handling = lookup(kHandlings, *h);
      if (!handling) return err("unknown handling '" + *h + "' for " + w);
      br.handling = *handling;
      if (b.has_child("params")) {
        auto p = strings(b["params"], "params of " + w);
        if (!p) return std::unexpected(p.error());
        for (auto& x : *p) x = lower(x);
        br.params = std::move(*p);
      }
      auto s = source(b, w);
      if (!s) return std::unexpected(s.error());
      br.source = *s;
      rs_.bodies.push_back(std::move(br));
    }
    return {};
  }

  Result<void> paths(ryml::ConstNodeRef n) {
    if (!n.is_seq()) return err("'paths' must be a sequence");
    for (const auto p : n.children()) {
      if (auto r = only_keys(p, {"segment", "source"}, "path rule"); !r) return r;
      auto seg = text(p, "segment", "path rule");
      if (!seg) return std::unexpected(seg.error());
      if (seg->empty() || seg->find_first_of("/?#%") != std::string::npos) return err("invalid path segment '" + *seg + "'");
      if (rs_.kept_segment(*seg)) return err("duplicate path segment '" + *seg + "'");
      auto s = source(p, "path " + *seg);
      if (!s) return std::unexpected(s.error());
      rs_.paths.push_back({*seg, *s});
    }
    return {};
  }

  Result<void> cookies(ryml::ConstNodeRef n) {
    if (auto r = only_keys(n, {"attributes"}, "cookies"); !r) return r;
    if (!n.has_child("attributes")) return {};
    const auto a = n["attributes"];
    if (!a.is_seq()) return err("cookie attributes must be a sequence");
    for (const auto c : a.children()) {
      if (auto r = only_keys(c, {"name", "action", "source"}, "cookie attribute"); !r) return r;
      HttpCookieAttr ca;
      auto name = text(c, "name", "cookie attribute");
      if (!name) return std::unexpected(name.error());
      ca.name = lower(*name);
      const std::string w = "cookie attribute " + ca.name;
      if (rs_.find_cookie_attribute(ca.name) != nullptr) return err("duplicate " + w);
      auto act = text(c, "action", w);
      if (!act) return std::unexpected(act.error());
      const auto action = lookup(kCookieActions, *act);
      if (!action) return err("unknown action '" + *act + "' for " + w);
      ca.action = *action;
      auto s = source(c, w);
      if (!s) return std::unexpected(s.error());
      ca.source = *s;
      rs_.cookie_attributes.push_back(std::move(ca));
    }
    return {};
  }

  Result<void> params(ryml::ConstNodeRef n, std::vector<HttpParamRule>& out, const std::string& kind, bool jwt) {
    if (!n.is_seq()) return err(kind + " rules must be a sequence");
    std::set<std::string> seen;
    for (const auto& r : out) seen.insert(r.name);
    for (const auto p : n.children()) {
      if (auto r = only_keys(p, {"name", "action", "value", "category", "reason", "source"}, kind + " rule"); !r) {
        return r;
      }
      HttpParamRule pr;
      auto name = text(p, "name", kind + " rule");
      if (!name) return std::unexpected(name.error());
      if (name->empty()) return err("empty " + kind + " name");
      pr.name = *name;
      const std::string w = kind + " " + pr.name;
      if (!seen.insert(pr.name).second) return err("duplicate " + w);
      auto act = text(p, "action", w);
      if (!act) return std::unexpected(act.error());
      const auto action = lookup(kActions, *act);
      if (!action) return err("unknown action '" + *act + "' for " + w);
      if (*action == HttpParamAction::shift && !jwt) return err("shift is a JWT claim action (" + w + ")");
      pr.action = *action;
      if (p.has_child("value")) {
        if (pr.action != HttpParamAction::keep) return err("value grammar without keep: " + w);
        const auto v = p["value"];
        if (v.is_map()) {
          if (auto r = only_keys(v, {"enum", "scope"}, "value of " + w); !r) return r;
          const bool is_enum = v.has_child("enum");
          if (is_enum == v.has_child("scope")) return err("value of " + w + " needs exactly one of enum, scope");
          auto vals = strings(v[is_enum ? "enum" : "scope"], "values of " + w);
          if (!vals) return std::unexpected(vals.error());
          if (vals->empty()) return err("empty value list for " + w);
          pr.value = is_enum ? HttpValueGrammar::enumeration : HttpValueGrammar::scope;
          pr.values = std::move(*vals);
        } else {
          const auto g = lookup(kGrammars, scalar(v));
          if (!g) return err("unknown value grammar '" + scalar(v) + "' for " + w);
          pr.value = *g;
        }
      } else if (pr.action == HttpParamAction::keep) {
        return err("keep needs a value grammar: " + w);
      }
      auto cat = text(p, "category", w, false);
      if (!cat) return std::unexpected(cat.error());
      if (!cat->empty()) {
        if (pr.action != HttpParamAction::pseudonymise) return err("category without pseudonymise: " + w);
        const auto c = lookup(kCategories, *cat);
        if (!c) return err("unknown category '" + *cat + "' for " + w);
        pr.category = *c;
      } else if (pr.action == HttpParamAction::pseudonymise) {
        return err("pseudonymise needs a category: " + w);
      }
      auto reason = text(p, "reason", w, false);
      if (!reason) return std::unexpected(reason.error());
      if (pr.action == HttpParamAction::remove) {
        if (*reason != "credential" && *reason != "free-text") return err("remove needs reason credential or free-text: " + w);
        pr.reason = *reason;
      } else if (!reason->empty()) {
        return err("reason without remove: " + w);
      }
      auto s = source(p, w);
      if (!s) return std::unexpected(s.error());
      pr.source = *s;
      out.push_back(std::move(pr));
    }
    return {};
  }

  HttpRuleSet& rs_;
};

const HttpParamRule* find_in(const std::vector<HttpParamRule>& v, std::string_view name) {
  for (const auto& r : v) {
    if (r.name == name) return &r;
  }
  return nullptr;
}

}  // namespace

bool http_source_allowed(std::string_view spec) {
  if (std::find(kWeb3gpp.begin(), kWeb3gpp.end(), spec) != kWeb3gpp.end()) return true;
  if (!spec.starts_with("RFC ")) return false;
  const auto num = spec.substr(4);
  if (num.empty() || num.size() > 5 || !std::all_of(num.begin(), num.end(), [](char c) { return c >= '0' && c <= '9'; })) {
    return false;
  }
  int n = 0;
  for (char c : num) n = n * 10 + (c - '0');
  return std::find(std::begin(kWebRfcs), std::end(kWebRfcs), n) != std::end(kWebRfcs);
}

const HttpBodyRule* HttpRuleSet::find_body(std::string_view content_type) const {
  const std::string ct = lower(content_type);
  for (const auto& b : bodies) {
    if (b.content_type == ct) return &b;
  }
  return nullptr;
}

bool HttpRuleSet::kept_segment(std::string_view segment) const {
  return std::any_of(paths.begin(), paths.end(), [&](const HttpPathRule& p) { return p.segment == segment; });
}

const HttpCookieAttr* HttpRuleSet::find_cookie_attribute(std::string_view which) const {
  const std::string n = lower(which);
  for (const auto& a : cookie_attributes) {
    if (a.name == n) return &a;
  }
  return nullptr;
}

const HttpParamRule* HttpRuleSet::find_param(std::string_view which) const { return find_in(params, which); }
const HttpParamRule* HttpRuleSet::find_jwt_header(std::string_view which) const { return find_in(jwt_header, which); }
const HttpParamRule* HttpRuleSet::find_jwt_claim(std::string_view which) const { return find_in(jwt_claims, which); }

std::string_view to_string(HttpBodyHandling h) { return name_of(kHandlings, h); }
std::string_view to_string(HttpParamAction a) { return name_of(kActions, a); }

Result<HttpRuleSet> load_http_ruleset(std::span<const RuleFile> files) {
  if (files.empty()) return fail(ErrorCode::internal, "HTTP rule set has no files");
  auto headers = load_http_header_rules(files);
  if (!headers) return std::unexpected(headers.error());
  std::vector<const RuleFile*> ordered;
  for (const auto& f : files) ordered.push_back(&f);
  std::sort(ordered.begin(), ordered.end(), [](const RuleFile* a, const RuleFile* b) { return a->name < b->name; });
  HttpRuleSet rs;
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
  rs.headers = std::move(*headers);
  rs.headers.name = rs.name;
  rs.headers.version = rs.version;
  rs.digest = rules::sha256_hex(combined);
  rs.headers.digest = rs.digest;
  return rs;
}

Result<HttpRuleSet> load_embedded_http_ruleset() {
  std::vector<RuleFile> files;
  for (const auto& f : embedded_http_rule_files()) files.push_back(RuleFile{std::string(f.name), std::string(f.text)});
  return load_http_ruleset(files);
}

}  // namespace mcxanon
