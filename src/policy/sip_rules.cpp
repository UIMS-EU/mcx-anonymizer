// SPDX-License-Identifier: GPL-3.0-or-later
#include "policy/sip_rules.hpp"

#include "bytes/hex.hpp"
#include "mcxanon/version.hpp"
#include "policy/http_rules.hpp"
#include "policy/ruleset_embedded.hpp"
#include "policy/yaml_util.hpp"

#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <initializer_list>
#include <iterator>
#include <set>
#include <utility>

namespace mcxanon {
namespace {

using yaml::key;
using yaml::str;

std::string lower(std::string_view s) {
  std::string out(s);
  for (auto& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return out;
}

bool iequal(std::string_view a, std::string_view b) {
  return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), [](char x, char y) {
           return std::tolower(static_cast<unsigned char>(x)) ==
                  std::tolower(static_cast<unsigned char>(y));
         });
}

// The documents a SIP rule may cite: exactly the documents of the SIP section of
// rules/SOURCES.md. A rule citing anything else is a load error: what an unavailable document defines stays removed.
constexpr std::array<std::string_view, 9> k3gpp{
    "TS 24.229", "TS 24.379", "TS 24.380", "TS 24.282", "TS 24.281",
    "TS 24.581", "TS 24.582", "TS 33.180", "TS 23.003"};
constexpr int kRfcs[] = {
    2045, 2046, 2606, 2617, 3261, 3262, 3264, 3310, 3311, 3312, 3313, 3323, 3325, 3326, 3327,
    3329, 3428, 3515, 3550, 3556, 3581, 3605, 3608, 3611, 3830, 3840, 3841, 3890, 3891, 3892,
    3903, 3911, 3966, 3986, 4028, 4032, 4145, 4302, 4303, 4412, 4457, 4488, 4538, 4566, 4567,
    4568, 4574, 4583, 4585, 4796, 4964, 4975, 5002, 5009, 5285, 5318, 5360, 5373, 5393, 5502,
    5506, 5547, 5576, 5626, 5627, 5761, 5875, 5888, 6050, 6086, 6135, 6236, 6432, 6442, 6665,
    6679, 6714, 6809, 6947, 7044, 7254, 7315, 7316, 7433, 7462, 7616, 7913, 7989, 8101, 8122,
    8224, 8262, 8498, 8839, 8842, 8858, 8866, 9410, 9562, 9796, 9878};

bool source_allowed(std::string_view spec, bool http) {
  if (http && http_source_allowed(spec)) return true;
  if (std::find(k3gpp.begin(), k3gpp.end(), spec) != k3gpp.end()) return true;
  if (!spec.starts_with("RFC ")) return false;
  const auto num = spec.substr(4);
  if (num.empty() || num.size() > 5 ||
      !std::all_of(num.begin(), num.end(), [](char c) { return c >= '0' && c <= '9'; })) {
    return false;
  }
  int n = 0;
  for (char c : num) n = n * 10 + (c - '0');
  return std::find(std::begin(kRfcs), std::end(kRfcs), n) != std::end(kRfcs);
}

// RFC 3261 §25.1 token characters.
bool is_token(std::string_view s) {
  return !s.empty() && std::all_of(s.begin(), s.end(), [](char c) {
    return std::isalnum(static_cast<unsigned char>(c)) != 0 ||
           std::string_view("-.!%*_+`'~").find(c) != std::string_view::npos;
  });
}

template <class E>
using Names = std::initializer_list<std::pair<std::string_view, E>>;

template <class E>
std::optional<E> lookup(Names<E> names, std::string_view s) {
  for (const auto& [n, v] : names) {
    if (n == s) return v;
  }
  return std::nullopt;
}

template <class E>
std::string_view name_of(Names<E> names, E e) {
  for (const auto& [n, v] : names) {
    if (v == e) return n;
  }
  return "?";
}

const Names<SipAction> kActions{{"keep", SipAction::keep},
                                {"pseudonymise", SipAction::pseudonymise},
                                {"uri", SipAction::uri},
                                {"blank", SipAction::blank},
                                {"remove", SipAction::remove}};

const Names<SipGrammar> kGrammars{
    {"name-addr", SipGrammar::name_addr},     {"name-addr-list", SipGrammar::name_addr_list},
    {"uri-list", SipGrammar::uri_list},       {"via", SipGrammar::via},
    {"call-id", SipGrammar::call_id},         {"cseq", SipGrammar::cseq},
    {"token", SipGrammar::token},             {"token-list", SipGrammar::token_list},
    {"number", SipGrammar::number},           {"date", SipGrammar::date},
    {"credentials", SipGrammar::credentials}, {"challenge", SipGrammar::challenge},
    {"security-mech", SipGrammar::security_mech}, {"pani", SipGrammar::pani},
    {"quoted-text", SipGrammar::quoted_text}, {"warning", SipGrammar::warning},
    {"reason", SipGrammar::reason},           {"retry-after", SipGrammar::retry_after},
    {"event", SipGrammar::event},             {"media-type", SipGrammar::media_type},
    {"session-id", SipGrammar::session_id},   {"opaque", SipGrammar::opaque},
    {"auth-params", SipGrammar::auth_params}, {"param-list", SipGrammar::param_list},
    {"host", SipGrammar::host},               {"etag-list", SipGrammar::etag_list},
    {"http-uri", SipGrammar::http_uri},       {"http-credentials", SipGrammar::http_credentials},
    {"cookie", SipGrammar::cookie},           {"set-cookie", SipGrammar::set_cookie},
    {"directives", SipGrammar::directives},   {"range", SipGrammar::range},
    {"identity", SipGrammar::identity}};

const Names<ParamValue> kParamValues{{"token", ParamValue::token},   {"quoted", ParamValue::quoted},
                                     {"host", ParamValue::host},     {"uri", ParamValue::uri},
                                     {"number", ParamValue::number}, {"flag", ParamValue::flag},
                                     {"any", ParamValue::any}};

const Names<SdpGrammar> kSdpGrammars{
    {"flag", SdpGrammar::flag},           {"opaque", SdpGrammar::opaque},
    {"token", SdpGrammar::token},         {"rtcp", SdpGrammar::rtcp},
    {"ssrc", SdpGrammar::ssrc},           {"ssrc-group", SdpGrammar::ssrc_group},
    {"candidate", SdpGrammar::candidate}, {"remote-candidates", SdpGrammar::remote_candidates},
    {"path", SdpGrammar::path},           {"fmtp-params", SdpGrammar::fmtp_params},
    {"key-mgmt", SdpGrammar::key_mgmt}};

const Names<SipCategory> kCategories{
    {"sip-user", SipCategory::sip_user},       {"domain", SipCategory::domain},
    {"display-name", SipCategory::display_name}, {"tel", SipCategory::tel},
    {"call-id", SipCategory::call_id},         {"tag", SipCategory::tag},
    {"branch", SipCategory::branch},           {"entity-tag", SipCategory::entity_tag},
    {"charging-id", SipCategory::charging_id}, {"session-id", SipCategory::session_id},
    {"imei", SipCategory::imei},               {"uuid", SipCategory::uuid},
    {"cell-id", SipCategory::cell_id},         {"spi", SipCategory::spi},
    {"ssrc", SipCategory::ssrc},               {"digest", SipCategory::digest},
    {"sdp-sess", SipCategory::sdp_sess},       {"boundary", SipCategory::boundary},
    {"msrp-session", SipCategory::msrp_session}, {"reg-token", SipCategory::reg_token},
    {"cname", SipCategory::cname},             {"host", SipCategory::host},
    {"ip", SipCategory::ip},                   {"port", SipCategory::port},
    {"instance", SipCategory::instance}};

const Names<BodyHandling> kHandlings{{"sdp", BodyHandling::sdp},
                                     {"multipart", BodyHandling::multipart},
                                     {"empty", BodyHandling::empty},
                                     {"xml", BodyHandling::xml},
                                     {"mikey", BodyHandling::mikey}};

const Names<FeatureValue> kFeatureValues{
    {"none", FeatureValue::none},         {"boolean", FeatureValue::boolean},
    {"token", FeatureValue::token},       {"string", FeatureValue::string},
    {"token-list", FeatureValue::token_list}, {"urn-list", FeatureValue::urn_list},
    {"uri", FeatureValue::uri},           {"identity", FeatureValue::identity}};

// Components each grammar's parser knows (src/sip/header_values.*).
std::set<std::string_view> components_of(SipGrammar g) {
  switch (g) {
    case SipGrammar::name_addr:
    case SipGrammar::name_addr_list:
    case SipGrammar::uri_list: return {"display-name", "uri"};
    case SipGrammar::via: return {"sent-protocol", "sent-by", "port"};
    case SipGrammar::call_id: return {"value"};
    case SipGrammar::credentials:
    case SipGrammar::challenge: return {"scheme"};
    case SipGrammar::security_mech: return {"mechanism"};
    case SipGrammar::pani: return {"access-type"};
    case SipGrammar::warning: return {"code", "agent", "text"};
    case SipGrammar::reason: return {"protocol"};
    case SipGrammar::host: return {"host", "port"};
    case SipGrammar::http_credentials: return {"scheme"};
    case SipGrammar::identity: return {"uri"};
    case SipGrammar::http_uri: return {"uri"};
    case SipGrammar::cseq:
    case SipGrammar::auth_params:
    case SipGrammar::param_list: return {};
    default: return {"value"};
  }
}

class Loader {
 public:
  explicit Loader(SipRuleSet& rs, bool http = false) : rs_(rs), http_(http) {}

  Result<void> file(const RuleFile& f, bool first) {
    file_ = &f;
    ryml::Tree tree = ryml::parse_in_arena(ryml::to_csubstr(f.name), ryml::to_csubstr(f.text));
    const auto root = tree.crootref();
    if (!root.is_map()) return err("top level must be a mapping");
    for (const auto c : root.children()) {
      const auto k = key(c);
      if (http_) {
        // The HTTP-only keys are read by load_http_ruleset.
        if (k != "ruleset" && k != "version" && k != "headers" && k != "methods" && k != "bodies" &&
            k != "paths" && k != "cookies" && k != "params" && k != "jwt" && k != "statuses") {
          return err("unknown key '" + k + "'");
        }
        continue;
      }
      if (k != "ruleset" && k != "version" && k != "headers" && k != "uri" && k != "sdp" &&
          k != "bodies" && k != "feature_tags" && k != "methods") {
        return err("unknown key '" + k + "'");
      }
    }
    if (!root.has_child("ruleset") || !root.has_child("version")) {
      return err("'ruleset' and 'version' are required");
    }
    const std::string name = scalar(root["ruleset"]);
    const std::string version = scalar(root["version"]);
    if (name != (http_ ? "mcxanon-http" : "mcxanon-sip")) {
      return err(http_ ? "ruleset must be 'mcxanon-http'" : "ruleset must be 'mcxanon-sip'");
    }
    if (version.empty()) return err("'version' must be non-empty");
    if (first) {
      rs_.name = name;
      rs_.version = version;
    } else if (version != rs_.version) {
      return err("rule set version differs from the other rule files");
    }
    if (root.has_child("headers")) {
      if (auto r = headers(root["headers"]); !r) return r;
    }
    if (http_) {
      if (root.has_child("methods")) {
        if (auto r = methods(root["methods"]); !r) return r;
      }
      return {};
    }
    if (root.has_child("uri")) {
      if (auto r = uri(root["uri"]); !r) return r;
    }
    if (root.has_child("sdp")) {
      if (auto r = sdp(root["sdp"]); !r) return r;
    }
    if (root.has_child("bodies")) {
      if (auto r = bodies(root["bodies"]); !r) return r;
    }
    if (root.has_child("feature_tags")) {
      if (auto r = feature_tags(root["feature_tags"]); !r) return r;
    }
    if (root.has_child("methods")) {
      if (auto r = methods(root["methods"]); !r) return r;
    }
    return {};
  }

  Result<void> methods(ryml::ConstNodeRef n) {
    if (!n.is_seq()) return err("'methods' must be a sequence");
    for (const auto m : n.children()) {
      if (auto r = only_keys(m, {"name", "source"}, "method rule"); !r) return r;
      auto name = text(m, "name", "method rule");
      if (!name) return std::unexpected(name.error());
      // RFC 3261 §25.1: Method = INVITEm / ... / extension-method; extension-method = token.
      if (name->empty() || !std::all_of(name->begin(), name->end(), [](char c) { return c >= 'A' && c <= 'Z'; })) {
        return err("method '" + *name + "' must be upper-case letters");
      }
      for (const auto& x : rs_.methods) {
        if (x.name == *name) return err("duplicate method '" + *name + "'");
      }
      auto src = source(m, "method " + *name);
      if (!src) return std::unexpected(src.error());
      rs_.methods.push_back({*name, *src});
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
      if (std::find(keys.begin(), keys.end(), k) == keys.end()) {
        return err("unknown key '" + k + "' in " + what);
      }
    }
    return {};
  }

  Result<std::string> text(ryml::ConstNodeRef n, std::string_view k, const std::string& what,
                           bool required = true) const {
    if (!n.has_child(ryml::to_csubstr(std::string(k)))) {
      if (required) return err(what + " needs '" + std::string(k) + "'");
      return std::string();
    }
    const auto c = n[ryml::to_csubstr(std::string(k))];
    if (!c.is_keyval()) return err("'" + std::string(k) + "' of " + what + " must be a scalar");
    return str(c);
  }

  Result<Source> source(ryml::ConstNodeRef n, const std::string& what) const {
    if (!n.has_child("source") || !n["source"].is_map()) return err(what + ": rule without source");
    const auto s = n["source"];
    if (auto r = only_keys(s, {"spec", "version", "clause"}, what + " source"); !r) {
      return std::unexpected(r.error());
    }
    Source src;
    for (auto [k, dst] : {std::pair{"spec", &src.spec}, std::pair{"version", &src.version},
                          std::pair{"clause", &src.clause}}) {
      auto v = text(s, k, what + " source");
      if (!v) return std::unexpected(v.error());
      if (v->empty()) return err(what + ": empty source field '" + std::string(k) + "'");
      *dst = *v;
    }
    if (!source_allowed(src.spec, http_)) {
      return err(what + ": source '" + src.spec + "' is not in the list of indexed documents");
    }
    return src;
  }

  Result<SipItemRule> item(ryml::ConstNodeRef n, const std::string& what, bool allow_uri) const {
    SipItemRule r;
    auto a = text(n, "action", what);
    if (!a) return std::unexpected(a.error());
    const auto action = lookup(kActions, *a);
    if (!action) return err("unknown action '" + *a + "' for " + what);
    if (*action == SipAction::uri && !allow_uri) return err("action 'uri' not allowed for " + what);
    r.action = *action;
    auto c = text(n, "category", what, false);
    if (!c) return std::unexpected(c.error());
    if (!c->empty()) {
      const auto cat = lookup(kCategories, *c);
      if (!cat) return err("unknown category '" + *c + "' for " + what);
      if (r.action != SipAction::pseudonymise) return err("category given without pseudonymise: " + what);
      r.category = cat;
    } else if (r.action == SipAction::pseudonymise) {
      return err("pseudonymise needs a category: " + what);
    }
    return r;
  }

  Result<SipItemRule> component(ryml::ConstNodeRef n, const std::string& what) const {
    if (auto r = only_keys(n, {"action", "category", "value"}, what); !r) {
      return std::unexpected(r.error());
    }
    auto r = item(n, what, true);
    if (!r) return r;
    auto v = text(n, "value", what, false);
    if (!v) return std::unexpected(v.error());
    r->value = *v;
    if (r->action == SipAction::blank && n.has_child("value") == false) {
      return err("blank needs a value: " + what);
    }
    return r;
  }

  Result<std::vector<SipParamRule>> params(ryml::ConstNodeRef n, const std::string& what) const {
    std::vector<SipParamRule> out;
    if (!n.is_seq()) return err("params of " + what + " must be a sequence");
    std::set<std::string> seen;
    for (const auto p : n.children()) {
      if (auto r = only_keys(p, {"name", "action", "category", "value", "source"}, what + " param");
          !r) {
        return std::unexpected(r.error());
      }
      SipParamRule pr;
      auto name = text(p, "name", what + " param");
      if (!name) return std::unexpected(name.error());
      if (name->empty()) return err("empty parameter name in " + what);
      pr.name = lower(*name);
      const std::string w = what + ";" + pr.name;
      if (!seen.insert(pr.name).second) return err("duplicate parameter " + w);
      auto it = item(p, w, true);
      if (!it) return std::unexpected(it.error());
      if (it->action == SipAction::blank) return err("blank is not a parameter action: " + w);
      pr.rule = *it;
      auto v = text(p, "value", w, false);
      if (!v) return std::unexpected(v.error());
      if (!v->empty()) {
        const auto pv = lookup(kParamValues, *v);
        if (!pv) return err("unknown value grammar '" + *v + "' for " + w);
        pr.value = *pv;
      }
      auto s = source(p, w);
      if (!s) return std::unexpected(s.error());
      pr.source = *s;
      out.push_back(std::move(pr));
    }
    return out;
  }

  Result<std::vector<std::string>> strings(ryml::ConstNodeRef n, const std::string& what) const {
    if (!n.is_seq()) return err(what + " must be a sequence");
    std::vector<std::string> out;
    for (const auto c : n.children()) {
      if (!c.is_val()) return err(what + " must hold scalars");
      out.push_back(str(c));
    }
    return out;
  }

  bool header_name_taken(std::string_view name) const {
    for (const auto& h : rs_.headers) {
      if (iequal(h.name, name)) return true;
      if (h.compact && name.size() == 1 && iequal(std::string_view(&*h.compact, 1), name)) return true;
      for (const auto& a : h.aliases) {
        if (iequal(a, name)) return true;
      }
    }
    return false;
  }

  Result<void> headers(ryml::ConstNodeRef n) {
    if (!n.is_seq()) return err("'headers' must be a sequence");
    for (const auto h : n.children()) {
      if (auto r = only_keys(h, {"name", "compact", "grammar", "multi", "action", "components",
                                 "params", "aliases", "values", "source", "note"},
                             "header rule");
          !r) {
        return r;
      }
      SipHeaderRule hr;
      auto name = text(h, "name", "header rule");
      if (!name) return std::unexpected(name.error());
      if (!is_token(*name)) return err("header name must be a token: '" + *name + "'");
      hr.name = *name;
      const std::string w = "header " + hr.name;
      if (header_name_taken(hr.name)) return err("duplicate header name " + hr.name);
      auto compact = text(h, "compact", w, false);
      if (!compact) return std::unexpected(compact.error());
      if (!compact->empty()) {
        if (compact->size() != 1 || std::isalpha(static_cast<unsigned char>((*compact)[0])) == 0) {
          return err("compact form must be one letter: " + w);
        }
        if (header_name_taken(*compact)) return err("duplicate compact form " + *compact);
        hr.compact = (*compact)[0];
      }
      auto g = text(h, "grammar", w);
      if (!g) return std::unexpected(g.error());
      const auto grammar = lookup(kGrammars, *g);
      if (!grammar) return err("unknown grammar '" + *g + "' for " + w);
      hr.grammar = *grammar;
      if (is_http_grammar(hr.grammar) && !http_) return err("grammar '" + *g + "' is HTTP only (" + w + ")");
      auto multi = text(h, "multi", w, false);
      if (!multi) return std::unexpected(multi.error());
      if (!multi->empty() && *multi != "true" && *multi != "false") {
        return err("multi must be true or false: " + w);
      }
      hr.multi = *multi == "true";
      if (h.has_child("components")) {
        const auto comps = h["components"];
        if (!comps.is_map()) return err("components of " + w + " must be a mapping");
        const auto known = components_of(hr.grammar);
        for (const auto c : comps.children()) {
          const auto cname = key(c);
          if (!known.contains(cname)) {
            return err("component '" + cname + "' unknown for grammar " + *g + " (" + w + ")");
          }
          auto rule = component(c, w + "." + cname);
          if (!rule) return std::unexpected(rule.error());
          hr.components.emplace(cname, *rule);
        }
      }
      if (h.has_child("params")) {
        auto p = params(h["params"], w);
        if (!p) return std::unexpected(p.error());
        hr.params = std::move(*p);
      }
      if (h.has_child("values")) {
        if (hr.grammar != SipGrammar::token && hr.grammar != SipGrammar::token_list &&
            hr.grammar != SipGrammar::directives) {
          return err("values need a token grammar (" + w + ")");
        }
        auto v = strings(h["values"], "values of " + w);
        if (!v) return std::unexpected(v.error());
        for (auto& x : *v) {
          if (!is_token(x)) return err("value '" + x + "' of " + w + " is not a token");
          for (auto& ch : x) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        }
        hr.values = std::move(*v);
      }
      if (h.has_child("aliases")) {
        auto a = strings(h["aliases"], "aliases of " + w);
        if (!a) return std::unexpected(a.error());
        for (const auto& alias : *a) {
          if (!is_token(alias) || header_name_taken(alias) || iequal(alias, hr.name)) {
            return err("invalid or duplicate alias '" + alias + "' of " + w);
          }
        }
        hr.aliases = std::move(*a);
      }
      auto a = text(h, "action", w, false);
      if (!a) return std::unexpected(a.error());
      if (a->empty()) {
        if (hr.components.empty() && hr.params.empty()) {
          return err(w + " needs an action or components");
        }
        hr.action = SipAction::pseudonymise;
      } else {
        const auto action = lookup(kActions, *a);
        if (!action || *action == SipAction::uri || *action == SipAction::blank) {
          return err("unknown action '" + *a + "' for " + w);
        }
        hr.action = *action;
      }
      auto s = source(h, w);
      if (!s) return std::unexpected(s.error());
      hr.source = *s;
      auto note = text(h, "note", w, false);
      if (!note) return std::unexpected(note.error());
      hr.note = *note;
      rs_.headers.push_back(std::move(hr));
    }
    return {};
  }

  Result<void> uri(ryml::ConstNodeRef n) {
    if (auto r = only_keys(n, {"schemes", "params", "keep"}, "uri"); !r) return r;
    if (n.has_child("keep")) {
      if (!n["keep"].is_seq()) return err("uri keep must be a sequence");
      for (const auto k : n["keep"].children()) {
        if (auto r = only_keys(k, {"value", "source"}, "uri keep entry"); !r) return r;
        auto v = text(k, "value", "uri keep entry");
        if (!v) return std::unexpected(v.error());
        if (v->empty() || v->find(':') == std::string::npos) return err("uri keep value needs a scheme");
        auto src = source(k, "uri keep " + *v);
        if (!src) return std::unexpected(src.error());
        rs_.uri.keep.push_back({*v, *src});
      }
    }
    if (n.has_child("schemes")) {
      auto s = strings(n["schemes"], "uri schemes");
      if (!s) return std::unexpected(s.error());
      for (auto& v : *s) rs_.uri.schemes.push_back(lower(v));
    }
    if (n.has_child("params")) {
      auto p = params(n["params"], "uri");
      if (!p) return std::unexpected(p.error());
      for (auto& pr : *p) {
        if (rs_.uri.find_param(pr.name) != nullptr) return err("duplicate URI parameter " + pr.name);
        rs_.uri.params.push_back(std::move(pr));
      }
    }
    return {};
  }

  Result<void> sdp(ryml::ConstNodeRef n) {
    if (auto r = only_keys(n, {"lines", "attributes"}, "sdp"); !r) return r;
    if (n.has_child("lines")) {
      const auto lines = n["lines"];
      if (!lines.is_seq()) return err("sdp lines must be a sequence");
      for (const auto l : lines.children()) {
        if (auto r = only_keys(l, {"type", "action", "value", "keep_values", "fields", "source"},
                               "sdp line");
            !r) {
          return r;
        }
        SdpLineRule lr;
        auto t = text(l, "type", "sdp line");
        if (!t) return std::unexpected(t.error());
        if (t->size() != 1 || std::islower(static_cast<unsigned char>((*t)[0])) == 0) {
          return err("sdp line type must be one lowercase letter: '" + *t + "'");
        }
        lr.type = (*t)[0];
        const std::string w = "sdp line " + *t + "=";
        if (rs_.find_sdp_line(lr.type) != nullptr) return err("duplicate " + w);
        auto act = text(l, "action", w);
        if (!act) return std::unexpected(act.error());
        const auto action = lookup(kActions, *act);
        if (!action || *action == SipAction::uri) return err("unknown action '" + *act + "' for " + w);
        lr.action = *action;
        if (lr.action == SipAction::pseudonymise && !l.has_child("fields")) {
          return err(w + ": pseudonymise needs fields");
        }
        auto v = text(l, "value", w, false);
        if (!v) return std::unexpected(v.error());
        lr.value = *v;
        if (lr.action == SipAction::blank && !l.has_child("value")) return err("blank needs a value: " + w);
        if (l.has_child("keep_values")) {
          auto kv = strings(l["keep_values"], "keep_values of " + w);
          if (!kv) return std::unexpected(kv.error());
          lr.keep_values = std::move(*kv);
        }
        if (l.has_child("fields")) {
          if (!l["fields"].is_map()) return err("fields of " + w + " must be a mapping");
          for (const auto f : l["fields"].children()) {
            auto rule = component(f, w + "." + key(f));
            if (!rule) return std::unexpected(rule.error());
            lr.fields.emplace(key(f), *rule);
          }
        }
        auto s = source(l, w);
        if (!s) return std::unexpected(s.error());
        lr.source = *s;
        rs_.sdp_lines.push_back(std::move(lr));
      }
    }
    if (n.has_child("attributes")) {
      const auto attrs = n["attributes"];
      if (!attrs.is_seq()) return err("sdp attributes must be a sequence");
      for (const auto a : attrs.children()) {
        if (auto r = only_keys(a, {"name", "format", "grammar", "action", "fields", "fmtp_params",
                                   "separators", "source"},
                               "sdp attribute");
            !r) {
          return r;
        }
        SdpAttributeRule ar;
        auto name = text(a, "name", "sdp attribute");
        if (!name) return std::unexpected(name.error());
        if (!is_token(*name)) return err("sdp attribute name must be a token: '" + *name + "'");
        ar.name = lower(*name);
        auto format = text(a, "format", "a=" + ar.name, false);
        if (!format) return std::unexpected(format.error());
        if (!format->empty()) ar.format = *format;
        const std::string w = "a=" + ar.name + (ar.format ? ":" + *ar.format : "");
        if (rs_.find_sdp_attribute(ar.name, ar.format.value_or("")) != nullptr &&
            (ar.format.has_value() ==
             rs_.find_sdp_attribute(ar.name, ar.format.value_or(""))->format.has_value())) {
          return err("duplicate " + w);
        }
        auto g = text(a, "grammar", w);
        if (!g) return std::unexpected(g.error());
        const auto grammar = lookup(kSdpGrammars, *g);
        if (!grammar) return err("unknown grammar '" + *g + "' for " + w);
        ar.grammar = *grammar;
        auto act = text(a, "action", w, false);
        if (!act) return std::unexpected(act.error());
        if (act->empty()) {
          ar.action = SipAction::pseudonymise;
          if (!a.has_child("fields") && !a.has_child("fmtp_params")) {
            return err(w + " needs an action, fields or fmtp_params");
          }
        } else {
          const auto action = lookup(kActions, *act);
          if (!action || *action == SipAction::uri || *action == SipAction::blank) {
            return err("unknown action '" + *act + "' for " + w);
          }
          ar.action = *action;
        }
        if (ar.grammar == SdpGrammar::opaque && ar.action == SipAction::pseudonymise) {
          return err(w + ": an opaque attribute can only be kept or removed");
        }
        if (a.has_child("fields")) {
          if (!a["fields"].is_map()) return err("fields of " + w + " must be a mapping");
          for (const auto f : a["fields"].children()) {
            auto rule = component(f, w + "." + key(f));
            if (!rule) return std::unexpected(rule.error());
            ar.fields.emplace(key(f), *rule);
          }
        }
        if (a.has_child("fmtp_params")) {
          auto p = params(a["fmtp_params"], w);
          if (!p) return std::unexpected(p.error());
          ar.fmtp_params = std::move(*p);
        }
        if (a.has_child("separators")) {
          auto sep = strings(a["separators"], "separators of " + w);
          if (!sep) return std::unexpected(sep.error());
          for (const auto& x : *sep) {
            if (x != ";" && x != ":") return err("separators of " + w + " must be ';' or ':'");
          }
          ar.separators = std::move(*sep);
        }
        auto s = source(a, w);
        if (!s) return std::unexpected(s.error());
        ar.source = *s;
        rs_.sdp_attributes.push_back(std::move(ar));
      }
    }
    return {};
  }

  Result<void> bodies(ryml::ConstNodeRef n) {
    if (!n.is_seq()) return err("'bodies' must be a sequence");
    for (const auto b : n.children()) {
      if (auto r = only_keys(b, {"content_type", "handling", "params", "source"}, "body rule"); !r) {
        return r;
      }
      SipBodyRule br;
      auto ct = text(b, "content_type", "body rule");
      if (!ct) return std::unexpected(ct.error());
      br.content_type = lower(*ct);
      const auto slash = br.content_type.find('/');
      if (slash == std::string::npos || !is_token(br.content_type.substr(0, slash)) ||
          !is_token(br.content_type.substr(slash + 1))) {
        return err("content_type must be type/subtype: '" + *ct + "'");
      }
      const std::string w = "body " + br.content_type;
      if (rs_.find_body(br.content_type) != nullptr) return err("duplicate " + w);
      auto h = text(b, "handling", w);
      if (!h) return std::unexpected(h.error());
      const auto handling = lookup(kHandlings, *h);
      if (!handling) return err("unknown handling '" + *h + "' for " + w);
      br.handling = *handling;
      if (b.has_child("params")) {
        auto p = strings(b["params"], "params of " + w);
        if (!p) return std::unexpected(p.error());
        for (auto& v : *p) br.params.push_back(lower(v));
      }
      auto s = source(b, w);
      if (!s) return std::unexpected(s.error());
      br.source = *s;
      rs_.bodies.push_back(std::move(br));
    }
    return {};
  }

  Result<void> feature_tags(ryml::ConstNodeRef n) {
    if (!n.is_seq()) return err("'feature_tags' must be a sequence");
    for (const auto t : n.children()) {
      if (auto r = only_keys(t, {"tag", "value", "value_type", "action", "category", "source"},
                             "feature tag rule");
          !r) {
        return r;
      }
      FeatureTagRule fr;
      const bool has_tag = t.has_child("tag");
      const bool has_value = t.has_child("value");
      if (has_tag == has_value) return err("a feature tag rule needs exactly one of tag and value");
      auto name = text(t, has_tag ? "tag" : "value", "feature tag rule");
      if (!name) return std::unexpected(name.error());
      if (name->empty()) return err("empty feature tag");
      fr.name = *name;
      fr.is_value = has_value;
      const std::string w = (has_tag ? "tag " : "value ") + fr.name;
      if ((has_tag ? rs_.find_feature_tag(fr.name) : rs_.find_feature_value(fr.name)) != nullptr) {
        return err("duplicate " + w);
      }
      auto vt = text(t, "value_type", w, false);
      if (!vt) return std::unexpected(vt.error());
      if (!vt->empty()) {
        const auto v = lookup(kFeatureValues, *vt);
        if (!v) return err("unknown value_type '" + *vt + "' for " + w);
        fr.value_type = *v;
      }
      auto it = item(t, w, true);
      if (!it) return std::unexpected(it.error());
      if (it->action == SipAction::blank) return err("blank is not a feature tag action: " + w);
      fr.rule = *it;
      auto s = source(t, w);
      if (!s) return std::unexpected(s.error());
      fr.source = *s;
      rs_.feature_tags.push_back(std::move(fr));
    }
    return {};
  }

  SipRuleSet& rs_;
  bool http_ = false;
  const RuleFile* file_ = nullptr;
};

std::string sha256_hex(std::string_view data) {
  std::array<unsigned char, SHA256_DIGEST_LENGTH> md{};
  SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), md.data());
  return to_hex(ByteView(md.data(), md.size()));
}

template <class Vec>
const SipParamRule* find_param_in(const Vec& v, std::string_view name) {
  for (const auto& p : v) {
    if (iequal(p.name, name)) return &p;
  }
  return nullptr;
}

}  // namespace

const SipParamRule* SipHeaderRule::find_param(std::string_view which) const {
  return find_param_in(params, which);
}

const SipParamRule* SipUriRules::find_param(std::string_view which) const {
  return find_param_in(params, which);
}

bool SipRuleSet::known_method(std::string_view method) const {
  if (methods.empty()) return true;
  return std::any_of(methods.begin(), methods.end(), [&](const SipMethodRule& m) { return m.name == method; });
}

bool SipUriRules::kept(std::string_view uri) const {
  for (const auto& k : keep) {
    if (k.value.ends_with(':') ? (uri.size() > k.value.size() && iequal(uri.substr(0, k.value.size()), k.value))
                               : iequal(uri, k.value)) {
      return true;
    }
  }
  return false;
}

const SipHeaderRule* SipRuleSet::find_header(std::string_view which) const {
  for (const auto& h : headers) {
    if (iequal(h.name, which)) return &h;
    if (h.compact && which.size() == 1 &&
        std::tolower(static_cast<unsigned char>(*h.compact)) ==
            std::tolower(static_cast<unsigned char>(which[0]))) {
      return &h;
    }
    for (const auto& a : h.aliases) {
      if (iequal(a, which)) return &h;
    }
  }
  return nullptr;
}

const SdpLineRule* SipRuleSet::find_sdp_line(char type) const {
  for (const auto& l : sdp_lines) {
    if (l.type == type) return &l;
  }
  return nullptr;
}

const SdpAttributeRule* SipRuleSet::find_sdp_attribute(std::string_view which,
                                                       std::string_view format) const {
  const SdpAttributeRule* generic = nullptr;
  for (const auto& a : sdp_attributes) {
    if (!iequal(a.name, which)) continue;
    if (a.format) {
      if (!format.empty() && iequal(*a.format, format)) return &a;
    } else {
      generic = &a;
    }
  }
  return generic;
}

const SipBodyRule* SipRuleSet::find_body(std::string_view content_type) const {
  for (const auto& b : bodies) {
    if (iequal(b.content_type, content_type)) return &b;
  }
  return nullptr;
}

const FeatureTagRule* SipRuleSet::find_feature_tag(std::string_view which) const {
  for (const auto& t : feature_tags) {
    if (!t.is_value && iequal(t.name, which)) return &t;
  }
  return nullptr;
}

const FeatureTagRule* SipRuleSet::find_feature_value(std::string_view value) const {
  // ICSI/IARI values are compared exactly (URN comparison is out of scope; allowlist only).
  for (const auto& t : feature_tags) {
    if (t.is_value && t.name == value) return &t;
  }
  return nullptr;
}

std::string_view to_string(SipAction a) { return name_of(kActions, a); }
std::string_view to_string(SipCategory c) { return name_of(kCategories, c); }

Result<SipRuleSet> load_sip_ruleset(std::span<const RuleFile> files) {
  if (files.empty()) return fail(ErrorCode::internal, "SIP rule set has no files");
  std::vector<const RuleFile*> ordered;
  for (const auto& f : files) ordered.push_back(&f);
  std::sort(ordered.begin(), ordered.end(),
            [](const RuleFile* a, const RuleFile* b) { return a->name < b->name; });
  SipRuleSet rs;
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
  rs.digest = sha256_hex(combined);
  return rs;
}

Result<SipRuleSet> load_http_header_rules(std::span<const RuleFile> files) {
  if (files.empty()) return fail(ErrorCode::internal, "HTTP rule set has no files");
  std::vector<const RuleFile*> ordered;
  for (const auto& f : files) ordered.push_back(&f);
  std::sort(ordered.begin(), ordered.end(),
            [](const RuleFile* a, const RuleFile* b) { return a->name < b->name; });
  SipRuleSet rs;
  Loader loader(rs, true);
  yaml::ScopedCallbacks callbacks;
  for (std::size_t i = 0; i < ordered.size(); ++i) {
    try {
      if (auto r = loader.file(*ordered[i], i == 0); !r) return std::unexpected(r.error());
    } catch (const yaml::YamlError& e) {
      return fail(ErrorCode::internal, "rule file " + ordered[i]->name + ": " + e.what());
    }
  }
  return rs;
}

bool is_http_grammar(SipGrammar g) {
  switch (g) {
    case SipGrammar::host:
    case SipGrammar::etag_list:
    case SipGrammar::http_uri:
    case SipGrammar::http_credentials:
    case SipGrammar::cookie:
    case SipGrammar::set_cookie:
    case SipGrammar::directives:
    case SipGrammar::range:
    case SipGrammar::identity: return true;
    default: return false;
  }
}

Result<SipRuleSet> load_embedded_sip_ruleset() {
  std::vector<RuleFile> files;
  for (const auto& f : embedded_sip_rule_files()) {
    files.push_back(RuleFile{std::string(f.name), std::string(f.text)});
  }
  return load_sip_ruleset(files);
}

std::string_view embedded_sip_ruleset_digest() { return sip_ruleset_digest; }

}  // namespace mcxanon
