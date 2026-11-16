// SPDX-License-Identifier: GPL-3.0-or-later
//
// Helpers shared by the feature-007 rule loaders (HTTP and TLS): key checks, scalars, sources
// limited to the documents of the rule set, and the SHA-256 digest of the files. Errors are
// values (ErrorCode::internal); rapidyaml errors are caught by the callers.
#pragma once

#include "mcxanon/error.hpp"

#include "policy/ruleset.hpp"
#include "policy/yaml_util.hpp"

#include <algorithm>
#include <functional>
#include <initializer_list>
#include <string>
#include <string_view>
#include <vector>

namespace mcxanon::rules {

class LoaderBase {
 public:
  explicit LoaderBase(std::function<bool(std::string_view)> allowed) : allowed_(std::move(allowed)) {}

 protected:
  const RuleFile* file_ = nullptr;

  [[nodiscard]] std::unexpected<Error> err(const std::string& msg) const {
    return std::unexpected(Error{ErrorCode::internal, "rule file " + (file_ ? file_->name : std::string("?")) + ": " + msg});
  }

  static std::string scalar(ryml::ConstNodeRef n) { return n.is_keyval() || n.is_val() ? yaml::str(n) : ""; }

  [[nodiscard]] Result<void> only_keys(ryml::ConstNodeRef n, std::initializer_list<std::string_view> keys,
                                       const std::string& what) const {
    if (!n.is_map()) return err(what + " must be a mapping");
    for (const auto c : n.children()) {
      const auto k = yaml::key(c);
      if (std::find(keys.begin(), keys.end(), k) == keys.end()) return err("unknown key '" + k + "' in " + what);
    }
    return {};
  }

  [[nodiscard]] Result<std::string> text(ryml::ConstNodeRef n, std::string_view k, const std::string& what,
                                         bool required = true) const {
    const std::string ks(k);
    if (!n.has_child(ryml::to_csubstr(ks))) {
      if (required) return err(what + " needs '" + ks + "'");
      return std::string();
    }
    const auto c = n[ryml::to_csubstr(ks)];
    if (!c.is_keyval()) return err("'" + ks + "' of " + what + " must be a scalar");
    return yaml::str(c);
  }

  [[nodiscard]] Result<std::vector<std::string>> strings(ryml::ConstNodeRef n, const std::string& what) const {
    if (!n.is_seq()) return err(what + " must be a sequence");
    std::vector<std::string> out;
    for (const auto c : n.children()) {
      if (!c.is_val()) return err(what + " must hold scalars");
      out.push_back(yaml::str(c));
    }
    return out;
  }

  [[nodiscard]] Result<Source> source(ryml::ConstNodeRef n, const std::string& what) const {
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
    if (!allowed_(src.spec)) return err(what + ": source '" + src.spec + "' is not in the list of indexed documents");
    return src;
  }

  // The ruleset and version keys of one file; the first file sets them, the others must agree.
  [[nodiscard]] Result<void> header(ryml::ConstNodeRef root, std::string_view expected, bool first,
                                    std::string& name, std::string& version) const {
    if (!root.has_child("ruleset") || !root.has_child("version")) return err("'ruleset' and 'version' are required");
    const std::string n = scalar(root["ruleset"]);
    const std::string v = scalar(root["version"]);
    if (n != expected) return err("ruleset must be '" + std::string(expected) + "'");
    if (v.empty()) return err("'version' must be non-empty");
    if (first) {
      name = n;
      version = v;
    } else if (v != version) {
      return err("rule set version differs from the other rule files");
    }
    return {};
  }

 private:
  std::function<bool(std::string_view)> allowed_;
};

std::string sha256_hex(std::string_view data);

}  // namespace mcxanon::rules
