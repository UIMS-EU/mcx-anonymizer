// SPDX-License-Identifier: GPL-3.0-or-later
//
// rapidyaml helpers shared by the rule loaders. rapidyaml reports errors through a callback;
// the one installed here throws a private exception that the loaders catch and turn into an
// error value, so it never leaves the policy module.
#pragma once

#include <c4/error.hpp>
#include <ryml.hpp>
#include <ryml_std.hpp>

#include <stdexcept>
#include <string>

namespace mcxanon::yaml {

struct YamlError : std::runtime_error {
  using std::runtime_error::runtime_error;
};

[[noreturn]] inline void on_basic(ryml::csubstr msg, const ryml::ErrorDataBasic&, void*) {
  throw YamlError(std::string(msg.str, msg.len));
}
[[noreturn]] inline void on_parse(ryml::csubstr msg, const ryml::ErrorDataParse&, void*) {
  throw YamlError(std::string(msg.str, msg.len));
}
[[noreturn]] inline void on_visit(ryml::csubstr msg, const ryml::ErrorDataVisit&, void*) {
  throw YamlError(std::string(msg.str, msg.len));
}

class ScopedCallbacks {
 public:
  ScopedCallbacks() : saved_(ryml::get_callbacks()) {
    ryml::Callbacks cb = saved_;
    cb.set_error_basic(&on_basic).set_error_parse(&on_parse).set_error_visit(&on_visit);
    ryml::set_callbacks(cb);
  }
  ScopedCallbacks(const ScopedCallbacks&) = delete;
  ScopedCallbacks& operator=(const ScopedCallbacks&) = delete;
  ~ScopedCallbacks() { ryml::set_callbacks(saved_); }

 private:
  ryml::Callbacks saved_;
};

inline std::string str(ryml::ConstNodeRef n) {
  std::string s;
  if (n.has_val()) s.assign(n.val().str, n.val().len);
  return s;
}

inline std::string key(ryml::ConstNodeRef n) { return std::string(n.key().str, n.key().len); }

}  // namespace mcxanon::yaml
