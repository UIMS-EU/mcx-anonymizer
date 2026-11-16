// SPDX-License-Identifier: GPL-3.0-or-later
//
// A test environment for the HTTP layer (feature 007): the embedded SIP, XML and HTTP rule sets,
// a fresh project mapping, the XML body rewriter and an http::Env over them.
#pragma once

#include "http/env.hpp"
#include "pipeline/mapper_adapter.hpp"
#include "policy/http_rules.hpp"
#include "policy/xml_rules.hpp"
#include "pseudo/pseudonymiser.hpp"
#include "xml/sip_bodies.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <optional>
#include <string>

namespace web_test {

inline mcxanon::Secret secret() {
  mcxanon::Secret s{};
  for (std::size_t i = 0; i < s.size(); ++i) s[i] = static_cast<std::uint8_t>(i * 11 + 5);
  return s;
}

struct Env {
  explicit Env(std::int64_t shift = 0) {
    opts.time_shift_s = shift;
    sctx.emplace(mcxanon::sip::Context{sip_rules, mapper, opts, sip_counters, nullptr, &xml_bodies});
    env.emplace(mcxanon::http::Env{http_rules, *sctx, counters, nullptr});
  }
  mcxanon::SipRuleSet sip_rules = *mcxanon::load_embedded_sip_ruleset();
  mcxanon::XmlRuleSet xml_rules = *mcxanon::load_embedded_xml_ruleset();
  mcxanon::HttpRuleSet http_rules = *mcxanon::load_embedded_http_ruleset();
  mcxanon::Secret key = secret();
  mcxanon::Mapping mapping;
  mcxanon::Pseudonymiser p{key, mapping};
  mcxanon::MapperAdapter mapper{p};
  mcxanon::sip::TextOptions opts;
  mcxanon::sip::SipCounters sip_counters;
  mcxanon::xml::Counters xml_counters;
  mcxanon::xml::SipXmlBodies xml_bodies{xml_rules, xml_counters};
  mcxanon::http::Counters counters;
  std::optional<mcxanon::sip::Context> sctx;
  std::optional<mcxanon::http::Env> env;
  mcxanon::http::Env& operator*() { return *env; }
  [[nodiscard]] bool removed(const std::string& v) const {
    for (const auto& [c, x] : sip_counters.removed_values) {
      if (x == v) return true;
    }
    return false;
  }
};

}  // namespace web_test
