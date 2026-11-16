// SPDX-License-Identifier: GPL-3.0-or-later
// The XML body rewriter with the embedded rule set: the first input byte selects one of the
// Content-Types switched on in rules/sip-bodies.yaml, the rest is the body. A rewritten body
// must read again (the rewriter's verify option aborts the run with an internal error
// otherwise); every value goes through a mapper that returns a value of a different length or
// declines, so both edit paths are exercised.
#include "policy/sip_rules.hpp"
#include "policy/xml_rules.hpp"
#include "xml/reader.hpp"
#include "xml/rewrite.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

namespace {

struct Mapper : mcxanon::xml::ValueMapper {
  mcxanon::Result<std::optional<std::string>> map(mcxanon::XmlCategory, std::string_view value) override {
    if (!value.empty() && value.front() == '!') return std::optional<std::string>{};
    return std::optional<std::string>("p<&>\"'-" + std::to_string(value.size()));
  }
  void removed(std::string_view) override {}
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  using namespace mcxanon;
  static const auto rules = load_embedded_xml_ruleset();
  static const auto types = [] {
    std::vector<std::string> t;
    const auto sip = load_embedded_sip_ruleset();
    if (sip) {
      for (const auto& b : sip->bodies) {
        if (b.handling == BodyHandling::xml) t.push_back(b.content_type);
      }
    }
    return t;
  }();
  if (!rules || types.empty() || size < 1) return 0;
  static xml::Counters counters;  // the rewriter keeps a reference; it grows with the keys seen
  static xml::BodyRewriter rw(*rules, counters, xml::RewriteOptions{true});
  Mapper m;
  const auto& ct = types[data[0] % types.size()];
  const std::string_view body(reinterpret_cast<const char*>(data + 1), size - 1);
  auto r = rw.rewrite(ct, "", body, m, 0);
  if (!r) std::abort();  // verify failed, overlapping edits, or another internal error
  if (r->rewritten) {
    xml::Reader again;
    if (!again.read(r->bytes)) std::abort();
  }
  return 0;
}
