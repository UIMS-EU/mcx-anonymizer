// SPDX-License-Identifier: GPL-3.0-or-later
//
// The XML layer as the SIP layer sees it: implements sip::XmlBodies over the
// BodyRewriter, mapping values with the SIP layer's mappings, so that one identity has one
// pseudonym in SIP headers, XML bodies, SDP and floor control (FR-013, SC-003).
#pragma once

#include "policy/xml_rules.hpp"
#include "sip/value_map.hpp"
#include "xml/counters.hpp"
#include "xml/rewrite.hpp"

namespace mcxanon::xml {

class SipXmlBodies : public sip::XmlBodies {
 public:
  SipXmlBodies(const XmlRuleSet& rules, Counters& counters, RewriteOptions options = {})
      : rewriter_(rules, counters, options), counters_(counters) {}

  Result<sip::XmlOutcome> rewrite(std::string_view content_type, std::string_view charset, std::string_view body,
                                  std::size_t depth, sip::Context& ctx) override;
  // Test seam (tests/leaktest): rewrite and count as usual, then keep the original body.
  void set_test_passthrough(bool on) { passthrough_ = on; }

 private:
  BodyRewriter rewriter_;
  Counters& counters_;
  bool passthrough_ = false;
};

// The value mapper over a SIP context (also used by tests).
class ContextMapper : public ValueMapper {
 public:
  explicit ContextMapper(sip::Context& ctx, Counters* counters = nullptr) : ctx_(ctx), counters_(counters) {}
  Result<std::optional<std::string>> map(XmlCategory category, std::string_view value) override;
  void removed(std::string_view value) override;
  // E10: an entry URI with a SIP, tel or URN scheme goes through the 002 URI mapping with the
  // embedded-body hook (FR-014a); any other value is an XCAP request URI (xcap_selector).
  Result<std::optional<std::string>> map_embedding(XmlCategory category, std::string_view value,
                                                   std::size_t depth) override;

 private:
  sip::Context& ctx_;
  Counters* counters_;
};

}  // namespace mcxanon::xml
