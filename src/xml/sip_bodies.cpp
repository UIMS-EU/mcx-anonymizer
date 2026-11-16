// SPDX-License-Identifier: GPL-3.0-or-later
#include "xml/sip_bodies.hpp"

#include "xml/categories.hpp"

#include "sip/rewrite.hpp"

#include <cctype>

#include <string>

namespace mcxanon::xml {

Result<std::optional<std::string>> ContextMapper::map(XmlCategory category, std::string_view value) {
  return map_category(category, value, ctx_);
}

void ContextMapper::removed(std::string_view value) { ctx_.counters.removed(value); }

Result<std::optional<std::string>> ContextMapper::map_embedding(XmlCategory category, std::string_view value,
                                                                std::size_t depth) {
  const auto has = [&](std::string_view scheme) {
    if (value.size() < scheme.size()) return false;
    for (std::size_t i = 0; i < scheme.size(); ++i) {
      if (std::tolower(static_cast<unsigned char>(value[i])) != scheme[i]) return false;
    }
    return true;
  };
  if (category != XmlCategory::uri) return map(category, value);
  if (has("sip:") || has("sips:") || has("tel:") || has("urn:")) {
    auto e = sip::rewrite_entry_uri(value, ctx_, depth);
    if (!e) return std::unexpected(e.error());
    if (counters_ != nullptr && !e->outcome.empty()) ++counters_->embedded[e->outcome];
    return std::move(e->uri);
  }
  return map(XmlCategory::xcap_selector, value);
}

Result<sip::XmlOutcome> SipXmlBodies::rewrite(std::string_view content_type, std::string_view charset,
                                              std::string_view body, std::size_t depth, sip::Context& ctx) {
  ContextMapper mapper(ctx, &counters_);
  auto o = rewriter_.rewrite(content_type, charset, body, mapper, depth);
  if (!o) return std::unexpected(o.error());
  if (!o->rewritten) return sip::XmlOutcome{false, {}, std::string(to_string(o->reason))};
  if (passthrough_) return sip::XmlOutcome{true, std::string(body), {}};
  return sip::XmlOutcome{true, std::move(o->bytes), {}};
}

}  // namespace mcxanon::xml
