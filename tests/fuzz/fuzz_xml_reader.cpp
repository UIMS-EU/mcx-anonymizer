// SPDX-License-Identifier: GPL-3.0-or-later
// The XML reader on any input: it either rejects with a reason or returns a document whose
// spans lie inside the body and nest properly; reading the same body again gives the same items.
#include "xml/reader.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string_view>
#include <vector>

namespace {

void check_span(const mcxanon::xml::Span& s, std::size_t size) {
  if (s.off > size || s.len > size - s.off) std::abort();
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  using namespace mcxanon::xml;
  static Reader reader;  // buffers are reused between bodies, as in the rewriter
  const std::string_view in(reinterpret_cast<const char*>(data), size);
  auto r = reader.read(in);
  if (!r) {
    if (r.error().offset > size) std::abort();
    return 0;
  }
  const Document& d = **r;
  if (d.elements.empty()) std::abort();  // a document has a root
  std::size_t last = 0;
  std::vector<Item> items = d.items;
  for (const auto& it : items) {
    check_span(it.span, size);
    if (it.span.off < last) std::abort();  // document order
    last = it.span.end();
    if (it.element != kNoElement && it.element >= d.elements.size()) std::abort();
  }
  for (const auto& e : d.elements) {
    check_span(e.start_tag, size);
    check_span(e.name_span, size);
    check_span(e.content, size);
    if (e.end_tag) check_span(*e.end_tag, size);
    if (e.parent != kNoElement && e.parent >= d.elements.size()) std::abort();
    if (e.attr_first + std::size_t{e.attr_count} > d.attributes.size()) std::abort();
  }
  for (const auto& a : d.attributes) {
    check_span(a.span, size);
    check_span(a.value_span, size);
    if (a.value_span.off < a.span.off || a.value_span.end() > a.span.end()) std::abort();
  }
  // Deterministic: a second read gives the same item spans.
  auto again = reader.read(in);
  if (!again || (*again)->items.size() != items.size()) std::abort();
  for (std::size_t i = 0; i < items.size(); ++i) {
    if (!((*again)->items[i].span == items[i].span)) std::abort();
  }
  return 0;
}
