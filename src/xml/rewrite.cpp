// SPDX-License-Identifier: GPL-3.0-or-later
#include "xml/rewrite.hpp"

#include "xml/escape.hpp"
#include "xml/values.hpp"

#include <algorithm>
#include <cctype>
#include <utility>
#include <vector>

namespace mcxanon::xml {
namespace {

constexpr std::string_view kXmlNs = "http://www.w3.org/XML/1998/namespace";
constexpr std::string_view kXencNs = "http://www.w3.org/2001/04/xmlenc#";

bool iequal(std::string_view a, std::string_view b) {
  return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), [](char x, char y) {
           return std::tolower(static_cast<unsigned char>(x)) == std::tolower(static_cast<unsigned char>(y));
         });
}

std::string lower(std::string_view s) {
  std::string out(s);
  for (auto& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return out;
}

EmptyReason from_reject(Reject r) {
  switch (r) {
    case Reject::malformed: return EmptyReason::malformed;
    case Reject::encoding: return EmptyReason::encoding;
    case Reject::limit: return EmptyReason::limit;
    case Reject::dtd: return EmptyReason::dtd;
  }
  return EmptyReason::malformed;
}

struct Edit {
  Span span;
  std::string replacement;
};

class Walker {
 public:
  Walker(const XmlRuleSet& rules, const Document& doc, std::string_view body, ValueMapper& mapper, Counters& counters,
         std::size_t depth, bool passthrough, std::int64_t time_shift_s = 0)
      : rules_(rules), doc_(doc), body_(body), mapper_(mapper), counters_(counters), depth_(depth),
        passthrough_(passthrough), time_shift_s_(time_shift_s) {}

  Result<std::vector<Edit>> run() {
    const auto n = doc_.elements.size();
    removed_.assign(n, 0);
    content_replaced_.assign(n, 0);
    verbatim_.assign(n, 0);
    enc_.assign(n, 0);
    direct_.assign(n, {});
    start_item_.assign(n, 0);
    for (std::uint32_t i = 0; i < doc_.items.size(); ++i) {
      const auto& it = doc_.items[i];
      if (it.kind == ItemKind::start || it.kind == ItemKind::empty) {
        start_item_[it.element] = i;
      } else if (it.element != kNoElement && it.kind != ItemKind::end) {
        direct_[it.element].push_back(i);
      }
    }
    for (std::uint32_t e = 0; e < n; ++e) {
      const auto& el = doc_.elements[e];
      if (el.parent != kNoElement && removed_[el.parent]) {
        removed_[e] = 1;
        continue;
      }
      if (el.parent != kNoElement && verbatim_[el.parent]) {
        verbatim_[e] = 1;
        continue;
      }
      if (el.parent != kNoElement) enc_[e] = enc_[el.parent];
      if (auto r = element(e); !r) return std::unexpected(r.error());
    }
    // Comments and processing instructions outside removed or replaced content (FR-009).
    for (const auto& it : doc_.items) {
      if (it.kind != ItemKind::comment && it.kind != ItemKind::pi) continue;
      if (it.element != kNoElement && (removed_[it.element] || content_replaced_[it.element] || verbatim_[it.element])) {
        continue;
      }
      remove(it.span);
      ++(it.kind == ItemKind::comment ? counters_.comments : counters_.processing_instructions);
    }
    // Comments and PIs inside replaced content are removed with it; count them too.
    for (const auto& it : doc_.items) {
      if ((it.kind == ItemKind::comment || it.kind == ItemKind::pi) && it.element != kNoElement &&
          !removed_[it.element] && content_replaced_[it.element]) {
        ++(it.kind == ItemKind::comment ? counters_.comments : counters_.processing_instructions);
      }
    }
    std::stable_sort(edits_.begin(), edits_.end(), [](const Edit& a, const Edit& b) { return a.span.off < b.span.off; });
    for (std::size_t i = 1; i < edits_.size(); ++i) {
      if (edits_[i].span.off < edits_[i - 1].span.end()) {
        return fail(ErrorCode::internal, "xml rewrite: overlapping edits");
      }
    }
    return std::move(edits_);
  }

 private:
  void remove(Span s) { edits_.push_back(Edit{s, {}}); }
  void replace(Span s, std::string r) { edits_.push_back(Edit{s, std::move(r)}); }

  Span element_span(const Element& el) const {
    const auto end = el.end_tag ? el.end_tag->end() : el.start_tag.end();
    return Span{el.start_tag.off, end - el.start_tag.off};
  }

  void count_element(const Element& el, std::string_view action) {
    ++counters_.elements[{el.name.ns, el.name.local}][std::string(action)];
    if (action == "remove" || action == "unknown" || action == "malformed") note_enc_removed(el);
  }

  void count_attr(const Element& el, const Attribute& a, std::string_view action) {
    ++counters_.attributes[{el.name.ns, el.name.local, a.name.ns, a.name.local}][std::string(action)];
    if (action == "remove" || action == "unknown" || action == "malformed") note_enc_removed(el);
  }

  // Feature 005 (FR-016): a part removed inside a kept EncryptedData subtree is counted.
  void note_enc_removed(const Element& el) {
    const auto e = static_cast<std::size_t>(&el - doc_.elements.data());
    if (e < enc_.size() && enc_[e]) ++counters_.encrypted_removed_parts;
  }

  // Feature 005 (FR-016): an EncryptedData is kept only as the whole
  // body or as the child of an element whose rule is encryptable.
  bool encryptable_parent(const Element& el) const {
    if (el.parent == kNoElement) return true;
    const auto& p = doc_.elements[el.parent];
    const auto* pns = rules_.ns(p.name.ns);
    if (pns == nullptr || pns->disposition != XmlDisposition::rules) return false;
    const std::string_view gp =
        p.parent == kNoElement ? std::string_view() : std::string_view(doc_.elements[p.parent].name.local);
    const auto* r = pns->element(p.name.local, gp);
    return r != nullptr && r->rule.encryptable;
  }

  // The unescaped text value of a simple element, and the single text item if there is exactly one.
  std::string text_value(std::uint32_t e, const Item** single) const {
    std::string v;
    std::size_t parts = 0;
    *single = nullptr;
    for (const auto i : direct_[e]) {
      const auto& it = doc_.items[i];
      if (it.kind == ItemKind::text) {
        v += unescape(body_.substr(it.span.off, it.span.len), false).value_or("");
        *single = &it;
        ++parts;
      } else if (it.kind == ItemKind::cdata) {
        v += body_.substr(it.span.off + 9, it.span.len - 12);
        ++parts;
      } else {
        ++parts;  // a comment or PI: the content is not one text run
      }
    }
    if (parts != 1) *single = nullptr;
    return v;
  }

  // Replaces the value of a simple element: inside the single text item, keeping the whitespace
  // around the value; otherwise the whole content.
  void replace_value(std::uint32_t e, const Item* single, std::string_view escaped) {
    const auto& el = doc_.elements[e];
    if (single != nullptr) {
      const auto raw = body_.substr(single->span.off, single->span.len);
      const auto core = trim_xml_space(raw);
      const auto off = single->span.off + static_cast<std::size_t>(core.data() - raw.data());
      replace(Span{off, core.size()}, std::string(escaped));
      return;
    }
    if (el.empty_tag) return;  // <x/>: nothing to replace and no place to write
    replace(el.content, std::string(escaped));
    content_replaced_[e] = 1;
  }

  void clear_content(std::uint32_t e) {
    const auto& el = doc_.elements[e];
    if (el.empty_tag || el.content.len == 0) return;
    remove(el.content);
    content_replaced_[e] = 1;
  }

  // Text values of a removed subtree become scan tokens (FR-015, FR-017).
  void tokens_of(std::uint32_t e) {
    const auto span = element_span(doc_.elements[e]);
    for (std::size_t i = start_item_[e]; i < doc_.items.size(); ++i) {
      const auto& it = doc_.items[i];
      if (it.span.off >= span.end()) break;
      std::string v;
      if (it.kind == ItemKind::text && !it.whitespace) {
        v = unescape(body_.substr(it.span.off, it.span.len), false).value_or("");
      } else if (it.kind == ItemKind::cdata) {
        v = std::string(body_.substr(it.span.off + 9, it.span.len - 12));
      }
      const auto t = trim_xml_space(v);
      if (!t.empty()) mapper_.removed(t);
    }
  }

  bool encrypted(const Element& el) const {
    const auto* a = doc_.attrs(el);
    for (std::uint32_t i = 0; i < el.attr_count; ++i) {
      if (!a[i].ns_decl && a[i].name.ns.empty() && a[i].name.local == "type" && trim_xml_space(a[i].value) == "Encrypted") {
        return true;
      }
    }
    return false;
  }

  Result<void> element(std::uint32_t e) {
    const auto& el = doc_.elements[e];
    const auto* nsr = rules_.ns(el.name.ns);
    if (nsr == nullptr) {
      remove(element_span(el));
      removed_[e] = 1;
      ++counters_.removed_namespaces[el.name.ns];
      return {};
    }
    if (nsr->disposition == XmlDisposition::remove_encrypted ||
        (nsr->disposition == XmlDisposition::encrypted_content && !enc_[e] &&
         (el.name.local != "EncryptedData" || !encryptable_parent(el)))) {
      remove(element_span(el));
      removed_[e] = 1;
      ++counters_.encrypted;
      return {};
    }
    if (nsr->disposition == XmlDisposition::encrypted_content && !enc_[e]) {
      // The root of a kept subtree (FR-016): copied as it is in passthrough mode (FR-017), else
      // its elements and attributes follow the xenc and dsig rules.
      if (passthrough_) {
        verbatim_[e] = 1;
        ++counters_.encrypted_passed_through;
        return {};
      }
      enc_[e] = 1;
      ++counters_.encrypted_kept;
    }
    if (nsr->disposition == XmlDisposition::remove_credential) {
      remove(element_span(el));
      removed_[e] = 1;
      tokens_of(e);
      count_element(el, "remove");
      return {};
    }
    const std::string_view parent_local =
        el.parent == kNoElement ? std::string_view() : std::string_view(doc_.elements[el.parent].name.local);
    const auto* rule = nsr->element(el.name.local, parent_local);
    if (rule == nullptr) {
      remove(element_span(el));
      removed_[e] = 1;
      count_element(el, "unknown");
      return {};
    }
    const auto& r = rule->rule;
    if (r.action == XmlAction::remove) {
      remove(element_span(el));
      removed_[e] = 1;
      tokens_of(e);
      count_element(el, "remove");
      return {};
    }
    if (r.action == XmlAction::pseudonymise && r.category == XmlCategory::mikey_hex) return mikey_hex(e);
    count_element(el, to_string(r.action));
    if (auto a = attributes(e, *nsr); !a) return a;

    if (r.action == XmlAction::container || !el.simple) {
      // Character data directly inside a container (or around the children of a value
      // element) is not classified: removed (FR-008).
      for (const auto i : direct_[e]) {
        const auto& it = doc_.items[i];
        if ((it.kind == ItemKind::text && !it.whitespace) || it.kind == ItemKind::cdata) {
          remove(it.span);
          count_element(el, "malformed");
        }
      }
      return {};
    }

    const Item* single = nullptr;
    const std::string value = text_value(e, &single);
    const std::string_view core = trim_xml_space(value);
    switch (r.action) {
      case XmlAction::keep:
        if (!matches(*r.value, value)) {
          clear_content(e);
          count_element(el, "malformed");
          if (!core.empty()) mapper_.removed(core);
        } else if (r.value->kind == XmlValueType::Kind::datetime_shifted && time_shift_s_ != 0) {
          auto shifted = shift_datetime(value, time_shift_s_);
          if (shifted) replace_value(e, single, escape_text(*shifted));
        }
        break;
      case XmlAction::zero:
        if (!core.empty()) {
          mapper_.removed(core);
          replace_value(e, single, escape_text(zero_text(value)));
        }
        break;
      case XmlAction::pseudonymise: {
        if (core.empty()) break;
        auto mapped = mapper_.map(*r.category, core);
        if (!mapped) return std::unexpected(mapped.error());
        if (!*mapped && *r.category == XmlCategory::xpk_id) {
          // Feature 005: a KeyName that is no 32-bit XPK-ID is removed, as 003 removed every one.
          remove(element_span(el));
          removed_[e] = 1;
          tokens_of(e);
          count_element(el, "remove");
          break;
        }
        if (!*mapped) {
          clear_content(e);
          count_element(el, "malformed");
          mapper_.removed(core);
        } else {
          replace_value(e, single, escape_text(**mapped));
        }
        break;
      }
      case XmlAction::fixed:
        if (encrypted(el)) break;
        if (el.empty_tag) break;
        if (el.content.len == 0) {
          replace(Span{el.content.off, 0}, escape_text(r.constant));
        } else {
          replace_value(e, single, escape_text(r.constant));
        }
        break;
      case XmlAction::empty:
        if (!core.empty()) mapper_.removed(core);
        clear_content(e);
        break;
      case XmlAction::container:
      case XmlAction::remove:
        break;
    }
    return {};
  }

  // Feature 005: a <GKTP> element holds the hexBinary of an I_MESSAGE, which
  // the MIKEY carrier rewrites in place. When it cannot (FR-020 c), or the element is not a plain
  // text value, the element is removed as a credential, as the former remove_credential
  // disposition did, and its text becomes a scan token.
  Result<void> mikey_hex(std::uint32_t e) {
    const auto& el = doc_.elements[e];
    const Item* single = nullptr;
    const std::string value = text_value(e, &single);
    std::optional<std::string> mapped;
    if (el.simple) {
      auto m = mapper_.map(XmlCategory::mikey_hex, trim_xml_space(value));
      if (!m) return std::unexpected(m.error());
      mapped = std::move(*m);
    }
    if (!mapped) {
      remove(element_span(el));
      removed_[e] = 1;
      tokens_of(e);
      count_element(el, "remove");
      return {};
    }
    count_element(el, "pseudonymise");
    if (auto a = attributes(e, *rules_.ns(el.name.ns)); !a) return a;
    replace_value(e, single, escape_text(*mapped));
    return {};
  }

  Result<void> attributes(std::uint32_t e, const XmlNamespaceRules& nsr) {
    const auto& el = doc_.elements[e];
    const auto* attrs = doc_.attrs(el);
    for (std::uint32_t i = 0; i < el.attr_count; ++i) {
      const auto& a = attrs[i];
      if (a.ns_decl) {
        // A declaration of a namespace without rules is removed, used or not.
        if (!a.value.empty() && a.value != kXmlNs && rules_.ns(a.value) == nullptr) remove(a.span);
        continue;
      }
      const XmlAttributeRule* rule = nullptr;
      if (!a.name.ns.empty()) {
        if (const auto* own = rules_.ns(a.name.ns)) rule = own->attribute(el.name.local, a.name.ns, a.name.local);
      }
      if (rule == nullptr) rule = nsr.attribute(el.name.local, a.name.ns, a.name.local);
      if (rule == nullptr) {
        remove(a.span);
        count_attr(el, a, "unknown");
        continue;
      }
      const auto& r = rule->rule;
      const std::string_view core = trim_xml_space(a.value);
      switch (r.action) {
        case XmlAction::zero:
          if (!core.empty()) mapper_.removed(core);
          replace(a.value_span, escape_attr(zero_text(a.value), a.quote));
          count_attr(el, a, "zero");
          break;
        case XmlAction::keep:
          if (matches(*r.value, a.value) && r.value->kind == XmlValueType::Kind::datetime_shifted &&
              time_shift_s_ != 0) {
            if (auto shifted = shift_datetime(a.value, time_shift_s_)) {
              replace(a.value_span, escape_attr(*shifted, a.quote));
              count_attr(el, a, "keep");
              break;
            }
          }
          if (matches(*r.value, a.value)) {
            count_attr(el, a, "keep");
          } else {
            remove(a.span);
            count_attr(el, a, "malformed");
            if (!core.empty()) mapper_.removed(core);
          }
          break;
        case XmlAction::pseudonymise: {
          if (core.empty()) {
            count_attr(el, a, "pseudonymise");
            break;
          }
          auto mapped = r.embeds_body ? mapper_.map_embedding(*r.category, core, depth_) : mapper_.map(*r.category, core);
          if (!mapped) return std::unexpected(mapped.error());
          if (!*mapped) {
            remove(a.span);
            count_attr(el, a, "malformed");
            mapper_.removed(core);
          } else {
            replace(a.value_span, escape_attr(**mapped, a.quote));
            count_attr(el, a, "pseudonymise");
          }
          break;
        }
        case XmlAction::fixed:
          replace(a.value_span, escape_attr(r.constant, a.quote));
          count_attr(el, a, "fixed");
          break;
        case XmlAction::empty:
          if (!core.empty()) mapper_.removed(core);
          replace(a.value_span, "");
          count_attr(el, a, "empty");
          break;
        case XmlAction::remove:
        case XmlAction::container:
          remove(a.span);
          count_attr(el, a, "remove");
          if (!core.empty()) mapper_.removed(core);
          break;
      }
    }
    return {};
  }

  const XmlRuleSet& rules_;
  const Document& doc_;
  std::string_view body_;
  ValueMapper& mapper_;
  Counters& counters_;
  std::size_t depth_;
  bool passthrough_;
  std::int64_t time_shift_s_ = 0;
  std::vector<Edit> edits_;
  std::vector<std::uint8_t> removed_;
  std::vector<std::uint8_t> verbatim_;  // inside a passthrough EncryptedData: copied as it is
  std::vector<std::uint8_t> enc_;       // inside a kept EncryptedData subtree
  std::vector<std::uint8_t> content_replaced_;
  std::vector<std::vector<std::uint32_t>> direct_;
  std::vector<std::uint32_t> start_item_;
};

}  // namespace

std::string_view to_string(EmptyReason r) {
  switch (r) {
    case EmptyReason::malformed: return "malformed";
    case EmptyReason::encoding: return "encoding";
    case EmptyReason::limit: return "limit";
    case EmptyReason::dtd: return "dtd";
    case EmptyReason::root: return "root";
    case EmptyReason::encrypted: return "encrypted";
  }
  return "malformed";
}

Result<Outcome> BodyRewriter::rewrite(std::string_view content_type, std::string_view charset, std::string_view body,
                                      ValueMapper& mapper, std::size_t depth) {
  auto& outcomes = counters_.bodies[lower(content_type)];
  const auto emptied = [&](EmptyReason r) {
    ++outcomes[std::string(to_string(r))];
    return Outcome{false, {}, r};
  };
  const auto cs = trim_xml_space(charset);
  if (!cs.empty() && !iequal(cs, "utf-8") && !iequal(cs, "us-ascii")) return emptied(EmptyReason::encoding);
  if (depth > kMaxEmbedDepth) return emptied(EmptyReason::limit);
  auto read = readers_[depth].read(body);
  if (!read) return emptied(from_reject(read.error().reason));
  const Document& doc = **read;
  const auto& root = doc.elements[0];
  // A wholly encrypted body (feature 005, FR-016): rewritten by the xenc rules or passed through
  // when the xenc namespace has the encrypted_content disposition; emptied otherwise (003).
  bool whole_encrypted = false;
  if (root.name.ns == kXencNs && root.name.local == "EncryptedData") {
    const auto* x = rules_.ns(kXencNs);
    if (x == nullptr || x->disposition != XmlDisposition::encrypted_content) return emptied(EmptyReason::encrypted);
    whole_encrypted = true;
  }
  const auto* drule = rules_.document(content_type);
  const bool known_root =
      whole_encrypted ||
      (drule != nullptr && std::any_of(drule->roots.begin(), drule->roots.end(), [&](const XmlRoot& r) {
         return r.ns == root.name.ns && r.local == root.name.local;
       }));
  if (!known_root) return emptied(EmptyReason::root);

  Walker w(rules_, doc, body, mapper, counters_, depth, options_.passthrough, options_.time_shift_s);
  auto edits = w.run();
  if (!edits) return std::unexpected(edits.error());
  std::string out;
  out.reserve(body.size());
  std::size_t at = 0;
  for (const auto& ed : *edits) {
    out.append(body.substr(at, ed.span.off - at));
    out.append(ed.replacement);
    at = ed.span.end();
  }
  out.append(body.substr(at));
  if (options_.verify && !verify_reader_.read(out)) {
    return fail(ErrorCode::internal, "xml rewrite produced a body that is not well-formed");
  }
  ++outcomes["rewritten"];
  return Outcome{true, std::move(out), EmptyReason::malformed};
}

}  // namespace mcxanon::xml
