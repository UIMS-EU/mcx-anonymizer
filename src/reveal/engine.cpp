// SPDX-License-Identifier: GPL-3.0-or-later
//
// The streaming engine: chunks are appended to a buffer; candidates are produced
// on a raw and, when the buffer holds escapes, a decoded view; the resolver decides; output is
// emitted up to a tail long enough for any match to be seen whole.
#include "reveal/engine.hpp"

#include "pseudo/project_impl.hpp"
#include "reveal/candidate.hpp"
#include "reveal/render.hpp"
#include "reveal/resolve.hpp"

#include <algorithm>
#include <memory>
#include <optional>

namespace mcxanon {

struct Revealer::Impl {
  std::shared_ptr<const reveal::Index> index;
  RevealOptions options;
  RevealSummary summary;
  std::size_t threshold = 65536;
  std::size_t max_token = reveal::kMaxToken;
  std::string buf;
  std::size_t ctx = 0;  // leading bytes of buf already emitted (left context only)
  std::uint64_t line = 1;
  std::uint64_t column = 1;

  [[nodiscard]] std::size_t tail() const { return 2 * max_token + 8; }

  void advance(std::size_t from, std::size_t to) {
    for (std::size_t k = from; k < to; ++k) {
      if (buf[k] == '\n') {
        ++line;
        column = 1;
      } else {
        ++column;
      }
    }
  }

  Result<void> emit(std::string_view bytes, const RevealSink& sink) {
    summary.bytes_out += bytes.size();
    if (bytes.empty()) return {};
    return sink(std::span(reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size()));
  }

  std::string render(const reveal::Match& m, const reveal::View* decoded) const {
    const auto& c = m.cand;
    std::string orig = c.hits.front().original;
    if (c.decoded && decoded != nullptr) {
      reveal::EscapeStyle st;
      for (std::size_t k = c.start; k < c.end; ++k) {
        if (decoded->esc[k] == reveal::Escape::none) continue;
        if (st.scheme == reveal::Escape::none) st.scheme = decoded->esc[k];
        const auto src = std::string_view(buf).substr(decoded->src[k], decoded->src[k + 1] - decoded->src[k]);
        st.escaped[static_cast<unsigned char>(decoded->text[k])] = std::string(src);
        if (decoded->esc[k] == reveal::Escape::percent) {
          st.lower_hex = st.lower_hex || std::any_of(src.begin(), src.end(), [](char ch) { return ch >= 'a' && ch <= 'f'; });
        }
      }
      orig = reveal::encode_like(orig, st);
    }
    if (options.annotate) {
      orig += "\xe2\x9f\xa6";  // U+27E6
      orig += std::string_view(buf).substr(c.src_start, c.src_end - c.src_start);
      orig += "\xe2\x9f\xa7";  // U+27E7
    }
    return orig;
  }

  Result<void> process(bool final, const RevealSink& sink) {
    if (buf.size() <= ctx) return {};
    const std::size_t accept_before = final ? buf.size() : buf.size() - tail();
    const std::size_t produce_before = final ? buf.size() : buf.size() - max_token - 1;
    const reveal::View raw = reveal::make_view(buf, false);
    std::optional<reveal::View> dec;
    if (reveal::has_escapes(std::string_view(buf).substr(ctx))) dec = reveal::make_view(buf, true);

    std::vector<reveal::Candidate> cands;
    const auto collect = [&](const reveal::View& v, bool decoded) {
      // Decoded positions whose source offset lies in [ctx, produce_before).
      const auto first = static_cast<std::size_t>(
          std::lower_bound(v.src.begin(), v.src.end() - 1, static_cast<std::uint32_t>(ctx)) - v.src.begin());
      const auto limit = static_cast<std::size_t>(
          std::lower_bound(v.src.begin(), v.src.end() - 1, static_cast<std::uint32_t>(produce_before)) - v.src.begin());
      const std::size_t before = cands.size();
      reveal::exact_candidates(v, first, limit, *index, cands);
      reveal::recognised_candidates(v, first, limit, *index, cands);
      for (std::size_t k = before; k < cands.size(); ++k) {
        auto& c = cands[k];
        c.src_start = v.src[c.start];
        c.src_end = v.src[c.end];
        c.decoded = decoded;
      }
    };
    collect(raw, false);
    if (dec) collect(*dec, true);
    // Candidates of both views with the same source span are merged by the resolver.
    const auto matches = reveal::resolve(std::move(cands), accept_before, *index, options);

    std::size_t pos = ctx;
    for (const auto& m : matches) {
      const auto& c = m.cand;
      if (c.src_start < pos) continue;
      if (auto r = emit(std::string_view(buf).substr(pos, c.src_start - pos), sink); !r) return r;
      advance(pos, c.src_start);
      const std::string_view matched = std::string_view(buf).substr(c.src_start, c.src_end - c.src_start);
      if (m.replace) {
        const std::string out = render(m, dec ? &*dec : nullptr);
        if (auto r = emit(out, sink); !r) return r;
        ++summary.revealed[std::string(to_string(c.hits.front().category))];
      } else {
        if (auto r = emit(matched, sink); !r) return r;
        if (m.kind == RevealKind::ambiguous) {
          ++summary.ambiguous[m.category];
        } else {
          ++summary.unknown[m.category];
        }
        summary.candidates.push_back(RevealCandidate{m.kind, m.ambiguity, line, column, m.category,
                                                     std::string(matched),
                                                     c.hits.empty() ? std::string() : c.hits.front().original});
      }
      advance(c.src_start, c.src_end);
      pos = c.src_end;
    }
    const std::size_t upto = std::max(pos, accept_before);
    if (auto r = emit(std::string_view(buf).substr(pos, upto - pos), sink); !r) return r;
    advance(pos, upto);
    const std::size_t keep = std::min<std::size_t>(upto, 16);
    buf.erase(0, upto - keep);
    ctx = keep;
    return {};
  }
};

Revealer::Revealer(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
Revealer::Revealer(Revealer&&) noexcept = default;
Revealer& Revealer::operator=(Revealer&&) noexcept = default;
Revealer::~Revealer() = default;

namespace reveal {

Result<Revealer> make_revealer(const Mapping& mapping, RevealOptions options, std::size_t threshold) {
  try {
    auto idx = Index::build(mapping);
    if (!idx) return std::unexpected(idx.error());
    return make_revealer(std::make_shared<const Index>(std::move(*idx)), options, threshold);
  } catch (const std::exception& e) {
    return fail(ErrorCode::internal, std::string("internal error: ") + e.what());
  }
}

Result<Revealer> make_revealer(std::shared_ptr<const Index> index, RevealOptions options, std::size_t threshold) {
  try {
    if (!index) return fail(ErrorCode::internal, "internal error: no reveal index");
    auto impl = std::make_unique<Revealer::Impl>();
    impl->index = std::move(index);
    impl->options = options;
    impl->threshold = threshold;
    impl->max_token = std::max(kMaxToken, impl->index->max_pattern());
    impl->summary.not_searchable = impl->index->not_searchable();
    return Revealer(std::move(impl));
  } catch (const std::exception& e) {
    return fail(ErrorCode::internal, std::string("internal error: ") + e.what());
  }
}

Result<std::string> reveal_string(const Mapping& mapping, std::string_view text, RevealOptions options,
                                  RevealSummary* summary) {
  auto r = make_revealer(mapping, options);
  if (!r) return std::unexpected(r.error());
  std::string out;
  const RevealSink sink = [&](std::span<const std::uint8_t> b) -> Result<void> {
    out.append(reinterpret_cast<const char*>(b.data()), b.size());
    return {};
  };
  if (auto f = r->feed(std::span(reinterpret_cast<const std::uint8_t*>(text.data()), text.size()), sink); !f) {
    return std::unexpected(f.error());
  }
  if (auto f = r->finish(sink); !f) return std::unexpected(f.error());
  if (summary) *summary = r->summary();
  return out;
}

}  // namespace reveal

Result<Revealer> Revealer::create(const Project& project, RevealOptions options) {
  return reveal::make_revealer(project.impl().mapping, options);
}

Result<void> Revealer::feed(std::span<const std::uint8_t> chunk, const RevealSink& sink) {
  try {
    impl_->buf.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
    impl_->summary.bytes_in += chunk.size();
    if (impl_->buf.size() >= impl_->ctx + impl_->tail() + impl_->threshold) return impl_->process(false, sink);
    return {};
  } catch (const std::exception& e) {
    return fail(ErrorCode::internal, std::string("internal error: ") + e.what());
  }
}

Result<void> Revealer::finish(const RevealSink& sink) {
  try {
    return impl_->process(true, sink);
  } catch (const std::exception& e) {
    return fail(ErrorCode::internal, std::string("internal error: ") + e.what());
  }
}

const RevealSummary& Revealer::summary() const { return impl_->summary; }

Result<std::string> reveal_text(const Project& project, std::string_view text, RevealOptions options,
                                RevealSummary* summary) {
  return reveal::reveal_string(project.impl().mapping, text, options, summary);
}

}  // namespace mcxanon
