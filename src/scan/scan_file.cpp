// SPDX-License-Identifier: GPL-3.0-or-later
#include "mcxanon/scan.hpp"

#include "scan/matcher.hpp"
#include "scan/patterns.hpp"
#include "scan/walker/sip_vocabulary.hpp"
#include "scan/walker/xml_vocabulary.hpp"
#include "scan/walker/mikey_carriers.hpp"
#include "scan/walker/web_carriers.hpp"
#include "scan/walker/passthrough.hpp"
#include "scan/walker/walker.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <deque>
#include <memory>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <unistd.h>

namespace mcxanon::scan {

std::string_view to_string(TokenCategory c) {
  switch (c) {
    case TokenCategory::mac: return "mac";
    case TokenCategory::ipv4: return "ipv4";
    case TokenCategory::ipv6: return "ipv6";
    case TokenCategory::string: return "string";
    case TokenCategory::number: return "number";
    case TokenCategory::binary: return "binary";
    case TokenCategory::deny: return "deny";
    case TokenCategory::key: return "key";
    case TokenCategory::bytes: return "bytes";
  }
  return "string";
}

namespace {

constexpr std::size_t kMaxHits = 10000;
constexpr std::size_t kMaxCandidates = 1u << 20;
// Pseudonyms longer than this are not used to cover a match; the context read
// around a candidate is bounded by it.
constexpr std::size_t kMaxPseudonym = 1024;

// Zero bytes after a header field that join its run for FR-032a; a short
// binary pattern is under 6 bytes, so a longer tail changes nothing.
constexpr std::uint64_t kZeroTail = 8;

// Reads up to n bytes at an absolute offset of the scanned file; returns the count read.
using ContextFn = std::function<std::size_t(std::uint64_t, std::uint8_t*, std::size_t)>;

struct Candidate {
  std::size_t pattern = 0;
  std::uint64_t offset = 0;
  std::uint64_t frame = 0;
};

struct ViewHash {
  using is_transparent = void;
  std::size_t operator()(std::string_view v) const noexcept { return std::hash<std::string_view>{}(v); }
};

// Per-scan state over a shared index.
struct Engine {
  explicit Engine(const Index::Impl& index) : ix(index) {}

  ScanResult result();
  void hit(std::size_t pattern, std::uint64_t offset, std::uint64_t frame, std::string_view via = {});
  // A text-encoded match of a 4-byte token, when the index has pseudonyms.
  [[nodiscard]] bool coverable(std::size_t pattern) const;
  // Resolves the deferred candidates once the whole file has been scanned.
  void resolve(const ContextFn& context);

  const Index::Impl& ix;
  bool passthrough_ = false;
  std::vector<detail::PassthroughRange> ranges_;  // absolute file offsets (passthrough only)
  std::vector<Candidate> candidates_;
  std::vector<Hit> hits_;
  std::vector<Warning> warnings_;
  std::set<std::pair<std::uint32_t, std::uint64_t>> seen_;
  std::uint64_t suppressed_ = 0;
};

}  // namespace

struct Index::Impl {
  Impl(std::vector<Token> t, std::vector<std::string> pseudo, std::vector<std::string> byte_pseudo)
      : tokens(std::move(t)) {
    std::set<std::size_t> lengths;
    for (auto& v : pseudo) {
      if (v.size() < detail::kMinPattern || v.size() > kMaxPseudonym) continue;
      lengths.insert(v.size());
      pseudonyms.insert(std::move(v));
    }
    pseudonym_lengths.assign(lengths.begin(), lengths.end());
    std::set<std::size_t> blengths;
    for (auto& v : byte_pseudo) {
      if (v.size() < 8 || v.size() > kMaxPseudonym) continue;
      blengths.insert(v.size());
      byte_pseudonyms.insert(std::move(v));
    }
    byte_pseudonym_lengths.assign(blengths.begin(), blengths.end());
    // Equal tokens (the same address from the mapping and from the input
    // harvest) are searched once; hits carry the label of the first one.
    std::vector<std::uint32_t> unique;
    {
      std::unordered_map<std::string, bool> distinct;  // value -> scannable
      for (std::uint32_t i = 0; i < tokens.size(); ++i) {
        std::string key(1, static_cast<char>(tokens[i].category));
        key.append(tokens[i].value.begin(), tokens[i].value.end());
        // A string token equal to or contained in the standard vocabulary the output keeps is
        // not searched; deny-list entries always are.
        // Feature 003: the XML vocabulary (namespace, element and attribute names, enumeration
        // values) too, under the same rule (proposal N3).
        const std::string_view text(reinterpret_cast<const char*>(tokens[i].value.data()), tokens[i].value.size());
        const bool vocabulary = tokens[i].category == TokenCategory::string &&
                                (detail::in_sip_vocabulary(text) || detail::within_xml_vocabulary(text));
        // Feature 005: a byte string or key identifier made of one repeated octet (a zero RAND) is
        // no identity, and it matches every zeroed region of the output; not searched.
        const auto& v = tokens[i].value;
        const bool degenerate = (tokens[i].category == TokenCategory::bytes || tokens[i].category == TokenCategory::key) &&
                                !v.empty() && std::all_of(v.begin(), v.end(), [&](std::uint8_t b) { return b == v[0]; });
        auto [it, fresh] = distinct.try_emplace(std::move(key), false);
        if (fresh) {
          bool ok = false;
          it->second = !vocabulary && !degenerate && !detail::expand(tokens[i], i, ok).empty();
          if (it->second) unique.push_back(i);
        }
        scannable += it->second ? 1u : 0u;
        if (!it->second) {
          ++unscannable_by_category[std::string(to_string(tokens[i].category)) +
                                    (degenerate ? "/degenerate"
                                     : vocabulary && tokens[i].value.size() >= detail::kMinPattern ? "/vocabulary"
                                                                                                    : "/short")];
        }
      }
    }
    // Two passes keep the pattern storage at its final size (no growth spikes).
    std::size_t exact = 0;
    std::size_t folded = 0;
    std::size_t bytes = 0;
    for (const std::uint32_t i : unique) {
      bool ok = false;
      for (const auto& p : detail::expand(tokens[i], i, ok)) {
        ++(p.fold ? folded : exact);
        bytes += p.bytes.size();
      }
    }
    matcher.reserve(exact, folded, bytes);
    for (const std::uint32_t i : unique) {
      bool ok = false;
      for (const auto& p : detail::expand(tokens[i], i, ok)) matcher.add(p);
    }
    matcher.seal();
  }

  std::vector<Token> tokens;
  std::unordered_set<std::string, ViewHash, std::equal_to<>> pseudonyms;
  std::vector<std::size_t> pseudonym_lengths;  // ascending
  std::unordered_set<std::string, ViewHash, std::equal_to<>> byte_pseudonyms;  // feature 007, D21
  std::vector<std::size_t> byte_pseudonym_lengths;                            // ascending
  detail::Matcher matcher;
  std::size_t scannable = 0;
  std::map<std::string, std::uint64_t> unscannable_by_category;
};

Index::Index(std::vector<Token> tokens, std::vector<std::string> pseudonyms, std::vector<std::string> byte_pseudonyms)
    : impl_(std::make_unique<Impl>(std::move(tokens), std::move(pseudonyms), std::move(byte_pseudonyms))) {}
Index::Index(Index&&) noexcept = default;
Index& Index::operator=(Index&&) noexcept = default;
Index::~Index() = default;
std::size_t Index::size() const { return impl_->tokens.size(); }

namespace {

ScanResult Engine::result() {
  ScanResult r;
  r.tokens = ix.tokens.size();
  r.patterns = ix.matcher.size();
  r.unscannable_tokens = ix.tokens.size() - ix.scannable;
  r.unscannable_by_category = ix.unscannable_by_category;
  // Deterministic order: by file offset.
  std::stable_sort(hits_.begin(), hits_.end(), [](const Hit& a, const Hit& b) { return a.file_offset < b.file_offset; });
  r.hits = std::move(hits_);
  std::stable_sort(warnings_.begin(), warnings_.end(),
                   [](const Warning& a, const Warning& b) { return a.file_offset < b.file_offset; });
  r.warnings = std::move(warnings_);
  r.suppressed_chance_matches = suppressed_;
  return r;
}

bool Engine::coverable(std::size_t pattern) const {
  const auto c = ix.tokens[ix.matcher.token(pattern)].category;
  if (c != TokenCategory::ipv4 && c != TokenCategory::binary && c != TokenCategory::key) return false;
  // The raw 4-byte form only inside a byte-string pseudonym (D21); text forms inside a text one.
  return ix.matcher.short_binary(pattern) ? !ix.byte_pseudonyms.empty() : !ix.pseudonyms.empty();
}

// A candidate is a chance match when some pseudonym occupies [a, a + L) with
// a <= offset and offset + length <= a + L, in the bytes of the file as written.
void Engine::resolve(const ContextFn& context) {
  if (candidates_.empty()) return;
  std::vector<std::uint8_t> buf;
  for (const auto& c : candidates_) {
    const bool raw = ix.matcher.short_binary(c.pattern);
    const auto& set = raw ? ix.byte_pseudonyms : ix.pseudonyms;
    const auto& lengths = raw ? ix.byte_pseudonym_lengths : ix.pseudonym_lengths;
    const std::size_t max_len = lengths.back();
    const std::size_t len = ix.matcher.length(c.pattern);
    const std::uint64_t lo = c.offset + len > max_len ? c.offset + len - max_len : 0;
    buf.resize(static_cast<std::size_t>(c.offset - lo) + max_len);
    buf.resize(context(lo, buf.data(), buf.size()));
    const std::string_view ctx(reinterpret_cast<const char*>(buf.data()), buf.size());
    const std::size_t s = static_cast<std::size_t>(c.offset - lo);  // match start in ctx
    bool covered = false;
    for (auto it = std::lower_bound(lengths.begin(), lengths.end(), len); it != lengths.end() && !covered; ++it) {
      const std::size_t L = *it;
      for (std::size_t a = s + len > L ? s + len - L : 0; a <= s && a + L <= ctx.size(); ++a) {
        if (set.contains(ctx.substr(a, L))) {
          covered = true;
          break;
        }
      }
    }
    if (covered) {
      ++suppressed_;
    } else {
      hit(c.pattern, c.offset, c.frame);
    }
  }
  candidates_.clear();
}

// One hit per (token, offset).
void Engine::hit(std::size_t pattern, std::uint64_t offset, std::uint64_t frame, std::string_view via) {
  const std::uint32_t tok = ix.matcher.token(pattern);
  const Token& t = ix.tokens[tok];
  // The caps come before the de-duplication set, so that a token matching at every offset cannot
  // grow it without bound (seen with a zero RAND in the project mapping, feature 005).
  if (passthrough_) {
    // Feature 005 (FR-018): a match in decoded carrier bytes is reported at the carrier's offset
    // (length 1 there); a raw match needs its whole length inside the element.
    const std::uint64_t len = via.empty() ? ix.matcher.length(pattern) : 1;
    if (const auto* r = detail::covering(ranges_, offset, len)) {
      if (warnings_.size() >= kMaxHits || !seen_.insert({tok, offset}).second) return;
      warnings_.push_back(Warning{frame, offset, r->carrier, t.category});
      return;
    }
  }
  if (hits_.size() >= kMaxHits || !seen_.insert({tok, offset}).second) return;
  std::string enc(ix.matcher.encoding(pattern));
  if (!via.empty()) enc = std::string(via) + "/" + enc;
  hits_.push_back(Hit{frame, offset, std::move(enc), t.category, t.label});
}

struct Window {
  std::uint64_t begin = 0;
  std::uint64_t end = 0;
  std::uint64_t frame = 0;
  bool framed = false;                    // a record of the parsed file structure, not raw bytes
  std::vector<detail::Range> header;      // merged runs of recognised header fields
  std::vector<detail::Range> fields;      // the same runs without the zero tail (M7)
  std::vector<std::uint64_t> ipv4_slots;  // sorted
};

// FR-032a: a short binary match is a chance match when it lies entirely inside
// a run of recognised header fields and does not sit exactly on a position
// where an IPv4 address can be (a MAC or IPv6 address is guarded by its own,
// longer token). Zero bytes right after a header field (a payload the anonymiser
// zeroed) belong to the run: they carry nothing.
bool chance_match(const Window& w, std::uint64_t offset, std::uint64_t end) {
  if (std::binary_search(w.ipv4_slots.begin(), w.ipv4_slots.end(), offset)) return false;
  return std::any_of(w.header.begin(), w.header.end(),
                     [&](const detail::Range& r) { return offset >= r.begin && end <= r.end; });
}

// FR-032a extension: no packet field crosses a record boundary
// of the capture file, so a short binary match that starts in one parsed record and ends in the
// next one (the last bytes of a packet and the next record header) is a chance match. Raw bytes
// of a file the walker cannot follow have no record boundaries.
bool crosses_records(const std::deque<Window>& history, const Window& first, std::uint64_t end) {
  if (!first.framed || end <= first.end) return false;
  return std::any_of(history.begin(), history.end(),
                     [&](const Window& w) { return w.framed && end - 1 >= w.begin && end - 1 < w.end; });
}

// FR-032a extension: a short binary match that starts inside a
// recognised header field, off every value slot, and runs past that field's run into the payload
// is a chance match: a leaked value lies wholly in the payload, and the header part is a header
// value (a recomputed checksum, a length, a pseudonymised address). A match that starts in the
// zeroed payload after the header is not covered.
bool header_into_payload(const Window& w, std::uint64_t offset, std::uint64_t end) {
  if (std::binary_search(w.ipv4_slots.begin(), w.ipv4_slots.end(), offset)) return false;
  return std::any_of(w.fields.begin(), w.fields.end(),
                     [&](const detail::Range& r) { return offset >= r.begin && offset < r.end && end > r.end; });
}

Result<ScanResult> scan_stream(const detail::ReadFn& read, const ContextFn& context, const Index& index,
                               ScanOptions options = {}) {
  Engine e(index.impl());
  e.passthrough_ = options.passthrough;
  detail::StreamScanner ss(e.ix.matcher);
  std::deque<Window> history;
  const auto on_match = [&](std::size_t pattern, std::uint64_t offset) {
    const std::uint64_t end = offset + e.ix.matcher.length(pattern);
    std::uint64_t frame = 0;
    for (const auto& w : history) {
      if (offset >= w.begin && offset < w.end) {
        frame = w.frame;
        if (e.ix.matcher.short_binary(pattern) &&
            ((end <= w.end && (chance_match(w, offset, end) || header_into_payload(w, offset, end))) ||
             crosses_records(history, w, end))) {
          ++e.suppressed_;
          return;
        }
        break;
      }
    }
    // At most kMaxCandidates deferred chance-match checks; beyond that a match is a hit at once
    // (fail-closed), so memory stays bounded however often a short token matches.
    if (e.coverable(pattern) && e.candidates_.size() < kMaxCandidates) {
      e.candidates_.push_back({pattern, offset, frame});
      return;
    }
    e.hit(pattern, offset, frame);
  };
  detail::walk(read, [&](const detail::WalkRecord& r) {
    // Adjacent header fields form one run: a match straddling two fields is a chance match too.
    Window w{r.offset, r.offset + r.bytes.size(), r.frame, r.type != detail::RecordType::raw, {}, {}, r.ipv4_slots};
    std::sort(w.ipv4_slots.begin(), w.ipv4_slots.end());
    // One sort: the field runs (M7) first, then the same ranges with their zero tail (I19); the
    // tail moves only the ends, so the order by begin holds.
    auto ranges = r.header;
    std::sort(ranges.begin(), ranges.end(), [](const auto& a, const auto& b) { return a.begin < b.begin; });
    for (const auto& x : ranges) {
      if (!w.fields.empty() && x.begin <= w.fields.back().end) {
        w.fields.back().end = std::max(w.fields.back().end, x.end);
      } else {
        w.fields.push_back(x);
      }
    }
    for (auto& x : ranges) {
      std::uint64_t i = x.end;
      while (i < w.end && i - x.end < kZeroTail && r.bytes[static_cast<std::size_t>(i - r.offset)] == 0) ++i;
      x.end = i;
    }
    for (const auto& x : ranges) {
      if (!w.header.empty() && x.begin <= w.header.back().end) {
        w.header.back().end = std::max(w.header.back().end, x.end);
      } else {
        w.header.push_back(x);
      }
    }
    history.push_back(std::move(w));
    // Feature 005 (FR-018): the passthrough elements of this record, before its bytes are matched.
    if (e.passthrough_ && r.packet_length > 0 && r.packet_offset + r.packet_length <= r.bytes.size()) {
      std::vector<detail::Payload> pls;
      detail::packet_payloads(r.linktype, r.bytes.subspan(r.packet_offset, r.packet_length), pls);
      for (const auto& p : pls) {
        const std::uint64_t base = r.offset + static_cast<std::uint64_t>(p.bytes.data() - r.bytes.data());
        for (auto x : detail::passthrough_ranges(p.bytes)) {
          x.offset += base;
          e.ranges_.push_back(std::move(x));
        }
      }
    }
    ss.feed(r.bytes, on_match);
    // Feature 005 (FR-022): the MIKEY carriers of the payloads, decoded by the scanner itself,
    // are searched too. A match in decoded bytes is a hit at the carrier's offset: no chance-match
    // rule applies, since the file bytes there are the encoded form (fail-closed).
    if (r.packet_length > 0 && r.packet_offset + r.packet_length <= r.bytes.size()) {
      std::vector<detail::Payload> pls;
      detail::packet_payloads(r.linktype, r.bytes.subspan(r.packet_offset, r.packet_length), pls);
      for (const auto& p : pls) {
        for (const auto& c : detail::find_mikey_carriers(p.bytes)) {
          const std::uint64_t at = r.offset + static_cast<std::uint64_t>(p.bytes.data() - r.bytes.data()) + c.offset;
          detail::StreamScanner ds(e.ix.matcher);
          const auto on_decoded = [&](std::size_t pattern, std::uint64_t) { e.hit(pattern, at, r.frame, "mikey-decoded"); };
          ds.feed(c.decoded, on_decoded);
          ds.finish(on_decoded);
        }
        // Feature 007 (FR-024): JWT segments and Huffman-coded HPACK strings.
        for (const auto& c : detail::find_web_carriers(p.bytes)) {
          const std::uint64_t at = r.offset + static_cast<std::uint64_t>(p.bytes.data() - r.bytes.data()) + c.offset;
          detail::StreamScanner ds(e.ix.matcher);
          const auto on_decoded = [&](std::size_t pattern, std::uint64_t) { e.hit(pattern, at, r.frame, "web-decoded"); };
          ds.feed(c.decoded, on_decoded);
          ds.finish(on_decoded);
        }
      }
    }
    const std::uint64_t keep_from = r.offset + r.bytes.size() > 2 * e.ix.matcher.max_len() + 64
                                        ? r.offset + r.bytes.size() - 2 * e.ix.matcher.max_len() - 64
                                        : 0;
    while (history.size() > 1 && history.front().end < keep_from) history.pop_front();
  });
  ss.finish(on_match);
  e.resolve(context);
  return e.result();
}

}  // namespace

Result<ScanResult> scan_file(const std::filesystem::path& path, std::span<const Token> tokens) {
  return scan_file(path, Index(std::vector<Token>(tokens.begin(), tokens.end())));
}

Result<ScanResult> scan_file(const std::filesystem::path& path, const Index& index, ScanOptions options) {
  std::FILE* f = std::fopen(path.c_str(), "rb");
  if (f == nullptr) {
    return fail(ErrorCode::input, "cannot open " + path.filename().string() + ": " + std::strerror(errno));
  }
  std::setvbuf(f, nullptr, _IOFBF, 1u << 20);
  const detail::ReadFn read = [f](std::uint8_t* out, std::size_t n) { return std::fread(out, 1, n, f); };
  const ContextFn context = [f](std::uint64_t off, std::uint8_t* out, std::size_t n) -> std::size_t {
    if (::fseeko(f, static_cast<off_t>(off), SEEK_SET) != 0) return 0;
    return std::fread(out, 1, n, f);
  };
  auto r = scan_stream(read, context, index, options);
  const bool err = std::ferror(f) != 0;
  std::fclose(f);
  if (err) return fail(ErrorCode::input, "read error while scanning " + path.filename().string());
  return r;
}

Result<ScanResult> scan_fd(int fd, std::span<const Token> tokens) {
  return scan_fd(fd, Index(std::vector<Token>(tokens.begin(), tokens.end())));
}

Result<ScanResult> scan_fd(int fd, const Index& index, ScanOptions options) {
  off_t pos = 0;
  bool err = false;
  const detail::ReadFn read = [&](std::uint8_t* out, std::size_t n) -> std::size_t {
    for (;;) {
      const ssize_t got = ::pread(fd, out, n, pos);
      if (got < 0 && errno == EINTR) continue;
      if (got < 0) {
        err = true;
        return 0;
      }
      pos += got;
      return static_cast<std::size_t>(got);
    }
  };
  const ContextFn context = [&](std::uint64_t off, std::uint8_t* out, std::size_t n) -> std::size_t {
    std::size_t done = 0;
    while (done < n) {
      const ssize_t got = ::pread(fd, out + done, n - done, static_cast<off_t>(off + done));
      if (got < 0 && errno == EINTR) continue;
      if (got < 0) err = true;
      if (got <= 0) break;
      done += static_cast<std::size_t>(got);
    }
    return done;
  };
  auto r = scan_stream(read, context, index, options);
  if (err) return fail(ErrorCode::input, "read error while scanning the output");
  return r;
}

ScanResult scan_bytes(std::span<const std::uint8_t> data, std::span<const Token> tokens) {
  return scan_bytes(data, Index(std::vector<Token>(tokens.begin(), tokens.end())));
}

ScanResult scan_bytes(std::span<const std::uint8_t> data, const Index& index) {
  Engine e(index.impl());
  detail::StreamScanner ss(e.ix.matcher);
  const auto on_match = [&](std::size_t pattern, std::uint64_t offset) { e.hit(pattern, offset, 0); };
  ss.feed(data, on_match);
  ss.finish(on_match);
  return e.result();
}

}  // namespace mcxanon::scan
