// SPDX-License-Identifier: GPL-3.0-or-later
#include "scan/matcher.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <random>
#include <set>
#include <string>

using namespace mcxanon;
using namespace mcxanon::scan::detail;

namespace {
Pattern pat(const std::string& t, bool fold = false, std::uint32_t token = 0) {
  return Pattern{std::vector<std::uint8_t>(t.begin(), t.end()), "text", fold, false, token};
}
std::vector<std::pair<std::size_t, std::uint64_t>> run(const Matcher& m, const std::vector<std::uint8_t>& d,
                                                       std::size_t chunk) {
  std::vector<std::pair<std::size_t, std::uint64_t>> hits;
  StreamScanner s(m);
  for (std::size_t i = 0; i < d.size(); i += chunk) {
    const std::size_t n = std::min(chunk, d.size() - i);
    s.feed(std::span(d.data() + i, n), [&](std::size_t p, std::uint64_t off) { hits.emplace_back(p, off); });
  }
  s.finish([&](std::size_t p, std::uint64_t off) { hits.emplace_back(p, off); });
  return hits;
}
}  // namespace

TEST_CASE("exact and case-folded matches with correct offsets", "[scan][matcher]") {
  const Matcher m({pat("needle"), pat("secret", true)});
  const std::string text = "xx needle yy SeCrEt zz needle";
  const std::vector<std::uint8_t> d(text.begin(), text.end());
  auto hits = run(m, d, d.size());
  std::sort(hits.begin(), hits.end(), [](const auto& a, const auto& b) { return a.second < b.second; });
  REQUIRE(hits.size() == 3);
  CHECK(hits[0] == std::make_pair(std::size_t{0}, std::uint64_t{3}));
  CHECK(hits[1] == std::make_pair(std::size_t{1}, std::uint64_t{13}));
  CHECK(hits[2] == std::make_pair(std::size_t{0}, std::uint64_t{23}));
  CHECK(run(Matcher({pat("NEEDLE")}), d, 64).empty());  // exact patterns are case-sensitive
}

TEST_CASE("matches across chunk boundaries are found exactly once", "[scan][matcher]") {
  const Matcher m({pat("boundary-token")});
  std::vector<std::uint8_t> d(1000, 'x');
  const std::string t = "boundary-token";
  std::copy(t.begin(), t.end(), d.begin() + 495);
  for (std::size_t chunk : {1u, 3u, 7u, 500u, 4096u}) {
    INFO(chunk);
    const auto hits = run(m, d, chunk);
    REQUIRE(hits.size() == 1);
    CHECK(hits[0].second == 495);
  }
}

TEST_CASE("no false negatives on random data with planted patterns", "[scan][matcher]") {
  std::mt19937 rng(42);
  std::vector<Pattern> ps;
  for (std::uint32_t i = 0; i < 300; ++i) {
    std::vector<std::uint8_t> b(4 + rng() % 12);
    for (auto& x : b) x = static_cast<std::uint8_t>(rng());
    ps.push_back(Pattern{b, "binary", false, false, i});
  }
  const Matcher m(ps);
  std::vector<std::uint8_t> d(200000);
  for (auto& x : d) x = static_cast<std::uint8_t>(rng());
  std::set<std::pair<std::size_t, std::uint64_t>> planted;
  for (int k = 0; k < 200; ++k) {
    const std::size_t p = rng() % ps.size();
    const std::size_t at = rng() % (d.size() - 20);
    std::copy(ps[p].bytes.begin(), ps[p].bytes.end(), d.begin() + static_cast<std::ptrdiff_t>(at));
    planted.insert({p, at});
  }
  const auto hits = run(m, d, 8192);
  const std::set<std::pair<std::size_t, std::uint64_t>> found(hits.begin(), hits.end());
  for (const auto& pl : planted) {
    // A later plant may overwrite an earlier one; check only intact plants.
    const auto& pb = ps[pl.first].bytes;
    if (std::equal(pb.begin(), pb.end(), d.begin() + static_cast<std::ptrdiff_t>(pl.second))) {
      CHECK(found.contains(pl));
    }
  }
}

TEST_CASE("an unsealed matcher checks every position and still finds every match", "[scan][matcher]") {
  Matcher m;
  m.add(pat("needle"));
  const std::string text = "a needle and another needle";
  const std::vector<std::uint8_t> d(text.begin(), text.end());
  CHECK(run(m, d, 5).size() == 2);
}

TEST_CASE("patterns with long constant prefixes are anchored on their selective bytes", "[scan][matcher]") {
  // IPv4-mapped IPv6 form: ten zero bytes, ff ff, then the address.
  std::vector<std::uint8_t> mapped(10, 0);
  mapped.insert(mapped.end(), {0xff, 0xff, 10, 1, 2, 3});
  const Matcher m({Pattern{mapped, "ipv4-in-ipv6", false, false, 0}});
  std::vector<std::uint8_t> d(4096, 0);  // a zeroed payload: no match, and cheap
  CHECK(run(m, d, 1000).empty());
  std::copy(mapped.begin(), mapped.end(), d.begin() + 2000);
  const auto hits = run(m, d, 1000);
  REQUIRE(hits.size() == 1);
  CHECK(hits[0].second == 2000);
}

TEST_CASE("no false negatives with a large pattern set (full-size bitmap)", "[scan][matcher]") {
  std::mt19937 rng(7);
  std::vector<Pattern> ps;
  for (std::uint32_t i = 0; i < 100000; ++i) {
    std::vector<std::uint8_t> b(4);
    for (auto& x : b) x = static_cast<std::uint8_t>(rng());
    ps.push_back(Pattern{b, "binary", false, true, i});
  }
  const Matcher m(ps);
  std::vector<std::uint8_t> d(1 << 16);
  for (auto& x : d) x = static_cast<std::uint8_t>(rng());
  std::set<std::pair<std::uint32_t, std::uint64_t>> planted;
  for (std::uint32_t k = 0; k < 64; ++k) {
    const std::uint32_t idx = static_cast<std::uint32_t>(rng() % ps.size());
    const std::uint64_t at = 16 + std::uint64_t{k} * 1000;
    std::copy(ps[idx].bytes.begin(), ps[idx].bytes.end(), d.begin() + static_cast<std::ptrdiff_t>(at));
    planted.insert({idx, at});
  }
  std::set<std::pair<std::uint32_t, std::uint64_t>> found;
  for (const auto& [p, off] : run(m, d, 4096)) found.insert({m.token(p), off});
  for (const auto& x : planted) CHECK(found.count(x) == 1);
}
