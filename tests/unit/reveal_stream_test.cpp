// SPDX-License-Identifier: GPL-3.0-or-later
//
// Streaming (FR-002, FR-003, FR-008).
#include "reveal_fixture.hpp"

#include <catch2/catch_test_macros.hpp>

#include <memory>
#include <string>

using namespace mcxanon;
using reveal_test::Fixture;

namespace {
struct Run {
  std::string out;
  RevealSummary summary;
};

Run run_chunked(const Mapping& m, std::string_view in, const std::vector<std::size_t>& cuts) {
  auto r = reveal::make_revealer(m, {}, 1);  // process as soon as the tail allows
  REQUIRE(r.has_value());
  Run run;
  const RevealSink sink = [&](std::span<const std::uint8_t> b) -> Result<void> {
    run.out.append(reinterpret_cast<const char*>(b.data()), b.size());
    return {};
  };
  std::size_t at = 0;
  for (auto c : cuts) {
    REQUIRE(r->feed(std::span(reinterpret_cast<const std::uint8_t*>(in.data()) + at, c - at), sink).has_value());
    at = c;
  }
  REQUIRE(r->feed(std::span(reinterpret_cast<const std::uint8_t*>(in.data()) + at, in.size() - at), sink).has_value());
  REQUIRE(r->finish(sink).has_value());
  run.summary = r->summary();
  return run;
}
}  // namespace

TEST_CASE("stream: any chunking gives the same output and summary", "[reveal][stream]") {
  Fixture f;
  const auto u = f.user("alice");
  const auto h = f.host("mcx.example.net");
  const auto c = f.text(Category::call_id, "4HHkVRn12z2Cx-SQ");
  const auto ip = reveal_test::dotted(f.ipv4(0x0A000001));
  const auto ss = f.ssrc(0x3C3C3C07);
  // A filler longer than the engine's tail, so that the input is processed in several rounds.
  std::string filler;
  while (filler.size() < 1200) filler += "lorem ipsum 12:34 ";
  std::string in = filler + "INVITE sip:" + u + "@" + h + " SIP/2.0\r\nCall-ID: " + c + "\r\nVia: SIP/2.0/UDP " + ip +
                   ":5060\r\nSSRC " + reveal_test::hex32(ss) + " (" + std::to_string(ss) + ")";
  in.push_back('\0');
  in += "\xff\xfe tail without newline";
  const std::string want = filler + "INVITE sip:alice@mcx.example.net SIP/2.0\r\nCall-ID: 4HHkVRn12z2Cx-SQ\r\nVia: "
                           "SIP/2.0/UDP 10.0.0.1:5060\r\nSSRC 0x3c3c3c07 (1010580487)" +
                           std::string(1, '\0') + "\xff\xfe tail without newline";
  const auto whole = run_chunked(f.mapping, in, {});
  CHECK(whole.out == want);
  CHECK(whole.summary.bytes_in == in.size());
  CHECK(whole.summary.bytes_out == want.size());
  for (std::size_t cut = 1; cut < in.size(); ++cut) {
    const auto r = run_chunked(f.mapping, in, {cut});
    REQUIRE(r.out == want);
    REQUIRE(r.summary.revealed == whole.summary.revealed);
  }
  std::vector<std::size_t> ones;
  for (std::size_t i = 1; i < in.size(); ++i) ones.push_back(i);
  CHECK(run_chunked(f.mapping, in, ones).out == want);
}

TEST_CASE("stream: positions are counted across chunks", "[reveal][stream]") {
  Fixture f;
  f.binary(Category::tac, 0x0C41);
  const auto tac = std::to_string(f.binary(Category::tac, 0x0C41));
  std::string filler;
  while (filler.size() < 1200) filler += "lorem ipsum\n";
  const std::string in = "line one\r\nline two\nxx " + tac + "\n" + filler + "yy " + tac + "\n";
  const auto a = run_chunked(f.mapping, in, {});
  const auto b = run_chunked(f.mapping, in, {12, 700});
  for (const auto* r : {&a, &b}) {
    REQUIRE(r->summary.candidates.size() == 2);
    CHECK(r->summary.candidates[0].line == 3);
    CHECK(r->summary.candidates[0].column == 4);
    CHECK(r->summary.candidates[1].line == 104);
    CHECK(r->summary.candidates[1].column == 4);
  }
}

TEST_CASE("stream: a token longer than the tail passes unmatched", "[reveal][stream]") {
  Fixture f;
  const auto u = f.user("alice");
  const std::string run(2 * reveal::kMaxToken, 'a');
  const std::string in = run + u + run + " " + u;
  CHECK(f.reveal(in) == run + u + run + " alice");
}

TEST_CASE("stream: a shared index gives the same reveal and lookups as the mapping", "[reveal][stream]") {
  Fixture f;
  const auto u = f.user("alice");
  const auto ip = reveal_test::dotted(f.ipv4(0x0A000001));
  const std::string in = "From: sip:" + u + "@x.invalid via " + ip + "\n";
  auto built = reveal::Index::build(f.mapping);
  REQUIRE(built.has_value());
  const auto idx = std::make_shared<const reveal::Index>(std::move(*built));
  for (int round = 0; round < 2; ++round) {  // two revealers over the same index
    auto r = reveal::make_revealer(idx, {}, 1);
    REQUIRE(r.has_value());
    std::string out;
    const RevealSink sink = [&](std::span<const std::uint8_t> b) -> Result<void> {
      out.append(reinterpret_cast<const char*>(b.data()), b.size());
      return {};
    };
    REQUIRE(r->feed(std::span(reinterpret_cast<const std::uint8_t*>(in.data()), in.size()), sink).has_value());
    REQUIRE(r->finish(sink).has_value());
    CHECK(out == f.reveal(in));
  }
  for (const std::string& v : {u, ip, std::string("alice"), std::string("10.0.0.1")}) {
    for (auto d : {LookupDirection::to_original, LookupDirection::to_pseudonym}) {
      auto a = reveal::lookup_mapping(f.mapping, v, d, nullptr);
      auto b = reveal::lookup_index(*idx, v, d, nullptr);
      REQUIRE(a.has_value());
      REQUIRE(b.has_value());
      REQUIRE(a->size() == b->size());
      for (std::size_t i = 0; i < a->size(); ++i) {
        CHECK((*a)[i].category == (*b)[i].category);
        CHECK((*a)[i].query == (*b)[i].query);
        CHECK((*a)[i].counterpart == (*b)[i].counterpart);
      }
    }
  }
  CHECK_FALSE(reveal::make_revealer(std::shared_ptr<const reveal::Index>{}, {}, 1).has_value());
}
