// SPDX-License-Identifier: GPL-3.0-or-later
// Reveal (feature 006) on any text against a fixed project with every kind of pseudonym: it never
// fails, any chunking gives the same output, and lookups in both directions never fail. The index is
// built once (building it per input made the target ~4x slower); the per-mapping entry points that
// build it themselves are checked against it on the first input.
#include "pseudo/mapping.hpp"
#include "pseudo/pseudonymiser.hpp"
#include "reveal/engine.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <string>
#include <string_view>

namespace {

using namespace mcxanon;

const Mapping& fixture() {
  static Mapping m;
  static bool built = false;
  if (built) return m;
  static Secret s{};
  for (std::size_t i = 0; i < s.size(); ++i) s[i] = static_cast<std::uint8_t>(i * 3 + 1);
  Pseudonymiser p(s, m);
  (void)p.text(Category::sip_user, "alice");
  (void)p.domain("mcx.example.net");
  (void)p.text(Category::call_id, "abc@mcx.example.net");
  (void)p.text(Category::opaque, "op@q.ue-1");
  (void)p.text(Category::uuid, "5f0e8c2a-3b71-4d9e-9a44-2c7b1e6f0d18");
  (void)p.text(Category::plmn, "260001");
  (void)p.text(Category::imei, "35209900176148");
  (void)p.tel("+48601234567");
  (void)p.tel("4711");
  (void)p.ipv4(0x0A000001);
  (void)p.ipv4(0xEF010203);
  (void)p.ipv6(Ipv6{0xfd, 0x12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5});
  (void)p.ipv6(Ipv6{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 2, 0, 0x5e, 0xff, 0xfe, 0, 0x53, 1});
  (void)p.ipv6(Ipv6{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0, 0x53, 1});
  (void)p.mac(Mac{0, 0, 0x5e, 0, 0x53, 1});
  (void)p.ssrc(0x3C3C3C07);
  (void)p.binary(Category::eci, 0x0A1B2C3);
  (void)p.binary(Category::tac, 0x0C41);
  (void)p.binary64(Category::nci, 0x123456789ULL);
  (void)p.vlan(214);
  built = true;
  return m;
}

const std::shared_ptr<const reveal::Index>& shared_index() {
  static const auto idx = [] {
    auto built = reveal::Index::build(fixture());
    if (!built) std::abort();
    return std::make_shared<const reveal::Index>(std::move(*built));
  }();
  return idx;
}

std::string run(std::string_view text, RevealOptions o, std::size_t step, std::size_t threshold) {
  auto r = reveal::make_revealer(shared_index(), o, threshold);
  if (!r) std::abort();
  std::string out;
  const RevealSink sink = [&](std::span<const std::uint8_t> b) -> Result<void> {
    out.append(reinterpret_cast<const char*>(b.data()), b.size());
    return {};
  };
  for (std::size_t at = 0; at < text.size(); at += step) {
    const std::size_t n = std::min(step, text.size() - at);
    if (!r->feed(std::span(reinterpret_cast<const std::uint8_t*>(text.data()) + at, n), sink)) std::abort();
  }
  if (!r->finish(sink)) std::abort();
  return out;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size == 0) return 0;
  const Mapping& m = fixture();
  RevealOptions o;
  o.replace_ambiguous = (data[0] & 1) != 0;
  o.annotate = (data[0] & 2) != 0;
  const std::string_view text(reinterpret_cast<const char*>(data) + 1, size - 1);
  // Chunks of 1-64 bytes. A processing round rescans the engine's tail (2 x 256 + 8 bytes), so the
  // threshold keeps it to ~64 rounds per input (one round per chunk made the target ~20x slower).
  const std::size_t step = 1 + (data[0] >> 2);
  const std::size_t threshold = 1 + text.size() / 64;
  const std::string whole = run(text, o, text.size() + 1, 65536);
  static bool checked_entry_points = false;
  if (!checked_entry_points) {
    checked_entry_points = true;
    const auto direct = reveal::reveal_string(m, text, o);
    if (!direct || *direct != whole) std::abort();
  }
  if (run(text, o, step, threshold) != whole) std::abort();
  if (!o.annotate && !o.replace_ambiguous && whole.size() > 64 * text.size() + 64) std::abort();
  if (text.size() <= 256) {
    std::string missing;
    if (!reveal::lookup_index(*shared_index(), text, LookupDirection::to_original, nullptr)) std::abort();
    if (!reveal::lookup_index(*shared_index(), text, LookupDirection::to_pseudonym, &missing)) std::abort();
  }
  return 0;
}
