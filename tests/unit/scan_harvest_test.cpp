// SPDX-License-Identifier: GPL-3.0-or-later
// FR-031 b: the scanner harvests sensitive input values on its own.
#include "mcxanon/scan.hpp"

#include "capture/pcapng.hpp"
#include "packet_builder.hpp"
#include "policy/ruleset.hpp"
#include "scan/walker/harvest.hpp"
#include "temp_dir.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <fstream>
#include <set>

using namespace mcxanon;
using namespace mcxanon::test;

namespace {
bool has(const std::vector<scan::Token>& ts, scan::TokenCategory c, const Bytes& v) {
  return std::any_of(ts.begin(), ts.end(), [&](const scan::Token& t) { return t.category == c && t.value == v; });
}
}  // namespace

TEST_CASE("harvest: pcapng metadata, NRB records and header addresses", "[scan][harvest]") {
  TempDir tmp;
  const Endian e = Endian::little;
  const Bytes frame = eth(kMacB, kMacA, 0x0800, udp4(kIpA, kIpB, 1, 2, {}));
  Bytes file = build_shb(e, {{1, text("shb comment here")}, {2, text("hardware-x")}});
  Bytes idb_body(8, 0);
  store16(idb_body, 0, 1, e);
  file = file + build_block(kPcapngIdb, idb_body,
                            {{2, text("eth-customer-7")}, {4, raw(kIpA) + Bytes{255, 255, 255, 0}},
                             {9, Bytes{6}}, {13, Bytes{4}}},
                            e);
  Bytes epb_body(20, 0);
  store32(epb_body, 12, static_cast<std::uint32_t>(frame.size()), e);
  store32(epb_body, 16, static_cast<std::uint32_t>(frame.size()), e);
  epb_body = epb_body + frame;
  file = file + build_block(kPcapngEpb, epb_body, {{1, text("packet comment")}, {2, Bytes{1, 0, 0, 0}}}, e);
  Bytes nrb;
  nrb = nrb + Bytes{1, 0, 16, 0} + raw(kIpB) + text("db.internal") + Bytes{0} + Bytes{0, 0, 0, 0};
  file = file + build_block(kPcapngNrb, nrb, {}, e);
  const auto p = tmp.path() / "h.pcapng";
  std::ofstream(p, std::ios::binary).write(reinterpret_cast<const char*>(file.data()),
                                           static_cast<std::streamsize>(file.size()));
  auto ts = scan::harvest_input(p);
  REQUIRE(ts.has_value());
  CHECK(has(*ts, scan::TokenCategory::string, text("shb comment here")));
  CHECK(has(*ts, scan::TokenCategory::string, text("hardware-x")));
  CHECK(has(*ts, scan::TokenCategory::string, text("eth-customer-7")));
  CHECK(has(*ts, scan::TokenCategory::string, text("packet comment")));
  CHECK(has(*ts, scan::TokenCategory::string, text("db.internal")));
  CHECK(has(*ts, scan::TokenCategory::ipv4, raw(kIpA)));
  CHECK(has(*ts, scan::TokenCategory::ipv4, raw(kIpB)));
  CHECK(has(*ts, scan::TokenCategory::mac, raw(kMacA)));
  CHECK(has(*ts, scan::TokenCategory::mac, raw(kMacB)));
  // Kept, decoding-only options are not harvested.
  CHECK_FALSE(has(*ts, scan::TokenCategory::string, Bytes{6}));
  for (const auto& t : *ts) {
    INFO(t.label);
    CHECK(t.label.rfind("input:", 0) == 0);
  }
}

TEST_CASE("harvest skips special addresses", "[scan][harvest]") {
  TempDir tmp;
  const V4 bcast{255, 255, 255, 255};
  const V4 any{0, 0, 0, 0};
  const Bytes frame = eth({0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, kMacA, 0x0800, udp4(any, bcast, 68, 67, {}));
  Bytes file = build_shb(Endian::little, {});
  Bytes idb_body(8, 0);
  store16(idb_body, 0, 1, Endian::little);
  file = file + build_block(kPcapngIdb, idb_body, {}, Endian::little);
  Bytes epb_body(20, 0);
  store32(epb_body, 12, static_cast<std::uint32_t>(frame.size()), Endian::little);
  store32(epb_body, 16, static_cast<std::uint32_t>(frame.size()), Endian::little);
  file = file + build_block(kPcapngEpb, epb_body + frame, {}, Endian::little);
  const auto p = tmp.path() / "s.pcapng";
  std::ofstream(p, std::ios::binary).write(reinterpret_cast<const char*>(file.data()),
                                           static_cast<std::streamsize>(file.size()));
  auto ts = scan::harvest_input(p);
  REQUIRE(ts.has_value());
  CHECK_FALSE(has(*ts, scan::TokenCategory::ipv4, raw(bcast)));
  CHECK_FALSE(has(*ts, scan::TokenCategory::ipv4, raw(any)));
  CHECK_FALSE(has(*ts, scan::TokenCategory::mac, Bytes(6, 0xff)));
  CHECK(has(*ts, scan::TokenCategory::mac, raw(kMacA)));
}

TEST_CASE("the harvester's option allowlist equals the rule set's kept options", "[scan][harvest]") {
  auto rs = load_embedded_ruleset();
  REQUIRE(rs.has_value());
  // FieldId -> (block type, option code) for the options the rules can keep.
  const std::vector<std::tuple<std::string, std::uint32_t, std::uint16_t>> options{
      {"pcapng.idb.tsresol", 1, 9}, {"pcapng.idb.fcslen", 1, 13}, {"pcapng.idb.tsoffset", 1, 14},
      {"pcapng.idb.speed", 1, 8}, {"pcapng.idb.name", 1, 2}, {"pcapng.epb.flags", 6, 2},
      {"pcapng.epb.dropcount", 6, 4}, {"pcapng.epb.hash", 6, 3}, {"pcapng.isb.starttime", 5, 2},
      {"pcapng.isb.endtime", 5, 3}, {"pcapng.isb.ifrecv", 5, 4}, {"pcapng.isb.ifdrop", 5, 5},
      {"pcapng.isb.filteraccept", 5, 6}, {"pcapng.isb.osdrop", 5, 7}, {"pcapng.isb.usrdeliv", 5, 8},
      {"pcapng.shb.hardware", 0x0A0D0D0A, 2}};
  for (const auto& [field, block, code] : options) {
    INFO(field);
    const Rule* r = rs->find(field);
    REQUIRE(r != nullptr);
    CHECK((r->action == Action::keep) == scan::detail::harvest_allows(block, code));
  }
}
