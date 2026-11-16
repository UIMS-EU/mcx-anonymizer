// SPDX-License-Identifier: GPL-3.0-or-later
#include "capture/pcapng.hpp"
#include "policy/decide.hpp"
#include "policy/ruleset.hpp"
#include "rewrite/pcapng_meta.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>

using namespace mcxanon;

namespace {
Bytes str(const std::string& s) { return Bytes(s.begin(), s.end()); }
}  // namespace

TEST_CASE("block and option FieldIds", "[pcapng][meta]") {
  CHECK(block_fid(kPcapngNrb) == Fid::pcapng_blk_nrb);
  CHECK(block_fid(0x80000001u) == Fid::pcapng_blk_other);
  CHECK(block_fid(kPcapngCustomNoCopy) == Fid::pcapng_blk_custom);
  CHECK(option_fid(kPcapngIdb, 2) == Fid::pcapng_idb_name);
  CHECK(option_fid(kPcapngShb, 1) == Fid::pcapng_opt_comment);
  CHECK(option_fid(kPcapngEpb, 19373) == Fid::pcapng_opt_custom);
  CHECK(option_fid(kPcapngPacketObsolete, 3) == Fid::pcapng_epb_hash);
  CHECK(option_fid(kPcapngIsb, 99) == Fid::pcapng_opt_other);
  CHECK(block_key(4) == "0x00000004");
  CHECK_FALSE(block_structure_known(kPcapngNrb));
  CHECK(block_structure_known(kPcapngIsb));
}

TEST_CASE("the embedded rules keep only decoding options and collect removed values",
          "[pcapng][meta]") {
  auto rs = load_embedded_ruleset();
  REQUIRE(rs.has_value());
  const Policy policy(*rs);
  RewriteStats stats;
  MetaStats meta;
  std::vector<RemovedValue> removed;
  const std::vector<PcapngOption> idb{
      {2, str("eth0-customer-site")}, {3, str("uplink to CORE-7")},
      {4, Bytes{10, 1, 2, 3, 255, 255, 255, 0}}, {6, Bytes{0, 1, 2, 3, 4, 5}},
      {9, Bytes{9}}, {13, Bytes{4}}, {11, Bytes{0, 'h', 'o', 's', 't'}}, {0x8001, str("local")}};
  const auto kept = filter_options(kPcapngIdb, idb, Endian::little, policy, stats, meta, removed);
  REQUIRE(kept.size() == 2);
  CHECK(kept[0].code == 9);
  CHECK(kept[1].code == 13);
  CHECK(meta.removed_options["0x00000001/2"] == 1);
  CHECK(meta.removed_options["0x00000001/32769"] == 1);
  CHECK(std::find(removed.begin(), removed.end(), RemovedValue{"string", str("eth0-customer-site")}) != removed.end());
  CHECK(std::find(removed.begin(), removed.end(), RemovedValue{"ipv4", Bytes{10, 1, 2, 3}}) != removed.end());
  CHECK(std::find(removed.begin(), removed.end(), RemovedValue{"mac", Bytes{0, 1, 2, 3, 4, 5}}) != removed.end());
  CHECK(std::find(removed.begin(), removed.end(), RemovedValue{"string", str("host")}) != removed.end());
  CHECK(keep_block(kPcapngEpb, policy, stats, meta));
  CHECK_FALSE(keep_block(kPcapngDsb, policy, stats, meta));
  CHECK(meta.removed_blocks["0x0000000a"] == 1);
}

TEST_CASE("Name Resolution Block values are collected", "[pcapng][meta]") {
  // NRB: ipv4 record (10.9.8.7 + "db.internal"), end record, ns_dnsname option.
  Bytes body;
  auto put16 = [&](std::uint16_t v) { body.push_back(static_cast<std::uint8_t>(v)); body.push_back(static_cast<std::uint8_t>(v >> 8)); };
  put16(1);
  put16(4 + 12);
  for (auto b : {10, 9, 8, 7}) body.push_back(static_cast<std::uint8_t>(b));
  for (char ch : std::string("db.internal")) body.push_back(static_cast<std::uint8_t>(ch));
  body.push_back(0);
  put16(0);
  put16(0);
  const Bytes block = build_block(kPcapngNrb, body, {{2, str("resolver.corp")}}, Endian::little);
  std::vector<RemovedValue> removed;
  collect_block_values(kPcapngNrb, block, Endian::little, removed);
  CHECK(std::find(removed.begin(), removed.end(), RemovedValue{"ipv4", Bytes{10, 9, 8, 7}}) != removed.end());
  CHECK(std::find(removed.begin(), removed.end(), RemovedValue{"string", str("db.internal")}) != removed.end());
  CHECK(std::find(removed.begin(), removed.end(), RemovedValue{"string", str("resolver.corp")}) != removed.end());
}
