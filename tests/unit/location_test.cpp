// SPDX-License-Identifier: GPL-3.0-or-later
//
// The Location and List of Locations fields (TS 24.380 §8.2.3.21, §8.2.3.22; FR-020).
#include "media_env.hpp"

#include <algorithm>

using namespace mcxanon;
using namespace mcxanon::test;

namespace {
Bytes location_out(MediaEnv& e, std::uint8_t id, const Bytes& value) {
  auto r = media::rewrite_rtcp(app("MCPT", 2, 1, {field(id, value)}), false, e.env);
  REQUIRE(r.has_value());
  REQUIRE(r->has_value());
  const auto f = fields_of(**r);
  REQUIRE(f.size() == 1);
  CHECK(f[0].first == id);
  return f[0].second;
}

// TS 24.008-style BCD PLMN: MCC2|MCC1, MNC3|MCC3, MNC2|MNC1 (MNC3 = F for a 2-digit MNC).
std::string plmn_digits(const Bytes& b, std::size_t off) {
  std::string d;
  d += static_cast<char>('0' + (b[off] & 0x0F));
  d += static_cast<char>('0' + (b[off] >> 4));
  d += static_cast<char>('0' + (b[off + 1] & 0x0F));
  d += static_cast<char>('0' + (b[off + 2] & 0x0F));
  d += static_cast<char>('0' + (b[off + 2] >> 4));
  if ((b[off + 1] >> 4) != 0x0F) d += static_cast<char>('0' + (b[off + 1] >> 4));
  return d;
}

const Bytes kPlmn{0x62, 0xF2, 0x10};  // 262-01
}  // namespace

TEST_CASE("ECGI: PLMN and ECI are pseudonymised per component, the spare bits kept", "[media][location]") {
  MediaEnv e;
  Bytes v{1};
  v.insert(v.end(), kPlmn.begin(), kPlmn.end());
  put32(v, 0x31234567);  // high 4 bits 0x3 are spare
  const auto out = location_out(e, 19, v);
  REQUIRE(out.size() == v.size());
  CHECK(out[0] == 1);
  CHECK((out[2] >> 4) == 0x0F);  // 2-digit MNC: filler kept
  const auto digits = plmn_digits(out, 1);
  CHECK(digits.size() == 5);
  CHECK(digits == *e.mapper.text(Category::plmn, "26201"));
  const auto word = get32(out, 4);
  CHECK((word >> 28) == 0x3);
  CHECK((word & 0x0FFFFFFF) == *e.mapper.binary(Category::eci, 0x1234567));
}

TEST_CASE("Tracking Area and PLMN ID share the PLMN pseudonym", "[media][location]") {
  MediaEnv e;
  Bytes ta{2};
  ta.insert(ta.end(), kPlmn.begin(), kPlmn.end());
  ta.push_back(0x12);
  ta.push_back(0x34);
  const auto o1 = location_out(e, 19, ta);
  CHECK(o1[0] == 2);
  CHECK(((o1[4] << 8) | o1[5]) == static_cast<int>(*e.mapper.binary(Category::tac, 0x1234)));
  Bytes pl{3};
  pl.insert(pl.end(), kPlmn.begin(), kPlmn.end());
  const auto o2 = location_out(e, 19, pl);
  CHECK(plmn_digits(o1, 1) == plmn_digits(o2, 1));
  CHECK(plmn_digits(o2, 1) != "26201");
}

TEST_CASE("MBMS service area and MBSFN area use their own categories", "[media][location]") {
  MediaEnv e;
  const auto sai = location_out(e, 19, Bytes{4, 0x00, 0x2A});
  CHECK(((sai[1] << 8) | sai[2]) == static_cast<int>(*e.mapper.binary(Category::mbms_sai, 42)));
  const auto mbsfn = location_out(e, 19, Bytes{5, 0x07});
  CHECK(mbsfn[1] == *e.mapper.binary(Category::mbsfn_area, 7));
}

TEST_CASE("coordinates and altitude are zeroed; the type is kept", "[media][location]") {
  MediaEnv e;
  const auto geo = location_out(e, 19, Bytes{6, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC});
  CHECK(geo == Bytes{6, 0, 0, 0, 0, 0, 0});
  const auto alt = location_out(e, 19, Bytes{7, 0x81, 0x23});
  CHECK(alt == Bytes{7, 0, 0});
  CHECK(location_out(e, 19, Bytes{0}) == Bytes{0});  // Not provided
}

TEST_CASE("an unknown location type is zeroed with its value", "[media][location]") {
  MediaEnv e;
  const auto out = location_out(e, 19, Bytes{9, 0xDE, 0xAD, 0xBE, 0xEF});
  CHECK(out == Bytes{0, 0, 0, 0, 0});
}

TEST_CASE("a malformed PLMN or a short value is zeroed", "[media][location]") {
  MediaEnv e;
  CHECK(location_out(e, 19, Bytes{3, 0xAB, 0xF2, 0x10}) == Bytes{0, 0, 0, 0});  // not BCD
  CHECK(location_out(e, 19, Bytes{1, 0x62, 0xF2}) == Bytes{0, 0, 0});         // too short
}

TEST_CASE("List of Locations: each item per type; an unknown item zeroes the rest (A6)", "[media][location]") {
  MediaEnv e;
  Bytes v{3};  // three locations
  v.push_back(3);
  v.insert(v.end(), kPlmn.begin(), kPlmn.end());
  v.insert(v.end(), {6, 1, 2, 3, 4, 5, 6});
  v.insert(v.end(), {9, 0xDE, 0xAD});  // unknown type: the item size is unknown
  const auto out = location_out(e, 20, v);
  REQUIRE(out.size() == v.size());
  CHECK(out[0] == 3);
  CHECK(out[1] == 3);
  CHECK(plmn_digits(out, 2) == *e.mapper.text(Category::plmn, "26201"));
  CHECK(Bytes(out.begin() + 5, out.begin() + 12) == Bytes{6, 0, 0, 0, 0, 0, 0});
  CHECK(std::all_of(out.begin() + 12, out.end(), [](std::uint8_t b) { return b == 0; }));
}
