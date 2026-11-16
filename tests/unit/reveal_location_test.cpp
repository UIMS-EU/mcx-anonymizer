// SPDX-License-Identifier: GPL-3.0-or-later
//
// Location composites (the XML forms of src/xml/location.hpp).
#include "reveal_fixture.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdio>
#include <string>

using namespace mcxanon;
using reveal_test::Fixture;

namespace {
std::string bits(std::uint64_t v, int n) {
  std::string o;
  for (int i = n - 1; i >= 0; --i) o.push_back(((v >> i) & 1) ? '1' : '0');
  return o;
}
std::string hexw(std::uint64_t v, int w, bool up) {
  char b[24];
  std::snprintf(b, sizeof b, up ? "%0*llX" : "%0*llx", w, static_cast<unsigned long long>(v));
  return b;
}
RevealOptions all() {
  RevealOptions o;
  o.replace_ambiguous = true;
  return o;
}
}  // namespace

TEST_CASE("location: ECGI, NCGI and TAI as PLMN digits and a bit field", "[reveal][location]") {
  Fixture f;
  const auto plmn = f.text(Category::plmn, "260001");
  const auto eci = f.binary(Category::eci, 0x0A1B2C3);
  const auto nci = f.binary64(Category::nci, 0x123456789ULL);
  const auto tac = f.binary(Category::tac, 0x0C41);
  CHECK(f.reveal("<Ecgi>" + plmn + bits(eci, 28) + "</Ecgi>") == "<Ecgi>260001" + bits(0x0A1B2C3, 28) + "</Ecgi>");
  CHECK(f.reveal("<Ncgi>" + plmn + bits(nci, 36) + "</Ncgi>") == "<Ncgi>260001" + bits(0x123456789ULL, 36) + "</Ncgi>");
  CHECK(f.reveal("<Tai>" + plmn + bits(tac, 16) + "</Tai>") == "<Tai>260001" + bits(0x0C41, 16) + "</Tai>");
}

TEST_CASE("location: hex forms keep width and letter case", "[reveal][location]") {
  Fixture f;
  const auto tac = f.binary(Category::tac, 0x0C41);
  const auto nrtac = f.binary(Category::nr_tac, 0x00AB12);
  const auto fsa = f.binary(Category::mbs_fsa, 0x0F0F0F);
  const auto sai = f.binary(Category::mbms_sai, 0x1234);
  CHECK(f.reveal("<tac>" + hexw(tac, 4, true) + "</tac>", all()) == "<tac>0C41</tac>");
  CHECK(f.reveal("<nrtac>" + hexw(nrtac, 6, false) + "</nrtac>", all()) == "<nrtac>00ab12</nrtac>");
  CHECK(f.reveal("<fsa>" + hexw(fsa, 6, true) + "</fsa>", all()) == "<fsa>0F0F0F</fsa>");
  CHECK(f.reveal("<sai>" + hexw(sai, 4, false) + "</sai>", all()) == "<sai>1234</sai>");
}

TEST_CASE("location: separate fields", "[reveal][location]") {
  Fixture f;
  f.text(Category::plmn, "260001");
  const auto eci = f.binary(Category::eci, 0x0A1B2C3);
  // The cell identity alone is a number; MCC and MNC alone are 3-digit fields and are not
  // searched (FR-015a): they stay as they are.
  CHECK(f.reveal("cell identity " + std::to_string(eci)) == "cell identity " + std::to_string(0x0A1B2C3));
  CHECK(f.reveal("MCC 338 MNC 169", all()) == "MCC 338 MNC 169");
}
