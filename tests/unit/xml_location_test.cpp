// SPDX-License-Identifier: GPL-3.0-or-later
//
// User Story 3 composites: ECGI,
// NCGI, TAI and the 5GS TAC are split into components that map with the 004 binary categories
// (so an ECI has one pseudonym in an XML location report and in a floor control Location field),
// and are written back with the same number of binary or hex digits; decimal MBMS SAI and MBSFN
// area IDs are written without padding; the PLMN is always 6 digits.
#include "pipeline/mapper_adapter.hpp"
#include "pseudo/pseudonymiser.hpp"
#include "xml/categories.hpp"

#include <catch2/catch_test_macros.hpp>

#include <bitset>
#include <cctype>
#include <string>

using namespace mcxanon;

namespace {
Secret secret() {
  Secret s{};
  for (std::size_t i = 0; i < s.size(); ++i) s[i] = static_cast<std::uint8_t>(i * 13 + 9);
  return s;
}

struct Fixture {
  SipRuleSet rules = *load_embedded_sip_ruleset();
  Secret key = secret();
  Mapping mapping;
  Pseudonymiser p{key, mapping};
  MapperAdapter mapper{p};
  sip::SipCounters counters;
  sip::Context ctx{rules, mapper, {}, counters};

  std::string map(XmlCategory c, std::string_view v) {
    auto r = xml::map_category(c, v, ctx);
    REQUIRE(r.has_value());
    REQUIRE(r->has_value());
    return **r;
  }
  bool fits(XmlCategory c, std::string_view v) {
    auto r = xml::map_category(c, v, ctx);
    REQUIRE(r.has_value());
    return r->has_value();
  }
};

template <std::size_t N>
std::string bits(std::uint64_t v) {
  return std::bitset<N>(v).to_string();
}
}  // namespace

TEST_CASE("ecgi: PLMN (6 digits) and the 28-bit ECI map like the 004 location field", "[xml][location]") {
  Fixture f;
  const std::uint32_t eci = 0x1A2B3C4;
  const auto out = f.map(XmlCategory::ecgi, "262010" + bits<28>(eci));
  REQUIRE(out.size() == 34);
  CHECK(out.substr(0, 6) == *f.mapper.text(Category::plmn, "262010"));
  CHECK(out.substr(6) == bits<28>(*f.mapper.binary(Category::eci, eci)));
  CHECK_FALSE(f.fits(XmlCategory::ecgi, "26201" + bits<28>(eci)));        // 5-digit PLMN
  CHECK_FALSE(f.fits(XmlCategory::ecgi, "262010" + bits<27>(eci) + "2"));  // not binary
}

TEST_CASE("ncgi: the 36-bit NCI keeps its width", "[xml][location]") {
  Fixture f;
  const std::uint64_t nci = 0x9ABCDEF12ull;
  const auto out = f.map(XmlCategory::ncgi, "262010" + bits<36>(nci));
  REQUIRE(out.size() == 42);
  CHECK(out.substr(0, 6) == *f.mapper.text(Category::plmn, "262010"));
  CHECK(out.substr(6) == bits<36>(*f.p.binary64(Category::nci, nci)));
  CHECK(out.substr(6).find_first_not_of("01") == std::string::npos);
}

TEST_CASE("tai and the 5GS TAC: 16 binary digits, 4 hex (tac) or 6 hex (nr_tac) with case kept", "[xml][location]") {
  Fixture f;
  const auto tai = f.map(XmlCategory::tai, "262010" + bits<16>(0x1234));
  CHECK(tai.substr(6) == bits<16>(*f.mapper.binary(Category::tac, 0x1234)));
  const auto t4 = f.map(XmlCategory::tac_bin, "1234");
  CHECK(std::stoul(t4, nullptr, 16) == *f.mapper.binary(Category::tac, 0x1234));
  CHECK(t4.size() == 4);
  const auto t6 = f.map(XmlCategory::tac_bin, "aBcDeF");
  REQUIRE(t6.size() == 6);
  CHECK(std::stoul(t6, nullptr, 16) == *f.mapper.binary(Category::nr_tac, 0xABCDEF));
  for (std::size_t i = 0; i < 6; ++i) {
    if (std::isalpha(static_cast<unsigned char>(t6[i])) != 0) {
      CHECK(static_cast<bool>(std::islower(static_cast<unsigned char>(t6[i]))) ==
            static_cast<bool>(std::islower(static_cast<unsigned char>("aBcDeF"[i]))));
    }
  }
  CHECK_FALSE(f.fits(XmlCategory::tac_bin, "12345"));
}

TEST_CASE("decimal SAI and MBSFN area, hex MBS FSA, PLMN alone", "[xml][location]") {
  Fixture f;
  CHECK(f.map(XmlCategory::mbms_sai, "4660") == std::to_string(*f.mapper.binary(Category::mbms_sai, 4660)));
  CHECK_FALSE(f.fits(XmlCategory::mbms_sai, "65536"));
  CHECK(f.map(XmlCategory::mbsfn_area, "17") == std::to_string(*f.mapper.binary(Category::mbsfn_area, 17)));
  CHECK_FALSE(f.fits(XmlCategory::mbsfn_area, "256"));
  const auto fsa = f.map(XmlCategory::mbs_fsa, "00ff10");
  CHECK(std::stoul(fsa, nullptr, 16) == *f.mapper.binary(Category::mbs_fsa, 0x00FF10));
  CHECK(fsa.size() == 6);
  CHECK(f.map(XmlCategory::plmn, "262010") == *f.mapper.text(Category::plmn, "262010"));
  CHECK_FALSE(f.fits(XmlCategory::plmn, "26201x"));
}

TEST_CASE("usage-document SAI in hex and the floor request SSRC and reference in decimal", "[xml][location]") {
  Fixture f;
  const auto sai = f.map(XmlCategory::mbms_sai_hex, "12aB");
  CHECK(sai.size() == 4);
  CHECK(std::stoul(sai, nullptr, 16) == *f.mapper.binary(Category::mbms_sai, 0x12AB));
  CHECK(f.map(XmlCategory::ssrc, "305419896") == std::to_string(*f.mapper.ssrc(305419896)));
  CHECK(f.map(XmlCategory::fc_ref, "4660") == std::to_string(*f.mapper.binary(Category::fc_ref, 4660)));
  CHECK_FALSE(f.fits(XmlCategory::ssrc, "4294967296"));
  CHECK_FALSE(f.fits(XmlCategory::mbms_sai_hex, "12345"));
}
