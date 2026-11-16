// SPDX-License-Identifier: GPL-3.0-or-later
//
// DER, X.509 rewriting, hellos and records.
#include "pipeline/mapper_adapter.hpp"
#include "policy/sip_rules.hpp"
#include "policy/tls_rules.hpp"
#include "pseudo/pseudonymiser.hpp"
#include "tls/der.hpp"
#include "tls/handshake.hpp"
#include "tls/session.hpp"
#include "tls/x509.hpp"

#include <catch2/catch_test_macros.hpp>

#include <optional>
#include <string>

using namespace mcxanon;
using namespace mcxanon::tls;

namespace {

Secret secret() {
  Secret s{};
  for (std::size_t i = 0; i < s.size(); ++i) s[i] = static_cast<std::uint8_t>(i * 3 + 9);
  return s;
}

struct Fx {
  Fx() {
    sctx.emplace(sip::Context{sip_rules, mapper, {}, sip_counters});
    env.emplace(Env{rules, *sctx, counters});
  }
  SipRuleSet sip_rules = *load_embedded_sip_ruleset();
  TlsRuleSet rules = *load_embedded_tls_ruleset();
  Secret key = secret();
  Mapping mapping;
  Pseudonymiser p{key, mapping};
  MapperAdapter mapper{p};
  sip::SipCounters sip_counters;
  Counters counters;
  std::optional<sip::Context> sctx;
  std::optional<Env> env;
};

std::string tlv(std::uint8_t tag, const std::string& c) {
  std::string out(1, static_cast<char>(tag));
  if (c.size() < 0x80) {
    out.push_back(static_cast<char>(c.size()));
  } else {
    out.push_back('\x82');
    out.push_back(static_cast<char>(c.size() >> 8));
    out.push_back(static_cast<char>(c.size() & 0xFF));
  }
  return out + c;
}
const std::string kCn = std::string("\x06\x03\x55\x04\x03", 5);  // OID 2.5.4.3
const std::string kC = std::string("\x06\x03\x55\x04\x06", 5);   // OID 2.5.4.6

std::string name(const std::string& cn) {
  return tlv(0x30, tlv(0x31, tlv(0x30, kC + tlv(0x13, "PL"))) + tlv(0x31, tlv(0x30, kCn + tlv(0x0c, cn))));
}

std::string cert() {
  const std::string alg = tlv(0x30, tlv(0x06, std::string("\x2a\x86\x48\xce\x3d\x04\x03\x02", 8)));
  const std::string spki = tlv(0x30, tlv(0x30, tlv(0x06, std::string("\x2a\x86\x48\xce\x3d\x02\x01", 7)) +
                                                    tlv(0x06, std::string("\x2a\x86\x48\xce\x3d\x03\x01\x07", 8))) +
                                         tlv(0x03, std::string("\x00\x04", 2) + std::string(64, '\x55')));
  const std::string san = tlv(0x30, tlv(0x06, std::string("\x55\x1d\x11", 3)) +
                                        tlv(0x04, tlv(0x30, tlv(0x82, "srv.secret-corp.example") + tlv(0x81, "alice@secret-corp.example"))));
  const std::string tbs = tlv(0x30, tlv(0xa0, tlv(0x02, "\x02")) + tlv(0x02, "\x7e\x11\x22\x33\x44") + alg + name("Secret CA") +
                                        tlv(0x30, tlv(0x17, "260101000000Z") + tlv(0x17, "271231235959Z")) +
                                        name("srv.secret-corp.example") + spki + tlv(0xa3, tlv(0x30, san)));
  return tlv(0x30, tbs + alg + tlv(0x03, std::string(1, '\0') + std::string(70, '\x66')));
}

}  // namespace

TEST_CASE("der: round trip, minimal lengths, refusals", "[tls][der]") {
  const auto c = cert();
  auto n = der::parse(c);
  REQUIRE(n);
  CHECK(der::write(*n) == c);
  CHECK_FALSE(der::parse(std::string("\x30\x80\x00\x00", 4)));        // indefinite length
  CHECK_FALSE(der::parse(std::string("\x04\x81\x05hello", 8)));      // non-minimal length
  CHECK_FALSE(der::parse(std::string("\x04\x05hel", 5)));            // truncated
  CHECK_FALSE(der::parse(std::string(40, '\x30') + std::string(40, '\0')));
  CHECK(der::oid_text(std::string("\x55\x04\x03", 3)) == "2.5.4.3");
}

TEST_CASE("x509: names, SAN and serial pseudonymised, key and signature zeroed", "[tls][x509]") {
  Fx f;
  auto r = rewrite_certificate(cert(), *f.env);
  REQUIRE(r.has_value());
  REQUIRE(r->has_value());
  const auto& out = **r;
  CHECK(out.find("secret-corp") == std::string::npos);
  CHECK(out.find("Secret CA") == std::string::npos);
  CHECK(out.find("alice") == std::string::npos);
  CHECK(out.find(std::string(1, '\x13') + std::string(1, '\x02') + "PL") != std::string::npos);  // country kept
  CHECK(out.find(std::string(64, '\x55')) == std::string::npos);
  CHECK(out.find(std::string(70, '\x66')) == std::string::npos);
  CHECK(out.find("260101000000Z") != std::string::npos);  // validity kept
  CHECK(out.find("\x11\x22\x33\x44") == std::string::npos);
  auto n = der::parse(out);
  REQUIRE(n);  // still DER
  CHECK(f.counters.certificates_rewritten == 1);
  // Deterministic and consistent: the same certificate gives the same output.
  CHECK(**rewrite_certificate(cert(), *f.env) == out);
  CHECK_FALSE(rewrite_certificate("garbage", *f.env)->has_value());
}

TEST_CASE("tls hello: SNI mapped, random kept in length, HRR constant kept", "[tls][hello]") {
  Fx f;
  stream::Connection conn;
  const std::string host = "kms.secret-corp.example";
  std::string sni = std::string(1, '\0') + std::string(1, static_cast<char>(host.size() >> 8)) +
                    static_cast<char>(host.size()) + host;
  sni = std::string(1, static_cast<char>(sni.size() >> 8)) + static_cast<char>(sni.size()) + sni;
  const std::string ext = std::string("\x00\x00", 2) + static_cast<char>(sni.size() >> 8) + static_cast<char>(sni.size()) + sni +
                          std::string("\xfe\x0d\x00\x04XYZW", 8);
  const std::string body = std::string("\x03\x03", 2) + std::string(32, '\x42') + std::string(1, '\0') +
                           std::string("\x00\x02\x13\x01\x01\x00", 6) + static_cast<char>(ext.size() >> 8) +
                           static_cast<char>(ext.size()) + ext;
  auto r = rewrite_hello(body, true, conn, *f.env);
  REQUIRE(r.has_value());
  CHECK(r->find("secret-corp") == std::string::npos);
  CHECK(r->find(".invalid") != std::string::npos);
  CHECK(r->find(std::string(32, '\x42')) == std::string::npos);
  CHECK(r->find("XYZW") == std::string::npos);  // unknown extension zeroed
  CHECK(r->find(std::string("\xfe\x0d\x00\x04", 4)) != std::string::npos);
  CHECK(f.counters.server_names == 1);
}

TEST_CASE("tls session: records framed, protected content zeroed, bad record zeroes the rest", "[tls][record]") {
  Fx f;
  auto s = open_tls_session(*f.env, std::make_shared<stream::Connection>());
  const std::string app = std::string("\x17\x03\x03\x00\x05", 5) + "HELLO";
  auto fr = s->frame(app);
  REQUIRE(fr.kind == stream::FrameKind::message);
  auto r = s->rewrite(app);
  REQUIRE(r.has_value());
  CHECK(r->bytes == std::string("\x17\x03\x03\x00\x05", 5) + std::string(5, '\0'));
  CHECK(s->frame(std::string("\x17\x03\x03\x00", 4)).kind == stream::FrameKind::more);
  CHECK(s->frame(std::string("\x63\x03\x03\x00\x01X", 6)).kind == stream::FrameKind::zero_rest);
  CHECK(is_record_start(std::string("\x16\x03\x01\x00\x10", 5)) == true);
  CHECK(is_record_start("GET /") == false);
}
