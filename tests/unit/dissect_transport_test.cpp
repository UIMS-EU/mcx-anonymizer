// SPDX-License-Identifier: GPL-3.0-or-later
#include "packet_builder.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace mcxanon;
using namespace mcxanon::test;

TEST_CASE("TCP options: MSS, window scale, SACK, timestamps, EOL", "[dissect][tcp]") {
  const Bytes opts = Bytes{2, 4, 0x05, 0xB4} + Bytes{1, 3, 3, 7} + Bytes{4, 2, 8, 10} +
                     b32(1) + b32(2) + Bytes{5, 10} + b32(100) + b32(200) + Bytes{0, 0};
  REQUIRE(opts.size() == 32);
  const auto d = dissect_checked(kLinkRaw, tcp4(kIpA, kIpB, 40000, 80, 1, 0, 0x02, opts, {}));
  CHECK(find(d, Fid::tcp_opt_mss) != nullptr);
  CHECK(find(d, Fid::tcp_opt_nop) != nullptr);
  CHECK(find(d, Fid::tcp_opt_wscale) != nullptr);
  CHECK(find(d, Fid::tcp_opt_sackperm) != nullptr);
  CHECK(find(d, Fid::tcp_opt_ts) != nullptr);
  CHECK(find(d, Fid::tcp_opt_sack) != nullptr);
  CHECK(find(d, Fid::tcp_opt_eol) != nullptr);
  CHECK(find(d, Fid::tcp_opt_padding) != nullptr);
  CHECK(find(d, Fid::payload_l7) == nullptr);
}

TEST_CASE("TCP options: MD5 signature, TCP-AO, unknown", "[dissect][tcp]") {
  const Bytes opts = Bytes{19, 18} + Bytes(16, 0x77) + Bytes{29, 6, 1, 2, 3, 4} +
                     Bytes{77, 4, 9, 9} + Bytes{1, 1, 1, 1};
  REQUIRE(opts.size() == 32);
  const auto d = dissect_checked(kLinkRaw, tcp4(kIpA, kIpB, 40000, 80, 1, 0, 0x02, opts, {}));
  REQUIRE(find(d, Fid::tcp_opt_md5_value) != nullptr);
  CHECK(find(d, Fid::tcp_opt_md5_value)->length == 16);
  REQUIRE(find(d, Fid::tcp_opt_ao_value) != nullptr);
  CHECK(find(d, Fid::tcp_opt_ao_value)->length == 4);
  CHECK(find(d, Fid::tcp_opt_other) != nullptr);
  CHECK(has_unknown(d, "tcp_option", 77));
}

TEST_CASE("TCP payload and malformed options", "[dissect][tcp]") {
  SECTION("payload after options") {
    const auto d = dissect_checked(kLinkRaw, tcp4(kIpA, kIpB, 1, 2, 5, 6, 0x18, {}, text("GET /")));
    CHECK(find(d, Fid::payload_l7)->length == 5);
  }
  SECTION("option overrunning the header") {
    const auto d = dissect_checked(kLinkRaw, tcp4(kIpA, kIpB, 1, 2, 5, 6, 0x18, Bytes{8, 30, 0, 0}, {}));
    CHECK(find(d, Fid::tcp_opt_malformed)->length == 4);
  }
  SECTION("data offset below 5") {
    Bytes p = tcp4(kIpA, kIpB, 1, 2, 5, 6, 0x18, {}, {});
    p[20 + 12] = 0x40;
    CHECK(dissect_checked(kLinkRaw, p).parse_failure);
  }
}

TEST_CASE("UDP length bounds the payload", "[dissect][udp]") {
  Bytes p = udp4(kIpA, kIpB, 1, 2, text("abc"));
  const auto d = dissect_checked(kLinkRaw, p);
  CHECK(find(d, Fid::udp_len) != nullptr);
  CHECK(find(d, Fid::payload_l7)->length == 3);
}

TEST_CASE("SCTP INIT parameters", "[dissect][sctp]") {
  const Bytes params = param(5, raw(kIpA)) + param(6, raw(kIp6A)) + param(11, text("host.example")) +
                       param(12, b16(5) + b16(6));
  const Bytes init = chunk(1, 0, b32(0x11) + b32(65535) + b16(10) + b16(10) + b32(1) + params);
  const auto d = dissect_checked(kLinkRaw, ipv4(kIpA, kIpB, 132, sctp(2905, 2905, 0, init)));
  CHECK(find(d, Fid::sctp_init_fixed) != nullptr);
  CHECK(find(d, Fid::sctp_param_ipv4) != nullptr);
  CHECK(find(d, Fid::sctp_param_ipv6) != nullptr);
  CHECK(find(d, Fid::sctp_param_other)->length == 12);  // host name
  CHECK(find(d, Fid::sctp_param_keep) != nullptr);      // supported address types
}

TEST_CASE("SCTP DATA, SACK, AUTH, ASCONF and unknown chunks", "[dissect][sctp]") {
  const Bytes data = chunk(0, 3, b32(1) + b16(0) + b16(0) + b32(46) + text("DIAMETER-REQUEST"));
  const Bytes sack = chunk(3, 0, b32(1) + b32(65535) + b16(0) + b16(0));
  const Bytes auth = chunk(15, 0, b16(1) + b16(1) + Bytes(20, 0x99));
  const Bytes asconf = chunk(0xC1, 0, b32(7) + param(5, raw(kIpA)) +
                                          param(0xC001, b32(9) + param(5, raw(kIpB))));
  const Bytes unk = chunk(0x55, 0, text("??"));
  const auto d = dissect_checked(kLinkRaw,
                                 ipv4(kIpA, kIpB, 132, sctp(1, 2, 3, data + sack + auth + asconf + unk)));
  CHECK(find(d, Fid::sctp_data_fixed) != nullptr);
  CHECK(find(d, Fid::payload_l7)->length == 16);
  CHECK(find(d, Fid::sctp_sack_body) != nullptr);
  CHECK(find(d, Fid::sctp_auth_hmac)->length == 20);
  CHECK(count(d, Fid::sctp_param_ipv4) == 2);
  CHECK(find(d, Fid::sctp_asconf_corr) != nullptr);
  CHECK(has_unknown(d, "sctp_chunk", 0x55));
  CHECK(find(d, Fid::sctp_padding) != nullptr);
}

TEST_CASE("SCTP chunk shorter than its header is a parse failure", "[dissect][sctp]") {
  const Bytes bad = Bytes{0, 0, 0, 2};
  const auto d = dissect_checked(kLinkRaw, ipv4(kIpA, kIpB, 132, sctp(1, 2, 3, bad)));
  CHECK(d.parse_failure);
}
