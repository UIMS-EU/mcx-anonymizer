// SPDX-License-Identifier: GPL-3.0-or-later
//
// HTTP/2 frames and header blocks (RFC 9113).
#include "http/h2.hpp"
#include "http/hpack.hpp"
#include "http/message.hpp"

#include "web_env.hpp"

using namespace mcxanon;
using namespace mcxanon::http;

namespace {

std::string frame(std::uint8_t type, std::uint8_t flags, std::uint32_t stream, const std::string& payload) {
  std::string f;
  const auto n = payload.size();
  f.push_back(static_cast<char>(n >> 16));
  f.push_back(static_cast<char>(n >> 8));
  f.push_back(static_cast<char>(n));
  f.push_back(static_cast<char>(type));
  f.push_back(static_cast<char>(flags));
  for (int s = 24; s >= 0; s -= 8) f.push_back(static_cast<char>((stream >> s) & 0xFF));
  return f + payload;
}

// Feeds `in` unit by unit, as the stream engine does; returns the output and whether the rest
// was given up.
std::pair<std::string, bool> run(H2& h, std::string in) {
  std::string out;
  while (!in.empty()) {
    const auto f = h.frame(in);
    if (f.kind == stream::FrameKind::zero_rest) return {out, true};
    REQUIRE((f.kind == stream::FrameKind::message || f.kind == stream::FrameKind::verbatim));
    if (f.kind == stream::FrameKind::verbatim) {
      out += in.substr(0, f.len);
    } else {
      auto r = h.rewrite(std::string_view(in).substr(0, f.len));
      REQUIRE(r.has_value());
      out += r->zeroed ? std::string(f.len, '\0') : r->bytes;
    }
    in.erase(0, f.len);
  }
  return {out, false};
}

std::vector<HeaderField> fields_of(std::string_view out, std::size_t at) {
  const std::size_t len = (std::size_t{static_cast<unsigned char>(out[at])} << 16) |
                          (std::size_t{static_cast<unsigned char>(out[at + 1])} << 8) |
                          std::size_t{static_cast<unsigned char>(out[at + 2])};
  HpackDecoder d;
  auto f = d.decode(out.substr(at + 9, len));
  REQUIRE(f);
  return *f;
}

std::string huff_literal(const std::string& name, const std::string& value) {
  // 0000 0000 + name literal (H) + value literal (H), RFC 7541 §6.2.2
  const auto hn = huffman_encode(name);
  const auto hv = huffman_encode(value);
  std::string s(1, '\0');
  s.push_back(static_cast<char>(0x80 | hn.size()));
  s += hn;
  s.push_back(static_cast<char>(0x80 | hv.size()));
  return s + hv;
}

}  // namespace

TEST_CASE("h2: a request header block is decoded, rewritten and re-encoded", "[http][h2]") {
  web_test::Env e;
  auto conn = std::make_shared<stream::Connection>();
  H2 h(*e, conn, true, true);
  const std::string block = hpack_encode({{":method", "GET"}, {":scheme", "http"}, {":authority", "gms.example.org"},
                                          {":path", "/org.3gpp.mcptt.user-profile/users/sip%3Afrank%40example.org/index"}}) +
                            huff_literal("x-secret", "TOPSECRET-VALUE");
  // HEADERS (no END_HEADERS) + CONTINUATION, then SETTINGS with an unknown id, PING, unknown type.
  const std::string in = std::string(kPreface) + frame(1, 0x1, 1, block.substr(0, 7)) + frame(9, 0x4, 1, block.substr(7)) +
                         frame(4, 0, 0, std::string("\x00\x01\x00\x00\x10\x00\xa0\xa0\x00\x00\x00\x07", 12)) +
                         frame(6, 0, 0, "PINGDATA") + frame(0xfa, 0, 0, "unknownpayload");
  const auto [out, gave_up] = run(h, in);
  CHECK_FALSE(gave_up);
  CHECK(out.starts_with(kPreface));
  const std::size_t hd = kPreface.size();
  CHECK(out[hd + 3] == 1);
  CHECK((static_cast<unsigned char>(out[hd + 4]) & 0x4) != 0);  // END_HEADERS: one frame now
  const auto f = fields_of(out, hd);
  REQUIRE(f.size() == 4);
  CHECK(f[0].name == ":method");
  CHECK(f[2].value.find("example") == std::string::npos);
  CHECK(f[3].value.find("frank") == std::string::npos);
  CHECK(out.find("TOPSECRET") == std::string::npos);
  CHECK(out.find("PINGDATA") == std::string::npos);
  CHECK(out.find("unknownpayload") == std::string::npos);
  CHECK(out.find(std::string("\x00\x01\x00\x00\x10\x00", 6)) != std::string::npos);  // HEADER_TABLE_SIZE kept
  CHECK(e.counters.removed_unknown["http-header"]["x-secret"] == 1);
}

TEST_CASE("h2: a response body is collected, rewritten at END_STREAM; others removed", "[http][h2]") {
  web_test::Env e;
  H2 h(*e, std::make_shared<stream::Connection>(), false, false);
  const std::string doc = R"(<?xml version="1.0"?><resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists"><list>)"
                          R"(<entry uri="sip:gina@example.org"/></list></resource-lists>)";
  const std::string in = frame(1, 0x4, 1, hpack_encode({{":status", "200"}, {"content-type", "application/resource-lists+xml"},
                                                         {"content-length", std::to_string(doc.size())}})) +
                         frame(0, 0x8, 1, std::string(1, '\x02') + doc.substr(0, 40) + "PP") + frame(0, 0x1, 1, doc.substr(40)) +
                         frame(1, 0x4, 3, hpack_encode({{":status", "200"}, {"content-type", "application/octet-stream"}})) +
                         frame(0, 0x1, 3, "BINARYSECRET");
  const auto [out, gave_up] = run(h, in);
  CHECK_FALSE(gave_up);
  CHECK(out.find("gina") == std::string::npos);
  CHECK(out.find("BINARYSECRET") == std::string::npos);
  CHECK(out.find("<resource-lists") != std::string::npos);
  const auto f = fields_of(out, 0);
  for (const auto& x : f) CHECK(x.name != "content-length");
  CHECK(e.counters.bodies["application/octet-stream"]["removed:no-rule"] == 1);
}

TEST_CASE("h2: an undecodable header block zeroes the rest of the direction", "[http][h2]") {
  web_test::Env e;
  H2 h(*e, std::make_shared<stream::Connection>(), false, false);
  const std::string in = frame(1, 0x4, 1, "\xbe") + frame(4, 0, 0, "");
  auto f = h.frame(in);
  REQUIRE(f.kind == stream::FrameKind::message);
  auto r = h.rewrite(std::string_view(in).substr(0, f.len));
  REQUIRE(r.has_value());
  CHECK(r->zeroed);
  CHECK(h.frame(std::string_view(in).substr(f.len)).kind == stream::FrameKind::zero_rest);
  CHECK(e.counters.h2_undecodable == 1);
  H2 big(*e, std::make_shared<stream::Connection>(), false, false);
  CHECK(big.frame(std::string("\x7f\xff\xff\x00\x00\x00\x00\x00\x01", 9)).kind == stream::FrameKind::zero_rest);
}
