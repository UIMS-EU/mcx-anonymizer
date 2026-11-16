// SPDX-License-Identifier: GPL-3.0-or-later
//
// The TCP stream layer with per-direction sessions (feature 007): a web recogniser
// opens a session from a direction's first bytes when they are not SIP; the session frames and
// rewrites, may remove the bytes after a message (drop_after) and may give up on the rest of the
// direction (zero_rest). The sessions here are stand-ins; the real ones are tested in the http
// and tls tests.
#include "stream/tcp.hpp"

#include <catch2/catch_test_macros.hpp>

#include <memory>
#include <string>
#include <vector>

using namespace mcxanon;
using namespace mcxanon::stream;

namespace {

const Bytes kC2S{10, 0, 0, 1, 10, 0, 0, 2, 0x9c, 0x40, 0x00, 0x50, 0};
const Bytes kS2C{10, 0, 0, 2, 10, 0, 0, 1, 0x00, 0x50, 0x9c, 0x40, 0};

std::optional<bool> starts(std::string_view d, std::string_view prefix) {
  if (d.size() < prefix.size()) return prefix.starts_with(d) ? std::nullopt : std::optional<bool>(false);
  return d.starts_with(prefix);
}

Framed sip_frame(std::string_view d) {
  const auto e = d.find("<EOM>\r\n");
  if (e == std::string_view::npos) return {FrameKind::more, 0};
  return {FrameKind::message, e + 7};
}

Result<RewrittenMessage> keep(std::string_view m) {
  RewrittenMessage r;
  r.bytes.assign(m);
  r.spans.push_back(Piece{0, m.size(), 0, m.size(), true});
  return r;
}

SipFns sip() { return SipFns{[](std::string_view d) { return starts(d, "INVITE "); }, sip_frame, keep}; }

// A text protocol: "PUT <n>\r\n" followed by n body bytes that leave the output; "GET\r\n" is
// rewritten to "GOT\r\n"; "BAD" makes the session give up on the rest; "SWAP\r\n" switches to
// a second mode where every message is one byte rewritten to '#'.
struct Toy : Session {
  bool swapped = false;
  int frames = 0;
  Framed frame(std::string_view d) override {
    ++frames;
    if (swapped) return d.empty() ? Framed{FrameKind::more, 0} : Framed{FrameKind::message, 1};
    if (d.starts_with("BAD")) return {FrameKind::zero_rest, 0};
    const auto e = d.find("\r\n");
    if (e == std::string_view::npos) return {FrameKind::more, 0};
    Framed f{FrameKind::message, e + 2};
    if (d.starts_with("PUT ")) f.drop_after = std::stoul(std::string(d.substr(4, e - 4)));
    return f;
  }
  Result<RewrittenMessage> rewrite(std::string_view m) override {
    RewrittenMessage r;
    if (swapped) {
      r.bytes = "#";
    } else if (m == "GET\r\n") {
      r.bytes = "GOT\r\n";
    } else if (m == "SWAP\r\n") {
      r.bytes.assign(m);
      swapped = true;
    } else {
      r.bytes = "PUT 0\r\n";
    }
    return r;
  }
  std::optional<bool> resync(std::string_view b) override {
    if (swapped) return false;
    return starts(b, "GET\r\n");
  }
  [[nodiscard]] bool text() const override { return !swapped; }
};

int opened = 0;
WebFns web() {
  return WebFns{[](const Bytes&, const Bytes&, std::string_view b, bool, bool) -> Opened {
    const auto r = starts(b, b.starts_with("P") ? "PUT " : b.starts_with("G") ? "GET\r\n" : "SWAP\r\n");
    if (!r) return {Opened::Kind::more, nullptr};
    if (!*r) return {Opened::Kind::none, nullptr};
    ++opened;
    return {Opened::Kind::session, std::make_unique<Toy>()};
  }};
}

TcpSegment segment(const Bytes& dir, const Bytes& rev, std::uint32_t seq, std::uint32_t ack, const std::string& p,
                   bool syn = false) {
  TcpSegment s;
  s.direction = dir;
  s.reverse = rev;
  s.seq = seq;
  s.ack = ack;
  s.syn = syn;
  s.has_ack = !syn;
  s.payload = ByteView(reinterpret_cast<const std::uint8_t*>(p.data()), p.size());
  s.data_len = p.size();
  return s;
}

std::string text(const Bytes& b) { return std::string(b.begin(), b.end()); }

struct Run {
  explicit Run(bool drop) : t(sip(), drop, {}, {}, web()) {
    REQUIRE(t.segment(segment(kC2S, kS2C, 100, 0, "", true), rdy)->ready);
    REQUIRE(t.segment(segment(kS2C, kC2S, 900, 101, "", true), rdy)->ready);
  }
  TcpOutput send(std::uint32_t seq, const std::string& p) {
    auto a = t.segment(segment(kC2S, kS2C, seq, 901, p), rdy);
    REQUIRE(a.has_value());
    auto o = t.take(a->ticket, true, rdy);
    REQUIRE(o.has_value());
    return *o;
  }
  TcpStreams t;
  std::vector<TcpStreams::Ticket> rdy;
};

}  // namespace

TEST_CASE("a web session opens on a non-SIP direction and rewrites its messages", "[stream][session]") {
  for (const bool drop : {false, true}) {
    opened = 0;
    Run r(drop);
    const auto o = r.send(101, "GET\r\nGET\r\n");
    CHECK(text(o.payload) == "GOT\r\nGOT\r\n");
    CHECK(opened == 1);
    CHECK(r.t.stats().streams_web == 1);
    CHECK(r.t.stats().streams_sip == 0);
  }
}

TEST_CASE("drop_after removes the body bytes in both payload modes and maps the sequence numbers",
          "[stream][session]") {
  for (const bool drop : {false, true}) {
    Run r(drop);
    const std::string head = "PUT 10\r\n";
    const auto o1 = r.send(101, head + "01234");                                  // head + half body
    const auto o2 = r.send(101 + static_cast<std::uint32_t>(head.size()) + 5, "56789GET\r\n");
    CHECK(text(o1.payload) == "PUT 0\r\n");
    CHECK(text(o2.payload) == "GOT\r\n");
    CHECK(o2.seq == 101 + 7);  // the dropped body takes no sequence space
  }
}

TEST_CASE("a lost segment inside a dropped body does not disturb the framing", "[stream][session]") {
  Run r(false);
  const std::string head = "PUT 10\r\n";
  const auto o1 = r.send(101, head + "0123");
  // bytes 4..7 of the body are never captured
  const auto o3 = r.send(101 + static_cast<std::uint32_t>(head.size()) + 8, "89GET\r\n");
  CHECK(text(o1.payload) == "PUT 0\r\n");
  CHECK(text(o3.payload) == "GOT\r\n");
  CHECK(o3.seq == 101 + 7);
}

TEST_CASE("zero_rest zeroes every later byte of the direction", "[stream][session]") {
  Run r(false);
  const auto o1 = r.send(101, "GET\r\nBAD stuff");
  const auto o2 = r.send(101 + 14, "GET\r\n");
  CHECK(text(o1.payload) == std::string("GOT\r\n") + std::string(9, '\0'));
  CHECK(o2.payload == Bytes(5, 0));
}

TEST_CASE("a session switches mode at a message boundary", "[stream][session]") {
  Run r(false);
  const auto o = r.send(101, "SWAP\r\nabc");
  CHECK(text(o.payload) == "SWAP\r\n###");
}

TEST_CASE("a text session resynchronises on its own start line after unframable bytes", "[stream][session]") {
  Run r(false);
  // A gap makes the bytes after it mid-message: the session's resync finds the next start line.
  (void)r.send(101, "GET\r\n");
  const auto o = r.send(101 + 5 + 3, "xx\r\nGET\r\n");
  CHECK(text(o.payload) == std::string(2, '\0') + "\r\nGOT\r\n");
}

TEST_CASE("SIP keeps priority over the web recogniser", "[stream][session]") {
  opened = 0;
  Run r(false);
  const auto o = r.send(101, "INVITE x<EOM>\r\n");
  CHECK(text(o.payload) == "INVITE x<EOM>\r\n");
  CHECK(opened == 0);
  CHECK(r.t.stats().streams_sip == 1);
}
