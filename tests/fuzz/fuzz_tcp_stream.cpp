// SPDX-License-Identifier: GPL-3.0-or-later
//
// Structure-aware fuzz target for the TCP stream layer: the input is a
// sequence of segments of one connection, each with a direction, flags, a sequence offset
// relative to the direction's next byte (so that reordering, overlaps and gaps occur), an
// acknowledgement offset and data. The real SIP framing and rewriter run behind the stream
// layer. Every ticket must resolve; forced outputs at the end must not fail.
#include "fuzz_sip_common.hpp"
#include "sip/rewrite.hpp"
#include "sip/stream_framing.hpp"
#include "stream/tcp.hpp"

#include <cstdint>
#include <cstdlib>
#include <vector>

namespace {
mcxanon::stream::Framed frame(std::string_view d) {
  const auto f = mcxanon::sip::stream_frame(d);
  using K = mcxanon::sip::StreamFrame::Kind;
  using F = mcxanon::stream::FrameKind;
  switch (f.kind) {
    case K::more: return {F::more, f.len};
    case K::message: return {F::message, f.len};
    case K::verbatim: return {F::verbatim, f.len};
    case K::oversized: return {F::oversized, f.len};
    case K::invalid: break;
  }
  return {F::invalid, 0};
}
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size < 2) return 0;
  fuzz::SipEnv env;
  const bool drop = (data[0] & 1) != 0;
  mcxanon::stream::SipFns fns{
      mcxanon::sip::stream_start, frame,
      [&](std::string_view m) -> mcxanon::Result<mcxanon::stream::RewrittenMessage> {
        auto r = mcxanon::sip::rewrite_message(m, mcxanon::sip::Transport::stream, env.ctx);
        if (!r) return std::unexpected(r.error());
        mcxanon::stream::RewrittenMessage out;
        out.zeroed = r->malformed == mcxanon::sip::Malformed::message;
        out.bytes = std::move(r->bytes);
        for (const auto& s : r->offset_map) out.spans.push_back({s.orig, s.orig_len, s.out, s.out_len, s.verbatim});
        return out;
      }};
  mcxanon::stream::TcpStreams streams(fns, drop);
  const mcxanon::Bytes key[2] = {{10, 0, 0, 1, 10, 0, 0, 2, 0x13, 0xc4, 0x9c, 0x40, 0},
                                 {10, 0, 0, 2, 10, 0, 0, 1, 0x9c, 0x40, 0x13, 0xc4, 0}};
  std::uint32_t next[2] = {1000, 900000};
  std::vector<mcxanon::stream::TcpStreams::Ticket> tickets;
  std::vector<mcxanon::stream::TcpStreams::Ticket> ready;
  std::size_t p = 1;
  std::uint64_t ts = 0;
  // Segment header: flags (bit 0 direction, 1 SYN, 2 FIN, 3 ACK, 4 truncated, 5-6 the length's
  // low bits), seq offset (int8 * 16), ack offset (int8 * 16), length (uint8 * 4).
  while (p + 4 <= size && tickets.size() < 256) {
    const std::uint8_t flags = data[p];
    const int d = flags & 1;
    const auto seq_off = static_cast<std::int32_t>(static_cast<std::int8_t>(data[p + 1])) * 16;
    const auto ack_off = static_cast<std::int32_t>(static_cast<std::int8_t>(data[p + 2])) * 16;
    std::size_t len = static_cast<std::size_t>(data[p + 3]) * 4 + ((flags >> 5) & 3u);
    p += 4;
    len = std::min(len, size - p);
    mcxanon::stream::TcpSegment s;
    s.direction = key[d];
    s.reverse = key[1 - d];
    s.seq = next[d] + static_cast<std::uint32_t>(seq_off);
    s.ack = next[1 - d] + static_cast<std::uint32_t>(ack_off);
    s.syn = (flags & 2) != 0;
    s.fin = (flags & 4) != 0;
    s.has_ack = (flags & 8) != 0;
    s.payload = mcxanon::ByteView(data + p, len);
    s.data_len = (flags & 16) != 0 ? len + 100 : len;
    s.ts_us = ts += 1000;
    p += len;
    auto a = streams.segment(s, ready);
    if (!a) continue;  // a tool failure (collision) is a valid outcome
    tickets.push_back(a->ticket);
    if (seq_off >= 0) next[d] = s.seq + static_cast<std::uint32_t>(len) + (s.syn ? 1u : 0u);
  }
  for (const auto t : tickets) {
    auto o = streams.take(t, true, ready);
    if (!o && o.error().code != mcxanon::ErrorCode::collision) std::abort();
  }
  if (streams.tickets() != 0) std::abort();
  return 0;
}
