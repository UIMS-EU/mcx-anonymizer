// SPDX-License-Identifier: GPL-3.0-or-later
//
// Per-direction TCP stream state: SIP framing over the byte stream, an offset map
// from original to output sequence space, and a cache of released output bytes for
// retransmissions. It replaces the drop-mode renumbering of feature 001: a non-SIP payload
// keeps its length (zero mode) or contributes a delta of minus its length (drop mode).
//
// The module knows no SIP grammar: recognition, framing and rewriting are callbacks (the
// pipeline passes the SIP layer). Every bound of leads to zeroing.
//
// Offsets are 64-bit positions in a direction's data, 0 being the first byte after the SYN
// (or the first byte seen, without SYN). Each segment gets a ticket; its output (payload,
// sequence and acknowledgement numbers) is known once the direction has determined its bytes
// and, for the acknowledgement, once the reverse direction has determined the acknowledged
// bytes.
#pragma once

#include "mcxanon/error.hpp"

#include "bytes/bytes.hpp"
#include "dissect/packet.hpp"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace mcxanon::stream {

// One span of original bytes and its output. A `linear` span maps offset by offset (clamped
// to its output length); an atomic span (a replaced token) maps every inner offset to the end
// of its replacement, so the replacement goes wholly to the segment where the token starts.
struct Piece {
  std::uint64_t orig = 0;
  std::uint64_t orig_len = 0;
  std::uint64_t out = 0;
  std::uint64_t out_len = 0;
  bool linear = false;
  bool crlf = false;  // the output is the line end "\r\n" (kept where a resynchronisation starts)
};

struct RewrittenMessage {
  std::string bytes;
  std::vector<Piece> spans;  // relative to the message; cover input and output contiguously
  bool zeroed = false;       // malformed: the message is zeroed (dropped in drop mode)
};

// zero_rest (feature 007): every later byte of the direction is zeroed (or dropped
// in drop mode), as 001/FR-018 does for a payload that is not understood.
enum class FrameKind { more, message, verbatim, invalid, oversized, zero_rest };
struct Framed {
  FrameKind kind = FrameKind::more;
  // message: its length; verbatim: bytes kept as they are (keep-alives); oversized: the length
  // the message declares, which is zeroed as unframable before framing resumes (R15).
  std::size_t len = 0;
  // message (feature 007): bytes after the message that leave the output (a removed HTTP body),
  // consumed as they arrive, in both payload modes.
  std::uint64_t drop_after = 0;
};

struct SipFns {
  // R3: true when the bytes start with a SIP start line; nullopt when more bytes are needed.
  std::function<std::optional<bool>(std::string_view)> is_start;
  std::function<Framed(std::string_view)> frame;
  std::function<Result<RewrittenMessage>(std::string_view)> rewrite;
};

// A per-direction protocol session (feature 007): created by the web recogniser
// from a direction's first bytes when they are not SIP; it frames and rewrites the direction's
// messages and may keep state between them (HPACK tables, TLS record protection) and switch
// protocol at a message boundary.
class Session {
 public:
  Session() = default;
  Session(const Session&) = delete;
  Session& operator=(const Session&) = delete;
  virtual ~Session() = default;
  virtual Framed frame(std::string_view buffered) = 0;
  virtual Result<RewrittenMessage> rewrite(std::string_view message) = 0;
  // A text protocol's start line at the front of `bytes` (nullopt: more bytes are needed), used
  // to resynchronise after unframable bytes. Only called while text() is true.
  virtual std::optional<bool> resync(std::string_view bytes) = 0;
  // False for binary protocols (h2, TLS): they never resynchronise, unframable bytes zero the
  // rest of the direction.
  [[nodiscard]] virtual bool text() const = 0;
};

struct Opened {
  enum class Kind { more, none, session };
  Kind kind = Kind::none;
  std::unique_ptr<Session> session;
};

struct WebFns {
  // A direction's first bytes (resync false), or a line start while searching (resync true):
  // a session, none, or more bytes needed. `syn`: the direction's SYN was seen.
  std::function<Opened(const Bytes& direction, const Bytes& reverse, std::string_view bytes, bool syn, bool resync)>
      open;
};

struct TcpSegment {
  Bytes direction;  // key of the original direction (addresses, ports, tunnel depth)
  Bytes reverse;    // key of the opposite direction
  std::uint32_t seq = 0;
  std::uint32_t ack = 0;
  bool syn = false;
  bool fin = false;
  bool has_ack = false;
  bool fragment = false;           // inside an IP fragment: the payload is not stream data
  std::vector<std::uint32_t> sack;  // SACK block edges, in option order
  ByteView payload;                 // the captured payload bytes
  std::size_t data_len = 0;         // payload length per the IP length (>= payload.size())
  std::uint64_t ts_us = 0;
};

// The segment of the outermost non-embedded TCP layer of a dissected packet, if any.
std::optional<TcpSegment> segment_of(const Dissection& d, ByteView data, std::uint64_t ts_us);

struct TcpOutput {
  Bytes payload;
  std::uint32_t seq = 0;
  std::optional<std::uint32_t> ack;
  std::vector<std::uint32_t> sack;  // mapped SACK edges, valid when sack_known
  bool sack_known = false;          // false: the edges cannot be mapped
  bool sip = false;                                 // the direction carries SIP
};

struct TcpStats {
  std::uint64_t streams_sip = 0;
  std::uint64_t streams_msrp = 0;  // directions framed with the second protocol (feature 004)
  std::uint64_t streams_web = 0;   // directions with a web session (feature 007)
  std::uint64_t bytes_unframable = 0;
  std::uint64_t retransmissions_replayed = 0;
  std::uint64_t retransmissions_zeroed = 0;
  std::uint64_t directions_evicted = 0;
  std::uint64_t forced = 0;  // incomplete messages given up (bound, timeout, end of capture)
};

class TcpStreams {
 public:
  using Ticket = std::uint64_t;
  struct Arrival {
    Ticket ticket = 0;
    bool ready = false;
  };

  // Without `fns.is_start`, every direction is non-SIP (the feature-001 behaviour). A direction
  // whose key `is_second` accepts when it is first seen uses `second` instead (feature 004:
  // MSRP on an announced connection); its bytes are framed and rewritten by those
  // callbacks with the same offset map, bounds and zeroing rules.
  // Feature 007: a direction that is not SIP (and not the second protocol) is offered to `web`,
  // whose session then frames and rewrites it.
  TcpStreams(SipFns fns, bool drop, SipFns second = {}, std::function<bool(const Bytes&)> is_second = {},
             WebFns web = {});

  // A segment arrives. Tickets of earlier segments whose output became known are appended to
  // `became_ready`. Errors come from the rewriter (tool failures).
  Result<Arrival> segment(const TcpSegment& s, std::vector<Ticket>& became_ready);
  [[nodiscard]] bool ready(Ticket t) const;
  // Removes a ticket and returns its output; with `force`, the incomplete bytes it waits for
  // are given up (zeroed), which may make other tickets ready.
  Result<TcpOutput> take(Ticket t, bool force, std::vector<Ticket>& became_ready);

  [[nodiscard]] const TcpStats& stats() const { return stats_; }
  // Test probes.
  [[nodiscard]] std::size_t breakpoints(const Bytes& direction) const;
  [[nodiscard]] std::size_t directions() const { return dirs_.size(); }
  [[nodiscard]] std::size_t tickets() const { return segs_.size(); }

 private:
  enum class Mode { unknown, searching, sip, non_sip };
  struct Dir {
    bool init = false;
    bool syn = false;
    std::uint32_t isn = 0;
    std::uint32_t base = 0;  // sequence number of offset 0
    Mode mode = Mode::unknown;
    bool second = false;  // framed by the second protocol's callbacks
    bool sip_seen = false;
    bool search_at_zero = true;   // the buffer's first byte is a line start
    std::uint64_t next = 0;       // bytes [0, next) were received contiguously
    std::uint64_t final_end = 0;  // output determined for [0, final_end)
    std::uint64_t out_end = 0;    // output offset at final_end
    std::string buffer;           // bytes [final_end, next)
    std::map<std::uint64_t, std::string> ooo;  // received beyond a gap
    std::size_t ooo_bytes = 0;
    std::deque<Piece> pieces;     // determined spans, in order, from offset 0
    std::uint64_t floor = 0;      // spans below were merged (pruned)
    std::string cache;            // output bytes [cache_base, out_end) of a SIP direction
    std::uint64_t cache_base = 0;
    std::uint64_t searched = 0;
    std::uint64_t discard = 0;  // bytes of an oversized message still to zero
    std::uint64_t pending_unframable = 0;  // zeroed before the direction proved to be SIP
    std::optional<std::uint64_t> fin;
    Bytes key;                          // this direction
    Bytes rev;                          // the opposite direction (from its first segment)
    std::unique_ptr<Session> session;   // feature 007
    std::unique_ptr<Session> pending;   // found while searching, installed at the start line
    std::uint64_t drop = 0;             // bytes still to drop (Framed::drop_after)
    std::uint64_t acked = 0;  // highest offset the peer acknowledged
    bool ack_init = false;    // drop mode without a reverse direction (001/R8)
    std::uint32_t ack_base = 0;
    std::multimap<std::uint64_t, Ticket> waiting;  // tickets needing final_end >= key
    std::uint64_t lru = 0;
  };
  struct Seg {
    Bytes direction;
    Bytes reverse;
    bool syn = false;
    bool in_window = true;
    bool retransmission = false;
    std::uint32_t seq = 0;
    std::int64_t s = 0;
    std::int64_t e = 0;
    std::uint64_t need_own = 0;  // final_end the output needs (a FIN's own number needs none)
    std::size_t captured = 0;
    bool complete = true;
    bool has_ack = false;
    std::uint32_t ack = 0;
    std::uint32_t ack_fallback = 0;
    std::vector<std::uint32_t> sack;
    bool rev_known = false;  // the offsets below are in the reverse direction's space
    std::int64_t ack_off = 0;
    std::vector<std::int64_t> sack_off;
    std::int64_t need_rev = 0;
    bool own_done = false;
    bool done = false;
    TcpOutput out;
  };

  Result<Dir*> touch(const Bytes& key, std::vector<Ticket>& rdy);
  [[nodiscard]] static std::int64_t offset_of(const Dir& d, std::uint32_t value);
  Result<void> feed(Dir& d, std::uint64_t s, std::string_view bytes, std::vector<Ticket>& rdy);
  static void absorb(Dir& d);
  Result<void> process(Dir& d, std::vector<Ticket>& rdy);
  void search(Dir& d, std::vector<Ticket>& rdy);
  void become_sip(Dir& d, bool web = false);
  std::optional<bool> start_at(Dir& d, std::string_view b);
  static void to_searching(Dir& d);
  void filler(Dir& d, std::uint64_t len, bool unframable, std::vector<Ticket>& rdy);
  void emit_crlf(Dir& d, std::vector<Ticket>& rdy);
  void emit(Dir& d, std::uint64_t orig_len, std::uint64_t out_len, std::string_view bytes,
            bool linear, std::vector<Ticket>& rdy);
  void emit_message(Dir& d, std::uint64_t orig_len, const RewrittenMessage& m,
                    std::vector<Ticket>& rdy);
  static void add_piece(Dir& d, const Piece& p);
  void advanced(Dir& d, std::vector<Ticket>& rdy);
  Result<void> give_up(Dir& d, std::uint64_t until, std::vector<Ticket>& rdy);
  void gap_to(Dir& d, std::uint64_t to, std::vector<Ticket>& rdy);
  void prune(Dir& d);
  [[nodiscard]] bool own_met(const Seg& g) const;
  [[nodiscard]] bool rev_met(const Seg& g) const;
  void check(Ticket t, std::vector<Ticket>& rdy);
  void compute_own(Seg& g);
  void compute_rev(Seg& g);
  [[nodiscard]] std::uint64_t map(const Dir& d, std::uint64_t off) const;
  [[nodiscard]] std::uint32_t map_seq(const Dir& d, std::int64_t off, std::uint32_t orig) const;

  [[nodiscard]] const SipFns& fns(const Dir& d) const { return d.second ? second_ : fns_; }

  SipFns fns_;
  bool drop_;
  SipFns second_;
  std::function<bool(const Bytes&)> is_second_;
  WebFns web_;
  std::map<Bytes, Dir> dirs_;
  std::map<std::uint64_t, Bytes> lru_;
  std::uint64_t lru_counter_ = 0;
  std::map<Ticket, Seg> segs_;
  Ticket next_ticket_ = 1;
  TcpStats stats_;
};

}  // namespace mcxanon::stream
