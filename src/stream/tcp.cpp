// SPDX-License-Identifier: GPL-3.0-or-later
#include "stream/tcp.hpp"

#include "bytes/endian.hpp"
#include "stream/limits.hpp"

#include <algorithm>
#include <iterator>

namespace mcxanon::stream {

// --- segment extraction --------------------------------------------------------------------

std::optional<TcpSegment> segment_of(const Dissection& d, ByteView data, std::uint64_t ts_us) {
  int ti = -1;
  for (std::size_t i = 0; i < d.layers.size(); ++i) {
    const Layer& l = d.layers[i];
    if (l.kind == LayerKind::tcp && !l.embedded && l.parent_ip >= 0 && l.end >= l.offset + 20) {
      ti = static_cast<int>(i);
      break;
    }
  }
  if (ti < 0) return std::nullopt;
  const Layer& l = d.layers[static_cast<std::size_t>(ti)];
  const Layer& ip = d.layers[static_cast<std::size_t>(l.parent_ip)];
  const bool v6 = ip.kind == LayerKind::ipv6;
  const std::size_t a_off = ip.offset + (v6 ? 8 : 12);
  const std::size_t a_len = v6 ? 16 : 4;
  if (a_off + 2 * a_len > data.size()) return std::nullopt;

  TcpSegment s;
  const auto put = [&](Bytes& k, std::size_t off, std::size_t len) {
    k.insert(k.end(), data.begin() + static_cast<std::ptrdiff_t>(off),
             data.begin() + static_cast<std::ptrdiff_t>(off + len));
  };
  put(s.direction, a_off, 2 * a_len);
  put(s.direction, l.offset, 4);
  s.direction.push_back(static_cast<std::uint8_t>(l.depth));
  put(s.reverse, a_off + a_len, a_len);
  put(s.reverse, a_off, a_len);
  put(s.reverse, l.offset + 2, 2);
  put(s.reverse, l.offset, 2);
  s.reverse.push_back(static_cast<std::uint8_t>(l.depth));

  s.seq = be32(data, l.offset + 4);
  s.ack = be32(data, l.offset + 8);
  const std::uint8_t flags = data[l.offset + 13];
  s.syn = (flags & 0x02u) != 0;
  s.fin = (flags & 0x01u) != 0;
  s.has_ack = (flags & 0x10u) != 0;
  const std::size_t doff = static_cast<std::size_t>(data[l.offset + 12] >> 4) * 4u;
  const std::size_t declared = ip.declared_end > l.offset ? ip.declared_end : l.end;
  s.data_len = declared > l.offset + doff ? declared - l.offset - doff : 0;
  const std::size_t pstart = std::min(l.end, l.offset + doff);
  s.payload = data.subspan(pstart, std::min(l.end - pstart, s.data_len));
  for (std::size_t i = 0; i < static_cast<std::size_t>(ti); ++i) {
    const Layer& x = d.layers[i];
    if ((x.kind == LayerKind::ipv4 || x.kind == LayerKind::ipv6) && (x.fragment_first || x.fragment_nonfirst)) {
      s.fragment = true;
    }
  }
  for (const auto& f : d.fields) {
    if (f.layer != ti || f.id != Fid::tcp_opt_sack) continue;
    for (std::size_t p = f.offset + 2; p + 4 <= f.offset + f.length; p += 4) s.sack.push_back(be32(data, p));
  }
  s.ts_us = ts_us;
  return s;
}

// --- direction table -----------------------------------------------------------------------

TcpStreams::TcpStreams(SipFns fns, bool drop, SipFns second, std::function<bool(const Bytes&)> is_second,
                       WebFns web)
    : fns_(std::move(fns)), drop_(drop), second_(std::move(second)), is_second_(std::move(is_second)),
      web_(std::move(web)) {}

std::int64_t TcpStreams::offset_of(const Dir& d, std::uint32_t value) {
  const std::uint32_t at = d.base + static_cast<std::uint32_t>(d.next);
  return static_cast<std::int64_t>(d.next) + static_cast<std::int32_t>(value - at);
}

Result<TcpStreams::Dir*> TcpStreams::touch(const Bytes& key, std::vector<Ticket>& rdy) {
  auto it = dirs_.find(key);
  if (it == dirs_.end()) {
    if (dirs_.size() >= kMaxTcpDirections && !lru_.empty()) {
      // R15: the least recently active direction is evicted; its pending bytes are zeroed.
      const Bytes victim = lru_.begin()->second;
      Dir& v = dirs_.at(victim);
      if (auto r = give_up(v, ~std::uint64_t{0}, rdy); !r) return std::unexpected(r.error());
      while (!v.waiting.empty()) {
        const Ticket t = v.waiting.begin()->second;
        v.waiting.erase(v.waiting.begin());
        auto g = segs_.find(t);
        if (g == segs_.end() || g->second.done) continue;
        if (!g->second.own_done) compute_own(g->second);
        compute_rev(g->second);
        g->second.done = true;
        rdy.push_back(t);
      }
      lru_.erase(v.lru);
      dirs_.erase(victim);
      ++stats_.directions_evicted;
    }
    it = dirs_.emplace(key, Dir{}).first;
    it->second.second = is_second_ && second_.is_start && is_second_(key);
    it->second.key = key;
  } else {
    lru_.erase(it->second.lru);
  }
  it->second.lru = ++lru_counter_;
  lru_.emplace(it->second.lru, key);
  return &it->second;
}

std::size_t TcpStreams::breakpoints(const Bytes& direction) const {
  const auto it = dirs_.find(direction);
  return it == dirs_.end() ? 0 : it->second.pieces.size();
}

// --- arrival ---------------------------------------------------------------------------------

Result<TcpStreams::Arrival> TcpStreams::segment(const TcpSegment& s, std::vector<Ticket>& rdy) {
  auto dp = touch(s.direction, rdy);
  if (!dp) return std::unexpected(dp.error());
  Dir& d = **dp;
  if (d.rev.empty()) d.rev = s.reverse;
  if (s.syn && !d.syn) {
    d.syn = true;
    d.isn = s.seq;
  }
  if (!d.init) {
    d.init = true;
    d.base = s.syn ? s.seq + 1 : s.seq;
  }
  const Ticket t = next_ticket_++;
  Seg& g = segs_[t];
  g.direction = s.direction;
  g.reverse = s.reverse;
  g.syn = s.syn;
  g.seq = s.seq;
  g.s = offset_of(d, s.seq + (s.syn ? 1u : 0u));
  g.e = g.s + static_cast<std::int64_t>(s.data_len);
  g.captured = std::min(s.payload.size(), s.data_len);
  g.complete = g.captured == s.data_len && !s.fragment;
  g.in_window = g.s >= 0 && g.s <= static_cast<std::int64_t>(d.next + kMaxHeldBytes);
  g.retransmission = s.data_len > 0 && g.s < static_cast<std::int64_t>(d.next);
  if (s.fin && !d.fin && g.in_window) d.fin = static_cast<std::uint64_t>(g.e);

  if (g.in_window && s.data_len > 0) {
    const auto us = static_cast<std::uint64_t>(g.s);
    const auto ue = static_cast<std::uint64_t>(g.e);
    if (s.fragment || g.captured < s.data_len) {
      // The stream bytes are not all in the capture: the range is a gap (R14).
      if (ue > d.next) {
        if (auto r = give_up(d, ue, rdy); !r) return std::unexpected(r.error());
        if (d.next < ue) gap_to(d, ue, rdy);
      }
    } else {
      const std::string_view bytes(reinterpret_cast<const char*>(s.payload.data()), g.captured);
      if (auto r = feed(d, us, bytes, rdy); !r) return std::unexpected(r.error());
    }
  }

  // The acknowledgement and SACK edges live in the reverse direction's sequence space.
  if (s.has_ack) {
    g.has_ack = true;
    g.ack = s.ack;
    g.sack = s.sack;
    auto r = dirs_.find(s.reverse);
    if (r != dirs_.end() && r->second.init) {
      Dir& rv = r->second;
      g.rev_known = true;
      g.ack_off = offset_of(rv, s.ack);
      std::int64_t need = g.ack_off;
      for (const auto edge : s.sack) {
        g.sack_off.push_back(offset_of(rv, edge));
        need = std::max(need, g.sack_off.back());
      }
      g.need_rev = std::clamp<std::int64_t>(need, 0, static_cast<std::int64_t>(rv.next));
      if (g.ack_off > 0 && static_cast<std::uint64_t>(g.ack_off) > rv.acked) {
        rv.acked = std::min<std::uint64_t>(static_cast<std::uint64_t>(g.ack_off), rv.final_end);
        prune(rv);
      }
    } else if (drop_) {
      Dir& own = dirs_.at(s.direction);
      if (!own.ack_init) {
        own.ack_init = true;
        own.ack_base = s.ack;
      }
      g.ack_fallback = own.ack_base;
    } else {
      g.ack_fallback = s.ack;
    }
  }

  Dir& own = dirs_.at(s.direction);
  if (g.in_window) {
    g.need_own = static_cast<std::uint64_t>(g.e);
    if (own.fin && g.need_own > *own.fin) g.need_own = *own.fin;
  }
  if (!g.own_done && own_met(g)) compute_own(g);
  if (!g.own_done) own.waiting.emplace(g.need_own, t);
  if (g.own_done && rev_met(g)) {
    compute_rev(g);
    g.done = true;
    return Arrival{t, true};
  }
  if (!rev_met(g)) dirs_.at(s.reverse).waiting.emplace(static_cast<std::uint64_t>(g.need_rev), t);
  return Arrival{t, false};
}

bool TcpStreams::ready(Ticket t) const {
  const auto it = segs_.find(t);
  return it != segs_.end() && it->second.done;
}

Result<TcpOutput> TcpStreams::take(Ticket t, bool force, std::vector<Ticket>& rdy) {
  auto it = segs_.find(t);
  if (it == segs_.end()) return fail(ErrorCode::internal, "unknown TCP segment ticket");
  if (!it->second.done) {
    if (!force) return fail(ErrorCode::internal, "TCP segment output taken before it is known");
    ++stats_.forced;
    const Seg& g = it->second;
    if (auto d = dirs_.find(g.direction); d != dirs_.end() && !g.own_done) {
      if (auto r = give_up(d->second, g.need_own, rdy); !r) {
        return std::unexpected(r.error());
      }
    }
    it = segs_.find(t);
    if (it == segs_.end()) return fail(ErrorCode::internal, "TCP segment ticket lost");
    if (!it->second.done && it->second.rev_known) {
      if (auto r = dirs_.find(it->second.reverse); r != dirs_.end()) {
        if (auto x = give_up(r->second, static_cast<std::uint64_t>(it->second.need_rev), rdy); !x) {
          return std::unexpected(x.error());
        }
      }
    }
    it = segs_.find(t);
    if (it == segs_.end()) return fail(ErrorCode::internal, "TCP segment ticket lost");
    Seg& g2 = it->second;
    if (!g2.own_done) compute_own(g2);
    if (!g2.done) {
      compute_rev(g2);
      g2.done = true;
    }
  }
  TcpOutput out = std::move(it->second.out);
  segs_.erase(it);
  return out;
}

// --- byte stream -----------------------------------------------------------------------------

Result<void> TcpStreams::feed(Dir& d, std::uint64_t s, std::string_view bytes, std::vector<Ticket>& rdy) {
  if (s + bytes.size() <= d.next) return {};  // a retransmission of known bytes
  if (s > d.next) {
    if (d.mode == Mode::non_sip) {
      filler(d, s - d.next, false, rdy);  // non-SIP bytes need no ordering
      d.next = s;
    } else if (d.ooo_bytes + bytes.size() > kMaxOutOfOrderBytes) {
      if (auto r = give_up(d, s, rdy); !r) return std::unexpected(r.error());
      if (d.next < s) gap_to(d, s, rdy);
      if (s + bytes.size() <= d.next) return {};
    } else {
      auto [it, fresh] = d.ooo.emplace(s, std::string(bytes));
      if (fresh) {
        d.ooo_bytes += bytes.size();
      } else if (it->second.size() < bytes.size()) {
        d.ooo_bytes += bytes.size() - it->second.size();
        it->second.assign(bytes);
      }
      return {};
    }
  }
  if (s < d.next) bytes.remove_prefix(d.next - s);
  d.buffer.append(bytes);
  d.next += bytes.size();
  absorb(d);
  return process(d, rdy);
}

void TcpStreams::absorb(Dir& d) {
  while (!d.ooo.empty()) {
    auto it = d.ooo.begin();
    if (it->first > d.next) break;
    const std::uint64_t end = it->first + it->second.size();
    if (end > d.next) {
      d.buffer.append(std::string_view(it->second).substr(d.next - it->first));
      d.next = end;
    }
    d.ooo_bytes -= it->second.size();
    d.ooo.erase(it);
  }
}

void TcpStreams::become_sip(Dir& d, bool web) {
  d.mode = Mode::sip;
  if (!d.sip_seen) {
    d.sip_seen = true;
    ++(web ? stats_.streams_web : d.second ? stats_.streams_msrp : stats_.streams_sip);
    d.cache_base = d.out_end;
  }
  stats_.bytes_unframable += d.pending_unframable;
  d.pending_unframable = 0;
}

std::optional<bool> TcpStreams::start_at(Dir& d, std::string_view b) {
  if (d.session) return d.session->resync(b);
  std::optional<bool> r = fns(d).is_start ? fns(d).is_start(b) : std::optional<bool>(false);
  if (!r || *r || d.second || !web_.open) return r;
  auto o = web_.open(d.key, d.rev, b, d.syn, true);
  if (o.kind == Opened::Kind::more) return std::nullopt;
  if (o.kind != Opened::Kind::session) return false;
  d.pending = std::move(o.session);
  return true;
}

void TcpStreams::to_searching(Dir& d) {
  if (d.mode == Mode::non_sip) return;
  if (d.session && !d.session->text()) {
    d.mode = Mode::non_sip;  // binary protocols never resynchronise
    return;
  }
  d.mode = Mode::searching;
  d.search_at_zero = false;
}

Result<void> TcpStreams::process(Dir& d, std::vector<Ticket>& rdy) {
  for (;;) {
    if (d.buffer.empty()) return {};
    if (d.discard > 0) {
      // An oversized message: zeroed to its declared end, whose last two bytes become a line
      // end so that a decoder resynchronises on the next message too.
      if (drop_ || d.discard > 2) {
        const std::uint64_t n = std::min<std::uint64_t>(d.buffer.size(), drop_ ? d.discard : d.discard - 2);
        filler(d, n, true, rdy);
        d.buffer.erase(0, n);
        d.discard -= n;
        continue;
      }
      if (d.buffer.size() < d.discard) return {};
      if (d.discard == 2) emit_crlf(d, rdy);
      else filler(d, d.discard, true, rdy);
      d.buffer.erase(0, d.discard);
      d.discard = 0;
      continue;
    }
    if (d.drop > 0) {
      // Feature 007: bytes after a message that leave the output (a removed body).
      const std::uint64_t n = std::min<std::uint64_t>(d.buffer.size(), d.drop);
      emit(d, n, 0, {}, true, rdy);
      d.buffer.erase(0, n);
      d.drop -= n;
      continue;
    }
    switch (d.mode) {
      case Mode::unknown: {
        std::optional<bool> r = false;
        if (fns(d).is_start) {
          // Keep-alive CRLFs (RFC 5626 §3.5.1) may precede the first message.
          std::string_view first = d.buffer;
          while (first.starts_with("\r\n")) first.remove_prefix(2);
          if (first.empty() || first == "\r") {
            if (d.buffer.size() < kMaxStreamMessageBytes) return {};
            first = d.buffer;
          }
          r = fns(d).is_start(first);
          if (!r) {
            if (d.buffer.size() < kMaxStreamMessageBytes) return {};
            r = false;
          }
        }
        if (*r) {
          become_sip(d);
          continue;
        }
        if (web_.open && !d.second) {
          // Feature 007: HTTP/1.1, h2 or TLS.
          auto o = web_.open(d.key, d.rev, d.buffer, d.syn, false);
          if (o.kind == Opened::Kind::more && d.buffer.size() < kMaxStreamMessageBytes) return {};
          if (o.kind == Opened::Kind::session) {
            d.session = std::move(o.session);
            become_sip(d, true);
            continue;
          }
        }
        if (!fns(d).is_start) {
          d.mode = Mode::non_sip;
          continue;
        }
        // R14: with the SYN seen, the first payload decides; without it, search.
        d.mode = d.syn ? Mode::non_sip : Mode::searching;
        continue;
      }
      case Mode::non_sip:
        filler(d, d.buffer.size(), false, rdy);
        d.buffer.clear();
        return {};
      case Mode::searching:
        search(d, rdy);
        if (d.mode == Mode::searching) return {};
        continue;
      case Mode::sip: {
        const Framed f = d.session ? d.session->frame(d.buffer) : fns(d).frame(d.buffer);
        if (f.kind == FrameKind::zero_rest) {
          d.mode = Mode::non_sip;
          continue;
        }
        if (f.kind == FrameKind::more) {
          if (d.buffer.size() < kMaxStreamMessageBytes) return {};
          // Oversized: zeroed as unframable, then resynchronised (R15).
          filler(d, d.buffer.size(), true, rdy);
          d.buffer.clear();
          to_searching(d);
          return {};
        }
        if (f.kind == FrameKind::oversized && f.len >= 2) {
          d.discard = f.len;
          continue;
        }
        if (f.kind != FrameKind::message && f.kind != FrameKind::verbatim) {
          to_searching(d);
          continue;
        }
        if (f.len == 0 || f.len > d.buffer.size()) {
          to_searching(d);
          continue;
        }
        const std::string_view msg = std::string_view(d.buffer).substr(0, f.len);
        if (f.kind == FrameKind::verbatim) {
          emit(d, f.len, f.len, msg, true, rdy);
        } else {
          auto m = d.session ? d.session->rewrite(msg) : fns(d).rewrite(msg);
          if (!m) return std::unexpected(m.error());
          if (m->zeroed) {
            filler(d, f.len, false, rdy);
          } else {
            emit_message(d, f.len, *m, rdy);
          }
        }
        d.buffer.erase(0, f.len);
        d.drop = f.drop_after;
        continue;
      }
    }
  }
}

void TcpStreams::search(Dir& d, std::vector<Ticket>& rdy) {
  const std::string_view b = d.buffer;
  const auto next_line = [&](std::size_t from) -> std::size_t {
    const auto p = b.find("\r\n", from);
    return p == std::string_view::npos ? p : p + 2;
  };
  const auto zero = [&](std::size_t n) {
    // The line end before a resynchronisation point stays, so that a decoder that reads the
    // zeroed bytes as one unfinished line does not swallow the message that follows.
    if (!drop_ && n >= 2 && b.substr(n - 2, 2) == "\r\n") {
      filler(d, n - 2, true, rdy);
      emit_crlf(d, rdy);
    } else {
      filler(d, n, true, rdy);
    }
    d.buffer.erase(0, n);
    d.searched += n;
    if (d.searched >= kMaxSearchBytes) {
      d.mode = Mode::non_sip;  // R14: 1 MiB without a start line
      d.pending_unframable = 0;
    }
  };
  std::size_t cand = d.search_at_zero ? 0 : next_line(0);
  while (cand != std::string_view::npos) {
    if (cand == b.size()) {
      zero(cand);
      d.search_at_zero = true;
      return;
    }
    const auto r = start_at(d, b.substr(cand));
    if (!r || *r) {
      zero(cand);
      d.search_at_zero = true;
      if (r && d.mode == Mode::searching) {
        const bool web = d.pending != nullptr;
        if (web) d.session = std::move(d.pending);
        become_sip(d, web);
      }
      d.pending.reset();
      return;
    }
    cand = next_line(cand);
  }
  const std::size_t keep = b.back() == '\r' ? 1 : 0;
  zero(b.size() - keep);
  d.search_at_zero = false;
}

// --- determination ---------------------------------------------------------------------------

void TcpStreams::filler(Dir& d, std::uint64_t len, bool unframable, std::vector<Ticket>& rdy) {
  if (len == 0) return;
  if (unframable) {
    if (d.sip_seen) stats_.bytes_unframable += len;
    else d.pending_unframable += len;
  }
  if (drop_) emit(d, len, 0, {}, true, rdy);
  else emit(d, len, len, {}, true, rdy);
}

void TcpStreams::emit_crlf(Dir& d, std::vector<Ticket>& rdy) {
  Piece p{d.final_end, 2, d.out_end, 2, true};
  p.crlf = true;
  add_piece(d, p);
  if (d.sip_seen) d.cache.append("\r\n");
  d.final_end += 2;
  d.out_end += 2;
  if (!d.sip_seen) d.cache_base = d.out_end;
  advanced(d, rdy);
}

void TcpStreams::add_piece(Dir& d, const Piece& p) {
  if (p.orig_len == 0 && p.out_len == 0) return;
  if (!d.pieces.empty() && p.linear && d.pieces.back().linear && !p.crlf && !d.pieces.back().crlf) {
    // Runs of kept-length or removed bytes stay one breakpoint (R14: one per changed token).
    Piece& b = d.pieces.back();
    const bool identity = b.out_len == b.orig_len && p.out_len == p.orig_len;
    const bool removed = b.out_len == 0 && p.out_len == 0;
    if (identity || removed) {
      b.orig_len += p.orig_len;
      b.out_len += p.out_len;
      return;
    }
  }
  d.pieces.push_back(p);
}

void TcpStreams::emit(Dir& d, std::uint64_t orig_len, std::uint64_t out_len, std::string_view bytes,
                      bool linear, std::vector<Ticket>& rdy) {
  add_piece(d, Piece{d.final_end, orig_len, d.out_end, out_len, linear});
  if (d.sip_seen) {
    if (bytes.empty()) d.cache.append(out_len, '\0');
    else d.cache.append(bytes);
  }
  d.final_end += orig_len;
  d.out_end += out_len;
  if (!d.sip_seen) d.cache_base = d.out_end;
  advanced(d, rdy);
}

void TcpStreams::emit_message(Dir& d, std::uint64_t orig_len, const RewrittenMessage& m,
                              std::vector<Ticket>& rdy) {
  std::vector<Piece> ps = m.spans;
  bool covers = !ps.empty();
  std::uint64_t o = 0;
  std::uint64_t u = 0;
  for (const auto& sp : ps) {
    covers = covers && sp.orig == o && sp.out == u;
    o += sp.orig_len;
    u += sp.out_len;
  }
  if (!covers || o != orig_len || u != m.bytes.size()) {
    ps.assign(1, Piece{0, orig_len, 0, m.bytes.size(), false});
  }
  // The segment that carries a message's last byte carries the last output byte too, so the
  // message completes in the same packet as in the input (the ladder keeps its frames).
  std::size_t k = ps.size();
  while (k > 0 && ps[k - 1].out_len == 0) --k;
  if (k > 0 && orig_len > 0) {
    Piece tail{ps[k - 1].orig, orig_len - ps[k - 1].orig, ps[k - 1].out, ps[k - 1].out_len, false};
    const bool exact = k == ps.size() && tail.orig_len == tail.out_len && ps[k - 1].linear;
    if (!exact) {
      ps.resize(k - 1);
      if (tail.orig_len > 1 || tail.out_len > 1) {
        ps.push_back(Piece{tail.orig, tail.orig_len - 1, tail.out, tail.out_len - 1, false});
      }
      ps.push_back(Piece{tail.orig + tail.orig_len - 1, 1, tail.out + tail.out_len - 1, 1, true});
    }
  }
  for (const auto& sp : ps) {
    add_piece(d, Piece{d.final_end + sp.orig, sp.orig_len, d.out_end + sp.out, sp.out_len, sp.linear});
  }
  d.cache.append(m.bytes);
  d.final_end += orig_len;
  d.out_end += m.bytes.size();
  advanced(d, rdy);
}

void TcpStreams::advanced(Dir& d, std::vector<Ticket>& rdy) {
  while (!d.waiting.empty() && d.waiting.begin()->first <= d.final_end) {
    const Ticket t = d.waiting.begin()->second;
    d.waiting.erase(d.waiting.begin());
    check(t, rdy);
  }
  // Tickets that needed the new bytes have taken them; the cache keeps the newest 256 KiB.
  if (d.cache.size() > kRetransCacheBytes) {
    const std::size_t cut = d.cache.size() - kRetransCacheBytes;
    d.cache.erase(0, cut);
    d.cache_base += cut;
  }
  prune(d);
}

Result<void> TcpStreams::give_up(Dir& d, std::uint64_t until, std::vector<Ticket>& rdy) {
  while (d.final_end < until) {
    d.discard = 0;
    if (!d.buffer.empty()) {
      filler(d, d.buffer.size(), d.mode != Mode::non_sip, rdy);
      d.buffer.clear();
      if (d.mode == Mode::unknown) d.mode = Mode::searching;
      to_searching(d);
      continue;
    }
    if (d.ooo.empty()) break;
    gap_to(d, d.ooo.begin()->first, rdy);
    absorb(d);
    if (auto r = process(d, rdy); !r) return std::unexpected(r.error());
  }
  return {};
}

void TcpStreams::gap_to(Dir& d, std::uint64_t to, std::vector<Ticket>& rdy) {
  if (to <= d.next) return;
  if (d.drop > 0) {
    // Feature 007: bytes missing inside a dropped body are dropped too; framing is not lost.
    const std::uint64_t n = std::min<std::uint64_t>(to - d.next, d.drop);
    emit(d, n, 0, {}, true, rdy);
    d.drop -= n;
    d.next += n;
    if (d.next == to) return;
  }
  // Precondition: the buffer is empty (final_end == next). Bytes after a gap are mid-message.
  d.discard = 0;
  filler(d, to - d.next, d.mode != Mode::non_sip, rdy);
  d.next = to;
  if (d.mode == Mode::unknown) d.mode = Mode::searching;
  to_searching(d);
  d.search_at_zero = true;  // the bytes after a gap may start a message (a lost segment)
}

void TcpStreams::prune(Dir& d) {
  // R14/R15: breakpoints below the peer's acknowledgement are merged into one coarse span.
  constexpr std::size_t kSoft = 64;
  if (d.pieces.size() <= kSoft) return;
  std::size_t k = 0;
  while (k < d.pieces.size() && d.pieces[k].orig + d.pieces[k].orig_len <= d.acked) ++k;
  if (d.pieces.size() > kMaxOffsetBreakpoints && k < d.pieces.size() / 2) k = d.pieces.size() / 2;
  if (k < 2) return;
  Piece merged{d.pieces[0].orig, 0, d.pieces[0].out, 0, true};  // kept line ends are forgotten
  for (std::size_t i = 0; i < k; ++i) {
    merged.orig_len += d.pieces[i].orig_len;
    merged.out_len += d.pieces[i].out_len;
  }
  d.pieces.erase(d.pieces.begin(), d.pieces.begin() + static_cast<std::ptrdiff_t>(k));
  d.pieces.push_front(merged);
  d.floor = merged.orig + merged.orig_len;
}

// --- outputs ---------------------------------------------------------------------------------

bool TcpStreams::own_met(const Seg& g) const {
  if (!g.in_window) return true;
  const auto d = dirs_.find(g.direction);
  return d == dirs_.end() || g.need_own <= d->second.final_end;
}

bool TcpStreams::rev_met(const Seg& g) const {
  if (!g.has_ack || !g.rev_known) return true;
  const auto r = dirs_.find(g.reverse);
  return r == dirs_.end() || static_cast<std::uint64_t>(g.need_rev) <= r->second.final_end;
}

void TcpStreams::check(Ticket t, std::vector<Ticket>& rdy) {
  auto it = segs_.find(t);
  if (it == segs_.end() || it->second.done) return;
  Seg& g = it->second;
  if (!g.own_done && own_met(g)) compute_own(g);
  if (g.own_done && rev_met(g)) {
    compute_rev(g);
    g.done = true;
    rdy.push_back(t);
  }
}

std::uint64_t TcpStreams::map(const Dir& d, std::uint64_t off) const {
  if (off >= d.final_end) {
    const bool removed = drop_ && d.mode != Mode::sip;
    return d.out_end + (removed ? 0 : off - d.final_end);
  }
  // The last piece starting at or before `off`.
  auto it = std::upper_bound(d.pieces.begin(), d.pieces.end(), off,
                             [](std::uint64_t v, const Piece& p) { return v < p.orig; });
  if (it == d.pieces.begin()) return 0;
  --it;
  // Zero-length insertions at the same offset: the bytes before `off` include them.
  const Piece& p = *it;
  const std::uint64_t in = off - p.orig;
  if (in >= p.orig_len) return p.out + p.out_len;
  if (p.linear) return p.out + std::min(in, p.out_len);
  return in == 0 ? p.out : p.out + p.out_len;
}

std::uint32_t TcpStreams::map_seq(const Dir& d, std::int64_t off, std::uint32_t orig) const {
  if (off < 0) return orig;
  auto u = static_cast<std::uint64_t>(off);
  std::uint64_t extra = 0;
  if (d.fin && u > *d.fin) {
    extra = 1;  // FIN consumes one sequence number (001/R8)
    u = *d.fin;
  }
  return d.base + static_cast<std::uint32_t>(map(d, u) + extra);
}

void TcpStreams::compute_own(Seg& g) {
  g.own_done = true;
  TcpOutput& o = g.out;
  const auto it = dirs_.find(g.direction);
  if (it == dirs_.end()) {
    o.seq = g.seq;
    if (!drop_) o.payload.assign(g.captured, 0);
    return;
  }
  const Dir& d = it->second;
  o.sip = d.sip_seen;
  o.seq = g.syn ? g.seq : map_seq(d, g.s, g.seq);
  if (!g.in_window) {
    if (!drop_) o.payload.assign(g.captured, 0);
    return;
  }
  const std::uint64_t a = map(d, static_cast<std::uint64_t>(g.s));
  const std::uint64_t b = std::max(a, map(d, static_cast<std::uint64_t>(g.e)));
  // A truncated segment (a gap) keeps at most its captured length.
  const std::uint64_t len = g.complete ? b - a : std::min<std::uint64_t>(b - a, g.captured);
  o.payload.assign(len, 0);
  bool missing = static_cast<std::uint64_t>(g.s) < d.floor && g.retransmission;
  if (!missing) {
    for (std::uint64_t i = 0; i < len; ++i) {
      const std::uint64_t at = a + i;
      if (at >= d.cache_base && at - d.cache_base < d.cache.size()) {
        o.payload[i] = static_cast<std::uint8_t>(d.cache[at - d.cache_base]);
      } else if (d.sip_seen) {
        missing = true;
      }
    }
  }
  if (missing) {
    std::fill(o.payload.begin(), o.payload.end(), std::uint8_t{0});
  } else if (len > 0) {
    // Kept line ends of a direction without a byte cache.
    auto p = std::upper_bound(d.pieces.begin(), d.pieces.end(), a,
                              [](std::uint64_t v, const Piece& x) { return v < x.out + x.out_len; });
    for (; p != d.pieces.end() && p->out < a + len; ++p) {
      if (!p->crlf) continue;
      for (std::uint64_t i = 0; i < 2; ++i) {
        if (p->out + i >= a && p->out + i < a + len) o.payload[p->out + i - a] = i == 0 ? '\r' : '\n';
      }
    }
  }
  if (g.retransmission && d.sip_seen && len > 0) {
    if (missing) ++stats_.retransmissions_zeroed;
    else ++stats_.retransmissions_replayed;
  }
}

void TcpStreams::compute_rev(Seg& g) {
  TcpOutput& o = g.out;
  if (!g.has_ack) return;
  const auto r = g.rev_known ? dirs_.find(g.reverse) : dirs_.end();
  if (r == dirs_.end()) {
    o.ack = g.rev_known ? g.ack : g.ack_fallback;
    if (!drop_) {
      o.sack = g.sack;
      o.sack_known = true;
    }
    return;
  }
  o.ack = map_seq(r->second, g.ack_off, g.ack);
  std::vector<std::uint32_t> edges;
  for (std::size_t i = 0; i < g.sack.size(); ++i) edges.push_back(map_seq(r->second, g.sack_off[i], g.sack[i]));
  o.sack = std::move(edges);
  o.sack_known = true;
}

}  // namespace mcxanon::stream
