// SPDX-License-Identifier: GPL-3.0-or-later
#include "stream/fragments.hpp"

#include "bytes/endian.hpp"
#include "stream/limits.hpp"

#include <algorithm>
#include <cstring>

namespace mcxanon::stream {

std::optional<FragmentInfo> fragment_of(const Dissection& d, ByteView data,
                                        bool (*recognise_sip)(ByteView payload)) {
  int fi = -1;
  for (std::size_t i = 0; i < d.layers.size(); ++i) {
    const Layer& l = d.layers[i];
    if ((l.kind == LayerKind::ipv4 || l.kind == LayerKind::ipv6) && !l.embedded &&
        (l.fragment_first || l.fragment_nonfirst)) {
      fi = static_cast<int>(i);
      break;
    }
  }
  if (fi < 0) return std::nullopt;
  const Layer& ip = d.layers[static_cast<std::size_t>(fi)];
  FragmentInfo f;
  f.layer = fi;
  const auto put = [&](std::size_t off, std::size_t len) {
    f.key.insert(f.key.end(), data.begin() + static_cast<std::ptrdiff_t>(off),
                 data.begin() + static_cast<std::ptrdiff_t>(off + len));
  };
  std::size_t pstart = 0;
  if (ip.kind == LayerKind::ipv4) {
    // RFC 791 §3.2: source, destination, protocol and identification name the datagram.
    f.key.push_back(4);
    put(ip.offset + 12, 8);
    put(ip.offset + 9, 1);
    put(ip.offset + 4, 2);
    const std::uint16_t frag = be16(data, ip.offset + 6);
    f.offset = static_cast<std::uint32_t>(frag & 0x1FFFu) * 8u;
    f.more = (frag & 0x2000u) != 0;
    f.udp = data[ip.offset + 9] == 17;
    pstart = ip.offset + ip.header_len;
  } else {
    // RFC 8200 §4.5: source, destination and the Fragment header's identification.
    const std::size_t q = ip.fragment_field;
    if (q + 8 > data.size()) return std::nullopt;
    f.key.push_back(6);
    put(ip.offset + 8, 32);
    put(q + 4, 4);
    const std::uint16_t fo = be16(data, q + 2);
    f.offset = static_cast<std::uint32_t>(fo >> 3) * 8u;
    f.more = (fo & 1u) != 0;
    f.udp = data[q] == 17;
    pstart = q + 8;
  }
  f.key.push_back(static_cast<std::uint8_t>(ip.depth));
  const std::size_t pend = std::min(ip.end, ip.declared_end);
  if (pstart > pend) return std::nullopt;
  f.payload = data.subspan(pstart, pend - pstart);
  f.whole = ip.end >= ip.declared_end;
  if (f.offset == 0) {
    f.sip = f.udp && f.payload.size() > 8 && recognise_sip != nullptr && recognise_sip(f.payload.subspan(8));
  }
  return f;
}

FragmentTable::Datagram FragmentTable::create(const Bytes& key, std::vector<Ticket>& rdy) {
  if (pending_.size() >= kMaxPendingDatagrams) {
    // R15: the oldest pending datagram is given up and zeroed.
    const Datagram old = pending_.front();
    auto it = dgs_.find(old);
    if (it != dgs_.end()) {
      ++stats_.datagrams_evicted;
      decide(it->second, Verdict::zero, rdy);
    }
  }
  const Datagram dg = next_dg_++;
  Dg& g = dgs_[dg];
  g.key = key;
  by_key_[key] = dg;
  pending_.push_back(dg);
  return dg;
}

void FragmentTable::decide(Dg& g, Verdict v, std::vector<Ticket>& rdy) {
  if (g.verdict != Verdict::pending) return;
  g.verdict = v;
  for (const auto& f : g.frags) rdy.push_back(f.ticket);
  const auto dg = by_key_.at(g.key);
  pending_.erase(std::remove(pending_.begin(), pending_.end(), dg), pending_.end());
  if (v == Verdict::zero) {
    g.frags.clear();
    g.data.clear();
  }
  if (g.open == 0) {
    finished_.push_back(dg);
    forget_finished();
  }
}

void FragmentTable::try_complete(Dg& g, std::vector<Ticket>& rdy) {
  if (!g.first || !g.total) return;
  std::vector<const Frag*> order;
  for (const auto& f : g.frags) order.push_back(&f);
  std::stable_sort(order.begin(), order.end(), [](const Frag* a, const Frag* b) { return a->offset < b->offset; });
  std::uint64_t covered = 0;
  for (const Frag* f : order) {
    if (f->offset > covered) return;  // a hole
    covered = std::max<std::uint64_t>(covered, f->offset + f->bytes.size());
  }
  if (covered < *g.total) return;
  g.data.assign(*g.total, 0);
  std::size_t largest = 0;
  for (const Frag* f : order) {
    if (f->offset + f->bytes.size() > g.data.size()) return;  // excluded on arrival; defensive
    if (f->bytes.empty()) continue;  // no payload: nothing to copy (memcpy from null is undefined)
    std::memcpy(g.data.data() + f->offset, f->bytes.data(), f->bytes.size());
    largest = std::max(largest, f->bytes.size());
    if (g.offsets.empty() || g.offsets.back() != f->offset) g.offsets.push_back(f->offset);
  }
  g.chunk = std::max<std::size_t>(8, largest / 8 * 8);
  ++stats_.datagrams_reassembled;
  for (auto& f : g.frags) f.bytes.clear();
  decide(g, Verdict::complete, rdy);
}

FragmentTable::Arrival FragmentTable::add(const FragmentInfo& f, std::vector<Ticket>& rdy) {
  if (!f.udp) return {};
  Datagram dg = 0;
  if (const auto k = by_key_.find(f.key); k != by_key_.end()) {
    if (dgs_.at(k->second).verdict != Verdict::pending) return {};  // a late fragment of a decided datagram
    dg = k->second;
  } else {
    dg = create(f.key, rdy);
  }
  Dg& g = dgs_.at(dg);
  if (f.offset == 0 && f.sip && !*f.sip) {
    ++stats_.datagrams_not_sip;
    decide(g, Verdict::zero, rdy);  // not SIP: every fragment follows feature 001
    return {};
  }
  const Ticket t = next_ticket_++;
  tickets_[t] = dg;
  ++g.open;
  Arrival a{true, t, dg, false};
  const std::uint64_t end = static_cast<std::uint64_t>(f.offset) + f.payload.size();
  bool ambiguous = !f.whole || end > kMaxDatagramBytes || (f.more && f.payload.size() % 8 != 0);
  if (!f.more) {
    if (g.total && *g.total != end) ambiguous = true;
    g.total = end;
  }
  // Every fragment ends within the datagram; one that says more follow ends before its end.
  if (g.total) {
    if (end > *g.total || (f.more && end >= *g.total)) ambiguous = true;
    for (const auto& e : g.frags) {
      const std::uint64_t e_end = e.offset + e.bytes.size();
      if (e_end > *g.total || (e.more && e_end >= *g.total)) ambiguous = true;
    }
  }
  for (const auto& e : g.frags) {
    const std::uint64_t lo = std::max<std::uint64_t>(e.offset, f.offset);
    const std::uint64_t hi = std::min<std::uint64_t>(e.offset + e.bytes.size(), end);
    if (lo < hi && std::memcmp(e.bytes.data() + (lo - e.offset), f.payload.data() + (lo - f.offset), hi - lo) != 0) {
      ambiguous = true;  // R16: a conflicting overlap or a differing duplicate
    }
  }
  g.bytes += f.payload.size();
  if (g.bytes > kMaxDatagramBytes * 2) ambiguous = true;  // endless duplicates
  g.frags.push_back(Frag{t, f.offset, Bytes(f.payload.begin(), f.payload.end()), f.more});
  if (f.offset == 0) g.first = true;
  if (ambiguous) {
    ++stats_.datagrams_ambiguous;
    decide(g, Verdict::zero, rdy);
  } else {
    try_complete(g, rdy);
  }
  a.ready = g.verdict != Verdict::pending;
  // The arriving ticket is reported by `ready`, not through `rdy`.
  rdy.erase(std::remove(rdy.begin(), rdy.end(), t), rdy.end());
  return a;
}

FragmentTable::Verdict FragmentTable::verdict(Datagram dg) const {
  const auto it = dgs_.find(dg);
  return it == dgs_.end() ? Verdict::zero : it->second.verdict;
}

bool FragmentTable::ready(Ticket t) const {
  const auto it = tickets_.find(t);
  return it == tickets_.end() || verdict(it->second) != Verdict::pending;
}

void FragmentTable::abandon(Datagram dg, Abandon why, std::vector<Ticket>& rdy) {
  auto it = dgs_.find(dg);
  if (it == dgs_.end() || it->second.verdict != Verdict::pending) return;
  switch (why) {
    case Abandon::missing: ++stats_.datagrams_incomplete; break;
    case Abandon::timeout: ++stats_.datagrams_timed_out; break;
    case Abandon::bound: ++stats_.datagrams_held_bound; break;
  }
  decide(it->second, Verdict::zero, rdy);
}

const Bytes& FragmentTable::reassembled(Datagram dg) const { return dgs_.at(dg).data; }
std::size_t FragmentTable::chunk_size(Datagram dg) const { return dgs_.at(dg).chunk; }
std::size_t FragmentTable::ranks(Datagram dg) const { return dgs_.at(dg).offsets.size(); }

std::size_t FragmentTable::rank(Ticket t) const {
  const Dg& g = dgs_.at(tickets_.at(t));
  for (const auto& f : g.frags) {
    if (f.ticket != t) continue;
    return static_cast<std::size_t>(std::lower_bound(g.offsets.begin(), g.offsets.end(), f.offset) - g.offsets.begin());
  }
  return 0;
}

void FragmentTable::release(Ticket t) {
  const auto it = tickets_.find(t);
  if (it == tickets_.end()) return;
  const Datagram dg = it->second;
  tickets_.erase(it);
  Dg& g = dgs_.at(dg);
  if (g.open > 0) --g.open;
  if (g.open == 0 && g.verdict != Verdict::pending) {
    finished_.push_back(dg);
    forget_finished();
  }
}

std::size_t FragmentTable::open(Datagram dg) const {
  const auto it = dgs_.find(dg);
  return it == dgs_.end() ? 0 : it->second.open;
}

void FragmentTable::forget_finished() {
  // Decided datagrams are remembered for a while, so that a late duplicate is not mistaken for
  // the start of a new datagram that waits for a first fragment that already passed.
  while (finished_.size() > kMaxPendingDatagrams) {
    const Datagram dg = finished_.front();
    finished_.pop_front();
    auto it = dgs_.find(dg);
    if (it == dgs_.end() || it->second.open != 0) continue;
    if (auto k = by_key_.find(it->second.key); k != by_key_.end() && k->second == dg) by_key_.erase(k);
    dgs_.erase(it);
  }
}

}  // namespace mcxanon::stream
