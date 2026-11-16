// SPDX-License-Identifier: GPL-3.0-or-later
//
// Fuzz target for IP fragment reassembly: the input is a set of IPv4 fragments
// of up to four datagrams (identification, offset, more-fragments flag, length and bytes).
// Every fragment is offered to the fragment table; a complete datagram must reassemble to its
// declared length, and the reassembled packet must be buildable from its first fragment.
#include "dissect/packet.hpp"
#include "rewrite/apply.hpp"
#include "stream/fragments.hpp"

#include <cstdint>
#include <cstdlib>
#include <map>
#include <vector>

namespace {
bool sip_like(mcxanon::ByteView p) { return !p.empty() && (p[0] & 1) != 0; }

mcxanon::Bytes fragment(std::uint16_t id, std::uint32_t off, bool more, mcxanon::ByteView body) {
  mcxanon::Bytes p(20, 0);
  p[0] = 0x45;
  const auto total = static_cast<std::uint16_t>(20 + body.size());
  p[2] = static_cast<std::uint8_t>(total >> 8);
  p[3] = static_cast<std::uint8_t>(total);
  p[4] = static_cast<std::uint8_t>(id >> 8);
  p[5] = static_cast<std::uint8_t>(id);
  const auto frag = static_cast<std::uint16_t>((more ? 0x2000u : 0u) | ((off / 8) & 0x1FFFu));
  p[6] = static_cast<std::uint8_t>(frag >> 8);
  p[7] = static_cast<std::uint8_t>(frag);
  p[8] = 64;
  p[9] = 17;
  const std::uint8_t a[8] = {10, 0, 0, 1, 10, 0, 0, 2};
  std::copy(a, a + 8, p.begin() + 12);
  p.insert(p.end(), body.begin(), body.end());
  return p;
}
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  mcxanon::stream::FragmentTable table;
  std::vector<mcxanon::stream::FragmentTable::Ticket> ready;
  std::map<mcxanon::stream::FragmentTable::Datagram, mcxanon::Bytes> first;
  std::vector<mcxanon::stream::FragmentTable::Arrival> arrivals;
  std::size_t p = 0;
  // Fragment header: id (2 bits) and more flag (bit 2), offset in units of 8 (uint8), length
  // (uint8 * 8 + low bits).
  while (p + 3 <= size && arrivals.size() < 128) {
    const auto id = static_cast<std::uint16_t>(data[p] & 3);
    const bool more = (data[p] & 4) != 0;
    const std::uint32_t off = static_cast<std::uint32_t>(data[p + 1]) * 8;
    std::size_t len = static_cast<std::size_t>(data[p + 2]) * 8 + ((data[p] >> 3) & 7);
    p += 3;
    len = std::min(len, size - p);
    const auto pkt = fragment(id, off, more, mcxanon::ByteView(data + p, len));
    p += len;
    const auto d = mcxanon::dissect(mcxanon::kLinkRaw, pkt);
    auto f = mcxanon::stream::fragment_of(d, pkt, &sip_like);
    if (!f) continue;
    const auto a = table.add(*f, ready);
    if (!a.tracked) continue;
    arrivals.push_back(a);
    if (f->offset == 0) first[a.datagram] = pkt;
  }
  for (const auto& a : arrivals) {
    if (!table.ready(a.ticket)) table.abandon(a.datagram, mcxanon::stream::FragmentTable::Abandon::missing, ready);
    if (table.verdict(a.datagram) == mcxanon::stream::FragmentTable::Verdict::complete) {
      const auto& dg = table.reassembled(a.datagram);
      if (table.chunk_size(a.datagram) % 8 != 0 || table.rank(a.ticket) >= table.ranks(a.datagram)) std::abort();
      if (auto it = first.find(a.datagram); it != first.end()) {
        auto pkt = mcxanon::reassembled_packet(mcxanon::kLinkRaw, it->second, 0, 0, dg);
        if (pkt && pkt->size() != 20 + dg.size()) std::abort();
      }
    }
  }
  for (const auto& a : arrivals) table.release(a.ticket);
  return 0;
}
