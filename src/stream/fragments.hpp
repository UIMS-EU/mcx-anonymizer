// SPDX-License-Identifier: GPL-3.0-or-later
//
// Bounded reassembly bookkeeping for fragmented UDP datagrams. The table decides
// when a datagram is complete, ambiguous or given up; the pipeline rewrites a complete SIP
// datagram and cuts the result into fragments again. Only UDP datagrams whose first fragment
// starts like SIP (R3), or whose first fragment has not arrived yet, are tracked; everything
// else keeps the feature-001 behaviour.
#pragma once

#include "bytes/bytes.hpp"
#include "dissect/packet.hpp"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <vector>

namespace mcxanon::stream {

struct FragmentInfo {
  Bytes key;                 // addresses, protocol (IPv4), identification, tunnel depth
  int layer = -1;            // index of the fragmented IP layer in the dissection
  std::uint32_t offset = 0;  // in bytes
  bool more = false;         // MF (IPv4) / M (IPv6)
  ByteView payload;          // the fragmentable part carried by this fragment
  bool whole = false;        // the capture holds the fragment completely
  bool udp = false;          // the datagram is UDP
  std::optional<bool> sip;   // offset 0 only: the UDP payload starts like SIP
};

// The outermost non-embedded fragmented IP layer of a packet, if any.
std::optional<FragmentInfo> fragment_of(const Dissection& d, ByteView data,
                                        bool (*recognise_sip)(ByteView payload));

struct FragmentStats {
  std::uint64_t datagrams_reassembled = 0;
  std::uint64_t datagrams_ambiguous = 0;   // conflicting overlaps or lengths: zeroed
  std::uint64_t datagrams_incomplete = 0;  // given up at the end of the capture
  std::uint64_t datagrams_timed_out = 0;   // given up after the pending timeout
  std::uint64_t datagrams_held_bound = 0;  // given up when the hold queue reached its bound
  std::uint64_t datagrams_evicted = 0;     // more than kMaxPendingDatagrams pending
  std::uint64_t datagrams_not_sip = 0;     // the first fragment does not start like SIP
};

class FragmentTable {
 public:
  using Ticket = std::uint64_t;
  using Datagram = std::uint64_t;
  enum class Verdict { pending, complete, zero };
  // Why a pending datagram is given up (the report's reasons "missing", "timeout", "bound").
  enum class Abandon { missing, timeout, bound };
  struct Arrival {
    bool tracked = false;  // false: the fragment keeps the feature-001 behaviour
    Ticket ticket = 0;
    Datagram datagram = 0;
    bool ready = false;
  };

  Arrival add(const FragmentInfo& f, std::vector<Ticket>& became_ready);
  [[nodiscard]] Verdict verdict(Datagram dg) const;
  [[nodiscard]] bool ready(Ticket t) const;
  // Gives up a pending datagram: its fragments are zeroed (feature 001).
  void abandon(Datagram dg, Abandon why, std::vector<Ticket>& became_ready);

  // A complete datagram: its fragmentable part, and the size of output fragments (the
  // largest original fragment payload rounded down to a multiple of 8).
  [[nodiscard]] const Bytes& reassembled(Datagram dg) const;
  [[nodiscard]] std::size_t chunk_size(Datagram dg) const;
  // Fragments ranked by offset: output fragment `rank` goes to the slot of the original
  // fragment with that rank; the last rank also carries surplus output fragments.
  [[nodiscard]] std::size_t ranks(Datagram dg) const;
  [[nodiscard]] std::size_t rank(Ticket t) const;
  // The ticket's record was emitted. A finished datagram is forgotten once all its records are.
  void release(Ticket t);
  [[nodiscard]] std::size_t open(Datagram dg) const;  // records of the datagram not yet released

  [[nodiscard]] const FragmentStats& stats() const { return stats_; }
  [[nodiscard]] std::size_t pending() const { return pending_.size(); }

 private:
  struct Frag {
    Ticket ticket = 0;
    std::uint32_t offset = 0;
    Bytes bytes;
    bool more = false;
  };
  struct Dg {
    Bytes key;
    Verdict verdict = Verdict::pending;
    std::vector<Frag> frags;  // arrival order
    std::optional<std::uint64_t> total;
    bool first = false;
    std::size_t bytes = 0;
    Bytes data;
    std::size_t chunk = 0;
    std::vector<std::uint32_t> offsets;  // distinct, sorted
    std::size_t open = 0;               // tickets not yet released
  };

  Datagram create(const Bytes& key, std::vector<Ticket>& became_ready);
  void decide(Dg& g, Verdict v, std::vector<Ticket>& became_ready);
  void try_complete(Dg& g, std::vector<Ticket>& became_ready);
  void forget_finished();

  std::map<Bytes, Datagram> by_key_;
  std::map<Datagram, Dg> dgs_;
  std::map<Ticket, Datagram> tickets_;
  std::deque<Datagram> pending_;   // creation order
  std::deque<Datagram> finished_;  // decided and fully released, kept to recognise late fragments
  Datagram next_dg_ = 1;
  Ticket next_ticket_ = 1;
  FragmentStats stats_;
};

}  // namespace mcxanon::stream
