// SPDX-License-Identifier: GPL-3.0-or-later
//
// Rewriting of one packet: dissect, apply the field decisions, handle the
// payload (zero or drop), fix lengths, TCP numbering (drop mode), multicast
// MACs and checksums (preserving their validity state).
#pragma once

#include "mcxanon/error.hpp"

#include "bytes/bytes.hpp"
#include "dissect/packet.hpp"
#include "policy/decide.hpp"
#include "rewrite/address_mapper.hpp"

#include <array>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace mcxanon {

enum class PayloadPolicy { zero, drop };

struct RewriteOptions {
  PayloadPolicy payload = PayloadPolicy::zero;
  bool pseudonymise_vlan = false;
  bool pseudonymise_ports = false;
  bool strict = false;  // unsupported link types / protocols are errors
};

struct ChecksumStats {
  std::uint64_t valid_kept_valid = 0;
  std::uint64_t invalid_kept_invalid = 0;
  std::uint64_t unverifiable_recomputed = 0;
  std::uint64_t udp_zero_kept = 0;
};

struct RewriteStats {
  // FieldId -> action -> count
  std::map<std::string, std::map<std::string, std::uint64_t>> counters;
  std::map<std::pair<std::string, std::uint64_t>, std::uint64_t> unknown;
  ChecksumStats checksums;
  std::uint64_t packets = 0;
  std::uint64_t packets_dropped = 0;
};

struct PacketOutput {
  Bytes data;
  bool drop = false;           // the whole packet is removed (drop mode, non-first fragment)
  bool truncated = false;      // drop mode removed the tail (original length = new length)
  bool l7_spliced = false;     // the SIP layer's bytes replaced the payload.sip field
};

// What the application-layer field is: payload.sip, or payload.media with the classifier's tag
// (feature 004).
struct L7Context {
  Fid field = Fid::payload_sip;
  int media_tag = 0;
};

// The application-layer hand-off (feature 002, feature 004):
// `recognise` marks a UDP payload as payload.sip; `classify_media` marks a UDP payload on an
// announced media endpoint as payload.media; `rewrite` returns the bytes that replace either
// one, or nullopt when it cannot be kept (then it is zeroed, or dropped in drop mode).
struct L7Hook {
  bool (*recognise)(ByteView payload) = nullptr;
  int (*classify_media)(const UdpFlowView& flow, ByteView payload, void* ctx) = nullptr;
  void* classify_media_ctx = nullptr;
  std::function<Result<std::optional<Bytes>>(ByteView payload, const L7Context& ctx)> rewrite;
};

// The TCP stream layer's verdict for one segment: the payload that replaces the
// captured one, and the mapped sequence, acknowledgement and SACK numbers. Without it, TCP
// numbers are kept and the payload follows the policy (zeroed, or removed in drop mode).
struct TcpOverride {
  Bytes payload;
  std::uint32_t seq = 0;
  std::optional<std::uint32_t> ack;
  std::vector<std::uint32_t> sack;  // mapped edges in option order, when sack_known
  bool sack_known = false;
  bool sip = false;  // the payload belongs to a SIP stream (counted as payload.sip)
};

// One output fragment of a reassembled and rewritten datagram: the bytes of the
// fragmentable part it carries, and its fragment offset and more-fragments flag. The packet's
// headers are those of the original fragment, rewritten per feature 001.
struct FragmentOverride {
  Bytes payload;
  std::uint32_t offset = 0;  // in bytes, a multiple of 8
  bool more = false;
};

Result<PacketOutput> rewrite_packet(std::uint16_t linktype, ByteView data, std::size_t fcs_len,
                                    const Policy& policy, AddressMapper& mapper,
                                    const RewriteOptions& options, RewriteStats& stats,
                                    const L7Hook* l7 = nullptr, const TcpOverride* tcp = nullptr,
                                    const FragmentOverride* frag = nullptr);

// The unfragmented packet of a reassembled datagram, built from its first fragment (R16): the
// first fragment's headers followed by the whole fragmentable part, with the IP layer
// `ip_layer` marked unfragmented (IPv6 keeps an atomic Fragment header, RFC 6946), every
// enclosing length adjusted, and the checksums that were valid made valid again.
Result<Bytes> reassembled_packet(std::uint16_t linktype, ByteView first, std::size_t fcs_len,
                                 int ip_layer, ByteView fragmentable);

// [begin, end) of the fragmentable part of IP layer `ip_layer` of a packet.
std::optional<std::pair<std::size_t, std::size_t>> fragmentable_region(std::uint16_t linktype, ByteView packet,
                                                                       std::size_t fcs_len, int ip_layer);

}  // namespace mcxanon
