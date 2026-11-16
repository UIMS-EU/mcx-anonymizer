// SPDX-License-Identifier: GPL-3.0-or-later
//
// L2-L4 dissection of one packet into layers and fields. The fields cover
// every byte of the packet data exactly once, in order; whatever is not
// understood is covered by a payload field (fail-closed: payload fields are
// zeroed or dropped, never passed through).
#pragma once

#include "bytes/bytes.hpp"
#include "dissect/fields.hpp"

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

namespace mcxanon {

// LINKTYPE values (draft-ietf-opsawg-pcaplinktype-18 §2.2.1).
inline constexpr std::uint16_t kLinkNull = 0;
inline constexpr std::uint16_t kLinkEthernet = 1;
inline constexpr std::uint16_t kLinkRaw = 101;
inline constexpr std::uint16_t kLinkSll = 113;
inline constexpr std::uint16_t kLinkIpv4 = 228;
inline constexpr std::uint16_t kLinkIpv6 = 229;
inline constexpr std::uint16_t kLinkSll2 = 276;

bool is_supported_linktype(std::uint16_t linktype);

enum class LayerKind {
  ethernet, vlan, sll, sll2, null_loop, arp,
  ipv4, ipv6, icmpv4, icmpv6, tcp, udp, sctp, gre, gtpu,
};

struct Layer {
  LayerKind kind = LayerKind::ethernet;
  std::size_t offset = 0;        // first byte of the layer's header
  std::size_t header_len = 0;    // bytes of header (incl. options / extension headers)
  std::size_t end = 0;           // end of the layer's extent within the captured data
  std::size_t declared_end = 0;  // end per the layer's own length field (may exceed data)
  int parent_ip = -1;            // enclosing IP layer, for pseudo headers
  int depth = 0;                 // tunnel nesting depth
  bool embedded = false;         // inside an ICMP error message
  // IP layers:
  std::size_t upper_offset = 0;  // first byte after IP header + extension headers
  bool fragment_first = false;
  bool fragment_nonfirst = false;
  std::size_t fragment_field = 0;  // offset of ipv4.frag or of the IPv6 Fragment header
  bool jumbo = false;
};

struct FieldInstance {
  Fid id = Fid::payload_unparsed;
  std::size_t offset = 0;
  std::size_t length = 0;
  int layer = -1;
};

struct UnknownProtocol {
  std::string_view kind;  // linktype, ethertype, ip_proto, ipv6_nh, gre_proto, gtpu_ext, ...
  std::uint64_t id = 0;
};

// The innermost IP addresses (4 or 16 octets) and UDP ports of a datagram (feature 004).
struct UdpFlowView {
  ByteView src;
  ByteView dst;
  std::uint16_t sport = 0;
  std::uint16_t dport = 0;
  int depth = 0;  // tunnel nesting depth of the UDP layer
};

struct DissectOptions {
  std::size_t fcs_len = 0;  // Ethernet FCS present at the end of the frame (0 or 4)
  int max_depth = 8;        // tunnel nesting bound
  // When set, a UDP payload for which it returns true is emitted as payload.sip instead of
  // payload.l7 (feature 002). The dissector itself knows no SIP grammar.
  bool (*recognise_sip)(ByteView payload) = nullptr;
  // The TCP stream layer found the segment's direction to carry SIP: the
  // payload of the non-embedded TCP layer is emitted as payload.sip.
  bool tcp_payload_sip = false;
  // When set, a UDP payload that is not SIP and for which it returns a non-zero tag is emitted
  // as payload.media, and the tag is stored in Dissection::media_tag (feature 004, research
  // R3). The dissector knows no media grammar; the tag is the caller's.
  int (*classify_media)(const UdpFlowView& flow, ByteView payload, void* ctx) = nullptr;
  void* classify_media_ctx = nullptr;
};

struct Dissection {
  std::uint16_t linktype = 0;
  std::vector<Layer> layers;
  std::vector<FieldInstance> fields;
  std::vector<UnknownProtocol> unknown;
  bool parse_failure = false;
  bool depth_exceeded = false;
  int media_tag = 0;  // the classify_media tag of the payload.media field, if any
};

Dissection dissect(std::uint16_t linktype, ByteView data, const DissectOptions& options = {});

}  // namespace mcxanon
