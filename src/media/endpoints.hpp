// SPDX-License-Identifier: GPL-3.0-or-later
//
// The media endpoint table: transport
// endpoints that an SDP of the capture announces as RTP, RTCP, a floor or transmission control
// channel, or MSRP. Keys are original (input) addresses. The table is bounded; the least
// recently used endpoint is evicted, deterministically by capture time and insertion order.
#pragma once

#include "bytes/bytes.hpp"
#include "media/limits.hpp"
#include "sip/value_map.hpp"

#include <array>
#include <compare>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string_view>
#include <tuple>
#include <variant>
#include <vector>

namespace mcxanon::media {

// An IPv4 address is held IPv4-mapped (RFC 4291 §2.5.5.2), so both families share one key.
struct Address {
  std::array<std::uint8_t, 16> bytes{};
  static Address v4(const std::array<std::uint8_t, 4>& a);
  static Address v6(const std::array<std::uint8_t, 16>& a);
  static std::optional<Address> from_bytes(ByteView raw);  // 4 or 16 octets
  auto operator<=>(const Address&) const = default;
};

enum class Transport : std::uint8_t { udp, tcp };
enum class Role : std::uint8_t { rtp, fc, tc, msrp };
// What a datagram or connection on an endpoint is.
enum class Kind : std::uint8_t { rtp, rtcp, mux, fc, tc, msrp };
enum class SkipReason : std::uint8_t { fqdn, unspecified, multicast, tls, rejected, unsupported, malformed };
enum class Match : std::uint8_t { dst, src };

std::string_view to_string(Kind k);
std::string_view to_string(SkipReason r);

struct Announcement {
  Address address;
  std::uint16_t port = 0;
  Transport transport = Transport::udp;
  Role role = Role::rtp;
  std::optional<std::uint16_t> rtcp_port;
  std::optional<Address> rtcp_address;
  bool rtcp_mux = false;
  bool secure = false;
  sip::KeyContext keys;  // feature 005: the MKI key context of a secure RTP endpoint
};

struct EndpointKey {
  Address address;
  std::uint16_t port = 0;
  Transport transport = Transport::udp;
  auto operator<=>(const EndpointKey&) const = default;
};

struct Lookup {
  Kind kind = Kind::rtp;
  bool secure = false;
  Match matched = Match::dst;
  std::uint32_t keys = 0;  // feature 005: key context id (EndpointTable::key_context), 0 = none
};

// The most key contexts a run keeps; later ones are not attached (no MKI match).
inline constexpr std::size_t kMaxKeyContexts = 4096;

// The address of an SDP connection field; the skip reason when it cannot name an endpoint.
std::variant<Address, SkipReason> connection_address(std::string_view addrtype, std::string_view address);

// The endpoint announcements of one SDP media description, or why it has none.
std::variant<std::vector<Announcement>, SkipReason> from_sdp(const sip::SdpMedia& m);

class EndpointTable {
 public:
  explicit EndpointTable(std::size_t max_endpoints = kMaxMediaEndpoints);

  // Registers the endpoints of one announcement at capture time `ts_us`. A port 0 announcement
  // is not registered and is counted as rejected.
  void announce(const Announcement& a, std::uint64_t ts_us);
  // Counts an SDP media description that produced no endpoint.
  void skip(SkipReason r) { ++skipped_[r]; }

  // By destination, then by source. A hit refreshes the entry's use time.
  std::optional<Lookup> lookup(const EndpointKey& dst, const EndpointKey& src, std::uint64_t ts_us);

  [[nodiscard]] std::size_t size() const { return entries_.size(); }
  [[nodiscard]] std::uint64_t evicted() const { return evicted_; }
  [[nodiscard]] std::size_t max_endpoints() const { return max_; }
  [[nodiscard]] const std::map<Kind, std::uint64_t>& registered() const { return registered_; }
  [[nodiscard]] const std::map<SkipReason, std::uint64_t>& skipped() const { return skipped_; }
  // The key context of a Lookup::keys id; nullptr for 0 or an unknown id.
  [[nodiscard]] const sip::KeyContext* key_context(std::uint32_t id) const {
    return id == 0 || id > contexts_.size() ? nullptr : &contexts_[id - 1];
  }

 private:
  struct Entry {
    Kind kind = Kind::rtp;
    bool secure = false;
    std::uint64_t last_used = 0;
    std::uint64_t seq = 0;
    std::uint32_t keys = 0;
  };
  void put(const EndpointKey& k, Kind kind, bool secure, std::uint64_t ts_us, std::uint32_t keys = 0);
  std::uint32_t intern(const sip::KeyContext& k);
  std::optional<Lookup> find(const EndpointKey& k, Match m, std::uint64_t ts_us);

  std::size_t max_;
  std::uint64_t next_seq_ = 0;
  std::uint64_t evicted_ = 0;
  std::map<EndpointKey, Entry> entries_;
  std::set<std::tuple<std::uint64_t, std::uint64_t, EndpointKey>> lru_;  // (last_used, seq, key)
  std::map<Kind, std::uint64_t> registered_;
  std::map<SkipReason, std::uint64_t> skipped_;
  std::vector<sip::KeyContext> contexts_;
  std::map<sip::KeyContext, std::uint32_t> context_ids_;
};

}  // namespace mcxanon::media
