// SPDX-License-Identifier: GPL-3.0-or-later
//
// Address pseudonymisation by class, backed by the project
// mapping. Special addresses are kept; every other value gets a consistent,
// HMAC-derived pseudonym of the same class.
#pragma once

#include "mcxanon/error.hpp"

#include "pseudo/hmac.hpp"
#include "pseudo/mapping.hpp"
#include "pseudo/ranges.hpp"

#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>

namespace mcxanon {

struct PseudonymiserOptions {
  bool prefix_preserving = false;
  std::uint16_t ephemeral_lo = 49152;
  std::uint16_t ephemeral_hi = 65535;
};

struct PseudonymiserStats {
  std::map<std::string, std::uint64_t> new_entries;
  std::map<std::string, std::uint64_t> reused_entries;
  std::uint64_t collisions_resolved = 0;
};

class Pseudonymiser {
 public:
  Pseudonymiser(const Secret& secret, Mapping& mapping, PseudonymiserOptions options = {});

  Result<Mac> mac(const Mac& original);
  Result<std::uint32_t> ipv4(std::uint32_t original);
  Result<Ipv6> ipv6(const Ipv6& original);
  Result<std::uint16_t> vlan(std::uint16_t vid);
  // Ports outside the ephemeral range are returned unchanged.
  Result<std::uint16_t> port(std::uint16_t port);

  // Text and numeric categories. See rewrite::AddressMapper for the forms.
  Result<std::string> text(Category c, std::string_view original);
  Result<std::string> domain(std::string_view name);
  Result<std::string> tel(std::string_view number);
  Result<std::string> sdp_version(std::string_view sess_id, std::string_view version);
  Result<std::uint32_t> spi(std::uint32_t original);
  Result<std::uint32_t> ssrc(std::uint32_t original);
  // The binary media categories (fc_ref, eci, tac, mbms_sai, mbsfn_area, nr_tac, mbs_fsa): a pseudonym of the
  // category's bit width. An original wider than the category is an internal error.
  Result<std::uint32_t> binary(Category c, std::uint32_t original);
  // The same for categories wider than 32 bits (nci, feature 003).
  Result<std::uint64_t> binary64(Category c, std::uint64_t original);
  // Feature 005. A key identifier keeps its 4-bit purpose tag (TS 33.180 Annex G); find_key_id
  // returns an existing pseudonym and never creates one (the MKI match).
  Result<std::uint32_t> key_id(std::uint32_t original);
  [[nodiscard]] std::optional<std::uint32_t> find_key_id(std::uint32_t original) const;
  // The byte-string categories nonce (1-255 octets) and uid (32 octets): same-length pseudonyms.
  Result<Bytes> bytes(Category c, ByteView original);

  [[nodiscard]] const PseudonymiserStats& stats() const { return stats_; }
  // Marks every entry used in this run (runs_seen accounting).
  void finish_run();

 private:
  Result<Bytes> assign(Category c, ByteView original);
  Result<Bytes> candidate(Category c, ByteView original, std::uint32_t counter,
                          bool& excluded) const;

  const Secret& secret_;
  Mapping& mapping_;
  PseudonymiserOptions options_;
  PseudonymiserStats stats_;
  std::map<std::pair<Category, Bytes>, bool> used_;
};

}  // namespace mcxanon
