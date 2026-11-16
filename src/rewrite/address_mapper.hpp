// SPDX-License-Identifier: GPL-3.0-or-later
//
// The rewriter's view of the pseudonymiser: original in, pseudonym out. The packet rewriter
// uses the address methods; the SIP layer also uses the text and fixed-format methods
// Every method is backed by the one project mapping.
#pragma once

#include "mcxanon/error.hpp"

#include "pseudo/category.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace mcxanon {

using MacAddr = std::array<std::uint8_t, 6>;
using Ipv6Addr = std::array<std::uint8_t, 16>;

class AddressMapper {
 public:
  AddressMapper() = default;
  AddressMapper(const AddressMapper&) = delete;
  AddressMapper& operator=(const AddressMapper&) = delete;
  virtual ~AddressMapper() = default;
  virtual Result<MacAddr> mac(const MacAddr& original) = 0;
  virtual Result<std::uint32_t> ipv4(std::uint32_t original) = 0;
  virtual Result<Ipv6Addr> ipv6(const Ipv6Addr& original) = 0;
  virtual Result<std::uint16_t> vlan(std::uint16_t vid) = 0;
  virtual Result<std::uint16_t> port(std::uint16_t port) = 0;

  // A text pseudonym of one of the text categories, in its rendered form
  // (for example "u-1a2b3c4d" for sip-user, 15 digits for imei). domain and tel delegate to
  // domain() and tel().
  virtual Result<std::string> text(Category category, std::string_view original) = 0;
  // A full domain name: one pseudonym per label, top label "invalid".
  virtual Result<std::string> domain(std::string_view name) = 0;
  // A telephone number in its written form: digits replaced, "+" and separators kept;
  // numbers of up to 3 digits are kept.
  virtual Result<std::string> tel(std::string_view number) = 0;
  // The SDP o= sess-version, shifted by a keyed offset of the sess-id (RFC 3264 §8).
  virtual Result<std::string> sdp_version(std::string_view sess_id, std::string_view version) = 0;
  // SPI (values 0-255 kept, RFC 4303 §2.1) and SSRC (one project-wide mapping, FR-021).
  virtual Result<std::uint32_t> spi(std::uint32_t original) = 0;
  virtual Result<std::uint32_t> ssrc(std::uint32_t original) = 0;
  // The binary media categories of feature 004 (fc_ref, eci, tac, mbms_sai, mbsfn_area): a
  // pseudonym of the category's bit width.
  virtual Result<std::uint32_t> binary(Category category, std::uint32_t original) = 0;
  // The 36-bit NR cell identity (feature 003, category nci).
  virtual Result<std::uint64_t> binary64(Category category, std::uint64_t original) {
    (void)category;
    (void)original;
    return fail(ErrorCode::internal, "64-bit binary category not supported by this mapper");
  }
  // Feature 005: a key identifier with its purpose tag kept (TS 33.180 Annex G).
  virtual Result<std::uint32_t> key_id(std::uint32_t original) {
    (void)original;
    return fail(ErrorCode::internal, "key identifiers not supported by this mapper");
  }
  // The existing pseudonym of a key identifier, if any; never creates one (the MKI match).
  [[nodiscard]] virtual std::optional<std::uint32_t> find_key_id(std::uint32_t original) const {
    (void)original;
    return std::nullopt;
  }
  // A byte-string category (nonce, uid): a pseudonym of the same length.
  virtual Result<Bytes> bytes(Category category, ByteView original) {
    (void)category;
    (void)original;
    return fail(ErrorCode::internal, "byte-string categories not supported by this mapper");
  }
};

}  // namespace mcxanon
