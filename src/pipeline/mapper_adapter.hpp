// SPDX-License-Identifier: GPL-3.0-or-later
//
// AddressMapper backed by the project's Pseudonymiser: the packet rewriter and the SIP layer
// see one mapping through it.
#pragma once

#include "pseudo/pseudonymiser.hpp"
#include "rewrite/address_mapper.hpp"

namespace mcxanon {

class MapperAdapter final : public AddressMapper {
 public:
  explicit MapperAdapter(Pseudonymiser& p) : p_(p) {}
  Result<MacAddr> mac(const MacAddr& a) override { return p_.mac(a); }
  Result<std::uint32_t> ipv4(std::uint32_t a) override { return p_.ipv4(a); }
  Result<Ipv6Addr> ipv6(const Ipv6Addr& a) override { return p_.ipv6(a); }
  Result<std::uint16_t> vlan(std::uint16_t v) override { return p_.vlan(v); }
  Result<std::uint16_t> port(std::uint16_t v) override { return p_.port(v); }
  Result<std::string> text(Category c, std::string_view v) override { return p_.text(c, v); }
  Result<std::string> domain(std::string_view v) override { return p_.domain(v); }
  Result<std::string> tel(std::string_view v) override { return p_.tel(v); }
  Result<std::string> sdp_version(std::string_view id, std::string_view v) override {
    return p_.sdp_version(id, v);
  }
  Result<std::uint32_t> spi(std::uint32_t v) override { return p_.spi(v); }
  Result<std::uint32_t> ssrc(std::uint32_t v) override { return p_.ssrc(v); }
  Result<std::uint32_t> binary(Category c, std::uint32_t v) override { return p_.binary(c, v); }
  Result<std::uint64_t> binary64(Category c, std::uint64_t v) override { return p_.binary64(c, v); }
  Result<std::uint32_t> key_id(std::uint32_t v) override { return p_.key_id(v); }
  [[nodiscard]] std::optional<std::uint32_t> find_key_id(std::uint32_t v) const override { return p_.find_key_id(v); }
  Result<Bytes> bytes(Category c, ByteView v) override { return p_.bytes(c, v); }

 private:
  Pseudonymiser& p_;
};

}  // namespace mcxanon
