// SPDX-License-Identifier: GPL-3.0-or-later
//
// Text forms of IPv4 and IPv6 addresses in SIP and SDP. Addresses written as text
// go through the same feature-001 mapping as binary addresses, and the output keeps the form
// class of the input: bracketed or not; full, compressed or mixed IPv6 notation; zero-padded
// groups; the letter case of the first hex letter.
#pragma once

#include "mcxanon/error.hpp"

#include "rewrite/address_mapper.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace mcxanon::sip {

struct TextAddress {
  enum class Form {
    dotted,      // IPv4 dotted decimal (RFC 3986 §3.2.2)
    full,        // IPv6, eight groups, no "::"
    compressed,  // IPv6 with "::"
    mixed,       // IPv6 with the last 32 bits in dotted decimal
  };
  bool v6 = false;
  std::uint32_t v4 = 0;
  Ipv6Addr v6addr{};
  Form form = Form::dotted;
  bool bracketed = false;
  bool padded = false;  // every IPv6 group written with 4 digits
  bool upper = false;   // first hex letter in upper case
};

std::optional<TextAddress> parse_ipv4_text(std::string_view text);
// With or without brackets (RFC 3261 §25.1 IPv6reference).
std::optional<TextAddress> parse_ipv6_text(std::string_view text);
std::optional<TextAddress> parse_address_text(std::string_view text);

// Renders the address of `a` in the form class of `a`. A compressed IPv6 address elides its
// longest run of two or more zero groups (the first one on a tie).
std::string format_address(const TextAddress& a);

// The pseudonym of an address written as text, in the input's form class; nullopt when `text`
// is not an address literal.
Result<std::optional<std::string>> map_address_text(std::string_view text, AddressMapper& mapper);

// A port written as decimal text (1 to 5 digits, at most 65535): the transport port policy of
// 001/FR-015. With `pseudonymise_ports` it goes through the feature-001 port mapping (ports
// outside the ephemeral range stay); otherwise it is kept. nullopt when not a port number.
Result<std::optional<std::string>> map_port_text(std::string_view text, AddressMapper& mapper,
                                                 bool pseudonymise_ports);

}  // namespace mcxanon::sip
