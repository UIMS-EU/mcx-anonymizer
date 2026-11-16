// SPDX-License-Identifier: GPL-3.0-or-later
//
// A bounded DER reader and writer for X.509 (feature 007): definite lengths only,
// single-octet tags only (every tag X.509 uses), depth at most 32 and at most 4096 nodes; the
// writer emits minimal lengths, so a tree read and written unchanged gives the same octets.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace mcxanon::tls::der {

// Universal tags and the class / constructed bits (X.690 §8.1.2).
inline constexpr std::uint8_t kInteger = 0x02, kBitString = 0x03, kOctetString = 0x04, kNull = 0x05, kOid = 0x06,
                              kUtf8 = 0x0c, kPrintable = 0x13, kT61 = 0x14, kIa5 = 0x16, kUtc = 0x17,
                              kGeneralized = 0x18, kVisible = 0x1a, kUniversal = 0x1c, kBmp = 0x1e, kBoolean = 0x01,
                              kSequence = 0x30, kSet = 0x31;

struct Node {
  std::uint8_t tag = 0;
  std::string content;          // primitive
  std::vector<Node> children;   // constructed
  [[nodiscard]] bool constructed() const { return (tag & 0x20) != 0; }
};

// nullopt on any violation of DER framing or of the bounds; `exact` requires the whole input to be
// one element.
std::optional<Node> parse(std::string_view b, bool exact = true);
std::string write(const Node& n);

// Dotted decimal of an OBJECT IDENTIFIER's content; empty when malformed.
std::string oid_text(std::string_view content);
bool is_string_type(std::uint8_t tag);

}  // namespace mcxanon::tls::der
