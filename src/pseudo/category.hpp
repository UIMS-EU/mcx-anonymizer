// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "mcxanon/error.hpp"

#include "bytes/bytes.hpp"

#include <string>
#include <string_view>

namespace mcxanon {

// Mapping categories. Each has its own pseudonym range.
enum class Category {
  mac,
  ipv4,
  ipv4_pp,      // prefix-preserving IPv4
  ipv6,
  ipv6_pp,      // prefix-preserving IPv6
  ipv6_iid_ll,  // interface identifier of a link-local IPv6 address
  ipv6_sn24,    // low 24 bits of a solicited-node multicast address
  ipv4_mcast,
  vlan,
  port_eph,
  // Text and numeric categories of feature 002.
  sip_user,
  domain,
  display_name,
  tel,
  call_id,
  tag,
  branch,
  entity_tag,
  charging_id,
  session_id,
  imei,
  uuid,
  cell_id,
  spi,
  ssrc,
  digest,
  sdp_sess,
  boundary,
  msrp_session,
  reg_token,
  cname,
  // Media-plane categories of feature 004.
  fc_ref,      // 32-bit floor / transmission participant reference
  plmn,        // MCC+MNC digits
  eci,         // 28-bit E-UTRAN cell identifier
  tac,         // 16-bit tracking area code
  mbms_sai,    // 16-bit MBMS service area identity
  mbsfn_area,  // 8-bit MBSFN area ID
  msrp_tid,    // MSRP transaction id (RFC 4975 ident)
  msrp_msgid,  // MSRP Message-ID (RFC 4975 ident)
  // XML body categories of feature 003.
  opaque,      // an identifier without a defined grammar: length and character classes kept
  nci,         // 36-bit NR cell identity
  nr_tac,      // 24-bit 5GS tracking area code
  mbs_fsa,     // 24-bit MBS frequency selection area ID
  // Key management categories of feature 005.
  key_id,      // 32-bit key identifier: the 4-bit purpose tag (TS 33.180 Annex G) is kept
  nonce,       // RAND and IV byte strings of 1-255 octets: same-length pseudonym
  uid,         // 32-octet MIKEY-SAKKE UID (TS 33.180 §F.2.1), opaque pseudonym
};

// Values of one family share a value space: an original of the family must
// never equal a pseudonym issued in any category of the same family. Each text
// category is a family of its own, so it never collides with an address family.
enum class Family {
  mac,
  ipv4,
  ipv6,
  ipv6_iid,
  ipv6_sn24,
  vlan,
  port,
  sip_user,
  domain,
  display_name,
  tel,
  call_id,
  tag,
  branch,
  entity_tag,
  charging_id,
  session_id,
  imei,
  uuid,
  cell_id,
  spi,
  ssrc,
  digest,
  sdp_sess,
  boundary,
  msrp_session,
  reg_token,
  cname,
  fc_ref,
  plmn,
  eci,
  tac,
  mbms_sai,
  mbsfn_area,
  msrp_tid,
  msrp_msgid,
  opaque,
  nci,
  nr_tac,
  mbs_fsa,
  key_id,
  nonce,
  uid,
};

// True for the text and numeric categories of features 002 and 004, including the binary
// value categories below.
bool is_text_category(Category c);

// True for the fixed-width binary value categories (SPI, SSRC and the binary media categories):
// their originals and pseudonyms are big-endian integers, not text.
bool is_binary_category(Category c);

// The width in bits of a binary value category (0 for other categories).
unsigned binary_bits(Category c);

// True for the byte-string categories of feature 005 (nonce, uid): their originals and pseudonyms
// are raw octets of any length, neither text nor a fixed-width integer.
bool is_byte_category(Category c);

std::string_view to_string(Category c);
Result<Category> category_from_string(std::string_view s);
Family family_of(Category c);

// A mapping value as `project show-map` prints it: binary categories of up to 32 bits in decimal
// (key-id as 8 hex digits), text as text, addresses in their usual form, anything else as hex.
std::string format_mapping_value(Category c, ByteView b);

}  // namespace mcxanon
