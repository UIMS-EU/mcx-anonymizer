// SPDX-License-Identifier: GPL-3.0-or-later
//
// Location identities in their XML text forms: each component maps with the 004 category of the same value
// (plmn, eci, tac, mbms_sai, mbsfn_area) or the 003 ones (nci, nr_tac, mbs_fsa) and is written
// back in the field's form.
//   ecgi        6 decimal digits (MCC+MNC) + 28 binary digits (ECI)
//   ncgi        6 decimal digits + 36 binary digits (NCI)
//   tai         6 decimal digits + 16 binary digits (TAC)
//   tac_bin     a 5GS TAC alone: 4 hex digits (tac) or 6 hex digits (nr_tac), letter case kept
//   plmn        6 decimal digits (the XML PLMN is always 6 digits, P4)
//   mbms_sai    decimal 0..65535, written without padding (P3)
//   mbsfn_area  decimal 0..255, written without padding (P3)
//   mbs_fsa, nr_tac  6 hex digits, letter case kept
//   mbms_sai_hex     an MBMS SAI as exactly 4 hex digits (usage documents, X4)
//   ssrc, fc_ref     decimal text of xs:unsignedLong up to 4294967295 (floor request, A14),
//                    with the 002/004 SSRC and 004 floor-control reference mappings
#pragma once

#include "mcxanon/error.hpp"

#include "policy/xml_rules.hpp"
#include "rewrite/address_mapper.hpp"

#include <optional>
#include <string>
#include <string_view>

namespace mcxanon::xml {

// True for the categories this file handles.
bool is_location_category(XmlCategory c);

// nullopt when the value does not have the category's form.
Result<std::optional<std::string>> map_location(XmlCategory c, std::string_view v, AddressMapper& mapper);

}  // namespace mcxanon::xml
