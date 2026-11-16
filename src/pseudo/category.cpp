// SPDX-License-Identifier: GPL-3.0-or-later
#include "pseudo/category.hpp"

#include <array>
#include <string>
#include <utility>

namespace mcxanon {
namespace {
constexpr std::array<std::pair<Category, std::string_view>, 46> kNames{{
    {Category::mac, "mac"},
    {Category::ipv4, "ipv4"},
    {Category::ipv4_pp, "ipv4-pp"},
    {Category::ipv6, "ipv6"},
    {Category::ipv6_pp, "ipv6-pp"},
    {Category::ipv6_iid_ll, "ipv6-iid-ll"},
    {Category::ipv6_sn24, "ipv6-sn24"},
    {Category::ipv4_mcast, "ipv4-mcast"},
    {Category::vlan, "vlan"},
    {Category::port_eph, "port-eph"},
    {Category::sip_user, "sip-user"},
    {Category::domain, "domain"},
    {Category::display_name, "display-name"},
    {Category::tel, "tel"},
    {Category::call_id, "call-id"},
    {Category::tag, "tag"},
    {Category::branch, "branch"},
    {Category::entity_tag, "entity-tag"},
    {Category::charging_id, "charging-id"},
    {Category::session_id, "session-id"},
    {Category::imei, "imei"},
    {Category::uuid, "uuid"},
    {Category::cell_id, "cell-id"},
    {Category::spi, "spi"},
    {Category::ssrc, "ssrc"},
    {Category::digest, "digest"},
    {Category::sdp_sess, "sdp-sess"},
    {Category::boundary, "boundary"},
    {Category::msrp_session, "msrp-session"},
    {Category::reg_token, "reg-token"},
    {Category::cname, "cname"},
    {Category::fc_ref, "fc-ref"},
    {Category::plmn, "plmn"},
    {Category::eci, "eci"},
    {Category::tac, "tac"},
    {Category::mbms_sai, "mbms-sai"},
    {Category::mbsfn_area, "mbsfn-area"},
    {Category::msrp_tid, "msrp-tid"},
    {Category::msrp_msgid, "msrp-msgid"},
    {Category::opaque, "opaque"},
    {Category::nci, "nci"},
    {Category::nr_tac, "nr-tac"},
    {Category::mbs_fsa, "mbs-fsa"},
    {Category::key_id, "key-id"},
    {Category::nonce, "nonce"},
    {Category::uid, "uid"},
}};
}  // namespace

std::string_view to_string(Category c) {
  for (const auto& [cat, name] : kNames) {
    if (cat == c) return name;
  }
  return "?";
}

Result<Category> category_from_string(std::string_view s) {
  for (const auto& [cat, name] : kNames) {
    if (name == s) return cat;
  }
  return fail(ErrorCode::input, "unknown mapping category '" + std::string(s) + "'");
}

Family family_of(Category c) {
  switch (c) {
    case Category::mac: return Family::mac;
    case Category::ipv4:
    case Category::ipv4_pp:
    case Category::ipv4_mcast: return Family::ipv4;
    case Category::ipv6:
    case Category::ipv6_pp: return Family::ipv6;
    case Category::ipv6_iid_ll: return Family::ipv6_iid;
    case Category::ipv6_sn24: return Family::ipv6_sn24;
    case Category::vlan: return Family::vlan;
    case Category::port_eph: return Family::port;
    case Category::sip_user: return Family::sip_user;
    case Category::domain: return Family::domain;
    case Category::display_name: return Family::display_name;
    case Category::tel: return Family::tel;
    case Category::call_id: return Family::call_id;
    case Category::tag: return Family::tag;
    case Category::branch: return Family::branch;
    case Category::entity_tag: return Family::entity_tag;
    case Category::charging_id: return Family::charging_id;
    case Category::session_id: return Family::session_id;
    case Category::imei: return Family::imei;
    case Category::uuid: return Family::uuid;
    case Category::cell_id: return Family::cell_id;
    case Category::spi: return Family::spi;
    case Category::ssrc: return Family::ssrc;
    case Category::digest: return Family::digest;
    case Category::sdp_sess: return Family::sdp_sess;
    case Category::boundary: return Family::boundary;
    case Category::msrp_session: return Family::msrp_session;
    case Category::reg_token: return Family::reg_token;
    case Category::cname: return Family::cname;
    case Category::fc_ref: return Family::fc_ref;
    case Category::plmn: return Family::plmn;
    case Category::eci: return Family::eci;
    case Category::tac: return Family::tac;
    case Category::mbms_sai: return Family::mbms_sai;
    case Category::mbsfn_area: return Family::mbsfn_area;
    case Category::msrp_tid: return Family::msrp_tid;
    case Category::msrp_msgid: return Family::msrp_msgid;
    case Category::opaque: return Family::opaque;
    case Category::nci: return Family::nci;
    case Category::nr_tac: return Family::nr_tac;
    case Category::mbs_fsa: return Family::mbs_fsa;
    case Category::key_id: return Family::key_id;
    case Category::nonce: return Family::nonce;
    case Category::uid: return Family::uid;
  }
  return Family::mac;
}

bool is_byte_category(Category c) { return c == Category::nonce || c == Category::uid; }

bool is_text_category(Category c) {
  return static_cast<int>(c) >= static_cast<int>(Category::sip_user) && c != Category::key_id &&
         !is_byte_category(c);
}

unsigned binary_bits(Category c) {
  switch (c) {
    case Category::spi:
    case Category::ssrc:
    case Category::fc_ref:
    case Category::key_id: return 32;
    case Category::nci: return 36;
    case Category::eci: return 28;
    case Category::nr_tac:
    case Category::mbs_fsa: return 24;
    case Category::tac:
    case Category::mbms_sai: return 16;
    case Category::mbsfn_area: return 8;
    default: return 0;
  }
}

bool is_binary_category(Category c) { return binary_bits(c) != 0; }

}  // namespace mcxanon
