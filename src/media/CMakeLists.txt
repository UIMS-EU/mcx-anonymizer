# SPDX-License-Identifier: GPL-3.0-or-later
#
# Media plane: RTP, RTCP, MCX RTCP APP and MSRP decoding and rule-driven rewriting, and the
# table of media endpoints announced by SDP. Sees the pseudonymiser only through the
# rewrite::AddressMapper interface (header only), and reuses the SIP URI and path mappings.
mcxanon_add_module(media
  SOURCES endpoints.cpp rtp.cpp rtcp.cpp app.cpp location.cpp msrp.cpp mki.cpp
  DEPS bytes policy sip)
mcxanon_assert_links_only(mcxanon_media mcxanon_bytes mcxanon_policy mcxanon_sip)
