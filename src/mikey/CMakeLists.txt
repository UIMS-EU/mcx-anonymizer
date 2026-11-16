# SPDX-License-Identifier: GPL-3.0-or-later
#
# MIKEY-SAKKE (feature 005): bounded parsing, rule-driven rewriting and re-encoding of the
# I_MESSAGEs carried in SDP a=key-mgmt, application/mikey bodies, <GKTP> elements and the MCPC
# PCK I_MESSAGE field. The carriers reach it only through sip::MikeyCarrier; the pseudonymiser
# is seen only through the rewrite::AddressMapper interface (header only).
mcxanon_add_module(mikey
  SOURCES decode.cpp encode.cpp rewrite.cpp carrier.cpp uid.cpp keyparams.cpp ledger.cpp rewriter.cpp
  DEPS bytes policy sip xml
  EXTERNAL OpenSSL::Crypto)
mcxanon_assert_links_only(mcxanon_mikey mcxanon_bytes mcxanon_policy mcxanon_sip mcxanon_xml OpenSSL::Crypto)
