# SPDX-License-Identifier: GPL-3.0-or-later
#
# TLS handshakes in the clear (feature 007): records, handshake messages, hello extensions, key
# exchange structure, and X.509 certificates rewritten in place with our own DER reader and
# writer. Sessions implement stream::Session; the pipeline creates them.
mcxanon_add_module(tls
  SOURCES der.cpp x509.cpp handshake.cpp session.cpp
  DEPS bytes policy sip xml stream)
mcxanon_assert_links_only(mcxanon_tls mcxanon_bytes mcxanon_policy mcxanon_sip mcxanon_xml mcxanon_stream)
