# SPDX-License-Identifier: GPL-3.0-or-later
#
# HTTP/1.1 and HTTP/2 in the clear (feature 007): message framing, request targets and XCAP
# selectors, header fields by the HTTP rule set, OAuth/OIDC parameters, JSON, JWT, cookies,
# bodies by content type (XML through sip::XmlBodies), HPACK. Sessions implement the
# stream::Session interface; the pipeline creates them.
mcxanon_add_module(http
  SOURCES message.cpp target.cpp params.cpp json.cpp jwt.cpp headers.cpp body.cpp session.cpp h2.cpp hpack.cpp hpack_tables.cpp
  DEPS bytes policy sip xml stream)
mcxanon_assert_links_only(mcxanon_http mcxanon_bytes mcxanon_policy mcxanon_sip mcxanon_xml mcxanon_stream)
