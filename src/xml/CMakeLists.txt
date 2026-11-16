# SPDX-License-Identifier: GPL-3.0-or-later
#
# MCX XML bodies: a span-preserving XML reader, value types, escaping, and the rule-driven
# byte-range rewriter that feature 002 calls through sip::XmlBodies. Reuses the SIP URI and
# value mappings; sees the pseudonymiser only through the rewrite::AddressMapper interface.
mcxanon_add_module(xml
  SOURCES reader.cpp escape.cpp values.cpp rewrite.cpp sip_bodies.cpp categories.cpp xcap.cpp location.cpp
  DEPS bytes policy sip)
mcxanon_assert_links_only(mcxanon_xml mcxanon_bytes mcxanon_policy mcxanon_sip)
