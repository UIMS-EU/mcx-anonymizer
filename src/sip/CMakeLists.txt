# SPDX-License-Identifier: GPL-3.0-or-later
#
# SIP, SDP and multipart parsing and rule-driven rewriting. Sees the pseudonymiser only
# through the rewrite::AddressMapper interface (header only).
mcxanon_add_module(sip
  SOURCES message.cpp uri.cpp header_values.cpp sdp.cpp multipart.cpp render.cpp rewrite.cpp
          value_map.cpp stream_framing.cpp
  DEPS bytes policy)
