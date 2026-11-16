# SPDX-License-Identifier: GPL-3.0-or-later
#
# Transport stream state: TCP offset maps and IP fragment reassembly.
mcxanon_add_module(stream
  SOURCES tcp.cpp fragments.cpp
  DEPS bytes dissect)
