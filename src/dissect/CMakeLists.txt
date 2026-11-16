# SPDX-License-Identifier: GPL-3.0-or-later
mcxanon_add_module(dissect
  SOURCES catalogue.cpp fields.cpp link.cpp l3.cpp icmp.cpp l4.cpp tunnel.cpp
  DEPS bytes capture)
