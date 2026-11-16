# SPDX-License-Identifier: GPL-3.0-or-later
mcxanon_add_module(rewrite
  SOURCES checksum.cpp apply.cpp pcapng_meta.cpp
  DEPS bytes capture dissect policy)
