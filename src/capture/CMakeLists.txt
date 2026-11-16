# SPDX-License-Identifier: GPL-3.0-or-later
mcxanon_add_module(capture
  SOURCES detect.cpp pcap.cpp pcapng.cpp reader.cpp writer.cpp
  DEPS bytes)
