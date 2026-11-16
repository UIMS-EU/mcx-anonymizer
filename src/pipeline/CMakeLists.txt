# SPDX-License-Identifier: GPL-3.0-or-later
mcxanon_add_module(pipeline
  SOURCES anonymizer.cpp hold_queue.cpp anonymize_file.cpp output_file.cpp report_builder.cpp tokens.cpp scan_command.cpp
  DEPS capture dissect policy sip media xml mikey stream http tls pseudo rewrite scan report
  EXTERNAL OpenSSL::Crypto)
