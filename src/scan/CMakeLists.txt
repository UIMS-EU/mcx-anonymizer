# SPDX-License-Identifier: GPL-3.0-or-later
#
# The residual-leak scanner is an independent code path: it may depend on the
# bytes helpers only, never on the capture readers, dissectors, policy,
# pseudonymiser or rewriter. Enforced here at configure time and by
# tools/check-scan-independence.sh for includes.
mcxanon_add_module(scan
  SOURCES patterns.cpp matcher.cpp scan_file.cpp denylist.cpp
          walker/framing.cpp walker/headers.cpp walker/harvest.cpp
          walker/sip_harvest.cpp walker/sip_vocabulary.cpp walker/media_harvest.cpp
          walker/xml_harvest.cpp walker/xml_vocabulary.cpp walker/mikey_harvest.cpp walker/mikey_carriers.cpp
          walker/passthrough.cpp walker/web_harvest.cpp walker/web_carriers.cpp walker/hpack_strings.cpp
          walker/hpack_strings_table.cpp
  DEPS bytes)

mcxanon_assert_links_only(mcxanon_scan mcxanon_bytes)
