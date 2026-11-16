# SPDX-License-Identifier: GPL-3.0-or-later
mcxanon_add_module(policy
  SOURCES ruleset.cpp decide.cpp sip_rules.cpp media_rules.cpp xml_rules.cpp mikey_rules.cpp http_rules.cpp tls_rules.cpp "${MCXANON_RULES_CPP}"
  DEPS dissect
  EXTERNAL ryml::ryml OpenSSL::Crypto)
# The embedded rule files are raw string literals; the XML location rules exceed the 65,536
# characters C++ guarantees, which every supported compiler accepts but clang reports under
# -Wpedantic (-Woverlength-strings).
set_source_files_properties("${MCXANON_RULES_CPP}" PROPERTIES
  COMPILE_OPTIONS "$<$<CXX_COMPILER_ID:Clang>:-Wno-overlength-strings>")
