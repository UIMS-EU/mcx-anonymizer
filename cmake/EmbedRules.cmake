# SPDX-License-Identifier: GPL-3.0-or-later
#
# Embeds the rule files into a generated C++ source. Four rule sets live in rules/:
#   - the L2-L4 rule set (mcxanon-l2l4): every rules/*.yaml except the SIP, media and XML files;
#   - the SIP rule set (mcxanon-sip): rules/sip-*.yaml and rules/sdp.yaml;
#   - the media rule set (mcxanon-media): rules/rtp.yaml, rules/rtcp.yaml, rules/rtcp-app.yaml
#     and rules/msrp.yaml;
#   - the XML rule set (mcxanon-xml): rules/xml-*.yaml;
#   - the MIKEY rule set (mcxanon-mikey): rules/mikey.yaml (feature 005);
#   - the HTTP rule set (mcxanon-http): rules/http*.yaml (feature 007);
#   - the TLS rule set (mcxanon-tls): rules/tls.yaml (feature 007).
# For each set it derives the name, version and digest (SHA-256 of the files concatenated
# in name order) and sets MCXANON_RULESET_NAME / _VERSION / _DIGEST,
# MCXANON_SIP_RULESET_NAME / _VERSION / _DIGEST, MCXANON_MEDIA_RULESET_NAME / _VERSION / _DIGEST
# MCXANON_XML_RULESET_NAME / _VERSION / _DIGEST and MCXANON_MIKEY_RULESET_NAME / _VERSION /
# _DIGEST in the parent scope.

function(_mcxanon_rule_entries files array_name out_entries out_name out_version out_digest tag)
  set(combined "")
  set(entries "")
  set(name "")
  set(version "")
  foreach(f IN LISTS files)
    file(READ "${f}" text)
    string(APPEND combined "${text}")
    get_filename_component(base "${f}" NAME)
    if(text MATCHES "\\)mcxrules\"")
      message(FATAL_ERROR "${base} contains the raw-string delimiter")
    endif()
    string(APPEND entries "    {\"${base}\", R\"mcxrules(${text})mcxrules\"},\n")
    if(name STREQUAL "")
      string(REGEX MATCH "(^|\n)ruleset:[ ]*([^\n]+)" _ "${text}")
      set(name "${CMAKE_MATCH_2}")
      string(REGEX MATCH "(^|\n)version:[ ]*([^\n]+)" _ "${text}")
      set(version "${CMAKE_MATCH_2}")
    endif()
  endforeach()
  set(combined_file "${PROJECT_BINARY_DIR}/generated/rules-combined-${tag}.txt")
  file(WRITE "${combined_file}" "${combined}")
  file(SHA256 "${combined_file}" digest)
  set(${out_entries} "const EmbeddedRuleFile ${array_name}[] = {\n${entries}};\n" PARENT_SCOPE)
  set(${out_name} "${name}" PARENT_SCOPE)
  set(${out_version} "${version}" PARENT_SCOPE)
  set(${out_digest} "${digest}" PARENT_SCOPE)
endfunction()

function(mcxanon_embed_rules out_cpp)
  file(GLOB rule_files CONFIGURE_DEPENDS "${PROJECT_SOURCE_DIR}/rules/*.yaml")
  list(SORT rule_files)
  # Re-run configure whenever a rule file changes, so the digests stay current.
  set_property(DIRECTORY "${PROJECT_SOURCE_DIR}" APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${rule_files})
  set(l2l4_files "")
  set(sip_files "")
  set(media_files "")
  set(xml_files "")
  set(mikey_files "")
  set(http_files "")
  set(tls_files "")
  foreach(f IN LISTS rule_files)
    get_filename_component(base "${f}" NAME)
    if(base MATCHES "^sip-.*\\.yaml$" OR base STREQUAL "sdp.yaml")
      list(APPEND sip_files "${f}")
    elseif(base MATCHES "^(rtp|rtcp|rtcp-app|msrp)\\.yaml$")
      list(APPEND media_files "${f}")
    elseif(base MATCHES "^xml-.*\\.yaml$")
      list(APPEND xml_files "${f}")
    elseif(base STREQUAL "mikey.yaml")
      list(APPEND mikey_files "${f}")
    elseif(base MATCHES "^http(-.*)?\\.yaml$")
      list(APPEND http_files "${f}")
    elseif(base STREQUAL "tls.yaml")
      list(APPEND tls_files "${f}")
    else()
      list(APPEND l2l4_files "${f}")
    endif()
  endforeach()
  if(NOT l2l4_files OR NOT sip_files OR NOT media_files OR NOT xml_files OR NOT mikey_files OR NOT http_files
     OR NOT tls_files)
    message(FATAL_ERROR "rules/ needs the L2-L4, SIP, media, XML, MIKEY, HTTP and TLS rule files")
  endif()
  _mcxanon_rule_entries("${l2l4_files}" kFiles l2l4_entries name version digest l2l4)
  _mcxanon_rule_entries("${sip_files}" kSipFiles sip_entries sip_name sip_version sip_digest sip)
  _mcxanon_rule_entries("${media_files}" kMediaFiles media_entries media_name media_version media_digest media)
  _mcxanon_rule_entries("${xml_files}" kXmlFiles xml_entries xml_name xml_version xml_digest xml)
  _mcxanon_rule_entries("${mikey_files}" kMikeyFiles mikey_entries mikey_name mikey_version mikey_digest mikey)
  _mcxanon_rule_entries("${http_files}" kHttpFiles http_entries http_name http_version http_digest http)
  _mcxanon_rule_entries("${tls_files}" kTlsFiles tls_entries tls_name tls_version tls_digest tls)
  file(WRITE "${out_cpp}.in"
    "// Generated from rules/*.yaml - do not edit.\n"
    "#include \"policy/ruleset_embedded.hpp\"\n\n"
    "namespace mcxanon {\n"
    "namespace {\n"
    "${l2l4_entries}"
    "${sip_entries}"
    "${media_entries}"
    "${xml_entries}"
    "${mikey_entries}"
    "${http_entries}"
    "${tls_entries}"
    "}  // namespace\n\n"
    "std::span<const EmbeddedRuleFile> embedded_rule_files() { return kFiles; }\n"
    "std::span<const EmbeddedRuleFile> embedded_sip_rule_files() { return kSipFiles; }\n"
    "std::span<const EmbeddedRuleFile> embedded_media_rule_files() { return kMediaFiles; }\n"
    "std::span<const EmbeddedRuleFile> embedded_xml_rule_files() { return kXmlFiles; }\n"
    "std::span<const EmbeddedRuleFile> embedded_mikey_rule_files() { return kMikeyFiles; }\n"
    "std::span<const EmbeddedRuleFile> embedded_http_rule_files() { return kHttpFiles; }\n"
    "std::span<const EmbeddedRuleFile> embedded_tls_rule_files() { return kTlsFiles; }\n\n"
    "}  // namespace mcxanon\n")
  configure_file("${out_cpp}.in" "${out_cpp}" COPYONLY)
  set(MCXANON_RULESET_NAME "${name}" PARENT_SCOPE)
  set(MCXANON_RULESET_VERSION "${version}" PARENT_SCOPE)
  set(MCXANON_RULESET_DIGEST "${digest}" PARENT_SCOPE)
  set(MCXANON_SIP_RULESET_NAME "${sip_name}" PARENT_SCOPE)
  set(MCXANON_SIP_RULESET_VERSION "${sip_version}" PARENT_SCOPE)
  set(MCXANON_SIP_RULESET_DIGEST "${sip_digest}" PARENT_SCOPE)
  set(MCXANON_MEDIA_RULESET_NAME "${media_name}" PARENT_SCOPE)
  set(MCXANON_MEDIA_RULESET_VERSION "${media_version}" PARENT_SCOPE)
  set(MCXANON_MEDIA_RULESET_DIGEST "${media_digest}" PARENT_SCOPE)
  set(MCXANON_XML_RULESET_NAME "${xml_name}" PARENT_SCOPE)
  set(MCXANON_XML_RULESET_VERSION "${xml_version}" PARENT_SCOPE)
  set(MCXANON_XML_RULESET_DIGEST "${xml_digest}" PARENT_SCOPE)
  set(MCXANON_MIKEY_RULESET_NAME "${mikey_name}" PARENT_SCOPE)
  set(MCXANON_MIKEY_RULESET_VERSION "${mikey_version}" PARENT_SCOPE)
  set(MCXANON_MIKEY_RULESET_DIGEST "${mikey_digest}" PARENT_SCOPE)
  set(MCXANON_HTTP_RULESET_DIGEST "${http_digest}" PARENT_SCOPE)
  set(MCXANON_TLS_RULESET_DIGEST "${tls_digest}" PARENT_SCOPE)
endfunction()
