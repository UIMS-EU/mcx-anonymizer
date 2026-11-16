# SPDX-License-Identifier: GPL-3.0-or-later
find_package(Catch2 3 REQUIRED)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
include(Catch)

# Unit tests (Catch2). Each module adds its test sources here.
add_executable(mcxanon_unit_tests
  unit/crypto_probe_test.cpp
  unit/bytes_test.cpp
  unit/checksum_test.cpp
  unit/pcap_io_test.cpp
  unit/pcapng_io_test.cpp
  unit/rules_loader_test.cpp
  unit/hmac_derivation_test.cpp
  unit/ranges_test.cpp
  unit/mapping_test.cpp
  unit/project_store_plain_test.cpp
  unit/lock_test.cpp
  unit/report_json_test.cpp
  unit/dissect_link_test.cpp
  unit/dissect_ip_test.cpp
  unit/dissect_icmp_ndp_test.cpp
  unit/dissect_transport_test.cpp
  unit/dissect_tunnel_test.cpp
  unit/rewrite_test.cpp
  unit/drop_mode_test.cpp
  unit/pseudonymiser_test.cpp
  unit/rule_coverage_test.cpp
  unit/pipeline_order_test.cpp
  unit/pcapng_metadata_policy_test.cpp
  unit/scan_patterns_test.cpp
  unit/scan_matcher_test.cpp
  unit/scan_walker_test.cpp
  unit/scan_harvest_test.cpp
  unit/scan_pseudonym_test.cpp
  unit/scan_cookie_test.cpp
  unit/denylist_test.cpp
  unit/crypto_container_test.cpp
  unit/passphrase_source_test.cpp
  unit/prefix_preserving_test.cpp
  unit/vlan_ports_test.cpp
  unit/time_shift_test.cpp
  unit/text_pseudonym_test.cpp
  unit/mapping_format2_test.cpp
  unit/sip_rules_test.cpp
  unit/report_format2_test.cpp
  unit/address_mapper_text_test.cpp
  unit/sip_message_test.cpp
  unit/sip_text_address_test.cpp
  unit/sip_uri_test.cpp
  unit/sip_header_values_test.cpp
  unit/sdp_test.cpp
  unit/multipart_test.cpp
  unit/sip_rewrite_test.cpp
  unit/apply_length_test.cpp
  unit/tokens_test.cpp
  unit/sip_vocabulary_test.cpp
  unit/sip_harvest_test.cpp
  unit/sip_harvest_fragment_test.cpp
  unit/hold_queue_test.cpp
  unit/tcp_streams_test.cpp
  unit/fragments_test.cpp
  unit/media_category_test.cpp
  unit/mapping_format3_test.cpp
  unit/media_rules_test.cpp
  unit/media_endpoints_test.cpp
  unit/sdp_announce_test.cpp
  unit/classify_udp_test.cpp
  unit/rtp_test.cpp
  unit/scan_rtp_runs_test.cpp
  unit/rtcp_tiling_test.cpp
  unit/rtcp_app_test.cpp
  unit/location_test.cpp
  unit/app_identity_test.cpp
  unit/rtcp_test.cpp
  unit/media_harvest_test.cpp
  unit/rtcp_app_families_test.cpp
  unit/tcp_protocols_test.cpp
  unit/msrp_test.cpp
  unit/xml_reader_test.cpp
  unit/xml_escape_test.cpp
  unit/xml_values_test.cpp
  unit/xml_category_test.cpp
  unit/mapping_format4_test.cpp
  unit/xml_rules_test.cpp
  unit/xml_rewrite_test.cpp
  unit/xml_prefix_test.cpp
  unit/xml_harvest_test.cpp
  unit/xml_vocabulary_test.cpp
  unit/xml_composite_test.cpp
  unit/xml_xcap_test.cpp
  unit/xml_embedded_test.cpp
  unit/xml_location_test.cpp
  unit/sip_xml_body_test.cpp
  unit/report_format4_test.cpp
  unit/report_self_check_test.cpp
  unit/reveal_index_test.cpp
  unit/reveal_resolve_test.cpp
  unit/reveal_stream_test.cpp
  unit/project_readonly_test.cpp
  unit/reveal_recognise_test.cpp
  unit/reveal_location_test.cpp
  unit/reveal_escape_test.cpp
  unit/reveal_render_test.cpp
  unit/reveal_lookup_test.cpp
  unit/base64_test.cpp
  unit/ntp_shift_test.cpp
  unit/mapping_format5_test.cpp
  unit/mikey_rules_test.cpp
  unit/mikey_decode_test.cpp
  unit/report_format5_test.cpp
  unit/mikey_rewrite_test.cpp
  unit/sdp_key_mgmt_test.cpp
  unit/mikey_harvest_test.cpp
  unit/mikey_carriers_scan_test.cpp
  unit/reveal_mikey_test.cpp
  unit/reveal_web_test.cpp
  unit/mikey_uid_test.cpp
  unit/mikey_carrier_test.cpp
  unit/mikey_keyparams_test.cpp
  unit/srtp_mki_test.cpp
  unit/xml_xenc_test.cpp
  unit/encrypted_uri_test.cpp
  unit/passthrough_locator_test.cpp
  unit/stream_session_test.cpp
  unit/http_rules_test.cpp
  unit/tls_rules_test.cpp
  unit/sip_header_export_test.cpp
  unit/hpack_test.cpp
  unit/http_message_test.cpp
  unit/http_target_test.cpp
  unit/http_params_test.cpp
  unit/h2_test.cpp
  unit/web_harvest_test.cpp
  unit/hpack_strings_test.cpp
  unit/tls_test.cpp
  ${PROJECT_SOURCE_DIR}/src/cli/duration.cpp
  ${PROJECT_SOURCE_DIR}/src/cli/passphrase.cpp)
target_link_libraries(mcxanon_unit_tests PRIVATE
  Catch2::Catch2WithMain OpenSSL::Crypto
  mcxanon mcxanon_bytes mcxanon_capture mcxanon_dissect mcxanon_policy mcxanon_pseudo
  mcxanon_rewrite mcxanon_report mcxanon_pipeline mcxanon_scan mcxanon_sip mcxanon_media mcxanon_xml mcxanon_mikey mcxanon_stream mcxanon_http mcxanon_tls mcxanon_reveal)
target_include_directories(mcxanon_unit_tests PRIVATE
  "${PROJECT_SOURCE_DIR}/include" "${PROJECT_SOURCE_DIR}/src" "${PROJECT_BINARY_DIR}/generated")
mcxanon_set_warnings(mcxanon_unit_tests)
catch_discover_tests(mcxanon_unit_tests PROPERTIES LABELS unit)

# Public API contract: allocation failures never escape as exceptions.
add_executable(mcxanon_public_api_test public_api_test.cpp)
target_link_libraries(mcxanon_public_api_test PRIVATE mcxanon)
add_test(NAME public-api COMMAND mcxanon_public_api_test)
set_tests_properties(public-api PROPERTIES LABELS unit)
add_test(NAME public-headers COMMAND bash "${PROJECT_SOURCE_DIR}/tools/check-public-headers.sh")
set_tests_properties(public-headers PROPERTIES LABELS gate)

# Repository gates.
add_test(NAME licenses
  COMMAND ${Python3_EXECUTABLE} "${PROJECT_SOURCE_DIR}/tools/check-licenses.py"
          --project "${PROJECT_SOURCE_DIR}")
set_tests_properties(licenses PROPERTIES LABELS gate)

add_test(NAME scan-independence
  COMMAND bash "${PROJECT_SOURCE_DIR}/tools/check-scan-independence.sh")
set_tests_properties(scan-independence PROPERTIES LABELS gate)

add_test(NAME spdx-headers COMMAND bash "${PROJECT_SOURCE_DIR}/tools/check-spdx.sh" "${PROJECT_SOURCE_DIR}")
set_tests_properties(spdx-headers PROPERTIES LABELS gate)

add_test(NAME tools-selftest
  COMMAND ${Python3_EXECUTABLE} "${PROJECT_SOURCE_DIR}/tests/integration/test_tools.py")
set_tests_properties(tools-selftest PROPERTIES LABELS unit)

# Report schema conformance: a fully populated report must validate.
add_executable(mcxanon_report_sample report_sample_main.cpp)
target_link_libraries(mcxanon_report_sample PRIVATE mcxanon_report)
add_test(NAME report-schema
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/validate_report.py"
          "${PROJECT_SOURCE_DIR}/schemas/report.schema.json" --command
          $<TARGET_FILE:mcxanon_report_sample>)
set_tests_properties(report-schema PROPERTIES LABELS unit)

# CLI.
if(TARGET mcxanon_cli)
add_test(NAME cli-basic
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_cli_basic.py"
          $<TARGET_FILE:mcxanon_cli>)
set_tests_properties(cli-basic PROPERTIES LABELS integration)
endif()

add_test(NAME fixturegen-selfcheck
  COMMAND ${Python3_EXECUTABLE}
          "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_fixturegen_selfcheck.py")
set_tests_properties(fixturegen-selfcheck PROPERTIES LABELS integration)

if(TARGET mcxanon_cli)
add_test(NAME anonymize-us1
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_anonymize_us1.py"
          $<TARGET_FILE:mcxanon_cli> "${CMAKE_BINARY_DIR}/fixtures")
set_tests_properties(anonymize-us1 PROPERTIES LABELS integration FIXTURES_REQUIRED fixtures)
endif()

if(TARGET mcxanon_cli)
add_test(NAME malformed
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_malformed.py"
          $<TARGET_FILE:mcxanon_cli> "${CMAKE_BINARY_DIR}/fixtures")
set_tests_properties(malformed PROPERTIES LABELS integration FIXTURES_REQUIRED fixtures)
endif()

if(TARGET mcxanon_cli)
add_test(NAME integrity
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_integrity.py"
          $<TARGET_FILE:mcxanon_cli> "${CMAKE_BINARY_DIR}/fixtures")
set_tests_properties(integrity PROPERTIES LABELS integrity FIXTURES_REQUIRED fixtures SKIP_RETURN_CODE 77)
endif()

add_subdirectory(leaktest)
if(TARGET mcxanon_cli)
add_test(NAME scan-gate
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_scan_gate.py"
          $<TARGET_FILE:mcxanon_cli> $<TARGET_FILE:mcxanon_leaktest> "${CMAKE_BINARY_DIR}/fixtures")
set_tests_properties(scan-gate PROPERTIES LABELS integration FIXTURES_REQUIRED fixtures)
endif()

if(TARGET mcxanon_cli)
add_test(NAME scan-corpus
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_scan_corpus.py"
          $<TARGET_FILE:mcxanon_cli>)
set_tests_properties(scan-corpus PROPERTIES LABELS integration)
endif()

if(TARGET mcxanon_cli)
foreach(t project_lifecycle encrypted_project options)
  string(REPLACE "_" "-" name ${t})
  add_test(NAME ${name}
    COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_${t}.py"
            $<TARGET_FILE:mcxanon_cli> "${CMAKE_BINARY_DIR}/fixtures")
  set_tests_properties(${name} PROPERTIES LABELS integration FIXTURES_REQUIRED fixtures)
endforeach()
add_test(NAME consistency
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_consistency.py"
          $<TARGET_FILE:mcxanon_cli>)
set_tests_properties(consistency PROPERTIES LABELS integration)
add_test(NAME sip-udp
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_sip_udp.py"
          $<TARGET_FILE:mcxanon_cli> "${CMAKE_BINARY_DIR}/fixtures")
set_tests_properties(sip-udp PROPERTIES LABELS integration FIXTURES_REQUIRED fixtures)
add_test(NAME media-rtp
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_media_rtp.py"
          $<TARGET_FILE:mcxanon_cli> "${CMAKE_BINARY_DIR}/fixtures")
set_tests_properties(media-rtp PROPERTIES LABELS "integration;integrity" FIXTURES_REQUIRED fixtures)
add_test(NAME media-app
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_media_app.py"
          $<TARGET_FILE:mcxanon_cli> "${CMAKE_BINARY_DIR}/fixtures")
set_tests_properties(media-app PROPERTIES LABELS "integration;integrity" FIXTURES_REQUIRED fixtures)
add_test(NAME media-rtcp
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_media_rtcp.py"
          $<TARGET_FILE:mcxanon_cli> "${CMAKE_BINARY_DIR}/fixtures")
set_tests_properties(media-rtcp PROPERTIES LABELS "integration;integrity" FIXTURES_REQUIRED fixtures)
add_test(NAME media-msrp
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_media_msrp.py"
          $<TARGET_FILE:mcxanon_cli> "${CMAKE_BINARY_DIR}/fixtures")
set_tests_properties(media-msrp PROPERTIES LABELS "integration;integrity" FIXTURES_REQUIRED fixtures)
add_test(NAME media-failclosed
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_media_failclosed.py"
          $<TARGET_FILE:mcxanon_cli> "${CMAKE_BINARY_DIR}/fixtures")
set_tests_properties(media-failclosed PROPERTIES LABELS integration FIXTURES_REQUIRED fixtures)
add_test(NAME sip-tcp
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_sip_tcp.py"
          $<TARGET_FILE:mcxanon_cli> "${CMAKE_BINARY_DIR}/fixtures")
set_tests_properties(sip-tcp PROPERTIES LABELS "integration;integrity" FIXTURES_REQUIRED fixtures)
add_test(NAME sip-fragments
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_sip_fragments.py"
          $<TARGET_FILE:mcxanon_cli> "${CMAKE_BINARY_DIR}/fixtures")
set_tests_properties(sip-fragments PROPERTIES LABELS "integration;integrity" FIXTURES_REQUIRED fixtures)
add_test(NAME sip-report
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_sip_report.py"
          $<TARGET_FILE:mcxanon_cli> "${CMAKE_BINARY_DIR}/fixtures")
set_tests_properties(sip-report PROPERTIES LABELS integration FIXTURES_REQUIRED fixtures)
# Feature 008: the patterns of the first pilot on third-party captures.
add_test(NAME pilot-fixes
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_pilot_fixes.py"
          $<TARGET_FILE:mcxanon_cli> "${CMAKE_BINARY_DIR}/fixtures")
set_tests_properties(pilot-fixes PROPERTIES LABELS "integration;integrity" FIXTURES_REQUIRED fixtures)
# The 256 MiB bound (SC-005) is measured on release builds only; sanitizers multiply RSS.
if(CMAKE_BUILD_TYPE STREQUAL "Release")
  set(MCXANON_BOUNDS_RSS "")
else()
  set(MCXANON_BOUNDS_RSS "--no-rss")
endif()
add_test(NAME sip-bounds
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_sip_bounds.py"
          $<TARGET_FILE:mcxanon_cli> ${MCXANON_BOUNDS_RSS})
set_tests_properties(sip-bounds PROPERTIES LABELS integration TIMEOUT 1800)
foreach(m consistency cross-capture)
  add_test(NAME sip-${m}
    COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_sip_consistency.py"
            $<TARGET_FILE:mcxanon_cli> "${CMAKE_BINARY_DIR}/fixtures" ${m})
  set_tests_properties(sip-${m} PROPERTIES LABELS integration FIXTURES_REQUIRED fixtures)
endforeach()
foreach(m canary unknown malformed)
  add_test(NAME sip-${m}
    COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_sip_failclosed.py"
            $<TARGET_FILE:mcxanon_cli> "${CMAKE_BINARY_DIR}/fixtures" ${m})
  set_tests_properties(sip-${m} PROPERTIES LABELS integration FIXTURES_REQUIRED fixtures)
endforeach()
# Feature 003, User Story 6: hostile, unknown or broken XML bodies (the 1 s bound in Release only).
if(CMAKE_BUILD_TYPE STREQUAL "Release")
  set(MCXANON_XML_TIME "")
else()
  set(MCXANON_XML_TIME "--no-time")
endif()
add_test(NAME xml-failclosed
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_xml_failclosed.py"
          $<TARGET_FILE:mcxanon_cli> "${CMAKE_BINARY_DIR}/fixtures" ${MCXANON_XML_TIME})
set_tests_properties(xml-failclosed PROPERTIES LABELS integration FIXTURES_REQUIRED fixtures)
add_test(NAME xml-mcptt
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_xml_mcptt.py"
          $<TARGET_FILE:mcxanon_cli> "${CMAKE_BINARY_DIR}/fixtures")
set_tests_properties(xml-mcptt PROPERTIES LABELS integration FIXTURES_REQUIRED fixtures)
foreach(t ietf embedded location mcx security)
  add_test(NAME xml-${t}
    COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_xml_${t}.py"
            $<TARGET_FILE:mcxanon_cli> "${CMAKE_BINARY_DIR}/fixtures")
  set_tests_properties(xml-${t} PROPERTIES LABELS integration FIXTURES_REQUIRED fixtures)
endforeach()
add_test(NAME determinism
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_determinism.py"
          $<TARGET_FILE:mcxanon_cli> "${CMAKE_BINARY_DIR}/fixtures")
set_tests_properties(determinism PROPERTIES LABELS integration FIXTURES_REQUIRED fixtures)
add_test(NAME demo-capture
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_demo_capture.py"
          $<TARGET_FILE:mcxanon_cli> "${CMAKE_BINARY_DIR}/fixtures")
set_tests_properties(demo-capture PROPERTIES LABELS integration FIXTURES_REQUIRED fixtures)
endif()

if(TARGET mcxanon_cli)
# Feature 006: reveal and lookup.
add_test(NAME reveal-cli
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_reveal.py"
          $<TARGET_FILE:mcxanon_cli> "${CMAKE_BINARY_DIR}/fixtures")
set_tests_properties(reveal-cli PROPERTIES LABELS integration FIXTURES_REQUIRED fixtures)
add_test(NAME reveal-demo
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_reveal_demo.py"
          $<TARGET_FILE:mcxanon_cli>)
set_tests_properties(reveal-demo PROPERTIES LABELS integration)
add_test(NAME reveal-ambiguity
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_reveal_ambiguity.py"
          $<TARGET_FILE:mcxanon_cli> "${CMAKE_BINARY_DIR}/fixtures")
set_tests_properties(reveal-ambiguity PROPERTIES LABELS integration FIXTURES_REQUIRED fixtures)
add_test(NAME lookup
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_lookup.py" $<TARGET_FILE:mcxanon_cli>)
set_tests_properties(lookup PROPERTIES LABELS integration)
add_test(NAME reveal-control
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_reveal_control.py"
          $<TARGET_FILE:mcxanon_cli>)
set_tests_properties(reveal-control PROPERTIES LABELS integration)
add_test(NAME reveal-tshark
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_reveal_tshark.py"
          $<TARGET_FILE:mcxanon_cli>)
set_tests_properties(reveal-tshark PROPERTIES LABELS integrity SKIP_RETURN_CODE 77)
endif()

if(TARGET mcxanon_cli)
# Feature 005: MIKEY-SAKKE key management.
add_test(NAME mikey-sdp
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_mikey_sdp.py"
          $<TARGET_FILE:mcxanon_cli> "${CMAKE_BINARY_DIR}/fixtures")
set_tests_properties(mikey-sdp PROPERTIES LABELS integration FIXTURES_REQUIRED fixtures)
add_test(NAME mikey-tshark
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_mikey_sdp.py"
          $<TARGET_FILE:mcxanon_cli> "${CMAKE_BINARY_DIR}/fixtures" --tshark)
set_tests_properties(mikey-tshark PROPERTIES LABELS integrity FIXTURES_REQUIRED fixtures SKIP_RETURN_CODE 77)
add_test(NAME mikey-hostile
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_mikey_hostile.py"
          $<TARGET_FILE:mcxanon_cli> "${CMAKE_BINARY_DIR}/fixtures")
set_tests_properties(mikey-hostile PROPERTIES LABELS integration FIXTURES_REQUIRED fixtures)
add_test(NAME mikey-hidden
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_mikey_hidden.py"
          $<TARGET_FILE:mcxanon_cli> "${CMAKE_BINARY_DIR}/fixtures")
set_tests_properties(mikey-hidden PROPERTIES LABELS integration FIXTURES_REQUIRED fixtures)
add_test(NAME mikey-body
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_mikey_body.py"
          $<TARGET_FILE:mcxanon_cli> "${CMAKE_BINARY_DIR}/fixtures")
set_tests_properties(mikey-body PROPERTIES LABELS integration FIXTURES_REQUIRED fixtures)
add_test(NAME mikey-gktp
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_mikey_gktp.py"
          $<TARGET_FILE:mcxanon_cli> "${CMAKE_BINARY_DIR}/fixtures")
set_tests_properties(mikey-gktp PROPERTIES LABELS integration FIXTURES_REQUIRED fixtures)
add_test(NAME mikey-mcpc
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_mikey_mcpc.py"
          $<TARGET_FILE:mcxanon_cli> "${CMAKE_BINARY_DIR}/fixtures")
set_tests_properties(mikey-mcpc PROPERTIES LABELS integration FIXTURES_REQUIRED fixtures)
add_test(NAME mikey-srtp
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_mikey_srtp.py"
          $<TARGET_FILE:mcxanon_cli> "${CMAKE_BINARY_DIR}/fixtures")
set_tests_properties(mikey-srtp PROPERTIES LABELS integration FIXTURES_REQUIRED fixtures)
add_test(NAME mikey-xenc
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_mikey_xenc.py"
          $<TARGET_FILE:mcxanon_cli> "${CMAKE_BINARY_DIR}/fixtures")
set_tests_properties(mikey-xenc PROPERTIES LABELS integration FIXTURES_REQUIRED fixtures)
add_test(NAME mikey-passthrough
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_mikey_passthrough.py"
          $<TARGET_FILE:mcxanon_cli> "${CMAKE_BINARY_DIR}/fixtures")
set_tests_properties(mikey-passthrough PROPERTIES LABELS integration FIXTURES_REQUIRED fixtures)
endif()

if(TARGET mcxanon_cli)
add_test(NAME offline
  COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_offline.sh" $<TARGET_FILE:mcxanon_cli>
          "${CMAKE_BINARY_DIR}/fixtures")
set_tests_properties(offline PROPERTIES LABELS integration FIXTURES_REQUIRED fixtures)
endif()

if(TARGET mcxanon_cli)
add_test(NAME perf-1gb
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/perf/test_perf_1gb.py" $<TARGET_FILE:mcxanon_cli>)
set_tests_properties(perf-1gb PROPERTIES LABELS perf SKIP_RETURN_CODE 77 TIMEOUT 900)
add_test(NAME sip-perf
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/perf/test_perf_sip.py" $<TARGET_FILE:mcxanon_cli>)
set_tests_properties(sip-perf PROPERTIES LABELS perf SKIP_RETURN_CODE 77 TIMEOUT 1200)
add_test(NAME media-perf
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/perf/test_perf_media.py" $<TARGET_FILE:mcxanon_cli>)
set_tests_properties(media-perf PROPERTIES LABELS perf SKIP_RETURN_CODE 77 TIMEOUT 1200)
add_test(NAME reveal-perf
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/perf/test_perf_reveal.py" $<TARGET_FILE:mcxanon_cli>)
set_tests_properties(reveal-perf PROPERTIES LABELS perf SKIP_RETURN_CODE 77 TIMEOUT 600)
add_test(NAME xml-perf
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/perf/test_perf_xml.py" $<TARGET_FILE:mcxanon_cli>)
set_tests_properties(xml-perf PROPERTIES LABELS perf SKIP_RETURN_CODE 77 TIMEOUT 1200)
add_test(NAME perf-mikey
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/perf/test_perf_mikey.py" $<TARGET_FILE:mcxanon_cli>)
set_tests_properties(perf-mikey PROPERTIES LABELS perf SKIP_RETURN_CODE 77 TIMEOUT 1800)
# Feature 007 SC-006: the 002 perf capture with HTTP and TLS (RLIMIT_AS 4 GiB in the driver).
add_test(NAME perf-web
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/perf/test_perf_web.py" $<TARGET_FILE:mcxanon_cli>)
set_tests_properties(perf-web PROPERTIES LABELS perf SKIP_RETURN_CODE 77 TIMEOUT 1800)
endif()

# The keys of every SIP rule that changes a value, from the embedded rule set.
add_executable(mcxanon_sip_rule_keys sip_rule_keys_main.cpp)
target_link_libraries(mcxanon_sip_rule_keys PRIVATE mcxanon_policy)
target_include_directories(mcxanon_sip_rule_keys PRIVATE "${PROJECT_SOURCE_DIR}/src" "${PROJECT_BINARY_DIR}/generated")
mcxanon_set_warnings(mcxanon_sip_rule_keys)
add_executable(mcxanon_media_rule_keys media_rule_keys_main.cpp)
target_link_libraries(mcxanon_media_rule_keys PRIVATE mcxanon_policy)
target_include_directories(mcxanon_media_rule_keys PRIVATE "${PROJECT_SOURCE_DIR}/src" "${PROJECT_BINARY_DIR}/generated")
mcxanon_set_warnings(mcxanon_media_rule_keys)
add_executable(mcxanon_http_rule_keys http_rule_keys_main.cpp)
target_link_libraries(mcxanon_http_rule_keys PRIVATE mcxanon_policy)
target_include_directories(mcxanon_http_rule_keys PRIVATE "${PROJECT_SOURCE_DIR}/src" "${PROJECT_BINARY_DIR}/generated")
mcxanon_set_warnings(mcxanon_http_rule_keys)
add_executable(mcxanon_tls_rule_keys tls_rule_keys_main.cpp)
target_link_libraries(mcxanon_tls_rule_keys PRIVATE mcxanon_policy)
target_include_directories(mcxanon_tls_rule_keys PRIVATE "${PROJECT_SOURCE_DIR}/src" "${PROJECT_BINARY_DIR}/generated")
mcxanon_set_warnings(mcxanon_tls_rule_keys)
add_executable(mcxanon_mikey_rule_keys mikey_rule_keys_main.cpp)
target_link_libraries(mcxanon_mikey_rule_keys PRIVATE mcxanon_policy)
target_include_directories(mcxanon_mikey_rule_keys PRIVATE "${PROJECT_SOURCE_DIR}/src" "${PROJECT_BINARY_DIR}/generated")
mcxanon_set_warnings(mcxanon_mikey_rule_keys)
add_executable(mcxanon_xml_rule_keys xml_rule_keys_main.cpp)
target_link_libraries(mcxanon_xml_rule_keys PRIVATE mcxanon_policy)
target_include_directories(mcxanon_xml_rule_keys PRIVATE "${PROJECT_SOURCE_DIR}/src" "${PROJECT_BINARY_DIR}/generated")
mcxanon_set_warnings(mcxanon_xml_rule_keys)
add_test(NAME rule-canary-coverage
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_rule_canary_coverage.py"
          "${CMAKE_BINARY_DIR}/fixtures" $<TARGET_FILE:mcxanon_sip_rule_keys> $<TARGET_FILE:mcxanon_media_rule_keys>
          $<TARGET_FILE:mcxanon_xml_rule_keys> $<TARGET_FILE:mcxanon_mikey_rule_keys>
          $<TARGET_FILE:mcxanon_http_rule_keys> $<TARGET_FILE:mcxanon_tls_rule_keys>)
set_tests_properties(rule-canary-coverage PROPERTIES LABELS integration FIXTURES_REQUIRED fixtures)

# Synthetic fixtures are generated at test time into the build tree; nothing is
# committed. Integration tests that need them declare FIXTURES_REQUIRED fixtures.
set(MCXANON_FIXTURE_DIR "${CMAKE_BINARY_DIR}/fixtures")
if(TARGET mcxanon_cli)
# Feature 007: HTTP and h2c (User Story 1).
add_test(NAME http-xcap
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_http_xcap.py"
          $<TARGET_FILE:mcxanon_cli> "${CMAKE_BINARY_DIR}/fixtures")
set_tests_properties(http-xcap PROPERTIES LABELS "integration;integrity" FIXTURES_REQUIRED fixtures)

add_test(NAME http-oauth
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_http_oauth.py"
          $<TARGET_FILE:mcxanon_cli> "${CMAKE_BINARY_DIR}/fixtures")
set_tests_properties(http-oauth PROPERTIES LABELS integration FIXTURES_REQUIRED fixtures)

add_test(NAME tls-hello
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_tls_hello.py"
          $<TARGET_FILE:mcxanon_cli> "${CMAKE_BINARY_DIR}/fixtures")
set_tests_properties(tls-hello PROPERTIES LABELS "integration;integrity" FIXTURES_REQUIRED fixtures)

add_test(NAME web-scan
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_web_scan.py"
          $<TARGET_FILE:mcxanon_cli> $<TARGET_FILE:mcxanon_leaktest> "${CMAKE_BINARY_DIR}/fixtures")
set_tests_properties(web-scan PROPERTIES LABELS integration FIXTURES_REQUIRED fixtures)

# Feature 007, User Story 5: hostile HTTP and TLS under a memory limit (the time bound in Release only).
add_test(NAME web-hostile
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_web_hostile.py"
          $<TARGET_FILE:mcxanon_cli> "${CMAKE_BINARY_DIR}/fixtures" ${MCXANON_XML_TIME})
set_tests_properties(web-hostile PROPERTIES LABELS integration FIXTURES_REQUIRED fixtures)

# Feature 007, User Story 4: reveal of the tshark exports of HTTP and TLS (needs tshark).
add_test(NAME web-reveal
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_web_reveal.py"
          $<TARGET_FILE:mcxanon_cli> "${CMAKE_BINARY_DIR}/fixtures")
set_tests_properties(web-reveal PROPERTIES LABELS integrity FIXTURES_REQUIRED fixtures SKIP_RETURN_CODE 77)

# Feature 007: the demo oracle (SC-001, SC-003, SC-004; needs tshark).
add_test(NAME web-demo
  COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_web_demo.py" $<TARGET_FILE:mcxanon_cli>)
set_tests_properties(web-demo PROPERTIES LABELS integrity SKIP_RETURN_CODE 77)
endif()

add_test(NAME generate-fixtures
  COMMAND ${Python3_EXECUTABLE} "${PROJECT_SOURCE_DIR}/tools/fixturegen/gen.py"
          --out "${MCXANON_FIXTURE_DIR}" --seed 1)
set_tests_properties(generate-fixtures PROPERTIES FIXTURES_SETUP fixtures LABELS integration)

# Labels: unit, integration, integrity (needs tshark), perf, fuzz-smoke, gate.
# Perf tests return 77 (skipped) unless MCXANON_RUN_PERF=1 is set, so the default
# test run stays fast; integrity tests return 77 when tshark is absent unless
# MCXANON_REQUIRE_TSHARK=1 is set.
set(MCXANON_SKIP_CODE 77)

if(MCXANON_BUILD_FUZZ)
  add_subdirectory(fuzz)
endif()
