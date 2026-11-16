# SPDX-License-Identifier: GPL-3.0-or-later
#
# Internal modules and their dependency direction:
#
#   bytes <- capture <- dissect <- policy <- sip <- rewrite <- pipeline <- (mcxanon) <- cli
#                                          sip <- media <- pipeline
#                                          sip <- xml   <- pipeline
#                                          sip, xml <- mikey <- pipeline  (feature 005; carriers call it via sip::MikeyCarrier)
#                       dissect <- stream <- pipeline
#                    sip, xml, stream <- http <- pipeline  (feature 007; sessions behind stream::Session)
#                    sip, xml, stream <- tls  <- pipeline  (feature 007)
#   bytes <- pseudo  <- pipeline
#   bytes <- scan    <- pipeline        (scan depends on bytes only)
#   bytes <- report  <- pipeline
#   pseudo, scan <- reveal <- (mcxanon)   (reveal reads a project mapping; feature 006)
#
# Each module declares its own sources in its CMakeLists.txt.

add_subdirectory(bytes)
add_subdirectory(capture)
add_subdirectory(dissect)
add_subdirectory(policy)
add_subdirectory(sip)
add_subdirectory(media)
add_subdirectory(xml)
add_subdirectory(mikey)
add_subdirectory(stream)
add_subdirectory(http)
add_subdirectory(tls)
add_subdirectory(pseudo)
add_subdirectory(rewrite)
add_subdirectory(scan)
add_subdirectory(report)
add_subdirectory(pipeline)
add_subdirectory(reveal)

# Public library: the pipeline plus the public headers in include/mcxanon/.
add_library(mcxanon INTERFACE)
target_include_directories(mcxanon INTERFACE "${PROJECT_SOURCE_DIR}/include" "${PROJECT_BINARY_DIR}/generated")
target_link_libraries(mcxanon INTERFACE mcxanon_pipeline mcxanon_pseudo mcxanon_report mcxanon_sip
                                         mcxanon_media mcxanon_xml mcxanon_mikey mcxanon_stream mcxanon_http mcxanon_tls mcxanon_reveal)

add_subdirectory(cli)
