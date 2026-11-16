# SPDX-License-Identifier: GPL-3.0-or-later
add_executable(mcxanon_cli main.cpp cmd_project.cpp cmd_anonymize.cpp cmd_scan.cpp cmd_reveal.cpp duration.cpp passphrase.cpp)
set_target_properties(mcxanon_cli PROPERTIES OUTPUT_NAME mcxanon)
target_include_directories(mcxanon_cli PRIVATE "${PROJECT_SOURCE_DIR}/src")
target_link_libraries(mcxanon_cli PRIVATE mcxanon mcxanon_pseudo mcxanon_reveal CLI11::CLI11)
mcxanon_set_warnings(mcxanon_cli)
