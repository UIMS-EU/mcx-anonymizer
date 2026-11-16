# SPDX-License-Identifier: GPL-3.0-or-later
# Test-only binary; never installed.
add_executable(mcxanon_leaktest leaktest_main.cpp)
target_link_libraries(mcxanon_leaktest PRIVATE mcxanon_pipeline)
mcxanon_set_warnings(mcxanon_leaktest)
