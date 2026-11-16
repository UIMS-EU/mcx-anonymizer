# SPDX-License-Identifier: GPL-3.0-or-later
cmake_minimum_required(VERSION 3.31)

project(mcxanon
  VERSION 0.1.0
  DESCRIPTION "Anonymizer for Mission Critical (MCX) packet captures"
  LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)

option(MCXANON_BUILD_TESTS "Build unit and integration tests" ON)
# Fuzz targets are enabled automatically when the compiler flags carry libFuzzer
# instrumentation (the container's `fuzz` profile adds -fsanitize=fuzzer-no-link).
if(CMAKE_CXX_FLAGS MATCHES "fuzzer-no-link")
  set(_mcxanon_fuzz_default ON)
else()
  set(_mcxanon_fuzz_default OFF)
endif()
option(MCXANON_BUILD_FUZZ "Build libFuzzer targets (requires Clang and the fuzz profile)"
       ${_mcxanon_fuzz_default})

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(McxanonModule)

find_package(OpenSSL REQUIRED)
find_package(ryml REQUIRED)
find_package(CLI11 REQUIRED)
find_package(nlohmann_json REQUIRED)

# The rule set is data embedded at build time; its name, version and digest go
# into version.hpp.
include(EmbedRules)
set(MCXANON_RULES_CPP "${CMAKE_CURRENT_BINARY_DIR}/generated/ruleset_embedded.cpp")
mcxanon_embed_rules("${MCXANON_RULES_CPP}")

configure_file(include/mcxanon/version.hpp.in
               "${CMAKE_CURRENT_BINARY_DIR}/generated/mcxanon/version.hpp" @ONLY)

add_subdirectory(src)

if(MCXANON_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
