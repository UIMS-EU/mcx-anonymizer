#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# CI build inside the .ci image: conan install + CMake configure + build (+ tests).
# Usage: .ci/build.sh PROFILE [test]
set -euo pipefail
profile="${1:-gcc14}"
type=Release
[[ "$profile" == asan || "$profile" == fuzz ]] && type=Debug
conan install . --build=missing -pr:h "$profile" -pr:b gcc14 -s compiler.cppstd=23 -s "build_type=$type"
preset="conan-$(echo "$type" | tr '[:upper:]' '[:lower:]')"
cmake --preset "$preset"
cmake --build --preset "$preset"
if [[ "${2:-}" == test ]]; then
  ctest --preset "$preset" --output-on-failure
fi
