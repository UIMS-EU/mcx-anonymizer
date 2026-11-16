#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Independence gate for the residual-leak scanner.
#
# The scanner must not reuse any parser, dissector or rewriter of the anonymiser,
# so a defect there cannot hide its own leak. This script rejects any include in
# src/scan/ of a header from another module (except bytes/) or of a public header
# other than mcxanon/scan.hpp and mcxanon/error.hpp.
# The link-level part of the gate is enforced at configure time in
# src/scan/CMakeLists.txt.
#
# Usage: tools/check-scan-independence.sh [--root DIR]
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "${1:-}" == "--root" ]]; then
  root="$2"
fi

scan_dir="$root/src/scan"
if [[ ! -d "$scan_dir" ]]; then
  echo "check-scan-independence: $scan_dir not found" >&2
  exit 2
fi

forbidden_modules='capture|dissect|policy|rewrite|pseudo|pipeline|report|cli|sip|stream|media|xml|mikey|http|tls'
forbidden_public='mcxanon/(anonymize|project|report|version)\.hpp'
pattern="^[[:space:]]*#[[:space:]]*include[[:space:]]*[<\"](\.\./)*((${forbidden_modules})/|${forbidden_public})"

violations=0
while IFS= read -r -d '' file; do
  while IFS= read -r hit; do
    echo "FORBIDDEN include in ${file#"$root"/}: $hit" >&2
    violations=$((violations + 1))
  done < <(grep -nE "$pattern" "$file" || true)
done < <(find "$scan_dir" -type f \( -name '*.hpp' -o -name '*.cpp' -o -name '*.h' -o -name '*.inc' \) -print0)

if (( violations > 0 )); then
  echo "check-scan-independence: $violations violation(s); src/scan may depend on bytes/ only" >&2
  exit 1
fi
echo "check-scan-independence: ok"
