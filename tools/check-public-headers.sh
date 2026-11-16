#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Public headers include only the standard library and other public headers;
# no internal header (and so no test seam) is reachable from include/mcxanon/.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bad=0
while IFS= read -r line; do
  echo "internal include in public header: $line" >&2
  bad=1
done < <(grep -nE '^[[:space:]]*#[[:space:]]*include[[:space:]]*"' "$root"/include/mcxanon/*.hpp* | grep -vE '#[[:space:]]*include[[:space:]]*"mcxanon/' || true)
if grep -rnE 'testing::|Hooks|ruleset_override' "$root"/include/mcxanon/ >/dev/null; then
  echo "test seam named in a public header" >&2
  bad=1
fi
exit $bad
