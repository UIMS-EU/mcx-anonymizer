#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Every source, build, script and configuration file carries the SPDX licence
# identifier within its first five lines. Documentation (*.md), the licence text
# and JSON data (no comment syntax) are exempt.
# Usage: tools/check-spdx.sh [REPO_ROOT]
set -euo pipefail
root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "$root"
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  files="$(git ls-files --cached --others --exclude-standard)"
else
  # No usable git (an exported tree): skip build output and generated files.
  files="$(find . \( -path ./build -o -path ./.git -o -name __pycache__ \) -prune -o -type f \
             -not -name '*.pyc' -not -name 'CMakeUserPresets.json' -print | sed 's|^\./||')"
fi
missing=0
while IFS= read -r f; do
  [[ -z "$f" || ! -f "$f" ]] && continue
  case "$f" in
    LICENSE|*.md|*.json) continue ;;
  esac
  if ! head -n 5 "$f" | grep -q 'SPDX-License-Identifier: GPL-3.0-or-later'; then
    echo "missing SPDX header: $f"
    missing=1
  fi
done <<< "$files"
if [[ $missing -ne 0 ]]; then
  exit 1
fi
echo "ok   every source file carries the SPDX header"
