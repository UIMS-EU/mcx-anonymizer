#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Guard against leaking real packet captures, pseudonym mappings or project
# secrets into this public repository.
#
# Usage:
#   tools/check-no-captures.sh --staged   # pre-commit: check files staged in the index
#   tools/check-no-captures.sh --tracked  # CI: check every tracked file
#
# Rejected:
#   * *.pcap / *.pcapng / *.cap (any case) outside tests/fixtures/synthetic/
#   * any file whose first bytes are a pcap or pcapng magic number, regardless of
#     its name, outside tests/fixtures/synthetic/
#   * pseudonym mappings (*.map.json), project secrets (*.secret), TLS key logs
#     (*.keylog) and anything inside a .mcxanon/ directory, anywhere
set -euo pipefail

readonly ALLOWED_CAPTURE_DIR="tests/fixtures/synthetic/"

mode="${1:-}"
case "$mode" in
  --staged)
    list_files() { git diff --cached --name-only -z --diff-filter=ACMR; }
    read_head()  { git show ":$1" 2>/dev/null | head -c 4 | od -An -tx1 | tr -d ' \n'; }
    ;;
  --tracked)
    list_files() { git ls-files -z; }
    read_head()  { head -c 4 -- "$1" 2>/dev/null | od -An -tx1 | tr -d ' \n'; }
    ;;
  *)
    echo "usage: $0 --staged|--tracked" >&2
    exit 2
    ;;
esac

failures=0
reject() {
  echo "REJECTED: $1 — $2" >&2
  failures=$((failures + 1))
}

while IFS= read -r -d '' path; do
  lower="${path,,}"
  base="${lower##*/}"

  case "/$lower" in
    */.mcxanon/*) reject "$path" "mcxanon project data directory"; continue ;;
  esac
  case "$base" in
    *.map.json) reject "$path" "pseudonym mapping file"; continue ;;
    *.secret)   reject "$path" "project secret file"; continue ;;
    *.keylog)   reject "$path" "TLS key log file"; continue ;;
  esac

  [[ "$path" == "$ALLOWED_CAPTURE_DIR"* ]] && continue

  case "$base" in
    *.pcap|*.pcapng|*.cap)
      reject "$path" "capture file outside $ALLOWED_CAPTURE_DIR"; continue ;;
  esac

  # Content check: pcap (µs and ns, both byte orders) and pcapng SHB.
  case "$(read_head "$path")" in
    a1b2c3d4|d4c3b2a1|a1b23c4d|4d3cb2a1|0a0d0d0a)
      reject "$path" "content is a pcap/pcapng capture (outside $ALLOWED_CAPTURE_DIR)" ;;
  esac
done < <(list_files)

if (( failures > 0 )); then
  cat >&2 <<MSG

$failures file(s) rejected. Real captures, mappings and secrets must never be
committed to this public repository. Test captures belong in
$ALLOWED_CAPTURE_DIR and must be generated synthetically by scripts in tools/.
MSG
  exit 1
fi
