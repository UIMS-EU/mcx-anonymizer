#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# / FR-043: no network access at run time.
# 1. Structural: the binary imports no socket or name-resolution functions.
#  2. Behavioural: init, anonymize, scan, reveal and lookup succeed without any network
#     (inside a network namespace when the system allows it; CI runs the whole
#     job with --network none).
# Usage: test_offline.sh MCXANON [FIXTURE_DIR]
set -euo pipefail
exe="$1"
fixtures="${2:-}"
fail=0
if nm -D --undefined-only "$exe" | grep -wE 'socket|connect|getaddrinfo|gethostbyname|gethostbyaddr|sendto|recvfrom|bind|listen|accept|socketpair'; then
  echo "FAIL the binary imports network functions" >&2
  fail=1
else
  echo "ok   no network functions imported"
fi
run() {
  if unshare -rn true 2>/dev/null; then unshare -rn "$@"; else "$@"; fi
}
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
input="$tmp/in.pcap"
if [[ -n "$fixtures" && -f "$fixtures/basic_eth.pcap" ]]; then
  cp "$fixtures/basic_eth.pcap" "$input"
else
  python3 "$(dirname "$0")/../../tools/fixturegen/gen.py" --out "$tmp/fx" --only basic_pcap >/dev/null
  cp "$tmp/fx/basic_eth.pcap" "$input"
fi
if run "$exe" --data-dir "$tmp/d" project init off >/dev/null &&
   run "$exe" --data-dir "$tmp/d" anonymize --project off "$input" -o "$tmp/out.pcap" 2>/dev/null &&
   run "$exe" --data-dir "$tmp/d" scan --project off "$tmp/out.pcap" 2>/dev/null; then
  echo "ok   init, anonymize and scan work offline"
else
  echo "FAIL a command failed offline" >&2
  fail=1
fi
# Feature 006: reveal and lookup.
if echo "see 240.0.0.1 and u-0badcafe" | run "$exe" --data-dir "$tmp/d" reveal --project off --quiet >/dev/null 2>&1 &&
   { run "$exe" --data-dir "$tmp/d" project lookup off 10.0.0.1 >/dev/null 2>&1; [[ $? -le 1 ]]; }; then
  echo "ok   reveal and lookup work offline"
else
  echo "FAIL reveal or lookup failed offline" >&2
  fail=1
fi
# Feature 005: passthrough with key periods, and the scanner in passthrough mode.
mk="$tmp/mikey.pcapng"
if [[ -n "$fixtures" && -f "$fixtures/mikey_sdp.pcapng" ]]; then
  cp "$fixtures/mikey_sdp.pcapng" "$mk"
else
  python3 "$(dirname "$0")/../../tools/fixturegen/gen.py" --out "$tmp/fm" --only mikey >/dev/null
  cp "$tmp/fm/mikey_sdp.pcapng" "$mk"
fi
if run "$exe" --data-dir "$tmp/d" anonymize --project off --encrypted passthrough \
       --kms-key-period kms.example.org=2592000:0 "$mk" -o "$tmp/mk-out.pcapng" 2>/dev/null &&
   run "$exe" --data-dir "$tmp/d" scan --project off --encrypted passthrough "$tmp/mk-out.pcapng" 2>/dev/null; then
  echo "ok   anonymize and scan --encrypted passthrough work offline"
else
  echo "FAIL a passthrough command failed offline" >&2
  fail=1
fi
exit $fail
