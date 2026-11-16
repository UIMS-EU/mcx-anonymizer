#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Runs every libFuzzer target for N seconds over seed corpora generated from the
# synthetic fixtures. Build first with: cppbuild -p fuzz -t Debug build -s compiler.cppstd=23
# Usage (inside the build container): tools/run-fuzzers.sh [SECONDS] [BUILD_DIR]
set -euo pipefail
secs="${1:-60}"
build="${2:-build/Debug}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
corpus="$build/fuzz-corpus"
rm -rf "$corpus"
mkdir -p "$corpus"/{capture,packets,rules,mapping,sip,sdp,siprules,tcp,frag}
python3 "$root/tools/fixturegen/gen.py" --out "$build/fuzz-fixtures" --seed 1 --corpus "$corpus/capture" >/dev/null
python3 "$root/tools/fixturegen/gen.py" --out "$build/fuzz-fixtures" --seed 1 --packet-corpus "$corpus/packets" >/dev/null
python3 "$root/tools/fixturegen/gen.py" --out "$build/fuzz-fixtures" --seed 1 --sip-corpus "$corpus/sip" --sdp-corpus "$corpus/sdp" >/dev/null
python3 "$root/tools/fixturegen/gen.py" --out "$build/fuzz-fixtures" --seed 1 --media-corpus "$corpus/media" >/dev/null
python3 "$root/tools/fixturegen/gen.py" --out "$build/fuzz-fixtures" --seed 1 --xml-corpus "$corpus/xml" >/dev/null
python3 "$root/tools/fixturegen/gen.py" --out "$build/fuzz-fixtures" --seed 1 --mikey-corpus "$corpus/mikey" >/dev/null
python3 "$root/tools/fixturegen/gen.py" --out "$build/fuzz-fixtures" --seed 1 --web-corpus "$corpus/web" >/dev/null
# fuzz_xml_rewrite: the first byte selects the Content-Type; seed each body with selector 0.
mkdir -p "$corpus/xmlsel"
for f in "$corpus"/xml/*; do { printf '\000'; cat "$f"; } > "$corpus/xmlsel/$(basename "$f")"; done
# The scanner walker also reads anonymised media captures (001/FR-032a): RTP and RTCP output
# payloads, whose header runs the walker treats apart (feature 004).
if [ -x "$build/src/cli/mcxanon" ]; then
  data="$build/fuzz-data"
  rm -rf "$data"
  "$build/src/cli/mcxanon" --data-dir "$data" project init fuzz >/dev/null
  for f in "$build"/fuzz-fixtures/{rtp,rtcp,app,msrp}_*.pcapng; do
    "$build/src/cli/mcxanon" --data-dir "$data" anonymize --project fuzz "$f" -o "$corpus/capture/out-$(basename "$f")" >/dev/null 2>&1 || true
  done
  rm -f "$corpus"/capture/*.report.json
fi
# Segment sequences (fuzz_tcp_stream): the SIP corpus as one connection, in-order segments of at
# most 1020 bytes; and fragment sets (fuzz_ip_reassembly): one datagram in three fragments.
python3 - "$corpus" <<'PY'
import os, sys
corpus = sys.argv[1]
msgs = [open(os.path.join(corpus, "sip", n), "rb").read() for n in sorted(os.listdir(os.path.join(corpus, "sip")))[:6]]
for k in range(3):
    out = bytearray([k & 1])
    for i, m in enumerate(msgs[k:k + 3]):
        d = 1 if m.startswith(b"SIP/2.0") else 0
        for off in range(0, len(m), 1020):
            seg = m[off:off + 1020]
            out += bytes([d | 8 | (len(seg) % 4) << 5, 0, 0, len(seg) // 4]) + seg
    open(os.path.join(corpus, "tcp", f"t{k}"), "wb").write(out)
body = bytes([1]) + bytes(range(255)) * 4
frag = bytearray()
for off, more in ((0, 4), (48, 4), (96, 0)):
    chunk = body[off * 8:(off + 48) * 8] if more else body[off * 8:]
    frag += bytes([more | ((len(chunk) % 8) << 3), off, len(chunk) // 8]) + chunk
open(os.path.join(corpus, "frag", "f0"), "wb").write(frag)
PY
cp "$root"/rules/*.yaml "$corpus/rules/"
cp "$root"/rules/sip-*.yaml "$root"/rules/sdp.yaml "$corpus/siprules/"
printf '{"format": 1, "entries": [{"category": "ipv4", "original": "0a000001", "pseudonym": "f0000001", "counter": 0, "runs_seen": 1}]}' > "$corpus/mapping/seed.json"
printf '{"format": 2, "entries": [{"category": "sip-user", "original": "616c696365", "pseudonym": "752d3030313161616262", "counter": 0, "runs_seen": 1}, {"category": "spi", "original": "12345678", "pseudonym": "9abcdef0", "counter": 0, "runs_seen": 1}]}' > "$corpus/mapping/seed2.json"
# Reveal (feature 006): texts with pseudonyms of every shape, plus the SIP and XML corpora.
mkdir -p "$corpus/reveal"
cp "$corpus"/sip/* "$corpus"/xml/* "$corpus/reveal/" 2>/dev/null || true
printf '\000sip:u-00000000@d-00000000.d-11111111.invalid 240.1.2.3 2001:db8::5 fe80::1:2:3:4 0x3c3c3c07 (1010580487) +48-601.234(567) 33:33:ff:00:53:01 c-0123456789abcdef@[2001:db8::1] 3381690010010000101110101111111100 %%40&amp;&#64;\n' > "$corpus/reveal/seed"
export UBSAN_OPTIONS="suppressions=$root/tests/fuzz/ubsan.supp:print_stacktrace=1:halt_on_error=1"
declare -A corpus_of=([fuzz_pcap]=capture [fuzz_pcapng]=capture [fuzz_rules]=rules [fuzz_mapping]=mapping
                      [fuzz_dissect]=packets [fuzz_rewrite]=packets [fuzz_scan_walker]=capture
                      [fuzz_denylist]=rules [fuzz_container]=mapping
                      [fuzz_sip_message]=sip [fuzz_sip_uri]=sip [fuzz_sdp]=sdp [fuzz_multipart]=sip
                      [fuzz_sip_harvest]=sip [fuzz_sip_rules]=siprules
                      [fuzz_tcp_stream]=tcp [fuzz_ip_reassembly]=frag
                      [fuzz_rtp]=media/rtp [fuzz_rtcp]=media/rtcp [fuzz_rtcp_app]=media/app
                      [fuzz_msrp]=media/msrp [fuzz_media_announce]=media/announce
                      [fuzz_media_harvest]=media/harvest [fuzz_xml_reader]=xml [fuzz_xml_harvest]=xml [fuzz_xml_rewrite]=xmlsel [fuzz_reveal]=reveal
                      [fuzz_mikey]=mikey [fuzz_mikey_carrier]=mikey [fuzz_mikey_harvest]=mikey
                      [fuzz_http_message]=web/http [fuzz_h2]=web/h2 [fuzz_hpack]=web/hpack [fuzz_json]=web/json
                      [fuzz_jwt]=web/jwt [fuzz_tls]=web/tls [fuzz_der]=web/der [fuzz_web_harvest]=web/harvest)
# Extra libFuzzer options per target. fuzz_reveal: inputs truncated to 4 KiB, since a full reveal of
# the 150 KB SIP/XML seeds under ASan takes ~0.1 s and left the target at ~10 runs/s (large texts
# are covered by reveal-demo, reveal-tshark and reveal-perf).
# The feature 007 stream targets: 64 KiB inputs keep ASan near 1000 runs/s; the 1 MiB h2 and
# hostile seeds are covered by web-hostile under the memory limit.
declare -A extra_of=([fuzz_reveal]="-max_len=4096" [fuzz_http_message]="-max_len=65536" [fuzz_h2]="-max_len=65536"
                     [fuzz_tls]="-max_len=65536" [fuzz_web_harvest]="-max_len=65536" [fuzz_der]="-max_len=16384"
                     [fuzz_json]="-max_len=16384" [fuzz_jwt]="-max_len=8192" [fuzz_hpack]="-max_len=16384")
status=0
for f in "$build"/fuzz/fuzz_*; do
  t="$(basename "$f")"
  c="${corpus_of[$t]:-capture}"
  echo "== $t ($secs s, corpus $c)"
  mkdir -p "$build/fuzz-artifacts/$t"
  # shellcheck disable=SC2086  # the extra options are word-split on purpose
  if ! "$f" -max_total_time="$secs" -print_final_stats=1 -artifact_prefix="$build/fuzz-artifacts/$t/" \
       ${extra_of[$t]:-} "$corpus/$c" > "$build/$t.log" 2>&1; then
    echo "FAILED: $t (see $build/$t.log)"
    status=1
  fi
  grep -E "^Done|SUMMARY" "$build/$t.log" | tail -2
done
exit $status
