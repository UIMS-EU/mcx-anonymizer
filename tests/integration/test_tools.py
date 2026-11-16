#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Self-tests for the repository gate scripts in tools/.

Run by CTest (label: unit). Exits non-zero on the first failing check.
"""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
LICENSES = REPO / "tools" / "check-licenses.py"
INDEPENDENCE = REPO / "tools" / "check-scan-independence.sh"

failures = 0


def check(name, condition, detail=""):
    global failures
    if condition:
        print(f"ok   {name}")
    else:
        failures += 1
        print(f"FAIL {name} {detail}")


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def graph(nodes):
    """Minimal `conan graph info --format=json` document."""
    return {"graph": {"nodes": {str(i): n for i, n in enumerate(nodes)}}}


def licenses_case(name, nodes, expect_ok):
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "graph.json"
        path.write_text(json.dumps(graph(nodes)))
        r = run([sys.executable, str(LICENSES), "--graph-json", str(path)])
        check(f"licenses: {name}", (r.returncode == 0) == expect_ok,
              f"rc={r.returncode} out={r.stdout.strip()} err={r.stderr.strip()}")
        return r


root = {"ref": "conanfile", "license": None, "context": "host"}

licenses_case("permissive set accepted", [
    root,
    {"ref": "a/1#x", "license": "MIT", "context": "host"},
    {"ref": "b/1#x", "license": "BSD-3-Clause", "context": "host"},
    {"ref": "c/1#x", "license": "Apache-2.0", "context": "host"},
    {"ref": "d/1#x", "license": "BSL-1.0", "context": "host"},
    {"ref": "e/1#x", "license": "Zlib", "context": "host"},
    {"ref": "f/1#x", "license": "Unlicense", "context": "host"},
    {"ref": "g/1#x", "license": "BSD-2-Clause", "context": "build"},
], True)
licenses_case("OR expression with one allowed alternative accepted",
              [root, {"ref": "ff/8#x", "license": "Apache-2.0 OR MIT OR BSL-1.0", "context": "host"}], True)
licenses_case("list of licences, all allowed, accepted",
              [root, {"ref": "l/1#x", "license": ["MIT", "Zlib"], "context": "host"}], True)
licenses_case("Apache-2.0 WITH LLVM-exception accepted",
              [root, {"ref": "llvm/19#x", "license": "Apache-2.0 WITH LLVM-exception", "context": "build"}], True)
licenses_case("ISC rejected", [root, {"ref": "i/1#x", "license": "ISC", "context": "host"}], False)
licenses_case("GPL rejected in test context",
              [root, {"ref": "g/1#x", "license": "GPL-2.0-only", "context": "host", "test": True}], False)
licenses_case("LGPL rejected in build context", [root, {"ref": "l/1#x", "license": "LGPL-2.1", "context": "build"}], False)
licenses_case("missing licence rejected", [root, {"ref": "m/1#x", "license": None, "context": "host"}], False)
licenses_case("list with one forbidden entry rejected",
              [root, {"ref": "l/1#x", "license": ["MIT", "GPL-3.0-or-later"], "context": "host"}], False)
r = licenses_case("offending reference is printed", [root, {"ref": "bad/9#x", "license": "AGPL-3.0", "context": "host"}], False)
check("licenses: offending reference named", "bad/9" in (r.stdout + r.stderr))


def independence_case(name, files, expect_ok):
    with tempfile.TemporaryDirectory() as d:
        for rel, text in files.items():
            p = Path(d) / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
        r = run(["bash", str(INDEPENDENCE), "--root", d])
        check(f"independence: {name}", (r.returncode == 0) == expect_ok,
              f"rc={r.returncode} out={r.stdout.strip()} err={r.stderr.strip()}")


independence_case("bytes and std includes allowed", {
    "src/scan/a.cpp": '#include "bytes/endian.hpp"\n#include <vector>\n#include "scan/patterns.hpp"\n',
    "src/scan/walker/w.cpp": '#include "mcxanon/scan.hpp"\n#include "mcxanon/error.hpp"\n',
}, True)
for forbidden in ["capture/pcap_reader.hpp", "dissect/field.hpp", "policy/ruleset.hpp",
                  "rewrite/apply.hpp", "pseudo/mapping.hpp", "pipeline/testing.hpp",
                  "report/report.hpp", "mcxanon/anonymize.hpp", "mcxanon/project.hpp",
                  "mcxanon/report.hpp", "../capture/x.hpp", "../../dissect/y.hpp",
                  "sip/uri.hpp", "stream/tcp.hpp", "media/rtp.hpp", "../media/app.hpp",
                  "xml/reader.hpp", "../xml/rewrite.hpp"]:
    independence_case(f"'{forbidden}' rejected",
                      {"src/scan/walker/w.cpp": f'#include  "{forbidden}"\n'}, False)
independence_case("angle-bracket form rejected", {"src/scan/x.hpp": "#include <capture/record.hpp>\n"}, False)
independence_case("empty scan directory accepted", {"src/scan/.keep": ""}, True)


def link_gate_case(name, scan_deps, expect_ok):
    """Configure a throw-away project that uses cmake/McxanonModule.cmake."""
    cmake = shutil.which("cmake")
    if cmake is None:
        print(f"skip {name} (cmake not available)")
        return
    with tempfile.TemporaryDirectory() as d:
        src = Path(d) / "src"
        src.mkdir()
        (src / "CMakeLists.txt").write_text(f"""
cmake_minimum_required(VERSION 3.31)
project(linkgate LANGUAGES NONE)
list(APPEND CMAKE_MODULE_PATH "{REPO / 'cmake'}")
include(McxanonModule)
mcxanon_add_module(bytes)
mcxanon_add_module(capture DEPS bytes)
mcxanon_add_module(scan DEPS {scan_deps})
mcxanon_assert_links_only(mcxanon_scan mcxanon_bytes)
""")
        r = run([cmake, "-S", str(src), "-B", str(Path(d) / "b")])
        check(f"link gate: {name}", (r.returncode == 0) == expect_ok,
              f"rc={r.returncode} err={r.stderr.strip()[-300:]}")


link_gate_case("scan -> bytes accepted", "bytes", True)
link_gate_case("scan -> capture rejected", "bytes capture", False)


# tshark-expert-diff.py: the parser of `tshark -z expert,error` (R20). tshark separates the
# columns with two spaces, and protocol names may contain one ("MIME multipart").
spec = importlib.util.spec_from_file_location("expert_diff", REPO / "tools" / "tshark-expert-diff.py")
expert_diff = importlib.util.module_from_spec(spec)
spec.loader.exec_module(expert_diff)
SAMPLE = """
=================================
Errors (9)
=============
   Frequency      Group           Protocol  Summary
           1  Malformed                SIP  Malformed Packet (Exception occurred)
           2  Malformed                SDP  Invalid media port 70000
           3  Malformed     MIME multipart  Malformed Packet (Exception occurred)
           1  Malformed               MSRP  Malformed Packet (Exception occurred)
           1  Malformed           ARP/RARP  Malformed Packet (Exception occurred)
           1  Reassemble              HTTP  Reassembly error, protocol TCP: New fragment overlaps old data
           1  Malformed    802.11 Radiotap  Malformed Packet (Exception occurred)
           4  Malformed                RTP  Padding bits error - MUST be 0

Warns (1)
=============
   Frequency      Group           Protocol  Summary
           7   Sequence                TCP  Previous segment(s) not captured
"""
got = expert_diff.parse_expert(SAMPLE)
protos = {proto for (_, proto, _) in got}
check("expert-diff: sip, sdp, msrp, multipart and arp compared",
      {"SIP", "SDP", "MIME multipart", "MSRP", "ARP/RARP"} <= protos, str(sorted(protos)))
check("expert-diff: TCP reassembly errors compared under any protocol", "HTTP" in protos, str(sorted(protos)))
check("expert-diff: link types and payloads the tool does not rewrite are not compared",
      not {"802.11 Radiotap", "RTP", "TCP"} & protos, str(sorted(protos)))
check("expert-diff: counts and normalised summaries",
      got.get(("Malformed", "MIME multipart", "Malformed Packet (Exception occurred)")) == 3
      and got.get(("Malformed", "SDP", "Invalid media port #")) == 2, str(got))
check("expert-diff: an SDP-set-up RTP flow lost in the output is reported",
      expert_diff.rtp_lost({1, 2, 3}, {1, 2}) == {3} and not expert_diff.rtp_lost({1, 2}, {1, 2, 5}))

sys.exit(1 if failures else 0)
