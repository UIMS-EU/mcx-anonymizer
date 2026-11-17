#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Independent oracle for User Story 1 (SC-001): the floor and transmission control sequence
of the output equals the input's, message by message, in the same frames.

For every RTCP APP message of the input (decoded by tshark, including the MCX names that have
no field decoder in tshark), the output must carry the same APP name and subtype in the same
frame and position. For the MCPT family, which tshark decodes field by field, the kept fields
must also have the same values (priority, duration, reject cause, queue information,
permission, queue size, message sequence number, source, floor indicator, message type,
location type). When tshark itself reports the input message as malformed (its MCPTT dissector
misreads the geographic coordinates of a List of Locations field, Wireshark 4.4, and goes on
reading the following bytes as fields), only the values it decoded from the input are compared:
each kept field of the output must start with the input's occurrences, since what tshark reads
after the misread are the bytes of pseudonymised values. Messages whose subtype the rules do not
know (unknown names or subtypes) are expected with zeroed data: their name and subtype are
compared only when --strict is not given and the input name is known (MCPT, MCPC, MCMC, MCNC,
MCSC, MCV0-MCV5, MCDM).

Usage: floor_ladder.py INPUT OUTPUT [--known-only]
Exit 0 when equal, 1 otherwise; prints the number of messages compared.
"""
import subprocess
import sys

KNOWN = {"MCPT", "MCPC", "MCMC", "MCNC", "MCSC", "MCV0", "MCV1", "MCV2", "MCV3", "MCV4", "MCV5", "MCDM"}
KEPT = ["rtcp.app_data.mcptt.priority", "rtcp.app_data.mcptt.duration", "rtcp.app_data.mcptt.rej_cause",
        "rtcp.app_data.mcptt.queue_pos_inf", "rtcp.app_data.mcptt.queue_pri_lev",
        "rtcp.app_data.mcptt.perm_to_req_floor", "rtcp.app_data.mcptt.queue_size",
        "rtcp.app_data.mcptt.msg_seq_num", "rtcp.app_data.mcptt.source", "rtcp.app_data.mcptt.floor_ind",
        "rtcp.app_data.mcptt.msg_type", "rtcp.app_data.mcptt.loc_type", "rtcp.app_data.mcptt.queueing_cap",
        "rtcp.app_data.mcptt.num_users", "rtcp.app_data.mcptt.num_ssrc", "rtcp.app_data.mcptt.num_loc"]


def rows(path):
    names = ["frame.number", "rtcp.app.name", "rtcp.app.subtype", "_ws.malformed"] + KEPT
    r = subprocess.run(["tshark", "-r", path, "-Y", "rtcp.app.name", "-T", "fields", "-E", "occurrence=a",
                        "-E", "aggregator=|"] + [x for n in names for x in ("-e", n)],
                       capture_output=True, text=True, check=True)
    out = {}
    for line in r.stdout.splitlines():
        c = line.split("\t")
        out[c[0]] = c[1:]
    return out


def main():
    a, b = rows(sys.argv[1]), rows(sys.argv[2])
    failures = []
    compared = 0
    for frame, row in a.items():
        names = row[0].split("|")
        if not any(n in KNOWN for n in names):
            continue
        other = b.get(frame)
        if other is None:
            failures.append(f"frame {frame}: APP {row[0]} missing from the output")
            continue
        if row[0] != other[0] or row[1] != other[1]:
            failures.append(f"frame {frame}: {row[0]}/{row[1]} became {other[0]}/{other[1]}")
            continue
        compared += 1
        if "MCPT" in names:
            malformed = bool(row[2])  # tshark misread the input message: compare what it decoded
            for name, x, y in zip(KEPT, row[3:], other[3:]):
                xs, ys = (x.split("|") if x else []), (y.split("|") if y else [])
                if (ys[:len(xs)] != xs) if malformed else (x != y):
                    failures.append(f"frame {frame}: {name} {x!r} became {y!r}")
    print(f"{compared} APP messages compared")
    for f in failures[:30]:
        print("FAIL " + f)
    return 1 if failures or compared == 0 else 0


if __name__ == "__main__":
    sys.exit(main())
