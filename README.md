# mcx-anonymizer

`mcxanon` anonymises packet captures (pcap and pcapng) from Mission Critical
communication systems (MCPTT, MCData, MCVideo) so that they can be handed to
vendors, support teams, test labs or AI-assisted analysis without exposing the
network that produced them.

It is built around three rules:

- **Fail closed.** Only what the tool understands and has a rule for is kept or
  pseudonymised. Everything else (unknown protocols, unknown metadata, unknown
  SIP headers and parameters, RTCP and floor control fields without a rule, any
  application payload other than SIP, SDP, the RTP and RTCP headers, floor and
  transmission control and MSRP framing) is zeroed or removed.
- **Check the result independently.** Before an output file becomes visible, a
  separate scanner with its own minimal parser searches it for every original
  value in many encodings. If anything is found, nothing is published.
- **Stay consistent.** Within a project, the same original address always gets
  the same pseudonym, across captures and across runs, so that captures taken at
  different points of the same system can still be correlated.

The tool works entirely offline. It has no network code and never contacts any
service.

## Status

**Version 0.1.0 is a preview.** Every rule cites the 3GPP, ETSI or IETF clause
it implements, and the tool is tested with unit tests, synthetic captures
containing a canary for every rule, tshark integrity checks, fuzzing and 1 GB
performance runs. It has not yet been validated on a wide range of real
captures. Until it has, check the report and open the output in Wireshark
before you share it, and read [Known limitations](#known-limitations).
Reports of wrong or missing anonymisation are very welcome; see
[SECURITY.md](SECURITY.md) for how to report one without sharing a capture.

## Install

The container image needs nothing else:

```bash
docker pull ghcr.io/uims-eu/mcx-anonymizer:0.1.0
mkdir -p "$HOME/.local/share/mcxanon"
alias mcxanon='docker run --rm -i --user "$(id -u):$(id -g)" -v "$PWD:/work" \
  -v "$HOME/.local/share/mcxanon:/data" ghcr.io/uims-eu/mcx-anonymizer:0.1.0'
mcxanon project init case-1042
mcxanon anonymize --project case-1042 capture.pcapng -o capture-anon.pcapng
```

Inside the container the working directory is `/work` and the data directory is
`/data`: mount the directory with your captures on `/work` and a persistent
directory for the projects on `/data`. Keep that directory on the machine, because
it holds the project secrets. The tool needs no network, so `--network none` can
be added to the `docker run` options.

Each [release](https://github.com/UIMS-EU/mcx-anonymizer/releases) also has a
Linux x86-64 binary (`mcxanon-<version>-linux-x86_64.tar.gz`, with SHA-256
sums). It is built on Debian 13 and needs glibc 2.41 and the C++ runtime of
GCC 14 or later (Debian 13, Ubuntu 25.04 or newer); on older distributions use
the container or [build it](#building).

## Quick start

```bash
mcxanon project init case-1042
mcxanon anonymize --project case-1042 capture.pcapng -o capture-anon.pcapng
```

The first command creates a project: a random 256-bit secret and an empty
mapping, stored in your data directory (see below). The second command writes
`capture-anon.pcapng` and a report `capture-anon.pcapng.report.json` that lists
what was pseudonymised, zeroed and removed, and the result of the leak scan.
Use the same project for every capture that belongs to the same case.

Other commands:

```bash
mcxanon scan --project case-1042 some-file.pcap      # scan any capture for this project's originals
mcxanon project list                                 # projects, without mapping contents
mcxanon project show-map case-1042                   # original -> pseudonym (local inspection only)
mcxanon reveal --project case-1042 findings.txt      # an analyst's text with the originals back (local only)
mcxanon project lookup case-1042 VALUE               # one pseudonym -> original (--original: the other way)
mcxanon project where                                # the resolved data directory
mcxanon --help                                       # every option
```

## Example: a dispatcher's MCX session

`tools/fixturegen/mcx_demo.py` writes a synthetic but complete MCX capture. Every
name, address and token in it is invented. Addresses come from private and
documentation ranges and names from `example.net`. The capture has 495 packets on
two interfaces:

- **Interface 0, the LAN of a dispatcher console** (VLAN 120, dual-stack):
  - network bring-up: DHCP, IPv6 router discovery with SLAAC, ARP, DNS;
  - OpenID Connect sign-in at the IdMS, with password, code and tokens in the clear;
  - key retrieval from the KMS over TLS;
  - SIP over TCP, with an IMS registration and an AKA challenge for each client:
    - the MCPTT client registers over IPv4 and the MCData client over IPv6, and
      receives the reg event NOTIFY;
    - service authorisation of both (`PUBLISH` poc-settings with the access token);
    - configuration management (`SUBSCRIBE`/`NOTIFY` xcap-diff);
    - affiliation of both clients: MCPTT to two groups, MCData to one;
    - a location reporting configuration, and a location report with cell ID and
      coordinates;
  - XCAP downloads of the UE configuration, the MCPTT and MCData user profiles,
    the service configuration and two group documents;
  - a pre-arranged group call with floor control (the floor request carries the
    serving cell), AMR-WB voice and RTCP;
  - an incoming private call whose INVITE is integrity-protected (a signed body);
  - a REFER for a pre-established session, with the SDP offer and the MCPTT
    information embedded in a resource-list entry URI;
  - an MCVideo private call with H.264 video and transmission control;
  - MCData short messages: a one-to-one message from the handheld and a group
    message from the console to its MCData group, and an SDS session over MSRP;
  - release, a late RTP packet with the ICMP error it causes, and de-registration.
- **Interface 1, an S1-U mirror at the eNodeB**: a handheld's traffic inside
  GTP-U. It carries the handheld's invitation into the call, its floor requests
  and its voice, the MCData message it sends and the group message it receives.
- **pcapng metadata**:
  - the operator's name and site, the laptop serial number;
  - interface names, descriptions, addresses and capture filters;
  - a name resolution block and a TLS key log;
  - packet comments and interface statistics.

```bash
python3 tools/fixturegen/mcx_demo.py --out demo
mcxanon project init demo
mcxanon scan --project demo --deny-list demo/mcx_demo.deny.txt demo/mcx_demo.pcapng   # exit 1: leaks found
mcxanon anonymize --project demo --deny-list demo/mcx_demo.deny.txt \
    demo/mcx_demo.pcapng -o demo/mcx_demo.anon.pcapng
```

```text
mcxanon: 495 frames; 2132 fields pseudonymised, 48 zeroed, 0 padded; 64 pcapng blocks/options removed; 0 unknown protocol kinds
sip: 66 messages (0 malformed), 5 headers removed (0 unknown), 8 bodies emptied, 0 unframable TCP bytes, 1 fragmented datagram rewritten
xml: 30 rewritten, 0 emptied
mcxanon: leak scan: clean; report: demo/mcx_demo.anon.pcapng.report.json
```

Some frames and fields before and after anonymisation, as decoded by `tshark`.
Your pseudonyms will differ, because they depend on the project secret.

| Original | Anonymised |
|---|---|
| `fe80::200:5eff:fe00:5311 → ff02::2` Router Solicitation from `00:00:5e:00:53:11` | `fe80::b5a8:ca41:6d51:1855 → ff02::2` Router Solicitation from `6e:fb:ea:3f:68:8d` |
| `:: → ff02::1:ff00:5311` Neighbor Solicitation for `fd12:3456:789a:1:200:5eff:fe00:5311` | `:: → ff02::1:ff9a:cf8c` Neighbor Solicitation for `2001:db8:c83f:b4e7:7b35:d065:a21b:a73c` |
| `10.45.12.34 → 172.16.40.30` TLS Client Hello (SNI=kms.mcx.example.net) | `241.3.120.78 → 240.31.111.190` TCP, payload zeroed |
| `10.45.12.34 → 172.16.20.10` SIP `REGISTER sip:mcx.example.net` | `245.22.98.16 → 245.198.158.97` SIP `REGISTER sip:d-92d25ccd.d-ad74f662.invalid` |
| SIP `PUBLISH sip:mcptt-part@mcx.example.net` | SIP `PUBLISH sip:u-e8366e68@d-92d25ccd.d-ad74f662.invalid` |
| SIP `NOTIFY sip:alice.nowak@10.45.12.34:5062;transport=tcp` | SIP `NOTIFY sip:u-2a30147a@245.22.98.16:5062;transport=tcp` |
| `From: <sip:alice.nowak@mcx.example.net>;tag=gc1` | `From: <sip:u-2a30147a@d-92d25ccd.d-ad74f662.invalid>;tag=t-c69d19ce` |
| `Authorization: Digest username="260011234567890@ims.mnc001.mcc260.3gppnetwork.org", realm="mcx.example.net", nonce="l83ZetTQ…", qop=auth, nc=00000001, …` | `Authorization: Digest username="u-d898417a@d-e0630782.d-36a160d1.d-12772874.d-7f904d23.invalid", realm="d-92d25ccd.d-ad74f662.invalid", nonce="t8zITRAa…", qop=auth, nc=00000001, …` |
| `P-Access-Network-Info: 3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=2600100A1B2C3D4` | `P-Access-Network-Info: 3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=8E120E6B3AE837C` |
| SDP `o=alice 2890844526 2890844526 IN IP4 10.45.12.34`, `c=IN IP4 10.45.12.34`, `a=fmtp:MCPTT mc_queueing;mc_priority=4` | SDP `o=u-302bd5a2 4486596408 4914690384 IN IP4 245.22.98.16`, `c=IN IP4 245.22.98.16`, `a=fmtp:MCPTT mc_queueing;mc_priority=4` |
| `MESSAGE` with `multipart/mixed;boundary=mcdata-b1`: mcdata-info, MCData signalling and payload (766 bytes) | `MESSAGE` with `multipart/mixed;boundary=mcxb-…`: mcdata-info rewritten (see below), signalling and payload parts kept with their headers and empty bodies (729 bytes) |
| RTP `10.45.12.34 → 172.16.30.5`, SSRC `0x1a2b3c4d`, PT 97, seq 1000, 61 bytes of AMR-WB | RTP `243.62.226.143 → 255.232.12.139`, SSRC `0xa02338f3`, PT 97, seq 1000, 61 zero bytes |
| RTCP SDES from `0x1a2b3c4d`: CNAME `con-fwMkbgdC@ue.example.net`, NAME `Console 0HKqHkwT` | RTCP SDES from `0xa02338f3`: CNAME `u-2b1ebaaa@d-7b650416.d-580ffb10.invalid`, NAME removed |
| MCPT Floor Release, User ID `sip:alice.nowak@mcx.example.net` | MCPT Floor Release, User ID `sip:u-b3129152@d-c9028823.d-580ffb10.invalid` |
| MSRP `SEND`, transaction `tEVgVttxcMs1i`, To-Path `msrp://172.16.30.5:2856/bhbZhpuDHdL0ccztF;tcp`, Message-ID `m96NWS7ZEhBwC` | MSRP `SEND`, transaction `mDHnHixdgPk5u`, To-Path `msrp://255.232.12.139:2856/ms-49e08d80373c2d6383c9;tcp`, Message-ID `w70QJP0CZjJvZ`, content zeroed |

The SIP ladder stays readable over UDP, over TCP and through the fragmented
datagram: `tshark` shows the same messages, in the same frames, with the same
methods, status codes, CSeq numbers and Call-ID grouping, and the RTP
conversations that the SDP announces are still set up, on the pseudonymised
addresses. The floor control ladder keeps its messages, priorities, durations and
sequence numbers in the same frames, and every SSRC and identity has one pseudonym
across SIP, SDP, RTP, RTCP, floor control and MSRP.

The generator also writes `mcx_demo.canaries.json`, which lists every identifying
value it planted. The `demo-capture` test uses that list to check that none of
these values survives anywhere in the output, in either payload mode, and that the
output decodes without new `tshark` errors. This version still zeroes HTTP (XCAP,
OpenID Connect); a later version will pseudonymise it too. Media payloads and
MSRP content are zeroed by design.

The MCPTT information of the group call INVITE, before and after:

```xml
<mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0">
<mcptt-Params>
<session-type>prearranged</session-type>
<mcptt-request-uri type="Normal"><mcpttURI>sip:fire-brigade-west@mcx.example.net</mcpttURI></mcptt-request-uri>
<mcptt-calling-user-id type="Normal"><mcpttURI>sip:alice.nowak@mcx.example.net</mcpttURI></mcptt-calling-user-id>
<emergency-ind type="Normal"><mcpttBoolean>false</mcpttBoolean></emergency-ind>
<alert-ind type="Normal"><mcpttBoolean>false</mcpttBoolean></alert-ind>
<imminentperil-ind type="Normal"><mcpttBoolean>false</mcpttBoolean></imminentperil-ind>
<broadcast-ind>false</broadcast-ind>
<mcptt-client-id type="Normal"><mcpttString>urn:uuid:5f0e8c2a-3b71-4d9e-9a44-2c7b1e6f0d18</mcpttString></mcptt-client-id>
<anyExt>
<urgency-ind>normal</urgency-ind>
<user-requested-priority>5</user-requested-priority>
</anyExt>
</mcptt-Params>
</mcpttinfo>
```

```xml
<mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0">
<mcptt-Params>
<session-type>prearranged</session-type>
<mcptt-request-uri type="Normal"><mcpttURI>sip:u-e7a860e1@d-3c71739c.d-da764d37.invalid</mcpttURI></mcptt-request-uri>
<mcptt-calling-user-id type="Normal"><mcpttURI>sip:u-e78738e0@d-3c71739c.d-da764d37.invalid</mcpttURI></mcptt-calling-user-id>
<emergency-ind type="Normal"><mcpttBoolean>false</mcpttBoolean></emergency-ind>
<alert-ind type="Normal"><mcpttBoolean>false</mcpttBoolean></alert-ind>
<imminentperil-ind type="Normal"><mcpttBoolean>false</mcpttBoolean></imminentperil-ind>
<broadcast-ind>false</broadcast-ind>
<mcptt-client-id type="Normal"><mcpttString>urn:uuid:052d701e-029a-4b11-a8f9-9c59b745c3d4</mcpttString></mcptt-client-id>
<anyExt>
<urgency-ind>normal</urgency-ind>
<user-requested-priority>5</user-requested-priority>
</anyExt>
</mcptt-Params>
</mcpttinfo>
```

The URIs are the pseudonyms the SIP headers and the floor control User ID fields
show for the same identities, and the client ID is the pseudonym of the same
`+sip.instance`.

## What the tool does

### Pseudonymised (consistent per project)

| What | Where | Pseudonym range |
|---|---|---|
| MAC addresses | Ethernet, Linux cooked capture (SLL, SLL2), ARP, NDP link-layer options | locally administered, individual/group bit kept |
| IPv4 addresses | IPv4 headers and options, ARP, inner headers of IP-in-IP, GRE and GTP-U, packets quoted by ICMP errors, SCTP address parameters, IPv4 embedded in IPv6 | `240.0.0.0/4` |
| IPv6 addresses | IPv6 headers and extension headers, NDP, inner and quoted headers, SCTP address parameters | `2001:db8::/32` |
| VLAN IDs (option `--pseudonymise-vlan`) | 802.1Q / 802.1ad tags at any depth | 1–4094 |
| Ephemeral ports (option `--pseudonymise-ephemeral-ports`) | TCP, UDP, SCTP | the configured ephemeral range |

Pseudonyms are derived with HMAC-SHA-256 from the project secret and recorded in
the project mapping. Addresses that carry no identity are kept: the unspecified
and loopback addresses, limited broadcast, well-known multicast and the
broadcast MAC. With `--prefix-preserving`, two addresses that share an n-bit
prefix get pseudonyms that share an n-bit prefix (up to the free bits of the
range).

After every change, length fields and the IPv4, ICMP, ICMPv6, UDP, TCP and SCTP
checksums and the Ethernet FCS are recomputed so that the output decodes
cleanly. A checksum that was invalid in the input stays invalid.

### SIP and SDP

SIP requests and responses are recognised over UDP and TCP on any port, in plain
IP and inside IP-in-IP, GRE and GTP-U. They are parsed header by header and
written back so that the call flow stays readable. Every header, parameter, SDP
line and attribute, media feature tag and body type has a rule with the clause of
the standard it comes from (RFC 3261 and the RFCs it references, 3GPP TS 24.229,
TS 24.379, TS 24.282, TS 24.281, TS 24.380; see `rules/sip-*.yaml`,
`rules/sdp.yaml` and `rules/SOURCES.md`).

**Kept:** methods, status codes, CSeq, Max-Forwards, Expires and the other
numeric and enumerated headers; header order, the compact forms and the case of
header names; capability sets (Allow, Supported, Require); the standard media
feature tags, ICSI and IARI values; digest `scheme`, `algorithm`, `qop` and
`nc`; security mechanisms and their `alg`, `ealg`, `prot` and `mod`; the access
type of P-Access-Network-Info; SDP `v=`, `t=`, `r=`, `z=`, `b=`, the media type,
protocol and formats of `m=`, the codec attributes `a=rtpmap` and `a=fmtp`
(including the MCPTT, MCVideo and MCData parameters), and the MCX
`i=` values `speech`, `audio component of MCVideo` and `video component of
MCVideo`.

**Pseudonymised**, with one mapping per kind of value, so that one original gets
one pseudonym in every header, parameter and SDP line, across captures of the
project:

| Value | Pseudonym |
|---|---|
| user part of SIP, SIPS and tel URIs | `u-<8 hex>` |
| domain names | each label `d-<8 hex>`, derived with its parent suffix; the top-level label becomes `invalid`, so no pseudonymised name resolves |
| IP addresses in URIs, Via, SDP `c=`, `o=`, `a=rtcp`, `a=candidate` | the address pseudonym of the IP header |
| display names | `"n-<8 hex>"` |
| telephone numbers | the same number of digits; numbers of up to 3 digits (emergency and short codes) are kept |
| Call-ID, `tag`, `branch` (keeping `z9hG4bK`), SIP-ETag, Content-ID, P-Charging-Vector values, Session-ID | fixed formats; dialogs and transactions still match, also inside Replaces, Target-Dialog and In-Reply-To |
| Authorization `username` (private identity) | the user and domain mappings, so the IMPI and the IMPU of a user stay correlated |
| digest `nonce`, `cnonce`, `response`, `opaque`, `auts`, `nextnonce`, `rspauth` | same encoding and length |
| `+sip.instance`, GRUUs | an IMEI stays a valid IMEI, a UUID stays a UUID |
| Security-Client/Server/Verify `spi-c`, `spi-s` | 32-bit values; the ESP header carries the same pseudonym |
| cell and location identities in P-Access-Network-Info | same length and character set |
| SDP session ID and version | same number of digits; version steps of +1 survive |
| SSRC and CNAME in `a=ssrc`, `mc_ssrc`, `mc_floor_ssrc` | one project-wide SSRC mapping |
| MSRP URIs in `a=path`, multipart boundaries, registration tokens | fixed formats |

Ports in SIP and SDP follow the transport port policy, and `--prefix-preserving`
applies to addresses in SIP and SDP text as it does to the headers. The Date
header follows `--time-shift`.

**Removed** and counted in the report: every header, header parameter, URI
parameter, feature tag and SDP attribute without a rule; User-Agent, Server,
Organization, Subject, Identity, User-to-User, P-Media-Authorization,
Geolocation-Routing, Restoration-Info and Service-Interact-Info; URI headers
(`?…`) and passwords; the IMS AKA `ik` and `ck`; the SDP keys and credentials
(`a=crypto`, `a=key-mgmt`, `a=ice-ufrag`, `a=ice-pwd`, `a=fingerprint`,
`a=tls-id`), free text and identities (`a=tool`, `a=cat`, `a=keywds`, the
`a=file-*` attributes, `a=altc`, the BFCP `a=floorctrl`, `a=confid`, `a=userid`
and `a=floorid`), value lists the rules do not model (`a=content`, `a=rtcp-xr`,
`a=extmap`, `a=ecn-capable-rtp`); SDP `u=`, `e=`, `p=`, `k=` and other `i=`
lines. The text of
Warning and the `text` parameter of Reason are blanked (an MCX warn code is
kept), `s=` becomes `-`, and the reason phrase of a status line becomes the
RFC 3261 default phrase for its code (`-` for codes without one).

**Emptied:** SDP and `multipart/*` bodies are parsed (multipart up to 4 levels),
and the MCX XML bodies are rewritten (next section). Every other body type,
including `application/mikey`, the MCData signalling and payload and
`text/plain`, keeps its Content-Type and part headers with an empty body, so the
analyst still sees which bodies were present. Content-Length is rewritten for the message and for
every part.

**Transport.** SIP over TCP is reassembled per direction and framed by
Content-Length; after a length change, the sequence numbers, acknowledgements
and SACK blocks of both directions are shifted, and a retransmission is
rewritten exactly like the first transmission. A UDP datagram fragmented at the
IP layer is reassembled, rewritten and fragmented again, keeping the
identification, the order and the timestamps of the original fragments, with no
fragment larger than the largest original one. SIP over TLS, SCTP, WebSocket and
inside ESP is not parsed and stays zeroed.

**Fail closed.** A message whose start line, header framing, one of Via, From,
To, Call-ID, CSeq, Content-Length or Content-Type, or body fails to parse is
zeroed (or dropped) as a whole and counted as malformed; another header that
fails to parse is removed and counted. TCP bytes that cannot be framed with
certainty (a stream that starts mid-message, a gap, out-of-window data) are
zeroed until a message boundary is found again. A fragmented datagram that
cannot be reassembled with certainty has all its fragments zeroed.

**Limits.** Messages and datagrams are held back only until they are complete,
within fixed bounds; exceeding one zeroes what is held, never passes it through:

| Bound | Value |
|---|---|
| SIP message over TCP | 1 MiB |
| bytes held in the output queue (all streams and datagrams) | 64 MiB |
| a message or datagram still incomplete after | 10 s of capture time |
| TCP directions tracked | 65,536 |
| fragmented datagrams pending | 4,096, each up to 64 KiB |
| header fields per message, one header field | 512, 64 KiB |
| multipart nesting, parts per body | 4, 64 |

A rewritten message can be longer than the original, so the snapshot length of
the output is raised to at least 262,144 bytes.

### RTP, RTCP, floor control and MSRP

Media is recognised only on the endpoints that an SDP offer or answer of the
capture announces (`m=`, `c=`, `a=rtcp`, `a=rtcp-mux`, `a=path`, the MCPTT and
MCVideo `m=application` lines), matched on the original addresses. A UDP flow that
no SDP announces stays zeroed, even when it looks like RTP. Every element has a
rule with its source (RFC 3550, RFC 3611, RFC 3711, RFC 4585, RFC 4975, RFC 5285,
3GPP TS 24.380, TS 24.581, TS 24.582; see `rules/rtp.yaml`,
`rules/rtcp.yaml`, `rules/rtcp-app.yaml`, `rules/msrp.yaml` and `rules/SOURCES.md`).

**Kept:** the RTP header (version, padding and marker bits, payload type, sequence
number, timestamp, the header extension structure and its element IDs); RTCP sender
and receiver report statistics, the SDES chunk structure, generic NACK, PLI, SLI
and RPSI feedback (the RPSI bit string zeroed), the extended report blocks of
RFC 3611 §4.1 to §4.7; for MCPTT floor control, MCVideo transmission control, and
the pre-established session, MBMS and MBS subchannel and notification messages of
MCPTT, MCVideo and MCData, the message types, priorities, reject
causes, durations, queue positions, indicators, sequence numbers and
acknowledgement requests; MSRP methods, status codes, Byte-Range, Success-Report and
Failure-Report, Content-Type and the message framing.

**Pseudonymised**, with the mappings of the SIP layer, so that each value has one
pseudonym in SIP, SDP and media:

| Value | Pseudonym |
|---|---|
| SSRC and CSRC in RTP, RTCP and floor control | the SSRC mapping of `a=ssrc` |
| SDES CNAME | the CNAME of `a=ssrc` |
| MCPTT, MCVideo and MCData IDs, group IDs and functional aliases in floor control | the SIP URI mapping |
| location in floor control: PLMN, E-UTRAN cell, tracking area, MBMS service area and MBSFN area | one mapping per component, same length |
| floor participant references | 32-bit values |
| MSRP To-Path and From-Path | the `a=path` mapping of the SDP |
| MSRP transaction IDs and Message-IDs | same length and character set; a REPORT keeps the Message-ID of its SEND |

**Zeroed or removed:** RTP and SRTP payloads (zeros of the same length, the
padding count kept), header extension element values, RTCP fields and blocks
without a rule, SDES items other than CNAME, BYE reasons, reject phrases and
other free text in floor control, the coordinates of a Location (its type is
kept), the Participant Type of Track Info (replaced by `unknown`), fields and
messages without a rule (an APP
packet whose name has no rules is removed from its datagram), MSRP content and
comments, and MSRP headers without a rule. Under SRTP and SRTCP only the
unencrypted header is decoded: the RTP header is kept as above, and of an SRTCP
packet only the first 8 octets (12 when they end in an APP name the rules know).
Everything after it, including the MKI, the authentication tag and the SRTCP
index, is zeroed with its length kept: the MKI can carry a key identifier derived
from the user's identity.
MSRP over TLS stays zeroed. A malformed RTP, RTCP, floor control or MSRP packet is
zeroed after its last header the tool understands, and counted by reason.

**Limits.** The table of announced media endpoints holds 65,536 entries; beyond
that, the least recently used one is evicted and its flows fall back to zeroing.

### MCX XML bodies

The XML bodies of SIP messages and multipart parts are rewritten in place, element
by element, for 30 Content-Types: MCPTT, MCData and MCVideo information, location,
affiliation, regroup, MBMS and MBS usage, floor and transmission requests, message
store control, signed bodies, and the IETF and OMA documents MCX uses (pidf with the
MCX presence extensions, resource-lists, reginfo, conference-info, xcap-diff,
poc-settings). Every element and attribute has a rule with its source (3GPP
TS 24.379 Annex F, TS 24.282 Annex D, TS 24.281 Annex F, TS 33.180, and the schemas
of TS 37.579-5; see `rules/xml-*.yaml` and `rules/SOURCES.md`). Rules are keyed on
the namespace and the local name, never on a prefix. Only the edited values change:
prefixes, quoting, whitespace and the order of everything else stay as written.

**Kept:** the element structure, enumerated and boolean values (session types,
emergency, alert and imminent-peril indicators, request and response types,
affiliation and registration states, report types), counters, intervals,
priorities, time stamps, location trigger configuration and trigger IDs, and the
signature and encryption algorithm identifiers. A kept value that does not match
the type its rule names (for example free text in an enumeration) is removed.

**Pseudonymised**, with the mappings of the SIP and media layers: MCPTT, MCData and
MCVideo IDs, group IDs and functional aliases (the SIP URI mapping), client IDs (the
`+sip.instance` mapping), display names, Call-IDs and tags (in Replaces values and
conference-info), entity tags (one pseudonym across xcap-diff, SIP-ETag and
SIP-If-Match), Content-IDs in signed bodies, SSRCs and floor participant references,
cell identities per component (an ECGI in a location report has the pseudonym the
floor control Location field gives it), and identifiers without a grammar (same
length and character classes). XCAP paths keep their application usage, tree and
fixed document names; the user part, group ID and other segments are pseudonymised.
Bodies embedded in a resource-list entry URI (the `body` URI header of a REFER for a
pre-established session) are decoded, rewritten like top-level bodies, and encoded
again.

**Removed or emptied:** access tokens, key material, free text (organisation names,
notes, reasons, subjects, alert texts), the signature and digest values of signed
bodies (the elements stay, empty), TMGIs and
MBS session IDs (the elements stay, empty), and every element, attribute or
namespace without a rule, comments and processing instructions. Coordinates,
altitude and accuracies are replaced by `0`, bearing and speed by zeros.

**Fail closed.** A body that is not well-formed XML 1.0 with namespaces, is not
UTF-8, contains a document type declaration, exceeds a bound (depth 32, 10,000
elements, 64 attributes per element, names of 256 bytes, values of 64 KiB, 1 MiB per
body), or has a root element without a rule is emptied as an unknown body would be,
and counted by reason. Encrypted content and group key transport payloads are
described under "Key management" below. External entities and schemas are
never fetched. The report counts bodies by Content-Type and outcome, and elements
and attributes by namespace, name and action.

### Key management (MIKEY-SAKKE) and encrypted content

MCX media security distributes its keys in MIKEY-SAKKE I_MESSAGEs (RFC 6509 as profiled by
3GPP TS 33.180 Annex E). The tool finds them in four places: the SDP attribute
`a=key-mgmt:mikey` (private calls, MBMS announcements, embedded SDP), `application/mikey`
bodies and parts (CSK upload and download, MuSiK download, MCData SDS, subscriptions to the
group management server; binary or base64), the `<GKTP>` elements of group key transport
documents and of `<MKFC-GKTPs>` (hexBinary), and the PCK I_MESSAGE field 192 of the
pre-established session Connect message. `--encrypted` chooses what happens to them and to
XML content encrypted with `xenc:EncryptedData` (TS 33.180 §9.3.4.2):

- **`ciphertext`** (default): the message structure is kept and every identifying field is
  rewritten. Initiator, responder and KMS identities take the same pseudonyms as in SIP, XML
  and floor control. Key identifiers (CSB ID, SPI, the DPPK-ID of the key parameters,
  XPK-IDs and the `key-id` of encrypted URIs) take one project-wide pseudonym that keeps the
  purpose tag (GMK, PCK, CSK, ...). RAND and IVs take same-length pseudonyms, the timestamp
  follows `--time-shift`, and the ECCSI signature is zeroed. **What stays as ciphertext:** the
  SAKKE encapsulated keys, the encrypted key parameters payload and the XML `CipherValue`.
  They open only with the receiver's or the group's key. `EncryptedData` under an element
  marked `type="Encrypted"` keeps its type, algorithm, key name (pseudonymised) and cipher
  value. Unknown parts are removed.
- **`passthrough`**: every recognised I_MESSAGE and `EncryptedData` subtree is copied byte
  for byte, for example to let a vendor check an ECCSI signature failure. Everything around
  them is anonymised as usual. **The output then contains original identities and key
  identifiers inside those elements.** The leak scan reports them as warnings (frame, offset,
  carrier, category; never the value) in `scan.warnings`, and the run states this on stderr
  and in the report. Any hit outside those elements still stops the run.
  `mcxanon scan --encrypted passthrough` applies the same rule to a published file.

**Signatures do not verify after anonymisation:** a rewritten I_MESSAGE carries a zeroed
ECCSI signature, and the report says so for every message. A message the tool does not
understand (not MIKEY-SAKKE, malformed, over a bound) is never passed through: the attribute is
removed, the body emptied, the `<GKTP>` removed, or the field zeroed, as before, with the
reason counted.

**Hidden identities.** UIDs (TS 33.180 §F.2.1) are opaque pseudonyms by default. With
`--kms-key-period <kms-uri>=<length>[:<offset>]` (seconds; once per KMS), a UID whose identity
appears in the same run is recomputed from the pseudonymised identity, KMS and timestamp, so
it still matches. The key periods never appear in the output or the report.

**Media keys.** On SRTP and SRTCP flows (`RTP/SAVP`), the trailer stays zeroed except for the
MKI. An MKI that equals a key identifier announced in the same SDP, or one already in the
project mapping, takes the key identifier pseudonym (GMK-ID || GUK-ID, PCK-ID, or a floor
control key ID). The report counts MKIs pseudonymised, unmatched and ambiguous.

`project show-map`, `project lookup` and `reveal` handle the new pseudonyms: key identifiers
(8 hex digits, as in Wireshark), RAND/IV values and UIDs (hex; UIDs also base64).

### HTTP and TLS

The HTTP-1 interfaces of MCX (TS 33.180 Annex B and Annex D) carry identities too: OpenID
Connect at the IdMS, XCAP at the configuration (CMS) and group (GMS) management servers, and key
material from the KMS. The tool recognises HTTP/1.1, HTTP/2 in the clear (h2c, prior knowledge
or Upgrade) and TLS 1.0 to 1.3 on any TCP port, including TLS inside an HTTP CONNECT tunnel.

- **HTTP messages.** Methods, status codes, versions, framing and the headers defined by the
  HTTP RFCs are kept. Request targets are rewritten segment by segment: XCAP AUIDs and the
  standard document names stay, the XCAP user (`users/sip:...`) and group identities
  (`global/byGroupID/sip:...`) take the same pseudonyms as in SIP, other segments become opaque
  pseudonyms. Host names follow the domain mapping. Bodies are rewritten by their type: the MCX
  XML documents (CMS, GMS, KMS) by the XML rules, JSON and forms by the OAuth rules. Chunked
  bodies leave with a `Content-Length`; compressed bodies (`Content-Encoding`) and bodies
  without rules are removed, and the removal is counted.
- **Credentials.** Passwords, authorization codes, PKCE verifiers, refresh tokens, cookie values
  and Basic credentials are removed. JWTs keep their structure: header and claims are rewritten
  (`sub` and the MCPTT ID claim take the SIP user pseudonyms, `iss` and `aud` the URL rules,
  times follow `--time-shift`), and the signature is zeroed. Other bearer tokens become opaque
  pseudonyms. Digest parameters follow the SIP rules.
- **h2c.** Header blocks are decoded (HPACK) and re-encoded as literals, so the output decodes
  without the input's table state; frame types, settings and error codes stay.
- **TLS.** Record headers, versions, cipher suites, extension types, groups and signature
  algorithms are kept, so the handshake can be checked against the TLS profile. Server names
  and certificate names take the domain and identity pseudonyms. Randoms, session ids,
  certificate serial numbers and key identifiers take same-length pseudonyms; key shares, key
  exchange values, public keys, signatures and tickets are zeroed with their lengths kept.
  Certificates are re-encoded as valid DER (they decode in Wireshark, but no signature
  verifies). Encrypted records keep their header and have their content zeroed.

The report has `http` and `tls` sections (messages, headers and parameters by action, removed
credentials by kind, certificates rewritten, records zeroed) and states that JWT, KMS and
certificate signatures no longer verify and that certificate validity dates are not shifted.
`reveal` and `lookup` work on the tshark exports of these protocols. The rule sources are listed
in [rules/SOURCES.md](rules/SOURCES.md).

### Zeroed or removed

- **Payload.** Everything above TCP, UDP and SCTP other than SIP, HTTP and TLS,
  and everything after a header the tool does not understand, is overwritten with
  zeros (`--payload zero`, the default) or removed (`--payload drop`; TCP
  sequence numbers are then renumbered so that streams stay consistent). SIP
  messages are kept and anonymised in both modes, and so are the RTP, RTCP, floor
  control and MSRP packets of announced media endpoints, with their payloads and
  content zeroed (see above). Any other application protocol is not parsed, so
  its content never reaches the output.
- **pcapng metadata.** Only options needed to decode packets (timestamp
  resolution and offset, FCS length, link type, snapshot length, packet flags
  and drop counts, interface statistics counters) are kept. Comments, interface
  names and descriptions, host and OS strings, capture filters, interface
  addresses, Name Resolution Blocks, Decryption Secrets Blocks, custom blocks
  and unknown blocks are removed and counted in the report.
- **Malformed packets** are never passed through: everything after the last
  fully understood header is zeroed or removed, and the run continues.

### Residual-leak scan

Before publishing, the output is scanned for:

- every original value in the project mapping;
- every address, and every SIP and SDP identity (URIs and their parts, display
  names, Call-IDs, tags, branches, Via hosts, Authorization usernames,
  `+sip.instance` values, cell identities, SDP addresses), and every SSRC, CNAME,
  floor control identity and MSRP path, transaction ID and Message-ID, that the
  scanner finds in the input on its own, with its own minimal parser;
- every value of the XML bodies of the input (attribute values, text, comments and
  the bodies embedded in entry URIs, in raw and unescaped form, and the URIs in
  them), and every unknown element or namespace name, found by the scanner's own
  lenient XML reader. Not searched, because the output keeps them on purpose:
  values of the standard XML vocabulary (namespace, element and attribute names,
  enumerations), booleans, dates and times, decimal numbers of fewer than 7 digits,
  hex values of up to 6 digits, Resource-Priority values, and the fields the rules
  keep as free tokens or wide numbers (trigger IDs, frequencies). An unknown element
  name is searched as a tag (`<name`), not as a bare word;
- every value the anonymiser removed during the run;
- every entry of an optional deny list (`--deny-list words.txt`, one entry per
  line, for host names, site names, subscriber identities and similar).

Each value is searched in binary form, in its text forms (upper and lower case,
compressed and full IPv6, every MAC separator), as hex, base64, UTF-16, URL
encoding (including SIP `%xx` escaping of every character), reverse DNS, IPv4
embedded in IPv6 and MAC in EUI-64 form; numbers on digit boundaries. Any hit
stops the run: no output file is created, the exit code is 1, and the report
lists the frame, file offset, encoding and the pseudonym of the leaked value
(never the value itself).

A 4-byte value (an IPv4 address, an SPI or SSRC) can match by chance in large
captures. Such a match is ignored, and counted in the report as a suppressed
chance match, only in these cases:

- its binary form lies entirely inside header fields that the scanner
  recognises, RTP and RTCP headers included, or in zero bytes right after them
  (a zeroed payload), and does not sit on a position that can hold an IPv4
  address, an SSRC or a CSRC;
- it starts in one record of the capture file and ends in the next one (for
  example the line feed that ends a SIP message and the timestamp of the next
  record): no packet field crosses a record boundary;
- it starts inside a recognised header field (not on an address, SSRC or CSRC
  position) and runs into the payload, for example a recomputed UDP checksum
  followed by the first letters of a SIP method: a leaked value lies wholly in
  the payload;
- its hex, base64 or decimal form lies entirely inside a pseudonym of the
  project mapping, for example the hex form `0a281477` of 10.40.20.119 inside
  the domain pseudonym `d-0a281477`. A pseudonym is derived from another value
  and carries nothing of the matched one.

Some values cannot be searched without meaningless matches. They are still
pseudonymised, and the report counts them as unscannable: values shorter than 4
bytes, and values equal to, or contained in, a standard term that the output
keeps on purpose (a header or parameter name, a feature tag, a method, a
Content-Type, an SDP attribute name). A user part `mcptt` is therefore
pseudonymised but not searched.

## Revealing an analyst's findings

The person who anonymised a capture keeps the project. Whoever analyses the
anonymised capture (a vendor, a compliance lab, an AI assistant) writes their
findings in terms of pseudonyms: "the INVITE from `sip:u-7990df25@d-d24d7026.d-51228bc4.invalid`
lacks …", "SSRC 0x38e5f406 sends a Floor Request after Floor Taken". `reveal`
turns such a text back into a text about your own network, locally:

```bash
mcxanon reveal --project case-1042 findings.txt -o findings.revealed.txt
some-tool | mcxanon reveal --project case-1042 > revealed.txt     # stdin to stdout
```

Any text works: a report, an e-mail, a ticket, an AI answer, a `tshark -V` or
`-T fields` export, a CSV. Every pseudonym of the project is replaced by its
original in the same style (a compressed IPv6 address stays compressed, a hex
SSRC stays hex in the same letter case, a percent-escaped value stays escaped),
and every other byte is left as it is. Hosts, user parts, telephone numbers,
addresses (including link-local interface identifiers, solicited-node addresses
and multicast MACs), Call-IDs, tags, branches, SSRCs, SPIs, UUIDs, IMEIs, cell
identities and the PLMN-plus-bits location forms of the XML bodies are
recognised.

stderr starts with a warning that the output contains original values, and ends
with a summary:

```text
mcxanon: revealed 8009 values (call-id 205, domain 506, ipv4 2017, mac 3526, sip-user 566, ssrc 446, ...)
mcxanon: left 3 ambiguous (opaque 1, sdp-sess 2), 0 unknown; 3 mapping entries not searchable
  17561:39 ambiguous  opaque    t-1577  -> r-0042
```

- **Ambiguous** values are left unchanged and listed with their line, column and
  the original they would map to: values of 6 characters or fewer, values of
  small spaces (VLAN IDs, ports, tracking area codes and similar), values that
  are a pseudonym in two categories, and values that are also an original in the
  project. `--replace-ambiguous` replaces all of them except the last kind.
- **Unknown** values look like pseudonyms of the tool (`u-…`, `d-….invalid`,
  `240.0.0.0/4`, `2001:db8::/32`) but are not in the project: a pseudonym of
  another project, or one an AI made up. They are left unchanged and listed.
- Pseudonyms of 1 to 3 characters are never searched (every `3` in a text would
  be a candidate); `project lookup` still resolves them.
- `--annotate` writes `original⟦pseudonym⟧`, so you can see what was replaced.
- `--report r.json` writes the counts and every listed value as JSON
  (`schemas/reveal-report.schema.json`). It contains original values.

`project lookup` resolves one value. Without options a pseudonym gives its
original; with `--original` an original that the project has already seen gives
its pseudonym, so you can point the analyst at a subscriber without naming them.
A composite value (a SIP URI, a host) is printed only when every part of it is
known; a lookup never creates a pseudonym. Put `--` before a value that starts
with `-`.

```bash
$ mcxanon project lookup case-1042 'sip:u-7990df25@d-09e7aeab.d-56a451d1.d-0efe11e0.d-b3949a86.invalid'
sip-user   u-7990df25                                          260011234567890
domain     d-09e7aeab.d-56a451d1.d-0efe11e0.d-b3949a86.invalid  ims.mnc001.mcc260.3gppnetwork.org
composite  sip:u-7990df25@d-09e7…invalid                        sip:260011234567890@ims.mnc001.mcc260.3gppnetwork.org
$ mcxanon project lookup case-1042 --original 10.200.0.1
ipv4       10.200.0.1                                          254.38.179.72
```

(Columns are tab-separated.) Only values that the anonymiser pseudonymised can
come back: what it zeroed or removed has no mapping entry. `reveal` and `lookup`
read the project and never change it; the project lock is held only while the
mapping is loaded. Their output and reports contain original values: never send
them to the analyst.

## Threat model

The tool protects against **identification of the network from the capture
contents**: addresses, names and metadata that would reveal who operates the
system, where it runs and which subscribers took part.

It assumes that the person running the tool is trusted, that the machine is not
compromised, and that the project directory (secret and mapping) stays on that
machine. Anyone holding the project secret or mapping can reverse the
pseudonyms, so never share them. Anyone holding a pseudonymised capture and an
original capture of the same traffic can link them through the properties
listed in the next section.

### What is NOT anonymised

Pseudonymisation of addresses does not hide everything. The following is kept
on purpose, because analysis depends on it, and can help someone who already
knows the network to recognise it:

- packet sizes, timing, ordering and the number of packets per flow;
- transport ports (unless ephemeral ports are pseudonymised) and VLAN IDs
  (unless pseudonymised);
- header values that can serve as fingerprints: IPv4 identification, TTL and
  hop limit, TCP window sizes, options and timestamps, GTP-U tunnel endpoint
  identifiers (TEIDs), GRE keys, SCTP verification tags and stream identifiers,
  IPsec SPIs and sequence numbers, IPv4 timestamp option values;
- the protocol mix and the behaviour of the implementations (retransmission
  patterns, timers, option ordering);
- the link-layer type and the capture's snapshot length and timestamp
  resolution;
- SIP: the sequence of request methods and response codes, and its timing;
- SIP: header order, header-name casing and compact forms, and the capability
  sets (Allow, Supported, Require), which can fingerprint an implementation;
- SIP and SDP: the length and character set of values a rule pseudonymises in
  place (telephone numbers, digest values, cell and location identities, SDP
  session IDs and versions);
- SIP: the pseudonym of a short telephone number (4 to 6 digits) can equal an
  original number seen later in the same project; such a collision stops the
  run (exit 4), and a re-run on a fresh project avoids it;
- RTP: sequence numbers, timestamps, payload types and marker bits;
- RTP and MSRP: payload lengths, which reveal codec modes, talk spurts and
  message sizes;
- RTCP: report statistics, including the RFC 3611 VoIP Metrics signal and
  noise levels, which are derived from the audio;
- floor and transmission control: message order and timing, priorities,
  durations, reject causes and queue positions;
- MSRP: Byte-Range values and status codes;
- MCX XML bodies: the element and attribute structure of kept documents (element
  order and which optional elements are present);
- MCX XML bodies: enumerated and boolean values (session types, emergency and
  imminent-peril indicators, affiliation and registration states, report types);
- MCX XML bodies: the configured location triggers (kinds, intervals, distances,
  trigger IDs) and the presence of coordinates, whose values are replaced by 0;
- MCX XML bodies: body lengths, which change only by the length differences of the
  rewritten values;
- MCX XML bodies: signature and encryption algorithm identifiers, and which parts
  were signed or encrypted;
- key management: which keys (by purpose tag) were distributed to whom and when, the key
  types, crypto session IDs, security policies and key parameters, the length of every
  MIKEY field, and the ciphertext of the encapsulated keys, encrypted key parameters and
  encrypted XML content (`ciphertext` mode); in `passthrough` mode, the whole I_MESSAGEs
  and `EncryptedData` subtrees as captured.

The report counts what the SIP layer kept, pseudonymised, removed and zeroed, per
header name, SDP line type and Content-Type, and what the XML layer did per body
type, element and attribute. Unknown header names, element names and Content-Types
come from the input and appear in the report by name, so a vendor
header whose name itself carries an identity (for example `X-<customer>-Id`)
would show it there. The report is checked like the output: a name that contains
a deny-list entry or a scanned value is replaced by `(invalid-name)`. Put such
names in the deny list.

Timestamps can be moved with `--time-shift` (for example `-30d` or `+1h30m`);
intervals between packets are preserved exactly.

## Known limitations

- **False leak reports in large captures.** A short original value (for example
  a 4- or 5-digit number, or a value of 2 or 3 characters) can appear by chance inside the
  digits or characters of a pseudonym that the tool wrote itself. The scanner
  then reports a residual leak and nothing is published (exit code 1), even
  though no original value is in the output. The chance grows with the size of
  the capture. The report shows the frame, the offset and the pseudonym of the
  matched value, so you can confirm that the match lies inside another
  pseudonym. Running again in a new project gives different pseudonyms, but it
  also breaks consistency with the captures of the old project. A fix is planned
  for 0.1.1.
- **Nothing is decrypted.** The content of TLS records after the handshake (SIP
  over TLS, HTTPS) and SRTP payloads is zeroed, with the headers kept, so what
  they carried cannot be analysed. Only TLS handshakes in the clear are
  rewritten.
- **HTTP paths in non-ASCII text.** A request whose path has a segment in
  non-ASCII text (for example a percent-encoded Cyrillic name) is zeroed
  instead of pseudonymised.
- **No Diameter.** Diameter (Rx, MB2-C) and every other protocol without a rule
  set is zeroed or removed with the rest of the payload.
- **Signatures no longer verify.** JWT, KMS and certificate signatures are
  zeroed or invalidated by the rewrite, and certificate validity dates are not
  shifted.

## Data directory

Projects live in `projects/<name>/` below the data directory, which is chosen in
this order:

1. `--data-dir <path>`;
2. the `MCXANON_DATA_DIR` environment variable;
3. portable mode: a directory named `mcxanon-data` next to the `mcxanon`
   executable, used only if it already exists;
4. the per-user application data directory: `$XDG_DATA_HOME/mcxanon` (default
   `~/.local/share/mcxanon`) on Linux, `~/Library/Application Support/mcxanon`
   on macOS, `%APPDATA%\mcxanon` on Windows.

`mcxanon project where` prints the resolved location and the rule that chose it.
Project directories are readable by their owner only. A project is locked while
a command uses it; a second command fails at once, or waits with `--wait`.

## Optional encryption

```bash
mcxanon project init --encrypt case-1042
```

An encrypted project keeps its secret and mapping encrypted at rest with
ChaCha20-Poly1305 under a key derived from a passphrase with Argon2id. The
passphrase is asked for on the terminal (without echo); for automation it can
come from `--passphrase-file <path>` or the `MCXANON_PASSPHRASE` environment
variable. It is never written anywhere. A wrong passphrase or a modified project
file stops the command before any capture is read. Encryption is off by
default.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | residual leak found; nothing was published |
| 2 | usage error (bad option, output exists without `--overwrite`, …) |
| 3 | input error (unreadable or unsupported file, wrong passphrase, …) |
| 4 | an original value equals a pseudonym already issued in the project |
| 5 | the project is in use by another command |
| 70 | internal error |

Every run of `anonymize` and `scan`, including a failed one, writes a JSON report
(schema in `schemas/report.schema.json`). These reports never contain original
values. `project lookup` exits with 1 when the value is not found. `reveal` and
`project lookup` print original values by design (see above).

## Building

The project uses C++23, CMake and Conan 2. The reference toolchain is the
container defined in `.ci/Dockerfile` (Debian 13, GCC 14, Clang 19):

```bash
docker build -t mcxanon-ci .ci
docker run --rm -v "$PWD:/work" -w /work mcxanon-ci bash .ci/build.sh gcc14 test
```

`.ci/build.sh` accepts the profiles `gcc14`, `clang19`, `asan` and `fuzz`. The
binary is `build/Release/src/cli/mcxanon`. Without the container:

```bash
conan install . --build=missing -s compiler.cppstd=23
cmake --preset conan-release
cmake --build --preset conan-release
ctest --preset conan-release
```

Tests use synthetic captures only, generated by `tools/fixturegen/`. Integrity
tests compare Wireshark's expert information before and after anonymisation and
need `tshark`; they are skipped when it is not installed.

## Licence

mcx-anonymizer is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version. See [LICENSE](LICENSE).

Copyright (C) 2026 UIMS.

A commercial licence is available for uses that the GPL does not allow; see
[COMMERCIAL.md](COMMERCIAL.md).

Contributions require a signed Contributor Licence Agreement; see
[CONTRIBUTING.md](CONTRIBUTING.md).
