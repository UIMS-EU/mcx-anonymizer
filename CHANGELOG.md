# Changelog

All notable changes are listed here. The project follows
[Semantic Versioning](https://semver.org/); while the version is 0.x, a minor
release can change the command line, the report format and the project format.

## [Unreleased]

Fixes from the first run on captures of a third-party MCX system.

### Fixed

- The residual-leak scanner no longer reports a leak for a value that a TCP
  segment boundary cut (`branch=z9hG` with `4bK…` in the next segment): such a
  fragment is searched only if the next segment does not give the whole value,
  and is counted as `scan.skipped_input_fragments`. Matches inside the
  `z9hG4bK` cookie of a `branch` parameter are counted as
  `scan.suppressed_cookie_matches` instead of failing the run.
- Namespace prefixes declared by the standards' schemas (`mcpttPI10`,
  `mcdataPI10`, `mcvideoPI10`, `mcs10Set`, …) are standard vocabulary: kept, and
  not searched by the scanner. Any other prefix is renamed to `ns1`, `ns2`, … and
  counted as `xml.prefixes_rewritten`.
- A TCP segment that starts inside a rewritten message and waits for a later
  message while the peer acknowledges no longer leaves a one-byte gap in the
  output sequence numbers.
- A Warning with warn code 399 and a text of the warning-text tables of
  TS 24.379, TS 24.281 or TS 24.282 keeps its text.
- `<video-pull-url>` and `<video-push-url>` of MCVideo are pseudonymised instead
  of removed.
- An XML value of decimal digits only (a location coordinate) and a PLMN of the
  project mapping are searched by the residual-leak scanner as numbers, on digit
  boundaries. Before, some projects
  failed on location reports with a false leak, because a cell identity
  pseudonym began with the same digits.

## [0.1.0] - 2026-11-16

First public release (preview). `mcxanon` anonymises pcap and pcapng captures
of Mission Critical systems (MCPTT, MCData, MCVideo). It works offline and fails
closed. Only what a rule from the standards covers is kept or pseudonymised.
Everything else is zeroed or removed. An independent scanner checks every
output before it is published.

### Capture foundation

- pcap and pcapng reading and writing. Supported layers: Ethernet, VLAN, Linux
  cooked capture, ARP, IPv4, IPv6, ICMP, ICMPv6/NDP, TCP, UDP and SCTP. The
  IP-in-IP, GRE and GTP-U tunnels are followed.
- Consistent per-project pseudonyms (HMAC-SHA-256) for MAC and IP addresses.
  Optional modes cover VLAN IDs, ephemeral ports, prefix preservation and a
  time shift. Lengths and checksums are recomputed.
- pcapng metadata is filtered down to what decoding needs.
- Projects can be encrypted (Argon2id, ChaCha20-Poly1305).

### SIP and SDP

- SIP over UDP and TCP, in plain IP and in tunnels. It is rewritten header by
  header from rule files that cite RFC 3261, TS 24.229, TS 24.379, TS 24.282,
  TS 24.281 and the RFCs they reference.
- The following are pseudonymised consistently with the IP layer: URIs, display
  names, dialog identifiers, credentials, security associations, access network
  information, SDP addresses, SSRCs and session identifiers.
- Multipart bodies. TCP reassembly with sequence and SACK shifting. IP fragment
  reassembly and refragmentation. All state is bounded.

### Media plane

- RTP and SRTP headers on SDP-announced endpoints, with payloads zeroed.
- RTCP reports, SDES, feedback and extended reports.
- MCPTT floor control, MCVideo transmission control and the other MCX RTCP APP
  families (TS 24.380, TS 24.581, TS 24.582).
- MSRP over TCP.

### MCX XML bodies

- Rules for the 30 MCX XML Content-Types (TS 24.379 Annex F, TS 24.282 Annex D,
  TS 24.281 Annex F, pidf, resource-lists, reginfo, conference-info, xcap-diff,
  poc-settings). Bodies are edited in place with the SIP and media mappings.
- Bodies embedded in resource-list entry URIs, encrypted and signed content,
  location identities and XCAP selectors.

### Key management

- MIKEY-SAKKE I_MESSAGEs in SDP, in `application/mikey` bodies, in `<GKTP>`
  elements and in MCPC field 192. Identities and key identifiers are
  pseudonymised and the UIDs of hidden identities are resolved.
- The SRTP and SRTCP MKI.
- Encrypted XML content and encrypted URIs. `--encrypted ciphertext` (the
  default) or `--encrypted passthrough`.

### HTTP and TLS

- HTTP/1.1 and HTTP/2 in the clear on any TCP port: XCAP (CMS, GMS), KMS and
  OpenID Connect (IdMS). Request targets, bodies, JWTs and OAuth parameters are
  rewritten. Credentials are removed.
- TLS 1.0 to 1.3 handshakes in the clear, including inside HTTP CONNECT tunnels.
  Server names and certificate names are pseudonymised. Certificates are
  re-encoded as valid DER. Key material is zeroed.

### Reveal

- `mcxanon reveal` maps the pseudonyms in an analyst's text (for example
  findings based on the anonymised capture) back to the originals, locally.
  `mcxanon project lookup` does the same for a single value.

### Reports and checks

- Every run writes a JSON report (format 6, `schemas/report.schema.json`). It
  says what every layer kept, pseudonymised, removed and zeroed, and it never
  contains original values.
- The residual-leak scanner has its own parsers and searches every original
  value in many encodings.

### Known limitations

See [Known limitations](README.md#known-limitations) in the README. The most
visible one is a false leak report: in large captures, a short original value
that appears by chance inside a pseudonym stops the run. A fix is planned for
0.1.1.

[0.1.0]: https://github.com/UIMS-EU/mcx-anonymizer/releases/tag/v0.1.0
