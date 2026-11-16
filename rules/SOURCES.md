# Normative sources of the rule set

Every rule in `rules/*.yaml` cites its source as `source: {spec, version, clause}`.
This table fixes the document versions the rule set is written against. Versions
were checked against the publishers' official pages on 2026-11-11.

| Area | Document | Version / date | Status and notes |
|---|---|---|---|
| pcapng blocks, options, timestamps | draft-ietf-opsawg-pcapng | -06, 2026-09-19 | Active WG Internet-Draft (Informational) |
| pcap file and record headers | draft-ietf-opsawg-pcap | -09, 2026-09-19 | Submitted to IESG (Historic) |
| LINKTYPE values | draft-ietf-opsawg-pcaplinktype | -18, 2026-04-06 | RFC Editor queue; not yet an RFC |
| Linux cooked capture v1 header | tcpdump.org, LINKTYPE_LINUX_SLL | page as of 2026-11-11 | Informative reference of draft-ietf-opsawg-pcaplinktype |
| Linux cooked capture v2 header | tcpdump.org, LINKTYPE_LINUX_SLL2 | page as of 2026-11-11 | Informative reference of draft-ietf-opsawg-pcaplinktype |
| VLAN tags (C-VLAN, S-VLAN) | IEEE Std 802.1Q | 802.1Q-2022 | Active; TPID values to be cited from the standard text |
| IEEE 802 identifiers (U/L, I/G bits) | RFC 9542 | 2024 | Obsoletes RFC 7042 |
| ARP | RFC 826 | Nov 1982 | Internet Standard; updated by RFC 5227, RFC 5494 |
| IPv4, options | RFC 791 | Sep 1981 | Internet Standard; updated by RFC 1349, 2474, 6864 |
| ICMP | RFC 792 | Sep 1981 | Internet Standard; updated by RFC 950, 4884, 6633, 6918 |
| IPv6 | RFC 8200 | Jul 2017 | Internet Standard (STD 86); updated by RFC 9673 |
| IPv6 addressing, modified EUI-64 | RFC 4291 | Feb 2006 | Draft Standard; updated by RFC 5952, 6052, 7136, 7346, 7371, 8064 |
| ICMPv6 | RFC 4443 | Mar 2006 | Internet Standard; updated by RFC 4884 |
| Neighbor Discovery | RFC 4861 | Sep 2007 | Draft Standard; updated by RFC 5942 and later |
| Segment Routing Header | RFC 8754 | 2020 | Proposed Standard; updated by RFC 9800 |
| Mobile IPv6 (Home Address option, type 2 routing header) | RFC 6275 | Jul 2011 | Proposed Standard |
| UDP | RFC 768 | Aug 1980 | Internet Standard; updated by RFC 9868 |
| TCP | RFC 9293 | 2022 | Internet Standard (STD 7) |
| TCP window scale, timestamps | RFC 7323 | Sep 2014 | Proposed Standard |
| TCP SACK | RFC 2018 | Oct 1996 | Proposed Standard |
| TCP MD5 signature option | RFC 2385 | Aug 1998 | Obsoleted by RFC 5925; cited only to recognise the option |
| TCP Authentication Option | RFC 5925 | Jun 2010 | Proposed Standard |
| SCTP | RFC 9260 | 2022 | Proposed Standard |
| SCTP ASCONF | RFC 5061 | Sep 2007 | Proposed Standard |
| SCTP AUTH | RFC 4895 | Aug 2007 | Proposed Standard |
| SCTP I-DATA | RFC 8260 | Nov 2017 | Proposed Standard |
| GRE | RFC 2784, RFC 2890 | Mar 2000, Sep 2000 | Proposed Standard; RFC 2784 updated by RFC 2890, 9601 |
| IP-in-IP | RFC 2003, RFC 2473 | Oct 1996, Dec 1998 | Proposed Standard |
| GTP-U | 3GPP TS 29.281 | V19.2.0 (2025-09) | Release 19; header in clause 5.1, extension headers in clause 5.2 |
| IPv6 Router Alert option | RFC 2711 | Oct 1999 | Proposed Standard |
| IPv6 Jumbo Payload option | RFC 2675 | Aug 1999 | Proposed Standard |
| IP Authentication Header | RFC 4302 | Dec 2005 | Proposed Standard |
| IP Encapsulating Security Payload | RFC 4303 | Dec 2005 | Proposed Standard |
| SCTP Partial Reliability (FORWARD TSN) | RFC 3758 | May 2004 | Proposed Standard |
| Internet checksum | RFC 1071, RFC 1624 | Sep 1988, May 1994 | Informational |
| Special-purpose address registries | RFC 6890; IANA IPv4 and IPv6 Special-Purpose Address Registries | BCP 153; registries last updated 2025-10-09 | RFC 6890 updated by RFC 8190 |
| 240.0.0.0/4 (reserved) | RFC 1112 §4; IANA IPv4 Special-Purpose Address Registry | Aug 1989 | Pseudonym range for IPv4 |
| 2001:db8::/32 (documentation) | RFC 3849 | Jul 2004 | Pseudonym range for IPv6; RFC 3849 updated by RFC 9637 (adds 3fff::/20) |
| MCAST-TEST-NET 233.252.0.0/24 | RFC 5771 | Mar 2010 | BCP 51 |
| IPv4/IPv6 translation prefix 64:ff9b::/96 | RFC 6052 | Oct 2010 | Proposed Standard |
| 6to4 2002::/16 | RFC 3056 | Feb 2001 | Proposed Standard |
| Teredo 2001::/32 | RFC 4380 | Feb 2006 | Proposed Standard; updated by RFC 5991, 6081, 9601 |
| Dynamic port range | RFC 6335 | Aug 2011 | BCP 165 |
| HMAC | RFC 2104 | Feb 1997 | Informational; updated by RFC 6151 |
| Argon2 | RFC 9106 | Sep 2021 | Informational |
| ChaCha20-Poly1305 | RFC 8439 | Jun 2018 | Informational |

Clause numbers of every rule were checked against the official RFC and draft
texts on 2026-11-12.

## SIP, SDP and MCX signalling (`rules/sip-*.yaml`, `rules/sdp.yaml`)

The SIP rule set (`ruleset: mcxanon-sip`) is written against the documents below. 3GPP
versions are the version of the specification text (for TS 24.229 and TS 23.003, the file
name of the release, `24229-j70` = V19.7.0 and `23003-k10` = V20.1.0); RFC versions are the
publication month printed on the RFC. Clause numbers were checked against the document texts
on 2026-11-12.

| Area | Document | Version / date | Used for |
|---|---|---|---|
| SIP core | RFC 3261 | 2002-06 | message grammar (§7, §25), header fields (§20), compact forms (§7.3.3), framing (§18.3), URI comparison (§19.1.4), tags (§19.3), branch cookie (§8.1.1.7) |
| IMS SIP profile | 3GPP TS 24.229 | 24229-j70 (V19.7.0) | profile tables of annex A (A.2.1.4.x), headers of §7.2, P-headers of §7.2A, media feature tags §7.9, feature-capability indicators §7.9A |
| MCPTT call control | 3GPP TS 24.379 | V19.6.0 | MCPTT SIP procedures, SDP offers, warn codes and warning texts (§4.4.1, §4.4.2; `sip-warning-texts.yaml`) |
| MCPTT media plane control | 3GPP TS 24.380 | V19.1.0 | `a=fmtp:MCPTT` (§12.1.2.3) |
| MCData signalling | 3GPP TS 24.282 | V19.6.0 | MCData SIP procedures, MSRP SDP, warning texts (§4.9.1, §4.9.2) |
| MCVideo signalling | 3GPP TS 24.281 | V19.5.0 | MCVideo SIP procedures and SDP, warning texts (§4.4.1, §4.4.2) |
| MCVideo media plane control | 3GPP TS 24.581 | V19.1.0 | `a=fmtp:MCVideo` (§12.1.2.3) |
| MCData media plane control | 3GPP TS 24.582 | V19.0.0 | `a=fmtp:MCDATA` (§13.5, §13.6) |
| MC security | 3GPP TS 33.180 | V20.0.0 | identities inside MIKEY (§E.7) |
| Numbering and identities | 3GPP TS 23.003 | 23003-k10 (V20.1.0) | private user identity (§13.3), public user identity (§13.4, §13.4B), instance ID (§13.8) |
| URIs | RFC 3966, RFC 3986 | 2004-12, 2005-01 | tel URI, generic URI, percent-encoding |
| SIP extensions | RFC 3262 (2002-06), RFC 3311 (2002-09), RFC 3313 (2003-01), RFC 3323 (2002-11), RFC 3325 (2002-11), RFC 3326 (2002-12), RFC 3327 (2002-12), RFC 3329 (2003-01), RFC 3428 (2002-12), RFC 3515 (2003-04), RFC 3581 (2003-08), RFC 3608 (2003-10), RFC 3840 (2004-08), RFC 3841 (2004-08), RFC 3891 (2004-09), RFC 3892 (2004-09), RFC 3903 (2004-10), RFC 3911 (2004-10), RFC 4028 (2005-04), RFC 4412 (2006-02), RFC 4457 (2006-04), RFC 4488 (2006-05), RFC 4538 (2006-06), RFC 4964 (2007-09), RFC 5002 (2007-08), RFC 5009 (2007-09), RFC 5318 (2008-12), RFC 5360 (2008-10), RFC 5373 (2008-11), RFC 5393 (2008-12), RFC 5502 (2009-04), RFC 5626 (2009-10), RFC 5627 (2009-10), RFC 6050 (2010-11), RFC 6086 (2011-01), RFC 6432 (2011-11), RFC 6442 (2011-12), RFC 6665 (2012-07), RFC 6809 (2012-11), RFC 7044 (2014-02), RFC 7315 (2014-07), RFC 7316 (2014-07), RFC 7433 (2015-01), RFC 7462 (2015-03), RFC 7913 (2016-06), RFC 7989 (2016-10), RFC 8101 (2017-03), RFC 8224 (2018-02), RFC 8262 (2017-10), RFC 8498 (2019-02), RFC 9410 (2023-07), RFC 9796 (2025-07), RFC 9878 (2025-11) | the header fields and parameters they define |
| Credentials | RFC 2617 (1999-06), RFC 7616 (2015-09), RFC 3310 (2002-09) | Digest and AKA credentials and challenges |
| SDP | RFC 8866 (2021-01), RFC 4566 (2006-07), RFC 3264 (2002-06) | SDP lines and core attributes, offer/answer |
| SDP attributes | RFC 3605 (2003-10), RFC 5761 (2010-04), RFC 4585 (2006-07), RFC 5576 (2009-06), RFC 5888 (2010-06), RFC 4145 (2005-09), RFC 4975 (2007-09), RFC 8839 (2021-01), RFC 4567 (2006-07), RFC 4568 (2006-07), RFC 8122 (2017-03), RFC 8842 (2021-01), RFC 3312 (2002-10), RFC 4032 (2005-03), RFC 3556 (2003-07), RFC 3890 (2004-09), RFC 4574 (2006-08), RFC 6135 (2011-02), RFC 6714 (2012-08), RFC 5547 (2009-05), RFC 4583 (2006-11), RFC 4796 (2007-02), RFC 5506 (2009-04), RFC 3611 (2003-11), RFC 5285 (2008-07), RFC 6236 (2011-05), RFC 6679 (2012-08), RFC 6947 (2013-05), RFC 8858 (2021-01), RFC 3550 (2003-07) | the SDP attributes they define |
| Identifier formats | RFC 7254 (2014-05), RFC 9562 (2024-05) | IMEI URN, UUID |
| MIME | RFC 2045, RFC 2046 | 1996-11 | MIME headers, multipart (§5.1.1: boundary of 1 to 70 characters) |
| Body types | RFC 5875, RFC 3830 | 2010-05, 2004-08 | `application/xcap-diff+xml`, `application/mikey` (emptied until features 003 and 005) |
| Reserved names | RFC 2606 | 1999-06 | reserved TLD `invalid` (§2) |
| IPsec SPI | RFC 4303 (2005-12) §2.1, RFC 4302 (2005-12) §2.4 | SPI values 1 to 255 are reserved; `esp.spi` and `ah.spi` pseudonymised with the SIP `spi-c`/`spi-s` mapping |

### Documents not yet available

The SIP rule set may cite only the documents above. These documents define headers,
attributes or feature tags met in MCX and IMS traffic, but were not available when the rule set
was written. What only they define is removed (fail-closed) until a rule with a verified source
is added:

- 3GPP TS 33.203 (Security-Client/-Server/-Verify procedures; the headers themselves are
  covered by RFC 3329 and TS 24.229 §7.2A.7);
- 3GPP TS 26.114 (`a=bw-info`, `a=3gpp_*`, `a=anbr`);
- 3GPP TS 26.346 (MBMS FEC attributes `a=FEC`, `a=FEC-declaration`, `a=FEC-OTI-extension`,
  `a=mbms-repair`);
- 3GPP TS 24.292 (`g.3gpp.ics`), TS 24.237 (`g.3gpp.atcf`, `g.3gpp.mid-call`), TS 24.186
  (`g.3gpp.datachannel`, `g.3gpp.dc-mux`), TS 24.173 (mmtel ICSI), TS 24.390 (USSD) and
  TS 23.228 (ICSI/IARI concept).

## Media plane (`rules/rtp.yaml`, `rules/rtcp.yaml`, `rules/rtcp-app.yaml`, `rules/msrp.yaml`)

The media rule set (`ruleset: mcxanon-media`) is written against the documents below, with
the same version conventions as the SIP rule set. Clause numbers were checked against the
document texts on 2026-11-12. The loader accepts only these documents
(`src/policy/media_rules.cpp`); keep both lists in sync. RFC 5761 and RFC 5506 define how
RTP and RTCP share a port and when RTCP is not compound; the dispatcher and the tiling follow
them, and no rule element needs them as a source.

| Area | Document | Version / date | Used for |
|---|---|---|---|
| RTP and RTCP | RFC 3550 | 2003-07 | RTP fixed header (§5.1), header extension (§5.3.1), RTCP packets (§6.1, §6.4–§6.7), RTCP port (§11), validity checks (§A.1, §A.2) |
| RTP header extensions | RFC 5285 | 2008-07 | one-byte and two-byte forms (§4.2, §4.3) |
| RTP/RTCP multiplexing | RFC 5761 | 2010-04 | demultiplexing on one port (§4) |
| Reduced-size RTCP | RFC 5506 | 2009-04 | non-compound RTCP (§3.4) |
| RTCP feedback | RFC 4585 | 2006-07 | FB packet format (§6.1), Generic NACK (§6.2.1), PLI, SLI, RPSI (§6.3.1–§6.3.3), application layer FB (§6.4) |
| RTCP extended reports | RFC 3611 | 2003-11 | XR packet (§2), report blocks (§4.1–§4.7) |
| SRTP and SRTCP | RFC 3711 | 2004-03 | packet formats (§3.1, §3.4) |
| Telephone events | RFC 4733 | 2006-12 | telephone-event payload (zeroed like any payload) |
| MSRP | RFC 4975 | 2007-09 | syntax (§9), framing and end-line (§7.1), headers (§7.1.1–§7.1.3, §7.2), URIs (§6) |
| MCPTT media plane control | 3GPP TS 24.380 | V19.1.0 | RTCP APP format (§8.1), MCPT, MCPC, MCMC, MCNC, MCSC messages and fields (§8.2–§8.6), media plane control channel (§4.3.3.1), Participant Type fallback (§6.5.4.2), security (§13.1) |
| MCVideo media plane control | 3GPP TS 24.581 | V19.1.0 | MCV0–MCV5 messages and fields (§9), transmission control channel (§4.3.3.1) |
| MCData media plane control | 3GPP TS 24.582 | V19.0.0 | MSRP use (§6, §7), MCDM (§11) |
| MCData signalling | 3GPP TS 24.282 | V19.6.0 | SDS over MSRP, MSRP SDP |
| MC security | 3GPP TS 33.180 | V20.0.0 | SRTP MKI = GMK-ID ‖ GUK-ID (§7.4.2): not kept |
| Numbering and identities | 3GPP TS 23.003 | 23003-k10 (V20.1.0) | ECI (§19.6), TMGI structure (§15.2), MBS session ID (§30.3) |
| Geographic shapes | 3GPP TS 23.032 | V19.0.0 | coordinates (§6.1) and altitude (§6.3), zeroed |

### Documents not yet available (media)

What only these documents define stays zeroed until a rule with a verified source is added:
- 3GPP TS 24.008 (TMGI octet coding, §10.5.6.13): TMGI and Alternative TMGI fields are
  zeroed with their length kept;
- 3GPP TS 24.501 (MBS Session ID coding, §9.11.4.30): MBS Session ID fields are zeroed;
- RFC 4976 (MSRP relays: AUTH, Use-Path, WWW-Authenticate, Authorization,
  Authentication-Info, Expires, Min-Expires, Max-Expires): AUTH messages are zeroed and the
  headers are removed;
- 3GPP TS 26.101, TS 26.201, TS 26.114 and RFC 3389 (codec frames, comfort noise): not
  needed, every RTP payload is zeroed;
- RFC 8285 (successor of RFC 5285): not needed, extension element data is zeroed.

## MCX XML bodies (`rules/xml-*.yaml`)

The XML rule set (`ruleset: mcxanon-xml`) is written against the documents below, with the
same version conventions as the SIP rule set. Clause numbers were checked against the
document texts on 2026-11-13. The loader accepts only these documents
(`src/policy/xml_rules.cpp`); keep both lists in sync. The IETF documents are cited through
their XML schemas as published in 3GPP TS 37.579-5, because the RFC texts were not available.

| Area | Document | Version / date | Used for |
|---|---|---|---|
| MCPTT documents | 3GPP TS 24.379 | V19.6.0 | Annex F: MCPTT information (§F.1), MBMS and MBS usage (§F.2, §F.2A), location (§F.3), (de)affiliation (§F.4), floor request (§F.5), signed bodies (§F.6), regroup (§F.7); pidf affiliation (§9.3.1), functional alias status (§9A), resource-lists (§4.8, §17.5), conference-info (§10.1.3) |
| MCData documents | 3GPP TS 24.282 | V19.6.0 | Annex D: MCData information (§D.1), (de)affiliation (§D.3), location (§D.4), MBMS (§D.5), regroup (§D.6), communications storage (§D.7), MBS (§D.8); presence and conference extensions (§8.4, §22.3, §25.6) |
| MCVideo documents | 3GPP TS 24.281 | V19.5.0 | Annex F: MCVideo information (§F.1), MBMS (§F.2), MBS (§F.2A), location (§F.3), (de)affiliation (§F.4), transmission request (§F.5), regroup (§F.6); presence and conference extensions (§8.3, §20.3, §9.2.3.6) |
| MC security | 3GPP TS 33.180 | V20.0.0 | XML content encryption (§9.3.4.2), URI attribute encryption (§9.3.4.3), integrity protection (§9.3.5) |
| XML schemas | 3GPP TS 37.579-5 | V19.1.0 | the schemas of RFC 3863 (pidf), RFC 3680 (reginfo), RFC 5628 (gruuinfo), RFC 4575 (conference-info), RFC 4826 (resource-lists), RFC 5874 (xcap-diff), RFC 5261 (patch operations), RFC 4354 (poc-settings), the `xml` namespace, XML Signature and XML Encryption, and the MCX schemas |
| xcap-diff event package | RFC 5875 | 2010-05 | document and element selectors (§4.4, §4.6, §4.7) |
| GRUU | RFC 5627 | 2009-10 | `pub-gruu` and `temp-gruu` in reginfo |
| SIP URIs | RFC 3261 | 2002-06 | URI headers and the `body` hname (§19.1.1) |
| IMS registration | 3GPP TS 24.229 | 24229-j70 (V19.7.0) | reginfo usage (§5.4.2.1.2) |
| Numbering and identities | 3GPP TS 23.003 | 23003-k10 (V20.1.0) | ECI (§19.6) and NCI (§19.6A) widths |
| MC configuration and groups | 3GPP TS 24.484, TS 24.481 | V19.5.0, V19.2.0 | XCAP AUIDs and document names in xcap-diff selectors; the GKTP namespace (TS 24.481 §7.7.4.2), removed as a credential |

Namespace prefixes (`prefixes:` of a namespace): the prefixes that a schema of the documents
above binds to the namespace (`xmlns:P="N"`) or that one of their "Assignment of prefixes to
namespace names" tables lists, for example TS 24.379 §9.3.1.2 (Table 9.3.1.2-2, `mcpttPI10`),
§7.4.1.2.2 (Table 7.4.1.2.2-1, `PoC1Set`, `mcs10Set`), TS 24.282 §8.4.1.2 (`mcdataPI10`),
TS 24.281 §8.3.1.2 (`mcvideoPI10`), TS 24.481 §7.2.2 (`rl`, `mcpttgi`), and the schemas of
TS 37.579-5 (`tns` for pidf, reginfo, gruuinfo and conference-info). Each entry cites the clause
it was taken from. The output keeps these prefixes; any other prefix is renamed (feature 008).

### Documents not yet available (XML)

What only these documents define is removed or emptied until a rule with a verified source is
added:
- W3C XML 1.0 (Fifth Edition) and Namespaces in XML 1.0 (Third Edition): the reader follows
  their grammar and cites it by production number; they are not otherwise a rule source;
- RFC texts of RFC 3863, RFC 3680, RFC 4575, RFC 4826, RFC 5366, RFC 5874, RFC 5261 and
  RFC 4354: rules cite their schemas through TS 37.579-5; semantics come from the 3GPP usage
  clauses;
- RFC 4825 (XCAP URI grammar): selectors are split by the TS 24.484 / RFC 5875 examples, path
  segments are pseudonymised as opaque values;
- RFC 5364 (`copyControl`): an unknown namespace, removed;
- 3GPP TS 29.061 and TS 23.247 (MBMS and MBS service area layouts): only a 4-hex-digit
  service area ID is pseudonymised, any other value is removed as malformed;
- 3GPP TS 24.008 (§10.5.6.13, TMGI) and TS 24.501 (§9.11.4.30, MBS session ID): the values
  are removed, the elements kept empty;
- 3GPP TS 23.032 Figure 17 (bearing and speed bit layout): the value is replaced by a fixed
  constant;
- 3GPP TS 24.229 §7.10 reginfo extensions: unknown namespaces, removed.

## MIKEY rule set (`rules/mikey.yaml`)

The MIKEY rule set (`ruleset: mcxanon-mikey`, feature 005) is written against the documents
below, with the same version conventions as the SIP rule set. Clause numbers were checked
against the document texts on 2026-11-14. The loader accepts only these documents
(`src/policy/mikey_rules.cpp`); keep both lists in sync. Rule changes that 005 makes in the SIP,
media and XML rule files cite their own sets' documents.

| Area | Document | Version / date | Used for |
|---|---|---|---|
| MIKEY | RFC 3830 | 2004-08 | common header (§6.1), SIGN (§6.5), T (§6.6), ID (§6.7), SP and the SRTP policy (§6.10, §6.10.1), RAND (§6.11), general extension (§6.15), `application/mikey` (§10.1) |
| MIKEY extensions | RFC 6043 | 2011-03 | GENERIC-ID map (§6.1, §6.1.1), byte-string ID type (§6.5), IDR payload and roles (§6.6) |
| MIKEY-SAKKE | RFC 6509 | 2012-01 | SAKKE data type and payload (§4.1, §4.2), ECCSI signature type (§4.3), IDRkmsi/IDRkmsr (§4.4) |
| MC security | 3GPP TS 33.180 | V20.0.0 | common fields (§E.1.2), CS IDs (§E.1.3), GMK, PCK, CSK and MuSiK messages and default profiles (§E.2–§E.4), SAKKE-to-self (§E.5), key parameters (§E.6, §8.5.4.1), identity hiding (§E.7), UID (§F.2.1), purpose tags (Annex G), key identifiers (§5.2.2) |
| Group key transport | 3GPP TS 24.481 | V19.2.0 | I_MESSAGE in the GKTP (§7.4.2), private-use ID roles 240/241 (§7.5.2) |
| MCPTT media plane control | 3GPP TS 24.380 | V19.1.0 | the PCK I_MESSAGE field (§8.3.3.10) |
| MCPTT and MCData signalling | 3GPP TS 24.379, TS 24.282 | V19.6.0, V19.6.0 | the requests that carry `application/mikey` (TS 24.379 §7.2.1, §7.2.2, §7.3.7, §7A.2.1, §14.2.2.5; TS 24.282 §9.2.2.2.1) |

## HTTP rule set (`rules/http.yaml`, `rules/http-oauth.yaml`)

The HTTP rule set (`ruleset: mcxanon-http`, feature 007) covers the HTTP-1 interfaces of MCX
(TS 33.180 Annex B and Annex D, TS 24.482, TS 24.484, TS 24.481): HTTP/1.1 and h2c messages,
OAuth 2.0 and OpenID Connect at the IdMS, XCAP at the CMS and GMS, and the KMS. The RFC texts were
added to the standards corpus for this rule set on 2026-11-15 and clause numbers were checked
against them on that day. The loader accepts only the documents listed in
`src/policy/http_rules.cpp` (`kWeb3gpp`, `kWebRfcs`); keep both lists in sync.

| Area | Document | Version / date | Used for |
|---|---|---|---|
| HTTP semantics | RFC 9110 | 2022-06 | fields and their grammar (§5.5, §5.6), Host (§7.2), Via (§7.6.3), content headers (§8.3–§8.8), methods (§9.3), request context (§10.1), response context (§10.2), authentication (§11.6, §11.7), conditional requests (§13.1), range requests (§14) |
| HTTP caching | RFC 9111 | 2022-06 | Age, Cache-Control, Expires, Pragma (§5.1–§5.4) |
| HTTP/1.1 | RFC 9112 | 2022-06 | message framing (§6), chunked coding (§7.1) |
| HTTP/2 | RFC 9113 | 2022-06 | connection preface (§3.4), frames (§4, §6), h2c Upgrade (deprecated, §3.1) |
| HPACK | RFC 7541 | 2015-05 | integer and string representations (§5), header field representations (§6), static table (Appendix A), Huffman code (Appendix B) |
| URIs | RFC 3986 | 2005-01 | URI and path grammar (§3), percent-encoding (§2.1) |
| MIME | RFC 2045, RFC 2046 | 1996-11 | multipart boundaries (RFC 2046 §5.1.1, §5.1.3) |
| Cookies | RFC 6265 | 2011-04 | Set-Cookie and its attributes (§4.1), Cookie (§4.2) |
| WebSocket | RFC 6455 | 2011-12 | the Upgrade handshake headers (§11.3) |
| Digest authentication | RFC 7616 | 2015-09 | WWW-Authenticate, Authorization and Authentication-Info parameters (§3.3–§3.5) |
| Basic authentication | RFC 7617 | 2015-09 | credentials removed (§2) |
| OAuth 2.0 | RFC 6749 | 2012-10 | client authentication (§2.3.1), authorization and token requests and responses (§4.1, §4.3, §5.1, §5.2), refresh (§6) |
| Bearer tokens | RFC 6750 | 2012-10 | the Bearer scheme (§2.1, §3.1) |
| PKCE | RFC 7636 | 2015-09 | code_challenge, code_challenge_method, code_verifier (§4.2, §4.3, §4.5) |
| JWT, JWS, JWE | RFC 7519, RFC 7515, RFC 7516 | 2015-05 | registered claims (RFC 7519 §4.1), JOSE header parameters (RFC 7515 §4.1), JWE compact form (RFC 7516 §7.1) |
| Token introspection, revocation | RFC 7662, RFC 7009 | 2015-10, 2013-08 | introspection response members (RFC 7662 §2.2), revocation request (RFC 7009 §2.1) |
| JSON | RFC 8259 | 2017-12 | the grammar the JSON reader follows |
| base64, base64url | RFC 4648 | 2006-10 | §4 and §5 |
| XCAP | RFC 4825, RFC 4826, RFC 5874, RFC 5875 | 2007-05, 2007-05, 2010-05, 2010-05 | XCAP URIs and media types, resource-lists, xcap-error, xcap-diff selectors |
| MC security | 3GPP TS 33.180 | V20.0.0 | the IdMS interface and token contents (Annex B), the KMS interface and documents (Annex D) |
| MC identity management | 3GPP TS 24.482 | V19.0.0 | X-3GPP-Asserted-Identity (§A.2.1.3) |
| MC configuration management | 3GPP TS 24.484 | V19.5.0 | XCAP AUIDs and documents (Annex B), document schemas (§10.2.2.3) for `rules/xml-cms.yaml` |
| MC group management | 3GPP TS 24.481 | V19.2.0 | group document AUIDs (§7.2.6, §7.3.2), group document schema (§7.2.2, §7.2.4.2) for `rules/xml-gms.yaml` |
| MC architecture | 3GPP TS 23.280 | V20.3.0 | the MC ID (§8.1.1), mapped like the SIP user part |

### Documents not yet available (HTTP)

What only these documents define is removed until a rule with a verified source is added:
- OpenID Connect Core 1.0 (not an IETF document; not in the corpus): the ID token claims
  `auth_time`, `azp`, `nonce`, `acr`, `amr`, `at_hash`, `sid` and the `nonce` request parameter
  are removed and counted;
- 3GPP TS 24.109 (not indexed): `X-3GPP-Intended-Identity` is removed as unknown;
- RFC 4825 `application/xcap-error+xml` documents have no XML rules yet: their bodies are removed.

## TLS rule set (`rules/tls.yaml`)

The TLS rule set (`ruleset: mcxanon-tls`, feature 007) covers TLS 1.0 to 1.3 in the clear:
records, handshake messages, extensions, cipher suite families and X.509 certificates. The RFC
texts were added to the standards corpus on 2026-11-15 and clause numbers were checked against
them on that day; the cipher suite rows were taken from the suite definitions of the RFCs below.

| Area | Document | Version / date | Used for |
|---|---|---|---|
| TLS 1.3 | RFC 8446 | 2018-08 | handshake messages (§4.1–§4.6), extensions (§4.2), record layer (§5.1, §5.2), alerts (§6), cipher suites (§B.4), downgrade sentinels (§4.1.3) |
| TLS 1.2 | RFC 5246 | 2008-08 | record layer (§6.2.1), change cipher spec (§7.1), handshake messages (§7.4), cipher suites (§A.5), compatibility (§E.1) |
| TLS extensions | RFC 6066 | 2011-01 | server_name (§3), max_fragment_length (§4), status_request (§8) |
| ALPN | RFC 7301 | 2014-07 | application_layer_protocol_negotiation (§3.1) |
| ECC cipher suites | RFC 8422 | 2018-08 | supported_groups, ec_point_formats (§5.1), ServerKeyExchange ECDHE (§5.4), suites (§6) |
| Session tickets | RFC 5077 | 2008-01 | SessionTicket extension and NewSessionTicket (§3.2, §3.3) |
| Extended master secret | RFC 7627 | 2015-09 | the extension (§5.1) |
| Renegotiation indication | RFC 5746 | 2010-02 | renegotiation_info (§3.2) |
| Encrypt-then-MAC | RFC 7366 | 2014-09 | the extension (§2) |
| Record size limit | RFC 8449 | 2018-08 | the extension (§4) |
| Padding | RFC 7685 | 2015-10 | the extension (§3) |
| Heartbeat | RFC 6520 | 2012-02 | the extension and messages (§2, §3) |
| PSK cipher suites | RFC 4279, RFC 5489 | 2005-12, 2009-03 | psk_identity and hint (RFC 4279 §6), ECDHE_PSK (RFC 5489 §3, §4) |
| AES-GCM, ChaCha20 suites | RFC 5288, RFC 5289, RFC 7905 | 2008-08, 2008-08, 2016-06 | suite families |
| FFDHE groups | RFC 7919 | 2016-08 | the named groups |
| X.509 | RFC 5280 | 2008-05 | certificate fields (§4.1), standard extensions (§4.2.1), private extensions (§4.2.2), attribute types (Appendix A.1) |
| Public keys | RFC 3279, RFC 5480 | 2002-04, 2009-03 | RSA keys (RFC 3279 §2.3.1), EC keys (RFC 5480 §2.2) |
| GBA | 3GPP TS 33.220 | V19.1.0 | the B-TID form of a PSK identity, base64 RAND `@` BSF server name (§4.4.7, §4.5.2): the RAND part takes an opaque pseudonym, the domain the domain pseudonym (in code, `src/tls/handshake.cpp`; no rule row) |
