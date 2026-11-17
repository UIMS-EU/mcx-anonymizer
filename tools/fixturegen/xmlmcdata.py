# SPDX-License-Identifier: GPL-3.0-or-later
"""MCData XML body fixtures (feature 003, Appendix C): mcdata-info (§C.3), MBMS usage (§C.5),
message store control (§C.7) and MBS usage under both Content-Type spellings (§C.8, X6).

Every element and attribute whose rule (rules/xml-mcdata.yaml) is not keep or container carries a
canary recorded with its XML rule key (the key format of xmlbodies.py); kept fields carry valid
values. Every value is invented; names come from example.net (RFC 2606).
"""
import xmlbodies as X

El, doc, el_key, attr_key = X.El, X.doc, X.el_key, X.attr_key

MCDATA_INFO = "urn:3gpp:ns:mcdataInfo:1.0"
MCDATA_INFO_CT = "application/vnd.3gpp.mcdata-info+xml"
MBMS_NS = "urn:3gpp:ns:mcdataMbmsUsage:1.0"
MBMS_CT = "application/vnd.3gpp.mcdata-mbms-usage-info+xml"
MBS_NS = "urn:3gpp:ns:mvdataMbsUsage:1.0"
MBS_CTS = ("application/vnd.3gpp.mvdata-mbs-usage-info+xml", "application/vnd.3gpp.mcdata-mbs-usage-info+xml")
MSGSTORE_NS = "urn:3gpp:ns:msgstoreControlRequest:1.0"
MSGSTORE_CT = "application/vnd.3gpp.mcdata-msgstore-ctrl-request+xml"
SIGNALLING_CT = "application/vnd.3gpp.mcdata-signalling"
PAYLOAD_CT = "application/vnd.3gpp.mcdata-payload"
DOMAIN = "mcdata.example.net"

# TS 24.282 §D.1.3 item 1: the elements that can be included with encrypted content.
ENCRYPTABLE = ("mcdata-access-token mcdata-request-uri mcdata-controller-psi mcdata-calling-user-id "
               "mcdata-called-party-id mcdata-calling-group-id alert-ind originated-by mcdata-client-id "
               "functional-alias-URI called-functional-alias-URI partner-mcdata-id migration-auth-result "
               "selected-user-profile-index primary-mcdata-id").split()


def dk(local, parent=None):
    """The rule key of an mcdataInfo element."""
    return el_key(MCDATA_INFO, parent, local)


def _host(cv, rule):
    return cv.s(rule, "cnry") + ".example.net"


# --- mcdata-info (§C.3) ---------------------------------------------------------------------
def mcdata_info_doc(cv, p="", quote='"', encrypted=False, request_type="one-to-one-sds"):
    """Every element and attribute of Appendix C §C.3. p: the prefix ("" = default namespace).
    With encrypted=True every encryptable element carries type="Encrypted" and
    xenc:EncryptedData instead of its value."""
    def e(name, *children, attrs=()):
        return El(p + name, *children, attrs=attrs, quote=quote)

    def ct(name, child):
        """A contentType element (TS 24.282 §D.1.2) with its type attribute. child: a function
        giving the plain content, called only when the element is not encrypted (so that no
        canary is recorded for a value the capture does not carry)."""
        if encrypted and name in ENCRYPTABLE:
            return e(name, X._enc_data(cv, "xml-mcdata-enc:" + name), attrs=(("type", "Encrypted"),))
        return e(name, child(), attrs=(("type", "Normal"),))

    def uri(name):
        return ct(name, lambda: e("mcdataURI", cv.uri(dk("mcdataURI"), DOMAIN)))

    def boolean(name, v="true"):
        return ct(name, lambda: e("mcdataBoolean", v))

    def entry():
        return e("entry", e("uri-entry", cv.uri(dk("uri-entry"), DOMAIN)),
                 e("display-name", cv.s(dk("display-name"), "Canary Name")), e("anyExt"))

    profile = (e("selected-user-profile-index", X._enc_data(cv, "xml-mcdata-enc:selected-user-profile-index"),
                 attrs=(("type", "Encrypted"),)) if encrypted else
               e("selected-user-profile-index", e("user-profile-index", "1"), attrs=(("type", "Normal"),)))
    any_ext = e(
        "anyExt",
        e("emergency-alert-area-ind", "true"),
        e("group-geo-area-ind", "false"),
        e("pre-established-session-ind", "true"),
        e("call-to-functional-alias-ind", "false"),
        e("mcdata-communication-state", "establish-success"),
        e("response-type", "get-userlist-adhoc-group-data-comn-response"),
        e("emergency-ind", "true"),
        e("alert-ind-rcvd", "true"),
        e("mc-org", cv.s(dk("mc-org"), "Canary Org")),
        uri("functional-alias-URI"),
        e("user-requested-priority", "3"),
        boolean("multiple-devices-ind", "false"),
        e("imminentperil-ind", "false"),
        e("emergency-ind-rcvd", "true"),
        e("binding-ind", "true"),
        e("binding-fa-uri", cv.uri(dk("binding-fa-uri"), DOMAIN)),
        e("unbinding-fa-uri", cv.uri(dk("unbinding-fa-uri"), DOMAIN)),
        uri("called-functional-alias-URI"),
        e("associated-group-id", cv.uri(dk("associated-group-id"), DOMAIN)),
        e("store-all-private-comms-in-msgstore", "true"),
        e("store-all-group-comms-in-msgstore", "false"),
        e("store-specific-private-comms-in-msgstore", "enable"),
        e("store-specific-group-comms-in-msgstore", "disable"),
        e("end-to-end-security", "true"),
        e("comn-participants-criteria", cv.s(dk("comn-participants-criteria"), "canary") + ",role=chief"),
        e("preconfigured-group-id", cv.uri(dk("preconfigured-group-id"), DOMAIN)),
        e("adhoc-grp-emg-alert-grp-ind", "true"),
        e("adhoc-emergency-ind", "true"),
        e("adhoc-additional-information", cv.s(dk("adhoc-additional-information"), "Canary text")),
        e("adhoc-alert-ind", "true"),
        e("adhoc-alert-ind-rcvd", "false"),
        e("adhoc-alert-participant-list", entry(), entry(), e("anyExt")),
        e("adhoc-alert-participant-not-ack-list", entry()),
        e("forwarding-reason", "migrated"),
        e("forwarding-target-id", cv.uri(dk("forwarding-target-id"), DOMAIN)),
        uri("partner-mcdata-id"),
        boolean("migration-auth-result", "true"),
        profile,
        uri("primary-mcdata-id"),
        uri("location-of-functional-alias-URI"),
        e("application-data", cv.s(dk("application-data"), "Canary app data")),
    )
    params = e(
        "mcdata-Params",
        ct("mcdata-access-token",
           lambda: e("mcdataString", cv.s(dk("mcdataString", "mcdata-access-token"), "eyJcanary"))),
        e("request-type", request_type),
        uri("mcdata-request-uri"),
        uri("mcdata-calling-user-id"),
        uri("mcdata-called-party-id"),
        uri("mcdata-calling-group-id"),
        boolean("alert-ind", "false"),
        uri("originated-by"),
        ct("mcdata-client-id",
           lambda: e("mcdataString", "urn:uuid:" + cv.uuid(dk("mcdataString", "mcdata-client-id")))),
        uri("mcdata-controller-psi"),
        e("gw-mcdata-usage", "false"),
        any_ext,
    )
    ns = (("", MCDATA_INFO),) if not p else ((p[:-1], MCDATA_INFO),)
    return El(p + "mcdatainfo", params, e("anyExt"), ns=ns, quote=quote)


def mcdata_info_odd(cv):
    """The parent-qualified shapes of mcdataString (C1, X1, X16): an mcdataString under a
    contentType other than the access token and the client ID (free text), and a bare UUID as
    the MCData client ID."""
    return El("mcdatainfo", El(
        "mcdata-Params",
        El("request-type", "notify"),
        El("originated-by", El("mcdataString", cv.s(dk("mcdataString"), "canary")), attrs=(("type", "Normal"),)),
        El("mcdata-client-id", El("mcdataString", cv.uuid(dk("mcdataString", "mcdata-client-id"))),
           attrs=(("type", "Normal"),))),
        ns=(("", MCDATA_INFO),))


def mcdata_info_small(cv, request_type):
    return El("mcdatainfo", El(
        "mcdata-Params",
        El("request-type", request_type),
        El("mcdata-calling-user-id", El("mcdataURI", cv.uri(dk("mcdataURI"), DOMAIN)), attrs=(("type", "Normal"),))),
        ns=(("", MCDATA_INFO),))


# --- MBMS usage (§C.5) ------------------------------------------------------------------------
def mbms_usage_doc(cv):
    lc = X.LocCv(cv, MBMS_NS)
    tmgi = lambda local="TMGI": El(local, lc.hexv(local, 12))  # noqa: E731
    group = lambda: El("group", cv.uri(lc.k("group"), DOMAIN))  # noqa: E731
    return El("mcdata-mbms-usage-info",
              El("mbms-listening-status",
                 El("mbms-listening-status", "listening"),
                 El("session-id", cv.uri(lc.k("session-id"), DOMAIN)),
                 El("general-purpose", "true"),
                 tmgi(), tmgi(),
                 El("anyExt")),
              El("mbms-suspension-status",
                 El("mbms-suspension-status", "suspending"),
                 El("number-of-reported-bearers", "3"),
                 tmgi("suspended-TMGI"),
                 tmgi("other-TMGI"), tmgi("other-TMGI"),
                 El("anyExt")),
              El("announcement",
                 tmgi(),
                 El("QCI", "69"),
                 El("frequency", "2680"),
                 El("mbms-service-areas",
                    El("mbms-service-area-id", X.short_hex(lc, "mbms-service-area-id")),
                    El("anyExt")),
                 El("GPMS", "2"),
                 El("report-suspension", "true"),
                 El("anyExt", El("mcdata-mbms-rohc"), El("max-cid", "15"))),
              El("version", "1"),
              El("anyExt",
                 El("mbms-defaultMuSiK-download", group(), group(), El("anyExt")),
                 El("mbms-explicitMuSiK-download", group(), El("anyExt"))),
              ns=(("", MBMS_NS),))


# --- MBS usage (§C.8) -------------------------------------------------------------------------
def mbs_usage_doc(cv):
    # One service area ID per element: a 4-hex-digit canary can occur by chance in other hex
    # text of the output, so the file plants as few of them as the coverage needs.
    lc = X.LocCv(cv, MBS_NS)
    hexel = lambda local, n=12: El(local, lc.hexv(local, n))  # noqa: E731
    group = lambda: El("group", cv.uri(lc.k("group"), DOMAIN))  # noqa: E731
    sai = lambda local: El(local, X.short_hex(lc, local))  # noqa: E731
    ip_entry = lambda child: El("IPInformationListEntry", child)  # noqa: E731
    related = El("multicast-mbs-session-related-info",
                 El("PlmnId", lc.plmn_canary("PlmnId"), attrs=(("TriggerId", "trig-plmn-exit"),)),
                 El("PlmnId", lc.plmn_canary("PlmnId"), attrs=(("TriggerId", "trig-plmn-exit-2"),)),
                 El("DNN", _host(cv, lc.k("DNN"))),
                 El("IPInformation",
                    ip_entry(El("IPv4Address", cv.c.ipv4(None, cv.f, rule=lc.k("IPv4Address")))),
                    ip_entry(El("IPv6Address", cv.c.ipv6(None, cv.f, rule=lc.k("IPv6Address")))),
                    ip_entry(El("FQDN", _host(cv, lc.k("FQDN")))),
                    ip_entry(El("anyExt")),
                    El("anyExt")),
                 El("MC-ID-ref-SNSSAI", lc.hexv("MC-ID-ref-SNSSAI", 8)),
                 El("anyExt"))
    session_info = El("mbs-session-info",
                      hexel("mbs-session-id"),
                      El("mbs-session-mode", "multicast"),
                      El("mc-service-group-id", lc.dec("mc-service-group-id", 10 ** 8, 10 ** 9)),
                      El("frequency", "3500"),
                      El("GPMS", "3"),
                      El("mbs-service-areas", sai("mbs-service-area-id"), El("anyExt")),
                      El("report-ue-session-join-notification", "true"),
                      related,
                      hexel("mbs-fsa-id", 6), hexel("mbs-fsa-id", 6),
                      El("mbs-session-de-announcement-acknowledgement", "false"),
                      El("anyExt"))
    bearer = El("eMBMS-bearer-info",
                hexel("TMGI"),
                El("Alternative-TMGI", hexel("Alternative-TMGI-id"), hexel("Alternative-TMGI-id"), El("anyExt")),
                El("QCI", "65"),
                El("frequency", "2680"),
                El("mbms-service-areas", sai("mbms-service-area-id"), El("anyExt")),
                El("GPMS", "4"),
                El("report-suspension", "false"),
                El("anyExt", El("mvdata-mbs-rohc"), El("max-cid", "255")))
    return El("mvdata-mbs-usage-info",
              El("mbs-listening-status",
                 El("mbs-listening-status", "not-listening"),
                 El("unicast-listening-status", "listening"),
                 El("session-id", cv.uri(lc.k("session-id"), DOMAIN)),
                 El("general-purpose", "false"),
                 hexel("mbs-session-id"), hexel("mbs-session-id"),
                 El("anyExt")),
              El("mbs-session-de-announcement-status",
                 El("mbs-session-de-announcement-status", "deleteing"),
                 El("number-of-reported-sessions", "2"),
                 hexel("deleted-mbs-session-id"),
                 hexel("other-mbs-session-id"), hexel("other-mbs-session-id"),
                 El("anyExt")),
              El("ue-session-join-notification",
                 El("mbs-multicast-joining-status", "ue-session-join"),
                 hexel("mbs-session-id"),
                 El("session-id", cv.uri(lc.k("session-id"), DOMAIN)),
                 El("anyExt")),
              El("announcement", session_info, bearer, El("anyExt")),
              El("version", "1"),
              El("anyExt",
                 El("mbs-defaultMuSiK-download", group(), El("anyExt")),
                 El("mbs-explicitMuSiK-download", group(), group(), El("anyExt"))),
              ns=(("", MBS_NS),))


# --- message store control (§C.7) -------------------------------------------------------------
def msgstore_doc(cv):
    k = lambda local: el_key(MSGSTORE_NS, None, local)  # noqa: E731
    group = lambda: El("group", cv.uri(k("group"), DOMAIN))  # noqa: E731
    private = lambda: El("private", cv.uri(k("private"), DOMAIN))  # noqa: E731
    return El("msgstore-ctrl-command-list",
              El("enable", group(), group(), private(), El("anyExt")),
              El("disable", group(), private(), private(), El("anyExt")),
              El("anyExt"),
              ns=(("", MSGSTORE_NS),))


# --- the capture -------------------------------------------------------------------------------
def _binary(c, n):
    """Arbitrary bytes standing for a TS 24.282 §15 TLV message (not XML, emptied as 002 does)."""
    return bytes([0x01]) + bytes(c.rng.getrandbits(8) for _ in range(n - 1))


def xml_mcdata(c, out):
    """An SDS MESSAGE (mcdata-info next to mcdata-signalling and mcdata-payload parts), the
    prefixed form in an INVITE with SDP, every encryptable element encrypted, the parent-qualified
    mcdataString shapes, MBMS usage, message store control with its mcdata-info, and MBS usage
    under both Content-Type spellings."""
    fname = "xml_mcdata.pcapng"
    cv = X.Cv(c, fname)
    tx = X.Sender(fname)
    tx.multipart("MESSAGE", [(MCDATA_INFO_CT, doc(mcdata_info_doc(cv)), []),
                             (SIGNALLING_CT, _binary(c, 48), []),
                             (PAYLOAD_CT, _binary(c, 32), [])])
    tx.multipart("INVITE", [("application/sdp", X.sdp_offer(), []),
                            (MCDATA_INFO_CT, doc(mcdata_info_doc(cv, "md:", "'", request_type="one-to-one-sds-session"),
                                                 indent=None), [])])
    tx.request("MESSAGE", MCDATA_INFO_CT, doc(mcdata_info_doc(cv, encrypted=True)))
    tx.request("MESSAGE", MCDATA_INFO_CT, doc(mcdata_info_odd(cv)))
    tx.request("MESSAGE", MBMS_CT, doc(mbms_usage_doc(cv)))
    tx.multipart("MESSAGE", [(MCDATA_INFO_CT, doc(mcdata_info_small(cv, "store-comms-in-msgstore-ctrl-req")), []),
                             (MSGSTORE_CT, doc(msgstore_doc(cv)), [])])
    for ct in MBS_CTS:
        tx.request("MESSAGE", ct, doc(mbs_usage_doc(cv)))
    tx.write(out)


FIXTURES = [xml_mcdata]
