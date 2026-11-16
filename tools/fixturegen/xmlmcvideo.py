# SPDX-License-Identifier: GPL-3.0-or-later
"""MCVideo XML body fixtures (feature 003, Appendix D): mcvideo-info (§D.3), MBMS usage (§D.4),
5G MBS usage (§D.5) and the transmission request (§D.8), with the rules of rules/xml-mcvideo.yaml.

Every value a non-keep rule classifies is a canary recorded with its XML rule key (see
xmlbodies.py); kept values are valid values of their rule. Every value is invented; names come
from example.net (RFC 2606).
"""
import xmlbodies as X
from xmlbodies import El

INFO = "urn:3gpp:ns:mcvideoInfo:1.0"
INFO_CT = "application/vnd.3gpp.mcvideo-info+xml"
MBMS = "urn:3gpp:ns:mcvideoMbmsUsage:1.0"
MBMS_CT = "application/vnd.3gpp.mcvideo-mbms-usage-info+xml"
MBS = "urn:3gpp:ns:mcvideoMbsUsage:1.0"
MBS_CT = "application/vnd.3gpp.mcvideo-mbs-usage-info+xml"
TREQ = "urn:3gpp:ns:transmissionRequest:1.0"
TREQ_CT = "application/vnd.3gpp.mcvideo-transmission-request+xml"


def vk(local, parent=None):
    """The rule key of an mcvideoInfo element."""
    return X.el_key(INFO, parent, local)


# TS 24.281 §F.1.3 item 1: the elements that can be included with encrypted content.
ENCRYPTABLE = ("mcvideo-access-token mcvideo-request-uri mcvideo-calling-user-id mcvideo-called-party-id "
               "mcvideo-calling-group-id emergency-ind alert-ind imminentperil-ind originated-by mcvideo-client-id "
               "functional-alias-URI multiple-devices-ind partner-mcvideo-id selected-user-profile-index "
               "migration-auth-result primary-mcvideo-id req-type resp-type").split()


def mcvideo_info_doc(cv, p="", quote='"', encrypted=False):
    """Every element and attribute of Appendix D §D.3. p: the prefix ("" = default namespace).
    Canaries in every value a rule does not keep; valid values in the kept ones. With
    encrypted=True every encryptable element carries type="Encrypted" and xenc:EncryptedData."""
    def e(name, *children, attrs=()):
        return El(p + name, *children, attrs=attrs, quote=quote)

    def ct(name, child):
        """A contentType element (TS 24.281 §F.1.2) with its type attribute."""
        if encrypted and name in ENCRYPTABLE:
            return e(name, X._enc_data(cv, "xml-ns-enc:mcvideo:" + name), attrs=(("type", "Encrypted"),))
        return e(name, child, attrs=(("type", "Normal"),))

    def uri(name):
        return ct(name, e("mcvideoURI", cv.uri(vk("mcvideoURI", name), "video.example.net")))

    def boolean(name, v="true"):
        return ct(name, e("mcvideoBoolean", v))

    def entry():
        return e("entry", e("uri-entry", cv.uri(vk("uri-entry"), "video.example.net")),
                 e("display-name", cv.s(vk("display-name"), "Canary Name")), e("anyExt"))

    def url(key):
        return f"https://{cv.s(key, 'canary')}.video.example.net/store/clip-0001.mp4"

    gktp = El("mvgktp:GKTP", cv.s(vk("MKFC-GKTPs"), "canary"), attrs=(("id", "1"),), ns=(("mvgktp", X.VGKTP),))
    profile = (e("selected-user-profile-index", X._enc_data(cv, "xml-ns-enc:mcvideo:selected-user-profile-index"),
                 attrs=(("type", "Encrypted"),)) if encrypted else
               e("selected-user-profile-index", e("user-profile-index", "3"), attrs=(("type", "Normal"),)))
    any_ext = e(
        "anyExt",
        e("release-reason", "authentication of the MIKEY-SAKE I_MESSAGE failed"),
        e("request-type", "fa-group-binding-req"),
        e("response-type", "group-selection-change-response"),
        e("selected-group-change-outcome", "fail"),
        e("affiliation-required", "true"),
        e("ambient-viewing-type", "local-init"),
        e("video-push-url", url(vk("video-push-url"))),
        uri("functional-alias-URI"),
        e("emergency-alert-area-ind", "false"),
        e("group-geo-area-ind", "1"),
        e("binding-ind", "true"),
        e("binding-fa-uri", cv.uri(vk("binding-fa-uri"), "video.example.net")),
        e("unbinding-fa-uri", cv.uri(vk("unbinding-fa-uri"), "video.example.net")),
        e("call-to-functional-alias-ind", "0"),
        e("user-requested-priority", "6"),
        e("end-to-end-security", "true"),
        e("call-participants-criteria", cv.s(vk("call-participants-criteria"), "canary") + ",unit=north"),
        e("preconfigured-group-id", cv.uri(vk("preconfigured-group-id"), "video.example.net")),
        e("adhoc-grp-emg-alert-grp-ind", "false"),
        uri("partner-mcvideo-id"),
        boolean("migration-auth-result", "false"),
        uri("primary-mcvideo-id"),
        uri("location-of-functional-alias-URI"),
        ct("req-type", e("mcvideoString", "functional-alias-status-determination")),
        ct("resp-type", e("mcvideoString", "migration-service-authorization-response")),
        profile,
        e("adhoc-alert-ind", "true"),
        e("adhoc-alert-ind-rcvd", "false"),
        e("adhoc-emergency-ind", "true"),
        e("adhoc-additional-information", cv.s(vk("adhoc-additional-information"), "Canary alert text")),
        e("adhoc-alert-participant-list", entry(), entry(), e("anyExt")),
        e("adhoc-alert-participant-not-ack-list", entry(), e("anyExt")),
        e("forwarding-reason", "migrated"),
        e("forwarding-target-id", cv.uri(vk("forwarding-target-id"), "video.example.net")),
    )
    params = e(
        "mcvideo-Params",
        ct("mcvideo-access-token", e("mcvideoString", cv.s(vk("mcvideoString", "mcvideo-access-token"), "eyJcanary"))),
        e("session-type", "one-to-server video push"),
        uri("mcvideo-request-uri"),
        uri("mcvideo-calling-user-id"),
        uri("mcvideo-called-party-id"),
        uri("mcvideo-calling-group-id"),
        boolean("required"),
        boolean("emergency-ind", "false"),
        boolean("alert-ind", "false"),
        boolean("imminentperil-ind", "false"),
        e("broadcast-ind", "false"),
        e("mc-org", cv.s(vk("mc-org"), "Canary Video Org")),
        e("associated-group-id", cv.uri(vk("associated-group-id"), "video.example.net")),
        uri("originated-by"),
        e("MKFC-GKTPs", gktp),
        ct("mcvideo-client-id", e("mcvideoString", "urn:uuid:" + cv.uuid(vk("mcvideoString", "mcvideo-client-id")))),
        boolean("alert-ind-rcvd"),
        boolean("multiple-devices-ind", "false"),
        ct("video-pull-url", e("mcvideoURI", url(vk("mcvideoURI", "video-pull-url")))),
        e("gw-mcvideo-usage", "true"),
        any_ext,
    )
    ns = (("", INFO),) if not p else ((p[:-1], INFO),)
    return El(p + "mcvideoinfo", params, e("anyExt"), ns=ns, quote=quote)


def mcvideo_info_odd(cv):
    """contentType children that §F.1.3 item 2 does not prescribe for their parent (no fallback
    rule: unknown, removed): a URI and a Boolean in the access token, a string in originated-by,
    a URI in emergency-ind; a session-type outside the enumeration."""
    k = "xml-unknown:mcvideo-content"
    body = (f'<mcvideoinfo xmlns="{INFO}"><mcvideo-Params>\r\n'
            f'<mcvideo-access-token type="Normal"><mcvideoURI>sip:{cv.s(k, "canary")}@video.example.net</mcvideoURI>'
            f'<mcvideoBoolean>{cv.s(k, "canary")}</mcvideoBoolean></mcvideo-access-token>\r\n'
            f'<originated-by type="Normal"><mcvideoString>{cv.s(k, "canary")}</mcvideoString></originated-by>\r\n'
            f'<emergency-ind type="Normal"><mcvideoURI>sip:{cv.s(k, "canary")}@video.example.net</mcvideoURI>'
            f'</emergency-ind>\r\n'
            f'<session-type>{cv.s("xml-malformed:mcvideo-session-type", "canary")}</session-type>\r\n'
            f'</mcvideo-Params></mcvideoinfo>\r\n')
    return body.encode()


def _hex(lc, local, n):
    """A random hex canary of n digits (a TMGI, an MBS session ID, an MBS FSA ID)."""
    return lc.hexv(local, n)


def mbms_usage_doc(cv):
    """Every element of Appendix D §D.4 in one document."""
    lc = X.LocCv(cv, MBMS)
    tmgi = lambda: El("TMGI", _hex(lc, "TMGI", 12))  # noqa: E731
    group = lambda: El("group", cv.uri(lc.k("group"), "video.example.net"))  # noqa: E731
    root = El(
        "mcvideo-mbms-usage-info",
        El("mbms-listening-status",
           El("mbms-listening-status", "listening"),
           El("session-id", cv.uri(lc.k("session-id"), "video.example.net")),
           El("general-purpose", "true"),
           tmgi(), tmgi(),
           El("anyExt")),
        El("mbms-suspension-status",
           El("mbms-suspension-status", "suspending"),
           El("number-of-reported-bearers", "3"),
           El("suspended-TMGI", _hex(lc, "suspended-TMGI", 12)),
           El("other-TMGI", _hex(lc, "other-TMGI", 12)),
           El("other-TMGI", _hex(lc, "other-TMGI", 12)),
           El("anyExt")),
        El("announcement",
           tmgi(),
           El("QCI", "65"),
           El("frequency", "2680000000"),
           El("mbms-service-areas",
              El("mbms-service-area-id", X.short_hex(lc, "mbms-service-area-id")),
              El("mbms-service-area-id", X.short_hex(lc, "mbms-service-area-id")),
              El("anyExt")),
           El("GPMS", "2"),
           El("report-suspension", "true"),
           El("anyExt", El("mcvid-mbms-rohc"), El("max-cid", "15"))),
        El("version", "1"),
        El("anyExt",
           El("mbms-defaultMuSiK-download", group(), El("anyExt")),
           El("mbms-explicitMuSiK-download", group(), group(), El("anyExt"))),
        ns=(("", MBMS),))
    return X.doc(root)


def mbs_usage_doc(cv):
    """Every element and attribute of Appendix D §D.5 in one document."""
    lc = X.LocCv(cv, MBS)
    f = cv.f
    group = lambda: El("group", cv.uri(lc.k("group"), "video.example.net"))  # noqa: E731
    session_id = lambda: El("mbs-session-id", _hex(lc, "mbs-session-id", 12))  # noqa: E731
    ip_list = El("IPInformation",
                 El("IPInformationListEntry", El("IPv4Address", cv.c.ipv4(None, f, rule=lc.k("IPv4Address")))),
                 El("IPInformationListEntry", El("IPv6Address", cv.c.ipv6(None, f, rule=lc.k("IPv6Address")))),
                 El("IPInformationListEntry", El("FQDN", cv.s(lc.k("FQDN"), "canary") + ".video.example.net"),
                    El("anyExt")),
                 El("anyExt"))
    session_info = El(
        "mbs-session-info",
        session_id(),
        El("mbs-session-mode", "broadcast"),
        El("mc-service-group-id", cv.c.number(f, 9, rule=lc.k("mc-service-group-id"))),
        El("frequency", "3750000000"),
        El("GPMS", "1"),
        El("mbs-service-areas",
           El("mbs-service-area-id", X.short_hex(lc, "mbs-service-area-id")),
           El("anyExt")),
        El("report-ue-session-join-notification", "true"),
        El("multicast-mbs-session-related-info",
           El("PlmnId", lc.text("PlmnId", lc.plmn), attrs=(("TriggerId", "trig-mbs-1"),)),
           El("PlmnId", lc.text("PlmnId", lc.plmn), attrs=(("TriggerId", "trig_mbs.2"),)),
           El("DNN", cv.s(lc.k("DNN"), "canary") + ".mnc001.mcc262.gprs"),
           ip_list,
           El("MC-ID-ref-SNSSAI", cv.s(lc.k("MC-ID-ref-SNSSAI"), "canary")),
           El("anyExt")),
        El("mbs-fsa-id", _hex(lc, "mbs-fsa-id", 6)),
        El("mbs-fsa-id", _hex(lc, "mbs-fsa-id", 6)),
        El("mbs-session-de-announcement-acknowledgement", "false"),
        El("anyExt"))
    bearer = El(
        "eMBMS-bearer-info",
        El("TMGI", _hex(lc, "TMGI", 12)),
        El("Alternative-TMGI",
           El("Alternative-TMGI-id", _hex(lc, "Alternative-TMGI-id", 12)),
           El("Alternative-TMGI-id", _hex(lc, "Alternative-TMGI-id", 12)),
           El("anyExt")),
        El("QCI", "69"),
        El("frequency", "763000000"),
        El("mbms-service-areas",
           El("mbms-service-area-id", X.short_hex(lc, "mbms-service-area-id")),
           El("anyExt")),
        El("GPMS", "3"),
        El("report-suspension", "false"),
        El("anyExt", El("mcvideo-mbs-rohc"), El("max-cid", "255")))
    root = El(
        "mcvideo-mbs-usage-info",
        El("mbs-listening-status",
           El("mbs-listening-status", "not-listening"),
           El("unicast-listening-status", "listening"),
           El("session-id", cv.uri(lc.k("session-id"), "video.example.net")),
           El("general-purpose", "false"),
           session_id(), session_id(),
           El("anyExt")),
        El("mbs-session-de-announcement-status",
           El("mbs-session-de-announcement-status", "deleting"),
           El("number-of-reported-sessions", "0A"),
           El("deleted-mbs-session-id", _hex(lc, "deleted-mbs-session-id", 12)),
           El("other-mbs-session-id", _hex(lc, "other-mbs-session-id", 12)),
           El("anyExt")),
        El("ue-session-join-notification",
           El("mbs-multicast-joining-status", "ue-session-join"),
           session_id(),
           El("session-id", cv.uri(lc.k("session-id"), "video.example.net")),
           El("anyExt")),
        El("announcement", session_info, bearer, El("anyExt")),
        El("version", "1"),
        El("anyExt",
           El("mbs-defaultMuSiK-download", group(), El("anyExt")),
           El("mbs-explicitMuSiK-download", group(), El("anyExt"))),
        ns=(("", MBS),))
    return X.doc(root)


def transmission_request_doc(cv):
    """Every element of Appendix D §D.8 (TS 24.281 §F.5.3)."""
    f = cv.f
    tk = lambda local: X.el_key(TREQ, None, local)  # noqa: E731
    root = El(
        "transmission-request",
        El("ssrc", cv.c.binary(f, tk("ssrc"), low=1 << 24)),
        El("transmission-priority", "200"),
        El("user-id", cv.uri(tk("user-id"), "video.example.net")),
        El("track-info",
           El("queueing-capability", "1"),
           El("participant-type", cv.s(tk("participant-type"), "canary")),
           El("transmission-participant-reference", cv.c.binary(f, tk("transmission-participant-reference"),
                                                                low=1 << 24)),
           El("transmission-participant-reference", cv.c.binary(f, tk("transmission-participant-reference"),
                                                                low=1 << 24)),
           El("anyExt")),
        El("transmission-indicator", "2"),
        El("anyExt"),
        ns=(("", TREQ),))
    return X.doc(root)


def xml_mcvideo(c, out):
    """mcvideo-info in an INVITE multipart next to SDP (default namespace, double quotes), in a
    200 OK (prefix, single quotes), encrypted in a REFER, the odd shapes in a MESSAGE; MBMS usage
    in a MESSAGE with SDP (the announcement references a media line); MBS usage in a MESSAGE;
    the transmission request in INFO (Info-Package, TS 24.281 §6.3.4.1.3)."""
    fname = "xml_mcvideo.pcapng"
    cv = X.Cv(c, fname)
    tx = X.Sender(fname)
    tx.multipart("INVITE", [("application/sdp", X.sdp_offer(), []), (INFO_CT, X.doc(mcvideo_info_doc(cv)), [])])
    tx.response(200, "OK", "INVITE", INFO_CT, X.doc(mcvideo_info_doc(cv, "v:", "'"), indent=None))
    tx.request("REFER", INFO_CT, X.doc(mcvideo_info_doc(cv, encrypted=True)),
               extra=[("Refer-To", "<sip:ue-c@example.net>")])
    tx.request("MESSAGE", INFO_CT, mcvideo_info_odd(cv))
    tx.multipart("MESSAGE", [("application/sdp", X.sdp_offer(), []), (MBMS_CT, mbms_usage_doc(cv), [])])
    tx.request("MESSAGE", MBS_CT, mbs_usage_doc(cv))
    tx.request("INFO", TREQ_CT, transmission_request_doc(cv),
               extra=[("Info-Package", "g.3gpp.mcvideo-transmission-request"),
                      ("Content-Disposition", "Info-Package")])
    tx.write(out)


FIXTURES = [xml_mcvideo]
