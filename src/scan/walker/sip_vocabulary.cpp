// SPDX-License-Identifier: GPL-3.0-or-later
#include "scan/walker/sip_vocabulary.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <string>

namespace mcxanon::scan::detail {
namespace {

constexpr std::string_view kTerms[] = {
    "+g.3gpp.anbr", "+g.3gpp.home-visited", "+g.3gpp.iari-ref", "+g.3gpp.icsi-ref",
    "+g.3gpp.in-call-access-update", "+g.3gpp.loopback", "+g.3gpp.mcdata.fd",
    "+g.3gpp.mcdata.ipconn", "+g.3gpp.mcdata.sds", "+g.3gpp.mcptt",
    "+g.3gpp.mcptt.ambient-listening-call-release", "+g.3gpp.mcvideo",
    "+g.3gpp.mcvideo.ambient-viewing-call-release", "+g.3gpp.mrb", "+g.3gpp.priority-share",
    "+g.3gpp.ps-data-off", "+g.3gpp.registration-token", "+g.3gpp.rlos", "+g.3gpp.thig-path",
    "+g.3gpp.trf", "+g.3gpp.verstat", "+sip.instance", "3ge2ae", "5gscid", "accept",
    "accept-contact", "accept-encoding", "accept-language", "accept-resource-priority",
    "accept-types", "accept-wrapped-types", "ack", "actor", "additional-identity", "alert-info",
    "alg", "algorithm", "allow", "allow-events", "altc", "answer-mode", "application",
    "application/conference-info+xml", "application/mikey", "application/pidf+xml", "application/poc-settings+xml",
    "application/resource-lists+xml", "application/sdp",
    "application/vnd.3gpp.location-info+xml", "application/vnd.3gpp.mcdata-info+xml",
    "application/vnd.3gpp.mcdata-payload", "application/vnd.3gpp.mcdata-signalling",
    "application/vnd.3gpp.mcptt-affiliation-command+xml", "application/vnd.3gpp.mcptt-info+xml",
    "application/vnd.3gpp.mcptt-location-info+xml",
    "application/vnd.3gpp.mcptt-mbms-usage-info+xml", "application/vnd.3gpp.mcvideo-info+xml",
    "application/vnd.3gpp.mcptt-floor-request+xml",
    "application/vnd.3gpp.mcptt-signed+xml",
    "application/vnd.3gpp.mcptt-regroup+xml",
    "application/vnd.3gpp.mcptt-mbs-usage-info+xml",
    "application/vnd.3gpp.mcdata-affiliation-command+xml",
    "application/vnd.3gpp.mcdata-location-info+xml",
    "application/vnd.3gpp.mcdata-mbms-usage-info+xml",
    "application/vnd.3gpp.mcdata-regroup+xml",
    "application/vnd.3gpp.mcdata-msgstore-ctrl-request+xml",
    "application/vnd.3gpp.mvdata-mbs-usage-info+xml",
    "application/vnd.3gpp.mcdata-mbs-usage-info+xml",
    "application/vnd.3gpp.mcvideo-mbms-usage-info+xml",
    "application/vnd.3gpp.mcvideo-mbs-usage-info+xml",
    "application/vnd.3gpp.mcvideo-location-info+xml",
    "application/vnd.3gpp.mcvideo-affiliation-command+xml",
    "application/vnd.3gpp.mcvideo-transmission-request+xml",
    "application/vnd.3gpp.mcvideo-regroup+xml",
    "application/reginfo+xml",
    "application/xcap-diff+xml", "attestation-info", "audio", "audio component of mcvideo",
    "auth-token", "authentication-info", "authorization", "automata", "auts", "bcid", "boundary",
    "branch", "bras", "bye", "call-id", "call-info", "call-reason", "cancel", "candidate", "cat",
    "cause", "ccf", "ccf-2", "cell-info-age", "cellular-network-info", "cgi-3gpp", "charset",
    "ci-3gpp2", "ci-3gpp2-femto", "cid", "ck", "class", "cnonce", "conf", "confid", "connection",
    "contact", "content", "content-disposition", "content-encoding", "content-id",
    "content-language", "content-length", "content-transfer-encoding", "content-type", "control", "cpc", "critical", "crypto",
    "cseq", "curr", "d-alg", "d-qop", "d-ver", "data", "date", "daylight-saving-time", "dc-info",
    "des", "description", "dsl-location", "dslcid", "duplex", "duration", "dvb-rcs2-node-id",
    "ealg", "early-only", "ecf", "ecf-2", "ecid", "ecn-capable-rtp", "epdg-ip-address",
    "eps-fallback", "error-info", "eth-location", "event", "events", "expires", "explicit",
    "extensions", "extmap", "feature-caps", "fiber-location", "file-date", "file-disposition",
    "file-icon", "file-range", "file-selector", "file-transfer-id", "file:///dev/null",
    "fingerprint", "floorctrl", "floorid", "flow-timer", "fmtp", "framerate", "from", "from-tag",
    "gcid", "geolocation", "geolocation-error", "geolocation-routing", "ggsn", "gr", "group",
    "gstn-location", "handling", "handover-info", "header", "history", "history-info",
    "i-wlan-node-id", "ice-lite", "ice-mismatch", "ice-options", "ice-pacing", "ice-pwd",
    "ice-ufrag", "icid-generated-at", "icid-value", "id", "identity", "ik", "imageattr",
    "in-reply-to", "inactive", "index", "info", "info-package", "integrity",
    "integrity-protected", "invite", "ip-edge", "isfocus", "join", "key-mgmt", "keywds", "label",
    "lang", "language", "local-tag", "local-time-zone", "lr", "maddr", "max-breadth",
    "max-forwards", "max-size", "maxprate", "maxptime", "mc_audio_ssrc", "mc_floor_ssrc",
    "mc_granted", "mc_implicit_request", "mc_no_floor_ctrl", "mc_priority", "mc_queueing",
    "mc_reception_priority", "mc_ssrc", "mc_transmission_ssrc", "mc_video_ssrc", "mcdata",
    "mcdata-ipconn-s-port", "mcptt", "mcvideo", "members", "message", "method", "methods", "mid",
    "mime-version", "min-expires", "min-se", "mobility", "mod", "mp", "msrp-cema",
    "multipart/alternative", "multipart/mixed", "nc", "network-provided", "nextnonce", "nonce",
    "none", "notify", "np", "ob", "oli", "opaque", "operator-specific-gi", "options",
    "organization", "orient", "orig", "orig-cdiv", "orig-ioi", "origination-id",
    "p-access-network-info", "p-answer-state", "p-asserted-identity", "p-asserted-service",
    "p-asserted-service-id", "p-associated-uri", "p-called-party-id",
    "p-charging-function-addresses", "p-charging-vector", "p-early-media",
    "p-media-authorization", "p-preferred-identity", "p-preferred-service",
    "p-private-network-indication", "p-profile-key", "p-refused-uri-list", "p-served-user",
    "p-user-database", "p-visited-network-id", "path", "pdngw", "permission-missing",
    "phone-context", "port-c", "port-s", "ppi", "prack", "priority", "priority-share",
    "priority-verstat", "priv-answer-mode", "privacy", "prot", "proxy-authenticate",
    "proxy-authorization", "proxy-require", "ptime", "pub-gruu", "publish", "purpose", "q",
    "qop", "quality", "rack", "rc", "realm", "reason", "received", "record-route", "recv-info",
    "recvonly", "refer", "refer-sub", "refer-to", "referred-by", "refresher", "reg-id",
    "register", "regstate", "reject-contact", "related-icid", "related-icid-generated-at",
    "relay-source", "relayed-charge", "remote", "remote-candidates", "remote-tag", "replaces",
    "reply-to", "request-disposition", "require", "resource-priority", "resource-share",
    "response", "response-source", "restoration-info", "retry-after", "route", "rport", "rseq",
    "rspauth", "rtcp", "rtcp-fb", "rtcp-mux", "rtcp-mux-only", "rtcp-rsize", "rtcp-xr", "rtpmap",
    "satellite-id", "schemes", "sdplang", "security-client", "security-server",
    "security-verify", "sendonly", "sendrecv", "server", "service-interact-info",
    "service-route", "sescase", "session", "session-expires", "session-id", "setup", "sip",
    "sip-etag", "sip-if-match", "sips", "smf", "sos", "speech", "spi-c", "spi-s", "ssrc",
    "ssrc-group", "stale", "subject", "subscribe", "subscription-state", "supported", "tag",
    "target-dialog", "target-uri", "tcp-source-port", "tel", "temp-gruu", "term-ioi", "text",
    "text/plain", "timestamp", "tls-id", "to", "to-tag", "tokenized-by", "tool", "transit-ioi",
    "transport", "trigger-consent", "ttl", "type", "u2n-relay-id", "udp-source-port",
    "ue-local-ip-address", "unsupported", "update", "uri", "urn:alert:",
    "urn:urn-7:3gpp-service.ims.icsi.mcdata", "urn:urn-7:3gpp-service.ims.icsi.mcdata.fd",
    "urn:urn-7:3gpp-service.ims.icsi.mcdata.ipconn",
    "urn:urn-7:3gpp-service.ims.icsi.mcdata.sds", "urn:urn-7:3gpp-service.ims.icsi.mcptt",
    "urn:urn-7:3gpp-service.ims.icsi.mcvideo", "urn:urn-7:3gpp-service.ims.icsi.rlos", "user",
    "user-agent", "user-to-user", "userid", "username", "utran-cell-id-3gpp", "utran-sai-3gpp",
    "version", "verstat", "via", "video", "video component of mcvideo", "warning", "www-authenticate",
};

}  // namespace

std::span<const std::string_view> sip_vocabulary() { return kTerms; }

bool in_sip_vocabulary(std::string_view token) {
  if (token.empty()) return false;
  std::string t(token);
  for (auto& c : t) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return std::any_of(std::begin(kTerms), std::end(kTerms),
                     [&](std::string_view term) { return term.find(t) != std::string_view::npos; });
}

}  // namespace mcxanon::scan::detail
