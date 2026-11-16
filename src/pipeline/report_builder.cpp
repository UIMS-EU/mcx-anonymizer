// SPDX-License-Identifier: GPL-3.0-or-later
#include "pipeline/report_builder.hpp"

#include "mcxanon/version.hpp"

#include "sip/limits.hpp"
#include "stream/limits.hpp"

namespace mcxanon {
namespace {
std::string fmt_name(CaptureFormat f) { return f == CaptureFormat::pcap ? "pcap" : "pcapng"; }
}  // namespace

std::string_view result_name(ErrorCode code) {
  switch (code) {
    case ErrorCode::leak: return "leak_found";
    case ErrorCode::usage: return "usage_error";
    case ErrorCode::input: return "input_error";
    case ErrorCode::collision: return "pseudonym_collision";
    case ErrorCode::busy: return "project_busy";
    case ErrorCode::internal: return "internal_failure";
  }
  return "internal_failure";
}

ReportBuilder::ReportBuilder(const AnonymizeFileRequest& request)
    : request_(request), rs_name_(ruleset_name), rs_version_(ruleset_version),
      rs_digest_(ruleset_digest) {}

void ReportBuilder::ruleset(const RuleSet& rs) {
  rs_name_ = rs.name;
  rs_version_ = rs.version;
  rs_digest_ = rs.digest.size() == 64 ? rs.digest : std::string(64, '0');
}

Report ReportBuilder::build(const RunSummary* s, const std::optional<Error>& error) const {
  Report r;
  r.command = "anonymize";
  r.tool_version = std::string(tool_version);
  r.ruleset_name = rs_name_;
  r.ruleset_version = rs_version_;
  r.ruleset_digest = rs_digest_;
  r.sip_ruleset = {std::string(sip_ruleset_name), std::string(sip_ruleset_version),
                   std::string(sip_ruleset_digest)};
  r.media_ruleset = {std::string(media_ruleset_name), std::string(media_ruleset_version),
                     std::string(media_ruleset_digest)};
  r.xml_ruleset = {std::string(xml_ruleset_name), std::string(xml_ruleset_version), std::string(xml_ruleset_digest)};
  const auto& o = request_.options;
  r.options.payload = o.payload == PayloadMode::drop ? "drop" : "zero";
  r.options.format = o.format == OutputFormat::same ? "same" : (o.format == OutputFormat::pcap ? "pcap" : "pcapng");
  r.options.pseudonymise_vlan = o.pseudonymise_vlan;
  r.options.pseudonymise_ephemeral_ports = o.pseudonymise_ephemeral_ports;
  r.options.ephemeral_range = std::to_string(o.ephemeral_lo) + "-" + std::to_string(o.ephemeral_hi);
  r.options.prefix_preserving = o.prefix_preserving;
  if (o.time_shift) r.options.time_shift_ns = o.time_shift->count();
  r.options.strict = o.strict;
  r.options.deny_list_entries = deny_;
  r.options.encrypted = o.encrypted == EncryptedMode::passthrough ? "passthrough" : "ciphertext";
  r.files.input = request_.input.string();
  if (input_format_) r.files.input_format = fmt_name(*input_format_);
  r.files.truncated_tail_bytes = tail_;
  r.scan = scan_;
  if (s != nullptr) {
    r.files.frames = s->frames;
    r.counters = s->rewrite.counters;
    for (const auto& [k, n] : s->rewrite.unknown) r.unknown_protocols.push_back({k.first, k.second, n});
    r.checksums.valid_kept_valid = s->rewrite.checksums.valid_kept_valid;
    r.checksums.invalid_kept_invalid = s->rewrite.checksums.invalid_kept_invalid;
    r.checksums.unverifiable_recomputed = s->rewrite.checksums.unverifiable_recomputed;
    r.checksums.udp_zero_kept = s->rewrite.checksums.udp_zero_kept;
    r.removed_blocks = s->meta.removed_blocks;
    r.removed_options = s->meta.removed_options;
    r.mapping.new_entries = s->new_entries;
    r.mapping.reused_entries = s->reused_entries;
    r.mapping.collisions_resolved = s->collisions_resolved;
    SipReport sip;
    const auto& in = s->sip;
    sip.requests = in.requests;
    sip.responses = in.responses;
    sip.malformed = in.malformed;
    sip.headers = in.counters.headers;
    sip.malformed_headers = in.counters.malformed_headers;
    sip.removed_unknown = in.counters.removed_unknown;
    sip.sdp = in.counters.sdp;
    sip.bodies = in.counters.bodies;
    sip.tcp.streams_sip = in.tcp.streams_sip;
    sip.tcp.bytes_unframable = in.tcp.bytes_unframable;
    sip.tcp.retransmissions_replayed = in.tcp.retransmissions_replayed;
    sip.tcp.retransmissions_zeroed = in.tcp.retransmissions_zeroed;
    sip.tcp.directions_evicted = in.tcp.directions_evicted;
    sip.fragments.datagrams_rewritten = in.fragmented_rewritten;
    const auto zeroed = [&](const char* why, std::uint64_t n) {
      if (n != 0) sip.fragments.datagrams_zeroed[why] = n;
    };
    zeroed("missing", in.fragments.datagrams_incomplete);
    zeroed("timeout", in.fragments.datagrams_timed_out);
    zeroed("ambiguous", in.fragments.datagrams_ambiguous);
    zeroed("bound", in.fragments.datagrams_evicted + in.fragments.datagrams_held_bound);
    zeroed("not-sip", in.fragments.datagrams_not_sip + in.fragmented_not_sip);
    sip.limits.max_message_bytes = sip::kMaxMessageBytes;
    sip.limits.max_tcp_directions = stream::kMaxTcpDirections;
    sip.limits.max_held_bytes = stream::kMaxHeldBytes;
    sip.limits.pending_timeout_ms = stream::kPendingTimeoutMs;
    sip.limits.retrans_cache_bytes = stream::kRetransCacheBytes;
    sip.limits.max_offset_breakpoints = stream::kMaxOffsetBreakpoints;
    sip.limits.max_pending_datagrams = stream::kMaxPendingDatagrams;
    r.sip = std::move(sip);
    MediaReport media;
    const auto& mi = s->media;
    const auto& mc = mi.counters;
    media.announcements.endpoints = mi.endpoints;
    media.announcements.skipped = mi.skipped;
    media.rtp.packets = mc.rtp_packets;
    media.rtp.by_payload_type = mc.rtp_by_payload_type;
    media.rtp.streams = mc.rtp_by_stream.size();
    media.rtp.by_stream = mc.rtp_by_stream;
    media.rtp.zeroed = mc.rtp_zeroed;
    media.rtcp.by_packet_type = mc.rtcp_by_packet_type;
    media.rtcp.feedback = mc.rtcp_feedback;
    media.rtcp.xr_blocks = mc.rtcp_xr;
    media.rtcp.sdes_removed = mc.sdes_removed;
    media.rtcp.srtcp_view = mc.srtcp_view;
    media.rtcp.zeroed = mc.rtcp_zeroed;
    media.app.messages = mc.app_messages;
    media.app.fields = mc.app_fields;
    media.app.unknown = mc.app_unknown;
    media.msrp.requests = mc.msrp_requests;
    media.msrp.responses = mc.msrp_responses;
    media.msrp.headers = mc.msrp_headers;
    media.msrp.zeroed = mc.msrp_zeroed;
    media.limits.max_endpoints = mi.max_endpoints;
    media.limits.endpoints_evicted = mi.endpoints_evicted;
    r.media = std::move(media);
    // Feature 003: namespace names with rules are written as they
    // are; any other name passes the 002 report-name check.
    const auto& xs = s->xml;
    const auto ns_name = [&](const std::string& ns) {
      return xs.known_namespaces.contains(ns) ? ns : report_name(ns);
    };
    const auto attr_ns = [&](const std::string& ns) { return ns.empty() ? std::string() : ns_name(ns) + " "; };
    XmlReport x;
    for (const auto& [ct, outcomes] : xs.counters.bodies) {
      for (const auto& [outcome, n] : outcomes) x.bodies[report_name(ct, true)][outcome] += n;
    }
    for (const auto& [k, actions] : xs.counters.elements) {
      auto& slot = x.elements[ns_name(k.first) + " " + report_name(k.second)];
      for (const auto& [a, n] : actions) slot[a] += n;
    }
    for (const auto& [k, actions] : xs.counters.attributes) {
      const auto& [ns, el, ans, an] = k;
      auto& slot = x.attributes[ns_name(ns) + " " + report_name(el) + " @" + attr_ns(ans) + report_name(an)];
      for (const auto& [a, n] : actions) slot[a] += n;
    }
    for (const auto& [ns, n] : xs.counters.removed_namespaces) x.removed.namespaces[report_name(ns)] += n;
    x.removed.comments = xs.counters.comments;
    x.removed.processing_instructions = xs.counters.processing_instructions;
    x.removed.encrypted = xs.counters.encrypted;
    x.embedded = xs.counters.embedded;
    r.xml = std::move(x);
    // Feature 005: present when a MIKEY carrier was met. Every key is
    // a fixed word of the schema; nothing from the input appears.
    const auto& mk = s->mikey.counters;
    const auto& mki = s->media.counters.mki;
    const auto& xc = xs.counters;
    if (mk.any() || mki.pseudonymised != 0 || mki.unmatched != 0 || mki.ambiguous != 0 || xc.encrypted_kept != 0 ||
        xc.encrypted_passed_through != 0) {
      r.mikey_ruleset = {s->mikey.ruleset_name, s->mikey.ruleset_version, s->mikey.ruleset_digest};
      MikeyReport m;
      for (const auto& [k, c] : mk.carriers) {
        auto& o2 = m.carriers[k];
        o2.rewritten = c.rewritten;
        o2.passed_through = c.passed_through;
        o2.fallback = c.fallback;
      }
      m.unexpected_carrier = mk.unexpected_carrier;
      m.payloads = mk.payloads;
      m.incomplete = mk.incomplete;
      m.uids.resolved = mk.uids_resolved;
      m.uids.unresolved = mk.uids_unresolved;
      m.key_ids = mk.key_ids;
      m.cs_ids = mk.cs_ids;
      m.mki.pseudonymised = mki.pseudonymised;
      m.mki.unmatched = mki.unmatched;
      m.mki.ambiguous = mki.ambiguous;
      m.encrypted_xml.kept = xc.encrypted_kept;
      m.encrypted_xml.passed_through = xc.encrypted_passed_through;
      m.encrypted_xml.removed_parts = xc.encrypted_removed_parts;
      m.encrypted_uri.structured = mk.encrypted_uri_structured;
      m.encrypted_uri.whole_user_part = mk.encrypted_uri_whole_user_part;
      r.mikey = std::move(m);
    }
  }
  if (s != nullptr && s->http.counters.messages + s->http.counters.h2_frames.size() > 0) {
    // Feature 007.
    const auto& h = s->http.counters;
    r.http_ruleset = {s->http.ruleset_name, s->http.ruleset_version, s->http.ruleset_digest};
    WebReport w;
    w.scalars = {{"messages", h.messages},
                 {"malformed", h.malformed},
                 {"header_blocks", h.header_blocks},
                 {"h2_undecodable", h.h2_undecodable},
                 {"cookie_names", h.cookie_names},
                 {"cookie_values_removed", h.cookie_values_removed},
                 {"xcap_selectors", h.xcap_selectors},
                 {"xcap_malformed", h.xcap_malformed},
                 {"oauth_messages", h.oauth_messages},
                 {"kms_messages", h.kms_messages}};
    w.maps = {{"requests", h.requests},       {"responses", h.responses},
              {"streams", h.streams},         {"upgrades", h.upgrades},
              {"h2_frames", h.h2_frames},     {"credentials_removed", h.credentials_removed},
              {"tokens", h.tokens},           {"zero_rest", h.zero_rest}};
    w.nested = {{"headers", h.headers},
                {"removed_unknown", h.removed_unknown},
                {"params", h.params},
                {"bodies", h.bodies},
                {"jwt_claims", h.jwt_claims}};
    r.http = std::move(w);
    if (h.tokens.contains("jwt")) r.web_statements.emplace_back("jwt-signatures-invalidated");
    if (s->xml.counters.elements.contains({"urn:3gpp:ns:mcsecKMSInterface:1.0", "PubAuthKey"}) ||
        s->xml.counters.elements.contains({"urn:3gpp:ns:mcsecKMSInterface:1.0", "PubEncKey"})) {
      r.web_statements.emplace_back("kms-signatures-invalidated");
    }
  }
  if (s != nullptr && s->tls.counters.connections > 0) {
    const auto& t = s->tls.counters;
    r.tls_ruleset = {s->tls.ruleset_name, s->tls.ruleset_version, s->tls.ruleset_digest};
    WebReport w;
    w.scalars = {{"connections", t.connections},
                 {"protected_zeroed", t.protected_zeroed},
                 {"server_names", t.server_names},
                 {"certificates_rewritten", t.certificates_rewritten}};
    w.maps = {{"records", t.records},       {"handshakes", t.handshakes}, {"psk_identities", t.psk_identities},
              {"certificates_zeroed", t.certificates_zeroed}, {"alerts", t.alerts}, {"zero_rest", t.zero_rest}};
    w.nested = {{"extensions", t.extensions}, {"x509", t.x509}};
    r.tls = std::move(w);
    if (t.certificates_rewritten > 0) {
      r.web_statements.emplace_back("certificate-signatures-invalidated");
      if (r.options.time_shift_ns && *r.options.time_shift_ns != 0) r.web_statements.emplace_back("certificate-validity-unshifted");
    }
  }
  if (error) {
    r.status.exit_code = static_cast<int>(error->code);
    r.status.result = std::string(result_name(error->code));
    r.status.message = error->message;
  } else {
    r.status.exit_code = 0;
    r.status.result = "published";
    r.files.output = request_.output.string();
    if (s != nullptr) r.files.output_format = fmt_name(s->output_format);
  }
  return r;
}

}  // namespace mcxanon
