// SPDX-License-Identifier: GPL-3.0-or-later
#include "mcxanon/report.hpp"

#include "report/self_check.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <filesystem>
#include <set>
#include <tuple>

namespace mcxanon {
namespace {

std::string base_name(const std::string& p) {
  return std::filesystem::path(p).filename().string();
}

nlohmann::json opt_string(const std::optional<std::string>& s, bool base = false) {
  if (!s) return nullptr;
  return base ? base_name(*s) : *s;
}

}  // namespace

namespace {

// RFC 3261 §25.1 token characters, without the apostrophe (the report schema excludes it).
bool is_report_token(std::string_view s) {
  return !s.empty() && s.size() <= 64 && std::all_of(s.begin(), s.end(), [](char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           std::string_view("-.!%*_+`~").find(c) != std::string_view::npos;
  });
}

// The characters the report schema allows in the type and subtype of a Content-Type.
bool is_restricted_name(std::string_view s) {
  return !s.empty() && s.size() <= 64 && std::all_of(s.begin(), s.end(), [](char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           std::string_view("!#$&^_.+-").find(c) != std::string_view::npos;
  });
}

constexpr std::string_view kInvalidName = "(invalid-name)";

nlohmann::json counts(const std::map<std::string, std::uint64_t>& m, bool content_type = false) {
  std::map<std::string, std::uint64_t> merged;
  for (const auto& [name, n] : m) merged[report_name(name, content_type)] += n;
  return merged;
}

nlohmann::json action_counts(const std::map<std::string, std::map<std::string, std::uint64_t>>& m) {
  nlohmann::json out = nlohmann::json::object();
  for (const auto& [name, actions] : m) {
    auto& slot = out[report_name(name)];
    if (slot.is_null()) slot = nlohmann::json::object();
    for (const auto& [action, n] : actions) {
      slot[action] = slot.value(action, std::uint64_t{0}) + n;
    }
  }
  return out;
}

nlohmann::json sip_json(const SipReport& s) {
  using nlohmann::json;
  json removed = json::object();
  for (const auto& [kind, names] : s.removed_unknown) {
    removed[kind] = counts(names, kind == "content-type");
  }
  // Rule names (headers, SDP items, Content-Types of known rules) come from the rule set;
  // they pass the same name check so that nothing from the input slips through unchecked.
  json bodies = json::object();
  for (const auto& [ct, handling] : s.bodies) {
    auto& slot = bodies[report_name(ct, true)];
    if (slot.is_null()) slot = json::object();
    for (const auto& [h, n] : handling) slot[h] = slot.value(h, std::uint64_t{0}) + n;
  }
  json sdp = json::object();
  for (const auto& [item, actions] : s.sdp) sdp[item] = actions;
  return {
      {"messages", {{"requests", counts(s.requests)}, {"responses", s.responses},
                    {"malformed", s.malformed}}},
      {"headers", action_counts(s.headers)},
      {"malformed_headers", counts(s.malformed_headers)},
      {"removed_unknown", removed},
      {"sdp", sdp},
      {"bodies", bodies},
      {"tcp", {{"streams_sip", s.tcp.streams_sip},
               {"bytes_unframable", s.tcp.bytes_unframable},
               {"retransmissions_replayed", s.tcp.retransmissions_replayed},
               {"retransmissions_zeroed", s.tcp.retransmissions_zeroed},
               {"directions_evicted", s.tcp.directions_evicted}}},
      {"fragments", {{"datagrams_rewritten", s.fragments.datagrams_rewritten},
                     {"datagrams_zeroed", s.fragments.datagrams_zeroed}}},
      {"limits", {{"max_message_bytes", s.limits.max_message_bytes},
                  {"max_tcp_directions", s.limits.max_tcp_directions},
                  {"max_held_bytes", s.limits.max_held_bytes},
                  {"pending_timeout_ms", s.limits.pending_timeout_ms},
                  {"retrans_cache_bytes", s.limits.retrans_cache_bytes},
                  {"max_offset_breakpoints", s.limits.max_offset_breakpoints},
                  {"max_pending_datagrams", s.limits.max_pending_datagrams}}},
  };
}

nlohmann::json media_json(const MediaReport& m) {
  return {
      {"announcements", {{"endpoints", m.announcements.endpoints}, {"skipped", m.announcements.skipped}}},
      {"rtp", {{"packets", m.rtp.packets},
               {"by_payload_type", m.rtp.by_payload_type},
               {"streams", m.rtp.streams},
               {"by_stream", m.rtp.by_stream},
               {"zeroed", m.rtp.zeroed}}},
      {"rtcp", {{"by_packet_type", m.rtcp.by_packet_type},
                {"feedback", m.rtcp.feedback},
                {"xr_blocks", m.rtcp.xr_blocks},
                {"sdes_removed", m.rtcp.sdes_removed},
                {"srtcp_view", m.rtcp.srtcp_view},
                {"zeroed", m.rtcp.zeroed}}},
      {"app", {{"messages", m.app.messages}, {"fields", m.app.fields}, {"unknown", m.app.unknown}}},
      {"msrp", {{"requests", m.msrp.requests},
                {"responses", m.msrp.responses},
                {"headers", m.msrp.headers},
                {"zeroed", m.msrp.zeroed}}},
      {"limits", {{"max_endpoints", m.limits.max_endpoints}, {"endpoints_evicted", m.limits.endpoints_evicted}}},
  };
}

}  // namespace

std::string report_name(std::string_view name, bool content_type) {
  if (!content_type) return is_report_token(name) ? std::string(name) : std::string(kInvalidName);
  const auto slash = name.find('/');
  if (slash == std::string_view::npos) return std::string(kInvalidName);
  if (!is_restricted_name(name.substr(0, slash)) || !is_restricted_name(name.substr(slash + 1))) {
    return std::string(kInvalidName);
  }
  return std::string(name);
}

static nlohmann::json xml_json(const XmlReport& x) {
  using nlohmann::json;
  const auto nested = [](const XmlReport::ActionCounts& m) {
    json out = json::object();
    for (const auto& [k, a] : m) out[k] = a;
    return out;
  };
  const auto& l = x.limits;
  return {
      {"bodies", nested(x.bodies)},
      {"elements", nested(x.elements)},
      {"attributes", nested(x.attributes)},
      {"removed", {{"namespaces", x.removed.namespaces},
                   {"comments", x.removed.comments},
                   {"processing_instructions", x.removed.processing_instructions},
                   {"encrypted", x.removed.encrypted}}},
      {"embedded", x.embedded},
      {"limits", {{"max_depth", l.max_depth}, {"max_elements", l.max_elements},
                  {"max_attributes", l.max_attributes}, {"max_name_bytes", l.max_name_bytes},
                  {"max_value_bytes", l.max_value_bytes}, {"max_body_bytes", l.max_body_bytes},
                  {"max_embed_depth", l.max_embed_depth}}},
  };
}

static nlohmann::json mikey_json(const MikeyReport& m) {
  using nlohmann::json;
  json carriers = json::object();
  for (const auto& [k, c] : m.carriers) {
    json fb = json::object();
    for (const auto& [reason, n] : c.fallback) fb[reason] = n;
    carriers[k] = {{"rewritten", c.rewritten}, {"passed_through", c.passed_through}, {"fallback", fb}};
  }
  json payloads = json::object();
  for (const auto& [k, counts] : m.payloads) {
    json o = json::object();
    for (const auto& [a, n] : counts) o[a] = n;
    payloads[k] = o;
  }
  json key_ids = json::object();
  for (const auto& [k, n] : m.key_ids) key_ids[k] = n;
  json cs_ids = json::object();
  for (const auto& [k, n] : m.cs_ids) cs_ids[k] = n;
  return {
      {"carriers", carriers},
      {"unexpected_carrier", m.unexpected_carrier},
      {"payloads", payloads},
      {"incomplete", m.incomplete},
      {"uids", {{"resolved", m.uids.resolved}, {"unresolved", m.uids.unresolved}}},
      {"key_ids", key_ids},
      {"cs_ids", cs_ids},
      {"mki", {{"pseudonymised", m.mki.pseudonymised}, {"unmatched", m.mki.unmatched}, {"ambiguous", m.mki.ambiguous}}},
      {"encrypted_xml", {{"kept", m.encrypted_xml.kept},
                         {"passed_through", m.encrypted_xml.passed_through},
                         {"removed_parts", m.encrypted_xml.removed_parts}}},
      {"encrypted_uri", {{"structured", m.encrypted_uri.structured},
                         {"whole_user_part", m.encrypted_uri.whole_user_part}}},
      {"limits", {{"max_message_bytes", m.limits.max_message_bytes},
                  {"max_payloads", m.limits.max_payloads},
                  {"max_id_bytes", m.limits.max_id_bytes}}},
  };
}

// The statements of the MIKEY report.
static std::vector<std::string> mikey_statements(const MikeyReport& m, const Report::Options& o) {
  std::vector<std::string> v;
  std::uint64_t invalidated = 0;
  if (const auto it = m.payloads.find("SIGN"); it != m.payloads.end()) {
    if (const auto jt = it->second.find("invalidated"); jt != it->second.end()) invalidated = jt->second;
  }
  if (invalidated > 0) {
    v.emplace_back(
        "MIKEY-SAKKE: signatures of rewritten I_MESSAGEs do not verify (identities, key identifiers and RAND were "
        "replaced; the ECCSI signature is zeroed)");
  }
  if (o.encrypted == "passthrough") {
    v.emplace_back(
        "passthrough: the output contains original identities and key identifiers inside key management messages "
        "and encrypted XML elements (see scan.warnings)");
  } else {
    v.emplace_back(
        "MIKEY-SAKKE: SAKKE encapsulated data, encrypted key parameters and XML cipher values are kept as ciphertext; "
        "they open only with the receiver's or the group's keys");
  }
  return v;
}

std::vector<std::string> not_anonymised_statements(const Report::Options& o) {
  std::vector<std::string> v{
      "packet sizes and capture lengths",
      "timing: inter-packet deltas" + std::string(o.time_shift_ns ? "" : " and absolute timestamps"),
      "packet order and the conversation structure (who talks to whom, how often)",
      "fingerprint-capable header values: IPv4 identification, TCP timestamp values, GTP-U TEIDs, "
      "GRE keys, SCTP verification tags",
      "behaviour of the implementations that produced the traffic",
      // FR-037: what the SIP layer keeps on purpose, so that the flow stays readable.
      "SIP: the sequence of request methods and response codes, and its timing",
      "SIP: header order, header-name casing and compact forms, and the capability sets "
      "(Allow, Supported, Require), which can fingerprint an implementation",
      "SIP and SDP: the length and character set of values a rule pseudonymises in place "
      "(telephone numbers, digest values, cell and location identities, SDP session IDs and "
      "versions)",
      // R9: the digit count is kept, so no reserved pseudonym range is possible.
      "SIP: pseudonyms of short telephone numbers (4 to 6 digits) can equal an original number "
      "seen later in the same project; such a collision stops the run (exit 4), and a re-run on a "
      "fresh project avoids it",
      // FR-033 (feature 004): what the media layer keeps on purpose.
      "RTP: sequence numbers, timestamps, payload types and marker bits",
      "RTP and MSRP: payload lengths, which reveal codec modes, talk spurts and message sizes",
      "RTCP: report statistics, including the RFC 3611 VoIP Metrics signal and noise levels",
      "floor and transmission control: message order and timing, priorities, durations, reject "
      "causes and queue positions",
      "MSRP: Byte-Range values and status codes",
      // FR-021 (feature 003): what the XML layer keeps on purpose.
      "MCX XML bodies: the element and attribute structure of kept documents (element order and "
      "which optional elements are present)",
      "MCX XML bodies: enumerated and boolean values (session types, emergency and imminent-peril "
      "indicators, affiliation and registration states, report types)",
      "MCX XML bodies: the configured location triggers (kinds, intervals, distances, trigger "
      "IDs) and the presence of coordinates, whose values are replaced by 0",
      "MCX XML bodies: body lengths, which change only by the length differences of the rewritten "
      "values",
      "MCX XML bodies: signature and encryption algorithm identifiers, and which parts were signed "
      "or encrypted",
  };
  if (!o.pseudonymise_ephemeral_ports) v.emplace_back("transport ports");
  if (!o.pseudonymise_vlan) v.emplace_back("VLAN IDs");
  return v;
}

namespace {

nlohmann::json document(const Report& r, bool statements) {
  using nlohmann::json;
  json counters = json::object();
  for (const auto& [field, actions] : r.counters) {
    json a = json::object();
    for (const auto& [action, n] : actions) a[action] = n;
    counters[field] = a;
  }
  std::vector<ReportUnknownProtocol> unknown = r.unknown_protocols;
  std::sort(unknown.begin(), unknown.end(), [](const auto& x, const auto& y) {
    return std::tie(x.kind, x.id) < std::tie(y.kind, y.id);
  });
  json unknown_j = json::array();
  for (const auto& u : unknown) unknown_j.push_back({{"kind", u.kind}, {"id", u.id}, {"count", u.count}});
  json hits = json::array();
  for (const auto& h : r.scan.hits) {
    hits.push_back({{"frame", h.frame}, {"offset", h.offset}, {"encoding", h.encoding},
                    {"category", h.category}, {"label", h.label}});
  }
  const auto& o = r.options;
  json options = {{"payload", o.payload},
                  {"format", o.format},
                  {"pseudonymise_vlan", o.pseudonymise_vlan},
                  {"pseudonymise_ephemeral_ports", o.pseudonymise_ephemeral_ports},
                  {"ephemeral_range", o.ephemeral_range},
                  {"prefix_preserving", o.prefix_preserving},
                  {"time_shift_ns", o.time_shift_ns ? json(*o.time_shift_ns) : json(nullptr)},
                  {"deny_list_entries", o.deny_list_entries},
                  {"strict", o.strict},
                  {"encrypted", o.encrypted}};
  json files = {{"input", base_name(r.files.input)},
                {"output", opt_string(r.files.output, true)},
                {"input_format", opt_string(r.files.input_format)},
                {"output_format", opt_string(r.files.output_format)},
                {"frames", r.files.frames},
                {"truncated_tail_bytes", r.files.truncated_tail_bytes}};
  if (!r.files.input_format) files.erase("input_format");
  json status = {{"exit_code", r.status.exit_code}, {"result", r.status.result}};
  if (!r.status.message.empty()) status["message"] = r.status.message;
  json doc = {
      {"format", 6},
      {"command", r.command},
      {"tool", {{"version", r.tool_version}}},
      {"ruleset", {{"name", r.ruleset_name}, {"version", r.ruleset_version}, {"digest", r.ruleset_digest}}},
      {"options", options},
      {"files", files},
      {"status", status},
      {"counters", counters},
      {"mapping", {{"new_entries", r.mapping.new_entries},
                   {"reused_entries", r.mapping.reused_entries},
                   {"collisions_resolved", r.mapping.collisions_resolved}}},
      {"pcapng_removed", {{"blocks", r.removed_blocks}, {"options", r.removed_options}}},
      {"unknown_protocols", unknown_j},
      {"checksums", {{"valid_kept_valid", r.checksums.valid_kept_valid},
                     {"invalid_kept_invalid", r.checksums.invalid_kept_invalid},
                     {"unverifiable_recomputed", r.checksums.unverifiable_recomputed},
                     {"udp_zero_kept", r.checksums.udp_zero_kept}}},
      {"scan", {{"performed", r.scan.performed},
                {"tokens", r.scan.tokens},
                {"patterns", r.scan.patterns},
                {"unscannable_tokens", r.scan.unscannable_tokens},
                {"suppressed_chance_matches", r.scan.suppressed_chance_matches},
                {"unscannable_by_category", r.scan.unscannable_by_category},
                {"hits", hits}}},
      {"not_anonymised", not_anonymised_statements(o)},
  };
  if (!r.sip_ruleset.name.empty()) {
    doc["sip_ruleset"] = {{"name", r.sip_ruleset.name},
                          {"version", r.sip_ruleset.version},
                          {"digest", r.sip_ruleset.digest}};
  }
  if (r.sip) doc["sip"] = sip_json(*r.sip);
  if (!r.media_ruleset.name.empty()) {
    doc["media_ruleset"] = {{"name", r.media_ruleset.name},
                            {"version", r.media_ruleset.version},
                            {"digest", r.media_ruleset.digest}};
  }
  if (r.media) doc["media"] = media_json(*r.media);
  if (!r.xml_ruleset.name.empty()) {
    doc["xml_ruleset"] = {{"name", r.xml_ruleset.name},
                          {"version", r.xml_ruleset.version},
                          {"digest", r.xml_ruleset.digest}};
  }
  if (r.xml) doc["xml"] = xml_json(*r.xml);
  if (!r.mikey_ruleset.name.empty() && r.mikey) {
    doc["mikey_ruleset"] = {{"name", r.mikey_ruleset.name},
                            {"version", r.mikey_ruleset.version},
                            {"digest", r.mikey_ruleset.digest}};
  }
  if (r.mikey) {
    doc["mikey"] = mikey_json(*r.mikey);
    for (auto& s : mikey_statements(*r.mikey, o)) doc["not_anonymised"].push_back(std::move(s));
  }
  const auto web = [](const WebReport& w) {
    json j = json::object();
    for (const auto& [k, x] : w.scalars) j[k] = x;
    for (const auto& [k, x] : w.maps) j[k] = x;
    for (const auto& [k, x] : w.nested) j[k] = x;
    return j;
  };
  if (r.http) {
    doc["http_ruleset"] = {{"name", r.http_ruleset.name}, {"version", r.http_ruleset.version}, {"digest", r.http_ruleset.digest}};
    doc["http"] = web(*r.http);
  }
  if (r.tls) {
    doc["tls_ruleset"] = {{"name", r.tls_ruleset.name}, {"version", r.tls_ruleset.version}, {"digest", r.tls_ruleset.digest}};
    doc["tls"] = web(*r.tls);
  }
  for (const auto& s : r.web_statements) doc["not_anonymised"].push_back(s);
  if (o.encrypted == "passthrough") {
    json warnings = json::array();
    for (const auto& w : r.scan.warnings) {
      warnings.push_back({{"frame", w.frame}, {"offset", w.offset}, {"carrier", w.carrier}, {"category", w.category}});
    }
    doc["scan"]["warnings"] = warnings;
  }
  if (!statements) doc.erase("not_anonymised");
  return doc;
}

// Property names, enumeration values and constants of the report schema.
const std::set<std::string>& schema_words() {
  static const std::set<std::string> words = [] {
    std::set<std::string> w;
    const auto schema = nlohmann::json::parse(
#include "report_schema_embedded.inc"
    );
    const auto walk = [&w](const auto& self, const nlohmann::json& j) -> void {
      if (j.is_object()) {
        for (const auto& [k, v] : j.items()) {
          if (k == "properties" && v.is_object()) {
            for (const auto& [name, _] : v.items()) w.insert(name);
          } else if (k == "enum" && v.is_array()) {
            for (const auto& e : v) {
              if (e.is_string()) w.insert(e.get<std::string>());
            }
          } else if (k == "const" && v.is_string()) {
            w.insert(v.get<std::string>());
          }
          self(self, v);
        }
      } else if (j.is_array()) {
        for (const auto& e : j) self(self, e);
      }
    };
    walk(walk, schema);
    return w;
  }();
  return words;
}

void self_check_text(const nlohmann::json& j, const std::set<std::string>& words, std::vector<std::string>& out) {
  if (j.is_object()) {
    for (const auto& [k, v] : j.items()) {
      if (!words.contains(k)) out.push_back(k);
      // Rule set digests: SHA-256 of the rule files compiled into the tool, not input data; a
      // short hex value from the input would match them by chance.
      if (k == "digest" && v.is_string()) continue;
      self_check_text(v, words, out);
    }
  } else if (j.is_array()) {
    for (const auto& e : j) self_check_text(e, words, out);
  } else if (j.is_string()) {
    const auto& s = j.get_ref<const std::string&>();
    if (!words.contains(s)) out.push_back(s);
  } else if (j.is_number()) {
    out.push_back(j.dump());
  }
}

}  // namespace

std::string to_json(const Report& r) { return document(r, true).dump(2) + "\n"; }

std::vector<std::string> to_json_for_self_check(const Report& r) {
  std::vector<std::string> out;
  self_check_text(document(r, false), schema_words(), out);
  return out;
}

}  // namespace mcxanon
