// SPDX-License-Identifier: GPL-3.0-or-later
//
// The run report (schemas/report.schema.json). It holds counts, identifiers
// and pseudonyms only: no original value, no secret, no absolute path and no
// wall-clock time.
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace mcxanon {

struct ReportScanHit {
  std::uint64_t frame = 0;
  std::uint64_t offset = 0;
  std::string encoding;
  std::string category;
  std::string label;  // pseudonym or token label, never an original
};

// A scanner hit inside a passthrough element (feature 005, FR-018): a warning, not a failure.
struct ReportScanWarning {
  std::uint64_t frame = 0;
  std::uint64_t offset = 0;
  std::string carrier;   // sdp, body, gktp, mcpc, encrypted-xml
  std::string category;  // the token category
};

struct ReportUnknownProtocol {
  std::string kind;
  std::uint64_t id = 0;
  std::uint64_t count = 0;
};

struct RulesetInfo {
  std::string name;
  std::string version;
  std::string digest;
};

// The SIP layer's counts (feature 002, report format 2). Names that come from the input
// (methods, unknown header names, Content-Types) are reported only when they match the
// RFC 3261 token grammar and are at most 64 bytes long; otherwise as "(invalid-name)".
struct SipReport {
  std::map<std::string, std::uint64_t> requests;   // method -> count
  std::map<std::string, std::uint64_t> responses;  // "1xx".."6xx" -> count
  std::uint64_t malformed = 0;                     // messages zeroed or dropped as malformed
  // header rule name -> action (keep, pseudonymise, blank, remove, zero, malformed) -> count
  std::map<std::string, std::map<std::string, std::uint64_t>> headers;
  std::map<std::string, std::uint64_t> malformed_headers;  // header name -> count
  // kind (sip-header, sip-param, sdp-attribute, content-type) -> name -> count
  std::map<std::string, std::map<std::string, std::uint64_t>> removed_unknown;
  // SDP line ("o=") or attribute ("a=rtcp", "a=fmtp:MCPTT") -> action -> count
  std::map<std::string, std::map<std::string, std::uint64_t>> sdp;
  // Content-Type of a known rule -> handling (sdp, multipart, emptied) -> count
  std::map<std::string, std::map<std::string, std::uint64_t>> bodies;
  struct Tcp {
    std::uint64_t streams_sip = 0;
    std::uint64_t bytes_unframable = 0;
    std::uint64_t retransmissions_replayed = 0;
    std::uint64_t retransmissions_zeroed = 0;
    std::uint64_t directions_evicted = 0;
  } tcp;
  struct Fragments {
    std::uint64_t datagrams_rewritten = 0;
    std::map<std::string, std::uint64_t> datagrams_zeroed;  // missing, ambiguous, bound, timeout, not-sip
  } fragments;
  struct Limits {
    std::uint64_t max_message_bytes = 0;
    std::uint64_t max_tcp_directions = 0;
    std::uint64_t max_held_bytes = 0;
    std::uint64_t pending_timeout_ms = 0;
    std::uint64_t retrans_cache_bytes = 0;
    std::uint64_t max_offset_breakpoints = 0;
    std::uint64_t max_pending_datagrams = 0;
  } limits;
};

// The media layer's counts (feature 004, report format 3). Keys are
// packet types, APP names and subtypes, rule names, pseudonymised SSRCs or fixed reason words.
// The XML layer (feature 003, report format 4). Keys are standard names
// or fixed reason words; names without rules are redacted before they get here.
struct XmlReport {
  using Counts = std::map<std::string, std::uint64_t>;
  using ActionCounts = std::map<std::string, Counts>;
  ActionCounts bodies;      // Content-Type -> outcome (rewritten, malformed, encoding, limit, dtd, root, encrypted)
  ActionCounts elements;    // "<namespace> <local>" -> action
  ActionCounts attributes;  // "<namespace> <element> @<attr namespace> <attr>" -> action
  struct Removed {
    Counts namespaces;
    std::uint64_t comments = 0;
    std::uint64_t processing_instructions = 0;
    std::uint64_t encrypted = 0;
  } removed;
  Counts embedded;  // outcome of bodies inside resource-lists entry URIs
  // Feature 008 (FR-004): declarations whose non-standard prefix was renamed, by namespace name.
  Counts prefixes_rewritten;
  struct Limits {
    std::uint64_t max_depth = 32;
    std::uint64_t max_elements = 10000;
    std::uint64_t max_attributes = 64;
    std::uint64_t max_name_bytes = 256;
    std::uint64_t max_value_bytes = 65536;
    std::uint64_t max_body_bytes = 1048576;
    std::uint64_t max_embed_depth = 1;
  } limits;
};

struct MediaReport {
  using Counts = std::map<std::string, std::uint64_t>;
  using ActionCounts = std::map<std::string, std::map<std::string, std::uint64_t>>;
  struct Announcements {
    Counts endpoints;  // rtp, rtcp, mux, fc, tc, msrp
    Counts skipped;    // fqdn, unspecified, multicast, tls, rejected, unsupported, malformed
  } announcements;
  struct Rtp {
    std::uint64_t packets = 0;
    Counts by_payload_type;
    std::uint64_t streams = 0;
    Counts by_stream;  // pseudonymised SSRC, 8 hex digits
    Counts zeroed;
  } rtp;
  struct Rtcp {
    Counts by_packet_type;
    ActionCounts feedback;
    ActionCounts xr_blocks;
    Counts sdes_removed;
    Counts srtcp_view;
    Counts zeroed;  // malformed
  } rtcp;
  struct App {
    Counts messages;
    ActionCounts fields;
    Counts unknown;
  } app;
  struct Msrp {
    Counts requests;
    Counts responses;
    ActionCounts headers;
    Counts zeroed;
  } msrp;
  struct Limits {
    std::uint64_t max_endpoints = 0;
    std::uint64_t endpoints_evicted = 0;
  } limits;
};

// Key management and encrypted content (feature 005).
struct MikeyReport {
  using Counts = std::map<std::string, std::uint64_t>;
  struct Carrier {
    std::uint64_t rewritten = 0;
    std::uint64_t passed_through = 0;
    Counts fallback;  // reason -> count
  };
  std::map<std::string, Carrier> carriers;  // sdp, body, gktp, mcpc
  std::uint64_t unexpected_carrier = 0;
  std::map<std::string, Counts> payloads;   // "T" -> "shifted" -> count
  std::uint64_t incomplete = 0;
  struct Uids {
    std::uint64_t resolved = 0;
    std::uint64_t unresolved = 0;
  } uids;
  Counts key_ids;  // purpose tag (GMK, PCK, ...) -> distinct key identifiers
  Counts cs_ids;   // undefined-cs-id
  struct Mki {
    std::uint64_t pseudonymised = 0;
    std::uint64_t unmatched = 0;
    std::uint64_t ambiguous = 0;
  } mki;
  struct EncryptedXml {
    std::uint64_t kept = 0;
    std::uint64_t passed_through = 0;
    std::uint64_t removed_parts = 0;
  } encrypted_xml;
  struct EncryptedUri {
    std::uint64_t structured = 0;
    std::uint64_t whole_user_part = 0;
  } encrypted_uri;
  struct Limits {
    std::uint64_t max_message_bytes = 65535;
    std::uint64_t max_payloads = 64;
    std::uint64_t max_id_bytes = 1024;
  } limits;
};

// HTTP and TLS (feature 007): counts under fixed words; the keys of the
// maps are protocol vocabulary (methods, header and parameter names, content types) or counted
// as "(invalid)", never values.
struct WebReport {
  using Counts = std::map<std::string, std::uint64_t>;
  std::map<std::string, std::uint64_t> scalars;
  std::map<std::string, Counts> maps;
  std::map<std::string, std::map<std::string, Counts>> nested;
};

struct Report {
  std::string command = "anonymize";
  std::string tool_version;
  std::string ruleset_name;
  std::string ruleset_version;
  std::string ruleset_digest = std::string(64, '0');
  RulesetInfo sip_ruleset;     // empty name: not reported
  std::optional<SipReport> sip;  // absent for `scan`
  RulesetInfo media_ruleset;         // empty name: not reported
  std::optional<MediaReport> media;  // absent for `scan`
  RulesetInfo xml_ruleset;           // empty name: not reported
  std::optional<XmlReport> xml;      // absent for `scan`
  RulesetInfo mikey_ruleset;           // empty name: not reported
  std::optional<MikeyReport> mikey;    // absent when no MIKEY carrier was met
  RulesetInfo http_ruleset;            // feature 007
  std::optional<WebReport> http;       // absent when no HTTP message was met
  RulesetInfo tls_ruleset;
  std::optional<WebReport> tls;        // absent when no TLS record was met
  std::vector<std::string> web_statements;

  struct Options {
    std::string payload = "zero";
    std::string format = "same";
    bool pseudonymise_vlan = false;
    bool pseudonymise_ephemeral_ports = false;
    std::string ephemeral_range = "49152-65535";
    bool prefix_preserving = false;
    std::optional<std::int64_t> time_shift_ns;
    std::uint64_t deny_list_entries = 0;
    bool strict = false;
    std::string encrypted = "ciphertext";  // feature 005: ciphertext or passthrough
  } options;

  struct Files {
    std::string input;                  // reduced to the base name on output
    std::optional<std::string> output;  // reduced to the base name; null when not published
    std::optional<std::string> input_format;
    std::optional<std::string> output_format;
    std::uint64_t frames = 0;
    std::uint64_t truncated_tail_bytes = 0;
  } files;

  struct Status {
    int exit_code = 0;
    std::string result = "published";
    std::string message;
  } status;

  // FieldId -> action -> count.
  std::map<std::string, std::map<std::string, std::uint64_t>> counters;

  struct MappingStats {
    std::map<std::string, std::uint64_t> new_entries;
    std::map<std::string, std::uint64_t> reused_entries;
    std::uint64_t collisions_resolved = 0;
  } mapping;

  std::map<std::string, std::uint64_t> removed_blocks;   // "0x%08x" -> count
  std::map<std::string, std::uint64_t> removed_options;  // "0x%08x/<code>" -> count
  std::vector<ReportUnknownProtocol> unknown_protocols;

  struct Checksums {
    std::uint64_t valid_kept_valid = 0;
    std::uint64_t invalid_kept_invalid = 0;
    std::uint64_t unverifiable_recomputed = 0;
    std::uint64_t udp_zero_kept = 0;
  } checksums;

  struct Scan {
    bool performed = false;
    std::uint64_t tokens = 0;
    std::uint64_t patterns = 0;
    std::uint64_t unscannable_tokens = 0;
    std::uint64_t suppressed_chance_matches = 0;
    // Feature 008: input values cut at the end of a TCP payload whose whole value was harvested
    // (FR-001), and matches inside the kept branch cookie (FR-002).
    std::uint64_t skipped_input_fragments = 0;
    std::uint64_t suppressed_cookie_matches = 0;
    std::map<std::string, std::uint64_t> unscannable_by_category;  // "<category>/<reason>"
    std::vector<ReportScanHit> hits;
    std::vector<ReportScanWarning> warnings;  // passthrough only (feature 005)
  } scan;
};

// The fixed list of what the tool does not anonymise (FR-037).
std::vector<std::string> not_anonymised_statements(const Report::Options& options);

// A name from the input as the report shows it: the name itself when it matches the RFC 3261
// token grammar (as restricted by the report schema) and is 1 to 64 bytes long, otherwise
// "(invalid-name)". For Content-Types, each of type and subtype must be such a name.
std::string report_name(std::string_view name, bool content_type = false);

// Deterministic JSON: sorted keys, fixed formatting, trailing newline.
std::string to_json(const Report& report);

}  // namespace mcxanon
