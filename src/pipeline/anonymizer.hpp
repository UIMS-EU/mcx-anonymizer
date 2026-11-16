// SPDX-License-Identifier: GPL-3.0-or-later
//
// Streaming anonymiser: one input record in, zero or more output records out.
// No file I/O; the project mapping is updated in memory.
#pragma once

#include "mcxanon/anonymize.hpp"
#include "mcxanon/error.hpp"

#include "capture/record.hpp"
#include "http/counters.hpp"
#include "tls/counters.hpp"
#include "media/counters.hpp"
#include "mikey/counters.hpp"
#include "policy/http_rules.hpp"
#include "policy/media_rules.hpp"
#include "policy/mikey_rules.hpp"
#include "policy/xml_rules.hpp"
#include "policy/ruleset.hpp"
#include "rewrite/apply.hpp"
#include "rewrite/pcapng_meta.hpp"
#include "sip/value_map.hpp"
#include "stream/fragments.hpp"
#include "stream/tcp.hpp"
#include "xml/counters.hpp"

#include <memory>
#include <set>
#include <optional>
#include <vector>

namespace mcxanon {

// What the media layer did in one run (feature 004, report format 3).
struct MediaSummary {
  media::MediaCounters counters;
  std::map<std::string, std::uint64_t> endpoints;  // endpoint kind -> registered
  std::map<std::string, std::uint64_t> skipped;    // skip reason -> SDP media descriptions
  std::uint64_t max_endpoints = 0;
  std::uint64_t endpoints_evicted = 0;
  std::string ruleset_name, ruleset_version, ruleset_digest;
};

// What the SIP layer did in one run (feature 002, report format 2).
struct SipSummary {
  std::uint64_t messages = 0;
  std::map<std::string, std::uint64_t> requests;   // method -> count
  std::map<std::string, std::uint64_t> responses;  // "1xx".."6xx" -> count
  std::uint64_t malformed = 0;                     // messages zeroed or dropped
  std::uint64_t trailing_zeroed_bytes = 0;         // datagram bytes after the body
  sip::SipCounters counters;
  stream::TcpStats tcp;
  stream::FragmentStats fragments;
  std::uint64_t fragmented_rewritten = 0;  // reassembled SIP datagrams rewritten and refragmented
  std::uint64_t fragmented_not_sip = 0;    // reassembled, but the message is malformed
  std::uint64_t held_forced = 0;  // held records given up (bound, timeout, end of capture)
};

// What the XML layer did in one run (feature 003, report format 4).
struct XmlSummary {
  xml::Counters counters;
  std::set<std::string> known_namespaces;  // namespace names with rules (written as they are)
  std::string ruleset_name, ruleset_version, ruleset_digest;
};

struct MikeySummary {
  mikey::Counters counters;
  std::string ruleset_name, ruleset_version, ruleset_digest;
};

// What the HTTP layer did in one run (feature 007, report format 6).
struct HttpSummary {
  http::Counters counters;
  std::string ruleset_name, ruleset_version, ruleset_digest;
};

struct TlsSummary {
  tls::Counters counters;
  std::string ruleset_name, ruleset_version, ruleset_digest;
};

struct RunSummary {
  CaptureFormat input_format = CaptureFormat::pcap;
  CaptureFormat output_format = CaptureFormat::pcap;
  std::uint64_t frames = 0;
  RewriteStats rewrite;
  MetaStats meta;
  std::vector<RemovedValue> removed_values;  // identity-bearing values removed (memory only)
  std::map<std::string, std::uint64_t> new_entries;
  std::map<std::string, std::uint64_t> reused_entries;
  std::uint64_t collisions_resolved = 0;
  SipSummary sip;
  MediaSummary media;
  XmlSummary xml;
  MikeySummary mikey;
  HttpSummary http;
  TlsSummary tls;
};

class Anonymizer {
 public:
  // The SIP rule set is the embedded one unless `sip_rules` is given (test seam).
  static Result<Anonymizer> create(Project& project, const AnonymizeOptions& options,
                                   CaptureFormat input_format, RuleSet rules,
                                   std::optional<SipRuleSet> sip_rules = std::nullopt);
  Anonymizer(Anonymizer&&) noexcept;
  Anonymizer& operator=(Anonymizer&&) noexcept;
  ~Anonymizer();

  Result<std::vector<Record>> process(const Record& record);
  // Ends the run: resolves every held record (zero-filling incomplete content), marks mapping
  // usage, and returns the remaining output records followed by the statistics.
  struct Finish {
    std::vector<Record> records;
    RunSummary summary;
  };
  Result<Finish> finish();
  [[nodiscard]] const RunSummary& summary() const;
  // Test seam (pipeline/testing.hpp): the SIP layer runs, fills the mapping, and then keeps the
  // original message bytes, so that only the independent scan stands between them and the output.
  void set_test_sip_passthrough(bool on);
  void set_test_xml_passthrough(bool on);
  void set_test_web_passthrough(bool on);

  struct Impl;

 private:
  explicit Anonymizer(std::unique_ptr<Impl> impl);
  std::unique_ptr<Impl> impl_;
};

CaptureFormat resolve_output_format(OutputFormat requested, CaptureFormat input);

}  // namespace mcxanon
