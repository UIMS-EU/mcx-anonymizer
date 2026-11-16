// SPDX-License-Identifier: GPL-3.0-or-later
#include "cli/commands.hpp"
#include "cli/duration.hpp"
#include "mcxanon/anonymize.hpp"

#include <algorithm>
#include <cstdio>
#include <memory>

namespace mcxanon::cli {
namespace {

struct AnonymizeArgs {
  std::string project;
  std::string input;
  std::string output;
  std::string payload = "zero";
  std::string format = "same";
  std::string report;
  std::string deny_list;
  std::string time_shift;
  std::string ephemeral_range = "49152-65535";
  std::string encrypted = "ciphertext";
  std::vector<std::string> kms_key_periods;
  bool overwrite = false;
  bool strict = false;
  bool vlan = false;
  bool ports = false;
  bool prefix = false;
};

Result<std::pair<std::uint16_t, std::uint16_t>> parse_range(const std::string& s) {
  const auto dash = s.find('-');
  try {
    if (dash == std::string::npos) throw std::invalid_argument("range");
    const unsigned long lo = std::stoul(s.substr(0, dash));
    const unsigned long hi = std::stoul(s.substr(dash + 1));
    if (lo == 0 || lo > hi || hi > 65535) throw std::invalid_argument("range");
    return std::make_pair(static_cast<std::uint16_t>(lo), static_cast<std::uint16_t>(hi));
  } catch (const std::exception&) {
    return fail(ErrorCode::usage, "invalid --ephemeral-range '" + s + "'; use LO-HI");
  }
}

// --kms-key-period KMS=LENGTH[:OFFSET]. The value itself never
// appears in a message: it is the customer's KMS configuration.
Result<KmsKeyPeriod> parse_kms_key_period(const std::string& s) {
  const auto bad = [] { return fail(ErrorCode::usage, "invalid --kms-key-period; use KMS=LENGTH[:OFFSET] in seconds"); };
  const auto eq = s.rfind('=');
  if (eq == std::string::npos || eq == 0 || eq + 1 == s.size()) return bad();
  KmsKeyPeriod k;
  k.kms = s.substr(0, eq);
  const std::string rest = s.substr(eq + 1);
  const auto colon = rest.find(':');
  const auto number = [](const std::string& t, std::uint64_t& out) {
    if (t.empty() || t.size() > 18 || !std::all_of(t.begin(), t.end(), [](char c) { return c >= '0' && c <= '9'; })) {
      return false;
    }
    out = std::stoull(t);
    return true;
  };
  if (!number(rest.substr(0, colon), k.length_s)) return bad();
  if (colon != std::string::npos && !number(rest.substr(colon + 1), k.offset_s)) return bad();
  if (k.length_s == 0 || k.offset_s >= k.length_s) return bad();
  return k;
}

std::uint64_t total(const Report& r, std::string_view action) {
  std::uint64_t n = 0;
  for (const auto& [field, actions] : r.counters) {
    const auto it = actions.find(std::string(action));
    if (it != actions.end()) n += it->second;
  }
  return n;
}

void print_summary(const Report& r, const std::string& report_path) {
  std::uint64_t removed = 0;
  for (const auto& [k, n] : r.removed_blocks) removed += n;
  for (const auto& [k, n] : r.removed_options) removed += n;
  std::fprintf(stderr,
               "mcxanon: %llu frames; %llu fields pseudonymised, %llu zeroed, %llu padded; "
               "%llu pcapng blocks/options removed; %zu unknown protocol kinds\n",
               static_cast<unsigned long long>(r.files.frames),
               static_cast<unsigned long long>(total(r, "pseudonymise")),
               static_cast<unsigned long long>(total(r, "zero")),
               static_cast<unsigned long long>(total(r, "pad")),
               static_cast<unsigned long long>(removed), r.unknown_protocols.size());
  if (r.sip) {
    // Counts and rule names only: unknown names are in the report, after its self-check.
    const auto sum = [](const auto& m, const char* action) {
      std::uint64_t n = 0;
      for (const auto& [name, actions] : m) {
        const auto it = actions.find(action);
        if (it != actions.end()) n += it->second;
      }
      return n;
    };
    std::uint64_t messages = 0;
    for (const auto& [k, n] : r.sip->requests) messages += n;
    for (const auto& [k, n] : r.sip->responses) messages += n;
    std::uint64_t unknown_headers = 0, unknown_bodies = 0;
    if (const auto it = r.sip->removed_unknown.find("sip-header"); it != r.sip->removed_unknown.end()) {
      for (const auto& [k, n] : it->second) unknown_headers += n;
    }
    if (const auto it = r.sip->removed_unknown.find("content-type"); it != r.sip->removed_unknown.end()) {
      for (const auto& [k, n] : it->second) unknown_bodies += n;
    }
    const std::uint64_t removed_headers = sum(r.sip->headers, "remove") + unknown_headers;
    const std::uint64_t emptied = sum(r.sip->bodies, "emptied") + unknown_bodies;
    std::fprintf(stderr,
                 "sip: %llu messages (%llu malformed), %llu headers removed (%llu unknown), "
                 "%llu bodies emptied, %llu unframable TCP bytes, %llu fragmented datagram%s rewritten\n",
                 static_cast<unsigned long long>(messages), static_cast<unsigned long long>(r.sip->malformed),
                 static_cast<unsigned long long>(removed_headers), static_cast<unsigned long long>(unknown_headers),
                 static_cast<unsigned long long>(emptied),
                 static_cast<unsigned long long>(r.sip->tcp.bytes_unframable),
                 static_cast<unsigned long long>(r.sip->fragments.datagrams_rewritten),
                 r.sip->fragments.datagrams_rewritten == 1 ? "" : "s");
  }
  if (r.xml) {
    // Feature 003: every outcome other than "rewritten" empties.
    std::uint64_t rewritten = 0, emptied = 0;
    for (const auto& [type, outcomes] : r.xml->bodies) {
      for (const auto& [outcome, n] : outcomes) (outcome == "rewritten" ? rewritten : emptied) += n;
    }
    std::fprintf(stderr, "xml: %llu rewritten, %llu emptied\n", static_cast<unsigned long long>(rewritten),
                 static_cast<unsigned long long>(emptied));
  }
  if (r.mikey) {
    // Feature 005: key management.
    std::uint64_t rewritten = 0, passed = 0, fallback = 0;
    for (const auto& [k, c] : r.mikey->carriers) {
      rewritten += c.rewritten;
      passed += c.passed_through;
      for (const auto& [reason, n] : c.fallback) fallback += n;
    }
    std::fprintf(stderr, "mikey: %llu rewritten, %llu passed through, %llu fallback, %llu/%llu UIDs resolved, %llu MKIs\n",
                 static_cast<unsigned long long>(rewritten), static_cast<unsigned long long>(passed),
                 static_cast<unsigned long long>(fallback), static_cast<unsigned long long>(r.mikey->uids.resolved),
                 static_cast<unsigned long long>(r.mikey->uids.resolved + r.mikey->uids.unresolved),
                 static_cast<unsigned long long>(r.mikey->mki.pseudonymised));
  }
  if (r.options.encrypted == "passthrough") {
    // FR-019: the statement, with the number of passthrough elements and warnings.
    std::uint64_t elements = 0;
    if (r.mikey) {
      for (const auto& [k, c] : r.mikey->carriers) elements += c.passed_through;
      elements += r.mikey->encrypted_xml.passed_through;
    }
    std::fprintf(stderr,
                 "mcxanon: passthrough: the output contains original identities and key identifiers inside key "
                 "management messages and encrypted XML elements (%llu element(s), %zu scan warning(s))\n",
                 static_cast<unsigned long long>(elements), r.scan.warnings.size());
  }
  std::fprintf(stderr, "mcxanon: leak scan: %s; report: %s\n",
               r.scan.performed ? (r.scan.hits.empty() ? "clean" : "HITS") : "not performed",
               report_path.c_str());
}

}  // namespace

void register_anonymize_command(CLI::App& app, const GlobalOptions& g,
                                std::vector<std::pair<CLI::App*, Command>>& commands) {
  auto a = std::make_shared<AnonymizeArgs>();
  CLI::App* sub = app.add_subcommand("anonymize", "anonymise a pcap/pcapng capture");
  sub->add_option("--project", a->project, "project name")->required();
  sub->add_option("input", a->input, "input capture")->required();
  sub->add_option("-o,--output", a->output, "output capture")->required();
  sub->add_option("--payload", a->payload, "zero (default) or drop")
      ->check(CLI::IsMember({"zero", "drop"}));
  sub->add_option("--format", a->format, "same (default), pcap or pcapng")
      ->check(CLI::IsMember({"same", "pcap", "pcapng"}));
  sub->add_option("--report", a->report, "report path (default <output>.report.json)");
  sub->add_option("--deny-list", a->deny_list, "file of words that must never appear");
  sub->add_option("--time-shift", a->time_shift, "shift all timestamps, e.g. -30d or +1h30m");
  sub->add_option("--ephemeral-range", a->ephemeral_range, "ephemeral port range LO-HI");
  sub->add_flag("--overwrite", a->overwrite, "replace an existing output file");
  sub->add_flag("--strict", a->strict, "fail on unsupported link types or protocols");
  sub->add_flag("--pseudonymise-vlan", a->vlan, "pseudonymise VLAN IDs");
  sub->add_flag("--pseudonymise-ephemeral-ports", a->ports, "pseudonymise ephemeral ports");
  sub->add_flag("--prefix-preserving", a->prefix, "prefix-preserving IP pseudonyms");
  sub->add_option("--encrypted", a->encrypted,
                  "ciphertext (default: keep ciphertext, anonymise around it) or passthrough")
      ->check(CLI::IsMember({"ciphertext", "passthrough", "decrypt"}));
  sub->add_option("--kms-key-period", a->kms_key_periods,
                  "KMS=LENGTH[:OFFSET] key period in seconds, to resolve hidden identities (repeatable)")
      ->expected(1)
      ->allow_extra_args(false)
      ->multi_option_policy(CLI::MultiOptionPolicy::TakeAll);
  commands.emplace_back(sub, [&g, a]() -> Result<void> {
    AnonymizeFileRequest req;
    req.input = a->input;
    req.output = a->output;
    if (!a->report.empty()) req.report_path = a->report;
    if (!a->deny_list.empty()) req.deny_list = a->deny_list;
    req.overwrite = a->overwrite;
    auto& o = req.options;
    o.payload = a->payload == "drop" ? PayloadMode::drop : PayloadMode::zero;
    o.format = a->format == "pcap" ? OutputFormat::pcap
                                   : (a->format == "pcapng" ? OutputFormat::pcapng : OutputFormat::same);
    o.strict = a->strict;
    o.pseudonymise_vlan = a->vlan;
    o.pseudonymise_ephemeral_ports = a->ports;
    o.prefix_preserving = a->prefix;
    if (a->encrypted == "decrypt") {
      return fail(ErrorCode::usage, "--encrypted decrypt: decryption is not available in this version");
    }
    o.encrypted = a->encrypted == "passthrough" ? EncryptedMode::passthrough : EncryptedMode::ciphertext;
    for (const auto& spec : a->kms_key_periods) {
      auto k = parse_kms_key_period(spec);
      if (!k) return std::unexpected(k.error());
      for (const auto& prev : o.kms_key_periods) {
        if (prev.kms == k->kms) return fail(ErrorCode::usage, "--kms-key-period: KMS given twice");
      }
      o.kms_key_periods.push_back(*k);
    }
    auto range = parse_range(a->ephemeral_range);
    if (!range) return std::unexpected(range.error());
    o.ephemeral_lo = range->first;
    o.ephemeral_hi = range->second;
    if (!a->time_shift.empty()) {
      auto d = parse_duration(a->time_shift);
      if (!d) return std::unexpected(d.error());
      o.time_shift = *d;
    }
    auto project = open_project(g, a->project);
    if (!project) {
      write_failure_report(req, project.error());
      return std::unexpected(project.error());
    }
    auto report = anonymize_file(*project, req);
    if (!report) return std::unexpected(report.error());
    print_summary(*report, req.report_path ? req.report_path->string()
                                           : req.output.string() + ".report.json");
    return {};
  });
}

}  // namespace mcxanon::cli
