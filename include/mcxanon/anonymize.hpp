// SPDX-License-Identifier: GPL-3.0-or-later
//
// Anonymisation of a capture file under a project.
#pragma once

#include "mcxanon/error.hpp"
#include "mcxanon/project.hpp"
#include "mcxanon/report.hpp"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace mcxanon {

enum class PayloadMode { zero, drop };
enum class OutputFormat { same, pcap, pcapng };
// What happens to encrypted content and key management messages (feature 005): `ciphertext`
// keeps the ciphertext and anonymises everything around and inside it; `passthrough` copies
// recognised I_MESSAGEs and xenc:EncryptedData subtrees byte for byte (scanner warnings).
enum class EncryptedMode { ciphertext, passthrough };

// The key period parameters of one KMS (TS 33.180 §F.2.1.1 P3 and P4), for UID resolution.
struct KmsKeyPeriod {
  std::string kms;              // the KMS identity as IDRkms* carries it (URI or host)
  std::uint64_t length_s = 0;   // key period length in seconds
  std::uint64_t offset_s = 0;   // key period offset in seconds (below the length)
};

struct AnonymizeOptions {
  PayloadMode payload = PayloadMode::zero;
  OutputFormat format = OutputFormat::same;
  bool pseudonymise_vlan = false;
  bool pseudonymise_ephemeral_ports = false;
  std::uint16_t ephemeral_lo = 49152;
  std::uint16_t ephemeral_hi = 65535;
  bool prefix_preserving = false;
  std::optional<std::chrono::nanoseconds> time_shift;
  bool strict = false;
  EncryptedMode encrypted = EncryptedMode::ciphertext;
  std::vector<KmsKeyPeriod> kms_key_periods;
};

struct AnonymizeFileRequest {
  std::filesystem::path input;
  std::filesystem::path output;
  std::optional<std::filesystem::path> report_path;  // default: <output>.report.json
  std::optional<std::filesystem::path> deny_list;
  bool overwrite = false;
  AnonymizeOptions options;
};

// Full pipeline: read, anonymise, persist the mapping, scan, publish, report.
// The report is written on success and on every failure after the request was
// validated; the returned error names the reason.
Result<Report> anonymize_file(Project& project, const AnonymizeFileRequest& request);

struct ScanFileRequest {
  std::filesystem::path file;
  std::optional<std::filesystem::path> report_path;  // default: <file>.scan.json
  std::optional<std::filesystem::path> deny_list;
  EncryptedMode encrypted = EncryptedMode::ciphertext;  // feature 005: passthrough downgrades hits (FR-018)
};

// Standalone residual-leak scan of a capture against the project's mapping and
// an optional deny-list. ErrorCode::leak when anything is found.
Result<Report> scan_capture(Project& project, const ScanFileRequest& request);

// Writes the report of a run that failed before anonymisation started (for
// example because the project could not be opened).
void write_failure_report(const AnonymizeFileRequest& request, const Error& error);

}  // namespace mcxanon
