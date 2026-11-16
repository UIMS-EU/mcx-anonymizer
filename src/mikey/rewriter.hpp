// SPDX-License-Identifier: GPL-3.0-or-later
//
// The MIKEY carrier rewriter of feature 005: the one implementation of sip::MikeyCarrier, created
// per run by the pipeline.
#pragma once

#include "mikey/counters.hpp"
#include "mikey/decode.hpp"
#include "mikey/ledger.hpp"
#include "policy/mikey_rules.hpp"
#include "sip/value_map.hpp"

#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace mcxanon::mikey {

struct KmsPeriod {
  std::string kms;
  std::uint64_t length_s = 0;
  std::uint64_t offset_s = 0;
};

struct RewriterOptions {
  bool passthrough = false;                 // --encrypted passthrough
  std::optional<std::int64_t> time_shift_ns;  // --time-shift
  std::vector<KmsPeriod> kms_periods;       // --kms-key-period
};

class Rewriter final : public sip::MikeyCarrier, public sip::UriObserver {
 public:
  Rewriter(const MikeyRuleSet& rules, RewriterOptions options, Counters& counters)
      : rules_(rules), options_(std::move(options)), counters_(counters) {}

  Result<std::optional<std::string>> rewrite(sip::MikeyCarrierKind kind, std::string_view value, std::string_view cte,
                                             sip::MikeyOutcome& outcome, sip::Context& ctx) override;
  void fallback(sip::MikeyCarrierKind kind, std::string_view reason) override;
  Result<std::uint32_t> key_identifier(std::uint32_t original, sip::Context& ctx) override;
  void encrypted_uri(bool structured) override;
  void on_uri(std::string_view original, std::string_view pseudonym) override;

 private:
  [[nodiscard]] sip::KeyContext key_context(const Message& m) const;

  const MikeyRuleSet& rules_;
  RewriterOptions options_;
  Counters& counters_;
  std::set<std::uint32_t> seen_key_ids_;
  Ledger ledger_;
};

std::string_view to_string(sip::MikeyCarrierKind k);

}  // namespace mcxanon::mikey
