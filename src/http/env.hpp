// SPDX-License-Identifier: GPL-3.0-or-later
//
// What the HTTP layer needs from the pipeline (feature 007): the rule
// set, the SIP context (mapper, options, XML bodies, MIKEY carrier) and the counters. One Env
// serves every web session of a run.
#pragma once

#include "http/counters.hpp"
#include "policy/http_rules.hpp"
#include "sip/value_map.hpp"

#include <cstdint>
#include <memory>

namespace mcxanon::stream {
class Session;
struct Connection;
}  // namespace mcxanon::stream

namespace mcxanon::http {

// Opens a TLS session for the bytes after a CONNECT (implemented by the pipeline
// with the TLS library, which the HTTP library does not depend on).
class TlsOpener {
 public:
  virtual ~TlsOpener() = default;
  virtual std::unique_ptr<stream::Session> open(std::shared_ptr<stream::Connection> connection) = 0;
};

struct Env {
  const HttpRuleSet& rules;
  sip::Context& sip;
  Counters& counters;
  TlsOpener* tls = nullptr;
  [[nodiscard]] std::int64_t shift_s() const { return sip.options.time_shift_s.value_or(0); }
  // A credential or secret that leaves the output: counted by kind and kept as an in-memory scan
  // token, so the independent scanner proves its absence (SC-002).
  void credential(std::string_view kind, std::string_view value) {
    Counters::bump(counters.credentials_removed, kind);
    if (!value.empty()) sip.counters.add_removed("string", std::string(value));
  }
};

}  // namespace mcxanon::http
