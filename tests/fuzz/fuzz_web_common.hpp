// SPDX-License-Identifier: GPL-3.0-or-later
//
// Shared by the feature 007 fuzz targets: an environment over the embedded SIP, XML, HTTP and TLS
// rule sets with a fresh mapping, and a driver that feeds bytes to a stream::Session the way the
// TCP engine does (frame, rewrite, drop the removed body, stop where the engine would zero the
// rest of the direction).
#pragma once

#include "http/env.hpp"
#include "pipeline/mapper_adapter.hpp"
#include "policy/http_rules.hpp"
#include "policy/sip_rules.hpp"
#include "policy/tls_rules.hpp"
#include "policy/xml_rules.hpp"
#include "pseudo/pseudonymiser.hpp"
#include "stream/connection.hpp"
#include "stream/tcp.hpp"
#include "tls/env.hpp"
#include "tls/session.hpp"
#include "xml/sip_bodies.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace fuzz_web {

inline mcxanon::Secret secret() {
  mcxanon::Secret s{};
  for (std::size_t i = 0; i < s.size(); ++i) s[i] = static_cast<std::uint8_t>(i * 7 + 1);
  return s;
}

inline const mcxanon::SipRuleSet& sip_rules() {
  static const mcxanon::SipRuleSet r = [] {
    auto x = mcxanon::load_embedded_sip_ruleset();
    if (!x) std::abort();
    return *x;
  }();
  return r;
}
inline const mcxanon::XmlRuleSet& xml_rules() {
  static const mcxanon::XmlRuleSet r = [] {
    auto x = mcxanon::load_embedded_xml_ruleset();
    if (!x) std::abort();
    return *x;
  }();
  return r;
}
inline const mcxanon::HttpRuleSet& http_rules() {
  static const mcxanon::HttpRuleSet r = [] {
    auto x = mcxanon::load_embedded_http_ruleset();
    if (!x) std::abort();
    return *x;
  }();
  return r;
}
inline const mcxanon::TlsRuleSet& tls_rules() {
  static const mcxanon::TlsRuleSet r = [] {
    auto x = mcxanon::load_embedded_tls_ruleset();
    if (!x) std::abort();
    return *x;
  }();
  return r;
}

// One fresh environment per input (the mapping and counters start empty).
struct Env final : mcxanon::http::TlsOpener {
  Env() {
    opts.time_shift_s = -7200;
    sctx.emplace(mcxanon::sip::Context{sip_rules(), mapper, opts, sip_counters, nullptr, &xml_bodies});
    http.emplace(mcxanon::http::Env{http_rules(), *sctx, http_counters, this});
    tls.emplace(mcxanon::tls::Env{tls_rules(), *sctx, tls_counters});
  }
  std::unique_ptr<mcxanon::stream::Session> open(std::shared_ptr<mcxanon::stream::Connection> c) override {
    return mcxanon::tls::open_tls_session(*tls, std::move(c));
  }
  mcxanon::Secret key = secret();
  mcxanon::Mapping mapping;
  mcxanon::Pseudonymiser p{key, mapping};
  mcxanon::MapperAdapter mapper{p};
  mcxanon::sip::TextOptions opts;
  mcxanon::sip::SipCounters sip_counters;
  mcxanon::xml::Counters xml_counters;
  mcxanon::xml::SipXmlBodies xml_bodies{xml_rules(), xml_counters};
  mcxanon::http::Counters http_counters;
  mcxanon::tls::Counters tls_counters;
  std::optional<mcxanon::sip::Context> sctx;
  std::optional<mcxanon::http::Env> http;
  std::optional<mcxanon::tls::Env> tls;
};

// Feeds `bytes` in segments of at most `segment` octets, as the engine would. Returns false where
// the engine stops framing the direction (zero_rest, invalid, a rewrite error).
inline bool drive(mcxanon::stream::Session& s, std::string_view bytes, std::size_t segment = 1400) {
  using mcxanon::stream::FrameKind;
  std::string buf;
  std::uint64_t drop = 0;
  std::size_t at = 0;
  while (at < bytes.size()) {
    std::string_view seg = bytes.substr(at, std::max<std::size_t>(segment, 1));
    at += seg.size();
    const std::size_t dropped = static_cast<std::size_t>(std::min<std::uint64_t>(drop, seg.size()));
    drop -= dropped;
    seg.remove_prefix(dropped);
    buf.append(seg);
    for (int guard = 0;; ++guard) {
      if (guard > 1'000'000) std::abort();  // no progress: a framing loop
      if (buf.empty()) break;
      const auto f = s.frame(buf);
      if (f.kind == FrameKind::more) {
        if (buf.size() > (64u << 20)) std::abort();  // the engine bounds a message at 64 MiB
        break;
      }
      if (f.kind == FrameKind::zero_rest || f.kind == FrameKind::invalid) return false;
      if (f.kind == FrameKind::oversized) return false;
      if (f.len == 0 || f.len > buf.size()) return false;  // the engine resynchronises
      if (f.kind == FrameKind::message) {
        auto m = s.rewrite(std::string_view(buf).substr(0, f.len));
        if (!m) return false;
        if (!m->zeroed) {
          std::size_t in = 0;
          std::size_t out = 0;
          for (const auto& p : m->spans) {
            in += p.orig_len;
            out += p.out_len;
          }
          if (!m->spans.empty() && (in != f.len || out != m->bytes.size())) std::abort();
        }
      }
      buf.erase(0, f.len);
      drop = f.drop_after;
      const std::size_t d = static_cast<std::size_t>(std::min<std::uint64_t>(drop, buf.size()));
      buf.erase(0, d);
      drop -= d;
    }
  }
  return true;
}

}  // namespace fuzz_web
