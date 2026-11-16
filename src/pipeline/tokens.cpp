// SPDX-License-Identifier: GPL-3.0-or-later
#include "pipeline/tokens.hpp"

#include "bytes/hex.hpp"
#include "report/self_check.hpp"

#include <cstdio>
#include <type_traits>

namespace mcxanon {
namespace {

std::string fmt_mac(const Bytes& b) {
  char buf[24];
  std::snprintf(buf, sizeof buf, "%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5]);
  return buf;
}
std::string fmt_v4(const Bytes& b) {
  return std::to_string(b[0]) + "." + std::to_string(b[1]) + "." + std::to_string(b[2]) + "." + std::to_string(b[3]);
}

bool clean(const std::string& s, const scan::Index& index) {
  const auto* p = reinterpret_cast<const std::uint8_t*>(s.data());
  return scan::scan_bytes(std::span(p, s.size()), index).hits.empty();
}

}  // namespace

std::vector<scan::Token> mapping_tokens(const Mapping& mapping) {
  std::vector<scan::Token> out;
  for (const auto& [key, e] : mapping.entries()) {
    switch (e.category) {
      case Category::mac:
        if (e.original.size() == 6) out.push_back({scan::TokenCategory::mac, e.original, fmt_mac(e.pseudonym)});
        break;
      case Category::ipv4:
      case Category::ipv4_pp:
      case Category::ipv4_mcast:
        if (e.original.size() == 4) out.push_back({scan::TokenCategory::ipv4, e.original, fmt_v4(e.pseudonym)});
        break;
      case Category::ipv6:
      case Category::ipv6_pp:
        if (e.original.size() == 16) {
          out.push_back({scan::TokenCategory::ipv6, e.original, "ipv6:" + to_hex(e.pseudonym)});
        }
        break;
      case Category::ipv6_iid_ll:
        out.push_back({scan::TokenCategory::string, e.original, "iid:" + to_hex(e.pseudonym)});
        break;
      // Feature 002 (FR-030): text categories as strings, numeric ones as
      // numbers, SPI and SSRC as 32-bit binary values. Labels are pseudonyms.
      case Category::tel: {
        Bytes digits;
        for (auto c : e.original) {
          if (c >= '0' && c <= '9') digits.push_back(c);
        }
        out.push_back({scan::TokenCategory::number, digits, "tel:" + std::string(e.pseudonym.begin(), e.pseudonym.end())});
        break;
      }
      case Category::imei:
      case Category::sdp_sess:
        out.push_back({scan::TokenCategory::number, e.original,
                       std::string(to_string(e.category)) + ":" + std::string(e.pseudonym.begin(), e.pseudonym.end())});
        break;
      case Category::spi:
      case Category::ssrc:
      case Category::fc_ref:
      case Category::eci:
        if (e.original.size() == 4) {
          const auto v = (std::uint32_t{e.pseudonym[0]} << 24) | (std::uint32_t{e.pseudonym[1]} << 16) |
                         (std::uint32_t{e.pseudonym[2]} << 8) | e.pseudonym[3];
          out.push_back({scan::TokenCategory::binary, e.original,
                         std::string(to_string(e.category)) + ":" + std::to_string(v)});
        }
        break;
      case Category::key_id:
        if (e.original.size() == 4) {
          out.push_back({scan::TokenCategory::key, e.original, "key-id:" + to_hex(e.pseudonym)});
        }
        break;
      case Category::nonce:
      case Category::uid:
        out.push_back({scan::TokenCategory::bytes, e.original,
                       std::string(to_string(e.category)) + ":" + to_hex(e.pseudonym)});
        break;
      default:
        if (is_text_category(e.category) && !is_binary_category(e.category)) {
          out.push_back({scan::TokenCategory::string, e.original,
                         std::string(e.pseudonym.begin(), e.pseudonym.end())});
        }
        // 3-byte solicited-node suffixes, VLAN IDs, ports, TAC, SAI and MBSFN area IDs: too
        // short to search
        break;
    }
  }
  return out;
}

std::vector<std::string> mapping_pseudonyms(const Mapping& mapping) {
  std::vector<std::string> out;
  for (const auto& [key, e] : mapping.entries()) {
    // SPI and SSRC pseudonyms are 4-byte binary values, not text.
    if (!is_text_category(e.category) || is_binary_category(e.category)) continue;
    out.emplace_back(e.pseudonym.begin(), e.pseudonym.end());
  }
  return out;
}

std::vector<std::string> mapping_byte_pseudonyms(const Mapping& mapping) {
  std::vector<std::string> out;
  for (const auto& [key, e] : mapping.entries()) {
    if (is_byte_category(e.category) && e.pseudonym.size() >= 8) out.emplace_back(e.pseudonym.begin(), e.pseudonym.end());
  }
  return out;
}

std::vector<scan::Token> removed_tokens(const std::vector<RemovedValue>& removed) {
  std::vector<scan::Token> out;
  std::size_t n = 0;
  for (const auto& r : removed) {
    const auto cat = r.category == "mac" ? scan::TokenCategory::mac
                     : r.category == "ipv4" ? scan::TokenCategory::ipv4
                     : r.category == "ipv6" ? scan::TokenCategory::ipv6 : scan::TokenCategory::string;
    out.push_back({cat, r.value, "removed:" + r.category + "#" + std::to_string(++n)});
  }
  return out;
}

std::vector<scan::Token> secret_tokens(const Secret& secret) {
  const Bytes raw(secret.begin(), secret.end());
  const std::string hex = to_hex(raw);
  return {scan::Token{scan::TokenCategory::string, raw, "secret"},
          scan::Token{scan::TokenCategory::string, Bytes(hex.begin(), hex.end()), "secret"}};
}

Report::Scan to_report_scan(const scan::ScanResult& r) {
  Report::Scan s;
  s.performed = true;
  s.tokens = r.tokens;
  s.patterns = r.patterns;
  s.unscannable_tokens = r.unscannable_tokens;
  s.suppressed_chance_matches = r.suppressed_chance_matches;
  s.unscannable_by_category = r.unscannable_by_category;
  for (const auto& h : r.hits) {
    s.hits.push_back({h.frame_number, h.file_offset, h.encoding, std::string(scan::to_string(h.category)), h.label});
  }
  for (const auto& w : r.warnings) {
    s.warnings.push_back({w.frame_number, w.file_offset, w.carrier, std::string(scan::to_string(w.category))});
  }
  return s;
}

bool sanitise_report(Report& report, const scan::Index& index) {
  const auto redact = [&](std::string& name) {
    if (!clean(std::filesystem::path(name).filename().string(), index)) name = "(redacted)";
  };
  redact(report.files.input);
  if (report.files.output) redact(*report.files.output);
  // Names that come from the input (FR-036): a name that contains a scan token is reported as
  // "(invalid-name)", the one replacement the report schema allows.
  const auto names = [&](auto& m) {
    using M = std::remove_reference_t<decltype(m)>;
    M out;
    for (auto& [name, v] : m) {
      if (clean(name, index)) {
        out[name] = v;
      } else if constexpr (std::is_same_v<typename M::mapped_type, std::uint64_t>) {
        out["(invalid-name)"] += v;
      } else {
        for (const auto& [k, n] : v) out["(invalid-name)"][k] += n;
      }
    }
    m = std::move(out);
  };
  if (report.sip) {
    names(report.sip->requests);
    names(report.sip->malformed_headers);
    for (auto& [kind, m] : report.sip->removed_unknown) names(m);
    names(report.sip->headers);
    names(report.sip->bodies);
  }
  if (report.xml) {
    // XML keys are space-separated names ("<namespace> <local>", "... @<attr>"): each part that
    // contains a scan token becomes "(invalid-name)", so the standard parts stay readable.
    const auto part = [&](const std::string& p) {
      const bool at = p.starts_with('@');
      const std::string name = at ? p.substr(1) : p;
      return clean(name, index) ? p : std::string(at ? "@" : "") + "(invalid-name)";
    };
    const auto key = [&](const std::string& k) {
      std::string out;
      std::size_t start = 0;
      while (start <= k.size()) {
        const auto sp = k.find(' ', start);
        const auto end = sp == std::string::npos ? k.size() : sp;
        if (!out.empty()) out.push_back(' ');
        out += part(k.substr(start, end - start));
        if (sp == std::string::npos) break;
        start = sp + 1;
      }
      return out;
    };
    const auto rekey = [&](auto& m) {
      std::remove_reference_t<decltype(m)> out;
      for (auto& [k, v] : m) {
        if constexpr (std::is_same_v<std::remove_cvref_t<decltype(v)>, std::uint64_t>) {
          out[key(k)] += v;
        } else {
          for (const auto& [a, n] : v) out[key(k)][a] += n;
        }
      }
      m = std::move(out);
    };
    names(report.xml->bodies);
    rekey(report.xml->elements);
    rekey(report.xml->attributes);
    rekey(report.xml->removed.namespaces);
    names(report.xml->embedded);
  }
  for (const auto& s : to_json_for_self_check(report)) {
    if (!clean(s, index)) return false;
  }
  return true;
}

}  // namespace mcxanon
