// SPDX-License-Identifier: GPL-3.0-or-later
//
// The SIP layer's context: the rule set, the mapper, the options and the counters, plus the
// one function that applies a rule category to a value. Every component of
// every grammar goes through map_value, so one original gets one pseudonym in every field
// (per-component binding, FR-033).
#pragma once

#include "mcxanon/error.hpp"

#include "policy/sip_rules.hpp"
#include "rewrite/address_mapper.hpp"

#include <algorithm>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <iterator>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace mcxanon::sip {

struct TextOptions {
  bool pseudonymise_ports = false;          // --pseudonymise-ephemeral-ports (FR-020, FR-035)
  std::optional<std::int64_t> time_shift_s;  // --time-shift for the Date header (FR-017)
};

using ActionCounts = std::map<std::string, std::map<std::string, std::uint64_t>>;

struct SipCounters {
  ActionCounts headers;          // header rule name -> action -> count
  ActionCounts sdp;              // "o=", "a=rtcp", "a=fmtp:MCPTT" -> action -> count
  ActionCounts bodies;           // Content-Type of a rule -> sdp / multipart / emptied -> count
  ActionCounts removed_unknown;  // sip-header / sip-param / sdp-attribute / content-type -> name
  std::map<std::string, std::uint64_t> malformed_headers;
  // Values removed by an explicit rule (free text, credentials, keys): in-memory scan tokens,
  // each (category, value) once, in the order first seen (R22: a value removed from every
  // message would otherwise be held once per message).
  std::vector<std::pair<std::string, std::string>> removed_values;

  void count(ActionCounts& m, const std::string& key, std::string_view action, std::uint64_t n = 1) {
    m[key][std::string(action)] += n;
  }
  void removed(std::string_view value) {
    if (!value.empty()) add_removed("string", std::string(value));
  }
  void add_removed(std::string category, std::string value) {
    std::string key = category;
    key += '\0';
    key += value;
    if (removed_seen_.insert(std::move(key)).second) removed_values.emplace_back(std::move(category), std::move(value));
  }
  // Adds the counts of `o`; with `actions` false, only its removed values (scan tokens).
  void merge(SipCounters&& o, bool actions = true) {
    if (actions) {
      for (auto [dst, src] : {std::pair{&headers, &o.headers}, std::pair{&sdp, &o.sdp},
                              std::pair{&bodies, &o.bodies}, std::pair{&removed_unknown, &o.removed_unknown}}) {
        for (const auto& [key, m] : *src) {
          for (const auto& [action, n] : m) (*dst)[key][action] += n;
        }
      }
      for (const auto& [key, n] : o.malformed_headers) malformed_headers[key] += n;
    }
    for (auto& [category, value] : o.removed_values) add_removed(std::move(category), std::move(value));
    o.removed_values.clear();
    o.removed_seen_.clear();
  }
  // Moves the removed values out and forgets them.
  std::vector<std::pair<std::string, std::string>> take_removed() {
    removed_seen_.clear();
    return std::exchange(removed_values, {});
  }

 private:
  std::unordered_set<std::string> removed_seen_;
};

// The key context of a secure media description (feature 005): the original key
// identifiers of the I_MESSAGEs of the same SDP (CSB ID and SPI words, session and media level)
// and the authentication tag octets after the MKI, from the SP payload or the default profile of
// the key (TS 33.180 §E.2.2-§E.4.2); unknown when no I_MESSAGE says.
struct KeyContext {
  std::vector<std::uint32_t> key_ids;
  std::optional<std::size_t> srtp_tag;
  std::optional<std::size_t> srtcp_tag;
  [[nodiscard]] bool empty() const { return key_ids.empty(); }
  void merge(const KeyContext& o) {
    for (auto k : o.key_ids) {
      if (std::find(key_ids.begin(), key_ids.end(), k) == key_ids.end()) key_ids.push_back(k);
    }
    if (!srtp_tag) srtp_tag = o.srtp_tag;
    if (!srtcp_tag) srtcp_tag = o.srtcp_tag;
  }
  auto operator<=>(const KeyContext&) const = default;
};

// One media description of an SDP as seen in the input (feature 004): the original
// connection address, port, proto and format, and the attributes that move RTCP or name an MSRP
// path. The values are the input's, never pseudonyms: packets are matched before rewriting.
struct SdpMedia {
  std::string media;     // m= <media>
  std::uint32_t port = 0;  // m= <port> (0: rejected, RFC 3264 §6)
  std::string proto;     // m= <proto>
  std::string fmt;       // first m= <fmt>
  std::string addrtype;  // c= <addrtype> (media level, else session level)
  std::string address;   // c= <connection-address> without /ttl and /count
  bool multicast_suffix = false;  // c= carried a /ttl or /count suffix
  std::optional<std::uint32_t> rtcp_port;  // a=rtcp (RFC 3605)
  std::string rtcp_addrtype, rtcp_address;  // a=rtcp with an address
  bool rtcp_mux = false;                    // a=rtcp-mux or a=rtcp-mux-only
  std::vector<std::string> paths;           // a=path URIs (RFC 4975 §8.2)
  KeyContext keys;                          // feature 005: a=key-mgmt at session and media level
};

// Receives the media descriptions of every SDP that rewrites without error (feature 004).
class MediaSink {
 public:
  virtual ~MediaSink() = default;
  virtual void announce(const SdpMedia& m) = 0;
};

struct Context;

// The outcome of an MCX XML body (feature 003): rewritten bytes, or emptied with a fixed reason
// word (malformed, encoding, limit, dtd, root, encrypted).
struct XmlOutcome {
  bool rewritten = false;
  std::string bytes;
  std::string reason;
};

// Rewrites the bodies whose rule has handling `xml` (feature 003). Implemented by
// the XML library (src/xml/sip_bodies.hpp) and attached by the pipeline; without one, such a
// body is emptied as in 002. `depth` is the embedding depth (0, or 1 inside an entry URI).
class XmlBodies {
 public:
  virtual ~XmlBodies() = default;
  virtual Result<XmlOutcome> rewrite(std::string_view content_type, std::string_view charset, std::string_view body,
                                     std::size_t depth, Context& ctx) = 0;
};

// The MIKEY carriers of feature 005: where an I_MESSAGE was found.
enum class MikeyCarrierKind { sdp, body, gktp, mcpc };

struct MikeyOutcome {
  enum class Kind { rewritten, passed_through, fallback };
  Kind kind = Kind::fallback;
  std::string reason;  // for a fallback: not-sakke, malformed, unknown-payload, limit, encoding
  KeyContext keys;     // a recognised I_MESSAGE: its original key identifiers (the MKI match)
};

// Rewrites one MIKEY carrier value (feature 005). Implemented by the MIKEY library
// (src/mikey/rewriter.hpp) and attached by the pipeline; without one, every carrier keeps its
// previous handling. `value` is the carrier text or bytes as found (base64, binary or hexBinary);
// `cte` is the Content-Transfer-Encoding of a body part, if any. The result is the replacement in
// the same encoding, or nullopt with outcome.kind == fallback.
class MikeyCarrier {
 public:
  virtual ~MikeyCarrier() = default;
  virtual Result<std::optional<std::string>> rewrite(MikeyCarrierKind kind, std::string_view value,
                                                     std::string_view cte, MikeyOutcome& outcome, Context& ctx) = 0;
  // A fallback the carrier decided before decoding (an application/mikey version other than 1).
  virtual void fallback(MikeyCarrierKind kind, std::string_view reason) = 0;
  // A key identifier outside an I_MESSAGE (an XPK-ID in XML, the key-id of an encrypted URI;
  // FR-012): its pseudonym through the one key identifier mapping, counted per purpose tag.
  virtual Result<std::uint32_t> key_identifier(std::uint32_t original, Context& ctx) = 0;
  // An encrypted URI attribute (TS 33.180 §9.3.4.3): structured, or the whole user part mapped.
  virtual void encrypted_uri(bool structured) = 0;
};

// Told about every SIP or tel URI the run rewrites, with its pseudonym (feature 005: the identity
// ledger that resolves hidden-identity UIDs).
class UriObserver {
 public:
  virtual ~UriObserver() = default;
  virtual void on_uri(std::string_view original, std::string_view pseudonym) = 0;
};

struct Context {
  const SipRuleSet& rules;
  AddressMapper& mapper;
  TextOptions options;
  SipCounters& counters;
  MediaSink* media = nullptr;  // feature 004: the media endpoint table, when attached
  XmlBodies* xml = nullptr;    // feature 003: the XML body rewriter, when attached
  MikeyCarrier* mikey = nullptr;  // feature 005: the MIKEY rewriter, when attached
  UriObserver* uris = nullptr;    // feature 005: the identity ledger, when attached
  // Feature 005: the original identity URIs of the message being rewritten (Request-URI, From, To,
  // P-Asserted-Identity, P-Preferred-Identity), collected before its body, for UID resolution.
  const std::vector<std::string>* message_uris = nullptr;
  // Feature 005: the method of the request being rewritten, empty for a response (FR-004 b: an
  // application/mikey body outside the expected requests is counted unexpected-carrier).
  std::string_view method = {};
  // Feature 007: the path segments the HTTP rule set keeps outside XCAP (TS 33.180 §D.2), so
  // that an http(s) URL in an XML document keeps the same segments as a request line.
  const std::vector<std::string>* kept_path_segments = nullptr;
};

// The pseudonym of `value` under `category`, in the value's own text form. nullopt when the
// value does not fit the category's syntax (the caller removes it and counts it malformed).
// Errors are tool failures (for example a pseudonym collision, exit 4).
Result<std::optional<std::string>> map_value(SipCategory category, std::string_view value,
                                             Context& ctx);

// A host that is a domain name or an IP literal (bracketed IPv6 included).
Result<std::optional<std::string>> map_host(std::string_view host, Context& ctx);

}  // namespace mcxanon::sip
