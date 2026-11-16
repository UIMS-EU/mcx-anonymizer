// SPDX-License-Identifier: GPL-3.0-or-later
//
// The scanner's own harvest of HTTP values from the input (feature 007, FR-024):
// by syntax alone, without the anonymiser's parsers or rules. From HTTP/1.1 text
// and h2c header blocks (its own HPACK string reader): Host and request-target identities, the
// credentials of Authorization, Cookie and Set-Cookie, the X-3GPP identity headers, and in query
// strings, forms and JSON the values of the OAuth/OIDC identity and credential parameters; JWTs
// anywhere are decoded (base64url) and their identity claims and signature harvested. The output
// side (web_carriers) decodes JWT segments and Huffman-coded HPACK strings for the search. From TLS
// handshakes in the clear: server names, PSK identities and hints, hello randoms and session ids,
// key exchange values, and from certificates every string, name, serial number, key identifier,
// public key and signature (its own record and DER walk).
#pragma once

#include "mcxanon/scan.hpp"

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace mcxanon::scan::detail {

class WebHarvest {
 public:
  void feed(std::span<const std::uint8_t> payload, const std::vector<std::uint8_t>& direction);
  std::vector<Token> take();

  // Exposed for the unit tests: one text run (HTTP/1.1 lines, forms, JSON, JWTs).
  void text(std::string_view t);

 private:
  struct Dir {
    std::string carry;  // the end of the previous payload (values straddling segments)
    bool h2 = false;
    std::string frames;  // undecoded h2 bytes
    std::string block;   // a header block awaiting END_HEADERS
    int tls = -1;        // -1 undecided, 0 no, 1 TLS records (feature 007, US3)
    std::string records; // undecoded TLS bytes
    std::string hs;      // handshake bytes awaiting a complete message
    bool protected_ = false;
  };
  void tls_records(Dir& d);
  void tls_message(std::uint8_t type, std::string_view body);
  void der_values(std::string_view der, int depth);
  void add_bytes(std::string_view v, const char* what);
  void header(std::string_view name, std::string_view value);
  void target(std::string_view t);
  void params(std::string_view q);
  void identity(std::string_view v);
  void token(std::string_view t);
  void h2_frames(Dir& d);
  void add(std::string_view v, const char* what);

  std::map<std::vector<std::uint8_t>, Dir> dirs_;
  std::vector<Token> tokens_;
  std::set<std::string> seen_;
  std::size_t n_ = 0;
};

// Own decoders (RFC 4648 §5 without padding, RFC 3986 §2.1).
std::optional<std::string> b64url_decode(std::string_view s);
std::optional<std::string> pct_decode(std::string_view s);

}  // namespace mcxanon::scan::detail
