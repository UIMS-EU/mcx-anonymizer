// SPDX-License-Identifier: GPL-3.0-or-later
//
// The residual-leak scanner. It is an independent code path: it never uses the
// anonymiser's readers or dissectors, only its own minimal framing walker, and
// it searches raw bytes for every token in every common encoding.
#pragma once

#include "mcxanon/error.hpp"

#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace mcxanon::scan {

// number: decimal digits, matched only when bounded by non-digits on both sides.
// binary: a 32-bit value (SPI, SSRC), matched as 4 big-endian bytes and as digit-bounded
// decimal text.
// key: a 32-bit key identifier (feature 005, TS 33.180 Annex G); bytes: a byte string of 4 or
// more octets (feature 005: UID, RAND, IV, signature).
enum class TokenCategory { mac, ipv4, ipv6, string, number, binary, deny, key, bytes };

struct Token {
  TokenCategory category = TokenCategory::string;
  std::vector<std::uint8_t> value;  // binary for addresses, UTF-8 for strings
  std::string label;                // pseudonym, removed:<cat>#n, input:<cat>#n or deny#<line>
};

struct Hit {
  std::uint64_t frame_number = 0;  // 0 outside any packet
  std::uint64_t file_offset = 0;
  std::string encoding;
  TokenCategory category = TokenCategory::string;
  std::string label;
};

// Feature 005 (FR-018): a hit wholly inside an element that --encrypted passthrough copies as it
// was (a MIKEY carrier or an xenc:EncryptedData subtree, located by the scanner itself).
struct Warning {
  std::uint64_t frame_number = 0;
  std::uint64_t file_offset = 0;
  std::string carrier;  // sdp, body, gktp, mcpc, encrypted-xml
  TokenCategory category = TokenCategory::string;
};

struct ScanOptions {
  bool passthrough = false;  // downgrade hits inside passthrough elements to warnings
};

struct ScanResult {
  std::vector<Hit> hits;
  std::vector<Warning> warnings;  // passthrough only
  std::uint64_t tokens = 0;
  std::uint64_t patterns = 0;
  std::uint64_t unscannable_tokens = 0;
  std::uint64_t suppressed_chance_matches = 0;
  // Unscannable tokens by "<category>/<reason>"; reason short (under 4 bytes) or vocabulary
  // (equal to or contained in a standard term the output keeps).
  std::map<std::string, std::uint64_t> unscannable_by_category;
};

std::string_view to_string(TokenCategory c);

// The search index built from a token list (every encoding of every token).
// Building it is the expensive part of a scan; one index serves many scans.
//
// pseudonyms: the values the anonymiser wrote on purpose (the text pseudonyms of the project
// mapping). A match of a 4-byte token (ipv4, binary) in a text encoding (hex, base64, decimal)
// that lies entirely inside an occurrence of one of them in a scanned capture is a chance
// match (FR-032a): the pseudonym is derived from another value and carries
// nothing of the token. The raw 4-byte form is never covered by this rule.
//
// byte_pseudonyms (feature 007): the byte-string pseudonyms of the mapping (nonce, uid: TLS
// randoms and session ids, MIKEY RANDs), of 8 octets or more, which the output carries as raw
// octets. A raw match of a 4-byte token that lies entirely inside one of them is a chance match
// for the same reason.
class Index {
 public:
  explicit Index(std::vector<Token> tokens, std::vector<std::string> pseudonyms = {},
                 std::vector<std::string> byte_pseudonyms = {});
  Index(Index&&) noexcept;
  Index& operator=(Index&&) noexcept;
  Index(const Index&) = delete;
  Index& operator=(const Index&) = delete;
  ~Index();
  [[nodiscard]] std::size_t size() const;  // number of tokens

  struct Impl;
  [[nodiscard]] const Impl& impl() const { return *impl_; }

 private:
  std::unique_ptr<Impl> impl_;
};

// Scans a capture file (or any file).
Result<ScanResult> scan_file(const std::filesystem::path& path, std::span<const Token> tokens);
Result<ScanResult> scan_file(const std::filesystem::path& path, const Index& index, ScanOptions options = {});
// Scans an open file descriptor from offset 0 (used for the unpublished output).
Result<ScanResult> scan_fd(int fd, std::span<const Token> tokens);
Result<ScanResult> scan_fd(int fd, const Index& index, ScanOptions options = {});
// Scans bytes that are not a capture (reports, summaries): no suppression.
ScanResult scan_bytes(std::span<const std::uint8_t> data, std::span<const Token> tokens);
ScanResult scan_bytes(std::span<const std::uint8_t> data, const Index& index);

// Deny-list file: UTF-8, one entry per line, '#' comments, entries >= 4 characters.
Result<std::vector<Token>> load_deny_list(const std::filesystem::path& path);

// The scanner's own harvest of sensitive values from an input capture: pcapng
// options and blocks outside its allowlist, comments, name resolution records,
// and the addresses of the L2-L4 headers its walker recognises.
Result<std::vector<Token>> harvest_input(const std::filesystem::path& path);

}  // namespace mcxanon::scan
