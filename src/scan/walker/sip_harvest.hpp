// SPDX-License-Identifier: GPL-3.0-or-later
//
// The scanner's own SIP/SDP harvester (FR-031): a minimal tokenizer that extracts
// identity values from the L4 payloads of the input by syntax alone. It shares no code with the
// anonymiser's SIP parsers and does not read the rule set.
#pragma once

#include "mcxanon/scan.hpp"

#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace mcxanon::scan::detail {

class SipHarvest {
 public:
  // One UDP or TCP payload. For TCP, the last 4 KiB of the same direction are prepended, so
  // values that straddle segment boundaries are found.
  void feed(std::span<const std::uint8_t> payload, const std::vector<std::uint8_t>& direction, bool tcp);
  std::vector<Token> take();
  // Feature 008 (FR-001): values read up to the end of a TCP payload that were dropped because
  // the next payload of the direction gave the whole value.
  [[nodiscard]] std::uint64_t fragments() const { return fragments_; }

  // Values found by the media harvester (feature 004): a text value (harvested whole when it is
  // printable, and for the URIs it contains) and a 32-bit SSRC (a binary token).
  void text_value(std::string_view v, const char* what);
  void ssrc(std::uint32_t v);
  // A MIKEY message found in the input (feature 005): its identities, key identifiers and the
  // byte strings the anonymiser replaces. Kept ciphertext gives no token.
  void mikey(std::span<const std::uint8_t> message);

 private:
  void scan(std::string_view text);
  void header_line(std::string_view line);
  void sdp_line(std::string_view line);
  void key_references(std::string_view text);
  void uris(std::string_view text);
  void params(std::string_view text);
  void display_names(std::string_view text);
  void host(std::string_view h);
  void add(TokenCategory c, std::string_view v, const char* what);
  void add_bytes(TokenCategory c, const std::vector<std::uint8_t>& v, const char* what);

  // Feature 008 (FR-001): a value whose source text ends at the end of a TCP text may be cut by
  // the segment boundary. It is kept pending for its direction and, in the next payload of that
  // direction (whose text starts with this one's tail), dropped once a value read from the same
  // position is seen whole; otherwise it is added as a token after all (fail-closed).
  enum class Kind : std::uint8_t { value, host };
  struct Fragment {
    Kind kind = Kind::value;
    TokenCategory category = TokenCategory::string;
    std::string value;
    const char* what = "";
    std::size_t start = 0;  // in the text it was read from; then from the end of that text (back)
    bool settled = false;   // resolved or superseded in the current payload
  };
  // True when `src` (a view into the current TCP text) runs to the text's end: the value is kept
  // pending instead of being added. Every call also settles the pending fragments of the previous
  // payload that start where `src` starts.
  bool fragment(std::string_view src, Kind kind, TokenCategory c, std::string_view value, const char* what);
  void materialise(const Fragment& f);

  std::vector<Token> tokens_;
  std::set<std::pair<int, std::vector<std::uint8_t>>> seen_;
  std::map<std::vector<std::uint8_t>, std::string> carry_;
  std::size_t n_ = 0;
  std::size_t budget_ = 0;  // token count at which the current payload stops harvesting
  bool nested_ = false;     // scanning a body embedded in an entry URI (not followed further)
  bool tcp_ = false;        // the payload being scanned is a TCP segment (it may end mid-value)
  std::string_view text_;   // the text of the current payload (carry and segment)
  std::size_t old_end_ = 0; // where the previous payload of the direction ended in text_
  std::vector<Fragment> old_;    // pending fragments of the previous payload, start in text_
  std::vector<Fragment> fresh_;  // fragments of the current payload
  std::map<std::vector<std::uint8_t>, std::vector<Fragment>> pending_;  // per direction, start = back
  std::uint64_t fragments_ = 0;
};

}  // namespace mcxanon::scan::detail
