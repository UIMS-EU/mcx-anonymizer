// SPDX-License-Identifier: GPL-3.0-or-later
//
// Rule-driven rewriting of one SIP message: the start line, every header field
// by its rule, the body by its Content-Type (SDP, multipart, emptied), and Content-Length.
// Everything is rendered from parsed structures; nothing unvalidated is copied, and every
// byte of the input is either rewritten or zeroed ("No partial
// pass-through").
#pragma once

#include "sip/message.hpp"
#include "sip/value_map.hpp"

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace mcxanon::sip {

enum class Malformed {
  none,
  header,   // at least one header failed its grammar and was removed (FR-029)
  message,  // the framing, start line or a dialog-defining part failed: the message is zeroed
};

// One span of the input and its replacement. The spans cover input and output contiguously,
// in order (the offset map that drives TCP sequence numbers).
struct OffsetSpan {
  std::size_t orig = 0;
  std::size_t orig_len = 0;
  std::size_t out = 0;
  std::size_t out_len = 0;
  bool verbatim = false;  // copied unchanged
};

struct SipRewriteResult {
  std::string bytes;
  std::vector<OffsetSpan> offset_map;
  Malformed malformed = Malformed::none;
  bool request = false;
  std::string method;    // requests
  int status_code = 0;   // responses
  std::size_t trailing_zeroed = 0;  // datagram bytes after the body (RFC 3261 §18.3)
};

// Rewrites one message: `data` holds exactly the message (a whole datagram, or one message
// framed by frame_stream). A malformed message becomes zeros of its length. Errors are tool
// failures (a pseudonym collision, exit 4).
Result<SipRewriteResult> rewrite_message(std::string_view data, Transport transport, Context& ctx);

// Feature 007: the value of one header field under `rule`, rendered as the SIP rewriter renders it
// inside a message (components, parameters, value lists); nullopt when it does not fit the rule's
// grammar (the caller removes it and counts it malformed), "" when every element was removed. The
// HTTP layer uses it for the 002 grammars of the HTTP rule set. Errors are tool failures.
Result<std::optional<std::string>> rewrite_header_value(const SipHeaderRule& rule, std::string_view value,
                                                        Context& ctx);

// A URI written as a value outside SIP headers (feature 004: MCX RTCP APP fields): the SIP URI
// rules and mappings, so that the same URI gets the same pseudonym as in SIP. nullopt when the
// text is not a URI the rules can keep. Errors are tool failures.
Result<std::optional<std::string>> rewrite_uri_text(std::string_view text, Context& ctx);

// A resource-lists entry URI (feature 003, FR-014a): the URI as rewrite_uri_text does, except
// that a `body` URI header is URL-decoded, rewritten as a body of the type its `Content-Type`
// URI header names (that header rewritten by the Content-Type rule) and re-encoded. `depth` is
// the embedding depth of the document holding the URI (0 for a SIP body); a body inside an
// embedded body is not followed. outcome: "" (no body), "rewritten", or why the body and its
// Content-Type were removed: undecodable, unknown-type, emptied, nested, limit, malformed or an
// XML body reason (encoding, dtd, root, encrypted).
struct EmbeddedUri {
  std::optional<std::string> uri;
  std::string outcome;
};
Result<EmbeddedUri> rewrite_entry_uri(std::string_view text, Context& ctx, std::size_t depth);

// An instance identifier (urn:uuid:…, urn:gsma:imei:…, optionally in angle brackets) mapped as
// the +sip.instance feature tag maps it (feature 003: the MCPTT and MCData client IDs). nullopt
// when it is neither URN form.
Result<std::optional<std::string>> map_instance(std::string_view text, Context& ctx);

// The output offset of an original offset: linear inside verbatim spans; inside a replaced span,
// the end of its replacement (an ACK inside a replaced token).
std::size_t map_offset(const std::vector<OffsetSpan>& map, std::size_t orig);

// The RFC 3261 §21 default reason phrase of a status code, or "-" for codes without one.
std::string_view default_reason(int code);

}  // namespace mcxanon::sip
