// SPDX-License-Identifier: GPL-3.0-or-later
//
// MIME multipart bodies (RFC 2046 §5.1.1): parsing into parts with their header
// fields. Rendering and the per-part rules live in the rewriter.
#pragma once

#include "sip/message.hpp"

#include <optional>
#include <string_view>
#include <vector>

namespace mcxanon::sip {

struct BodyPart {
  std::vector<HeaderField> headers;  // spans relative to the multipart body
  std::string_view body;
};

struct MultipartBody {
  std::vector<BodyPart> parts;
  bool preamble = false;  // text before the first delimiter (removed on output)
  bool epilogue = false;  // text after the close delimiter (removed on output)
};

// RFC 2046 §5.1.1: boundary := 0*69<bchars> bcharsnospace.
bool is_boundary(std::string_view b);

// nullopt when the body does not follow the grammar, has more than kMaxParts parts, or a part
// header section cannot be parsed.
std::optional<MultipartBody> parse_multipart(std::string_view body, std::string_view boundary);

}  // namespace mcxanon::sip
