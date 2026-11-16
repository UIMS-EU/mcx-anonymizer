// SPDX-License-Identifier: GPL-3.0-or-later
//
// HTTP/2 in the clear (h2c, RFC 9113; feature 007): one direction's frames. Frame
// headers, stream ids, flags, SETTINGS, PRIORITY, WINDOW_UPDATE, RST_STREAM and GOAWAY codes are
// kept; PING and GOAWAY opaque data and padding are zeroed; unknown frame types keep their header
// with zeroed payload. Header blocks are decoded with HPACK (RFC 7541) and re-encoded as literals
// without indexing and without Huffman coding, so the receiver's table stays empty and consistent
// with the output. Bodies follow the HTTP/1.1 body rules per stream. A block that does not decode
// zeroes the rest of the direction.
#pragma once

#include "mcxanon/error.hpp"

#include "http/env.hpp"
#include "stream/connection.hpp"
#include "stream/tcp.hpp"

#include <memory>
#include <string_view>

namespace mcxanon::http {

class H2 {
 public:
  // `preface`: the direction starts with the client connection preface.
  H2(Env& env, std::shared_ptr<stream::Connection> connection, bool client, bool preface);
  H2(const H2&) = delete;
  H2& operator=(const H2&) = delete;
  ~H2();
  stream::Framed frame(std::string_view b);
  Result<stream::RewrittenMessage> rewrite(std::string_view m);

  struct Impl;

 private:
  std::unique_ptr<Impl> impl_;
};

}  // namespace mcxanon::http
