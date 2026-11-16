// SPDX-License-Identifier: GPL-3.0-or-later
#include "http/session.hpp"

#include "http/body.hpp"
#include "http/h2.hpp"
#include "http/headers.hpp"
#include "http/limits.hpp"
#include "http/message.hpp"
#include "http/target.hpp"

#include <algorithm>
#include <string>

namespace mcxanon::http {

namespace {

using stream::FrameKind;
using stream::Framed;
using stream::Piece;
using stream::RewrittenMessage;

// A TLS record header at the front (RFC 8446 §5.1): content type 20-23, legacy version 3.x.
std::optional<bool> tls_record(std::string_view b) {
  if (b.empty()) return std::nullopt;
  const auto t = static_cast<unsigned char>(b[0]);
  if (t < 20 || t > 23) return false;
  if (b.size() < 2) return std::nullopt;
  if (static_cast<unsigned char>(b[1]) != 3) return false;
  if (b.size() < 5) return std::nullopt;
  const auto len = (static_cast<std::size_t>(static_cast<unsigned char>(b[3])) << 8) | static_cast<unsigned char>(b[4]);
  return static_cast<unsigned char>(b[2]) <= 4 && len > 0 && len <= 16384 + 2048;
}

class WebSession final : public stream::Session {
 public:
  WebSession(Env& env, std::shared_ptr<stream::Connection> c, Start start) : env_(env), conn_(std::move(c)) {
    if (start != Start::http1) {
      mode_ = Mode::h2;
      client_ = start == Start::h2_client;
      h2_ = std::make_unique<H2>(env_, conn_, client_, start == Start::h2_client);
      Counters::bump(env_.counters.streams, "h2");
    } else {
      Counters::bump(env_.counters.streams, "http1");
    }
  }

  Framed frame(std::string_view b) override {
    switch (mode_) {
      case Mode::dead: return {FrameKind::zero_rest, 0};
      case Mode::inner: return inner_->frame(b);
      case Mode::h2: return h2_->frame(b);
      case Mode::tls_pending: {
        const auto t = tls_record(b);
        if (!t) return {FrameKind::more, 0};
        if (*t && env_.tls != nullptr) {
          inner_ = env_.tls->open(conn_);
          if (inner_) {
            mode_ = Mode::inner;
            return inner_->frame(b);
          }
        }
        const auto s = is_start(b);
        if (!s) return {FrameKind::more, 0};
        if (!*s) return dead("tunnel");
        mode_ = Mode::http1;
        return frame(b);
      }
      case Mode::h2_pending: {
        const auto p = is_preface(b);
        if (!p) return {FrameKind::more, 0};
        if (*p) {
          mode_ = Mode::h2;
          conn_->h2_preface = true;
          h2_ = std::make_unique<H2>(env_, conn_, true, true);
          Counters::bump(env_.counters.streams, "h2");
          return h2_->frame(b);
        }
        mode_ = Mode::http1;
        return frame(b);
      }
      case Mode::chunk_drop: return chunk_frame(b);
      case Mode::http1: break;
    }
    return http1_frame(b);
  }

  Result<RewrittenMessage> rewrite(std::string_view m) override {
    switch (mode_) {
      case Mode::inner: return inner_->rewrite(m);
      case Mode::h2: return h2_->rewrite(m);
      case Mode::chunk_drop: {
        RewrittenMessage r;  // a chunk line or the last chunk of a removed body: nothing leaves
        r.spans.push_back(Piece{0, m.size(), 0, 0, false});
        if (pending_.last_chunk) mode_ = Mode::http1;
        return r;
      }
      default: break;
    }
    return http1_rewrite(m);
  }

  std::optional<bool> resync(std::string_view b) override {
    const auto r = is_start(b);
    if (r && *r) mode_ = Mode::http1;
    return r;
  }

  [[nodiscard]] bool text() const override {
    switch (mode_) {
      case Mode::http1:
      case Mode::chunk_drop:
      case Mode::tls_pending:
      case Mode::h2_pending: return true;
      case Mode::inner: return inner_->text();
      case Mode::h2:
      case Mode::dead: return false;
    }
    return false;
  }

 private:
  enum class Mode { http1, chunk_drop, h2_pending, h2, tls_pending, inner, dead };

  struct Pending {
    std::size_t head = 0;
    BodyPlan plan;
    BodyDecision body;
    bool dechunked = false;  // the message holds the whole chunked body
    bool last_chunk = false;
  };

  Framed dead(std::string_view why) {
    Counters::bump(env_.counters.zero_rest, why);
    mode_ = Mode::dead;
    return {FrameKind::zero_rest, 0};
  }

  [[nodiscard]] std::string_view answered_method() const {
    return conn_->methods.empty() ? std::string_view() : std::string_view(conn_->methods.front());
  }

  Framed http1_frame(std::string_view b) {
    Head h;
    switch (parse_head(b, h)) {
      case Parse::more: return {FrameKind::more, 0};
      case Parse::bad: return {FrameKind::invalid, 0};
      case Parse::ok: break;
    }
    pending_ = Pending{};
    pending_.head = h.length;
    pending_.plan = plan_body(h, h.request ? std::string_view() : answered_method());
    if (pending_.plan.kind == BodyPlan::Kind::bad) return {FrameKind::invalid, 0};
    pending_.body = decide_body(h, pending_.plan, env_);
    const auto& d = pending_.body;
    const auto& p = pending_.plan;
    if (d.kind == BodyDecision::Kind::none) return {FrameKind::message, h.length};
    if (d.kind == BodyDecision::Kind::rewrite) {
      if (p.kind == BodyPlan::Kind::length) {
        const auto need = h.length + static_cast<std::size_t>(p.length);
        if (b.size() < need) return {FrameKind::more, 0};
        return {FrameKind::message, need};
      }
      const auto dc = dechunk(b.substr(h.length), kMaxRewrittenBody);
      switch (dc.kind) {
        case Dechunked::Kind::more: return {FrameKind::more, 0};
        case Dechunked::Kind::done:
          pending_.dechunked = true;
          return {FrameKind::message, h.length + dc.encoded};
        case Dechunked::Kind::bad: return {FrameKind::invalid, 0};
        case Dechunked::Kind::over:
          pending_.body.kind = BodyDecision::Kind::remove;
          pending_.body.reason = "limit";
          break;
      }
    }
    // Removed: the head leaves now, the body is dropped as it arrives.
    switch (p.kind) {
      case BodyPlan::Kind::length: return {FrameKind::message, h.length, p.length};
      case BodyPlan::Kind::to_close: return {FrameKind::message, h.length, kDropRest};
      case BodyPlan::Kind::chunked: return {FrameKind::message, h.length, 0};
      default: return {FrameKind::message, h.length};
    }
  }

  Framed chunk_frame(std::string_view b) {
    const auto c = chunk_at(b);
    pending_.last_chunk = false;
    switch (c.kind) {
      case Chunk::Kind::more: return {FrameKind::more, 0};
      case Chunk::Kind::bad: mode_ = Mode::http1; return {FrameKind::invalid, 0};
      case Chunk::Kind::data: return {FrameKind::message, c.line, c.size + 2};
      case Chunk::Kind::last: pending_.last_chunk = true; return {FrameKind::message, c.total};
    }
    return {FrameKind::invalid, 0};
  }

  static RewrittenMessage zeroed() {
    RewrittenMessage r;
    r.zeroed = true;
    return r;
  }

  Result<RewrittenMessage> http1_rewrite(std::string_view m) {
    Head h;
    if (parse_head(m, h) != Parse::ok) return zeroed();
    ++env_.counters.messages;
    std::string out;
    bool to_tls = false;
    bool to_h2 = false;
    bool to_dead = false;
    if (h.request) {
      client_ = true;
      if (!env_.rules.headers.known_method(h.method)) {
        ++env_.counters.malformed;
        Counters::bump(env_.counters.removed_unknown, "http-method", counted_name(h.method));
        return zeroed();
      }
      auto t = rewrite_target(h.target, h.method, env_);
      if (!t) return std::unexpected(t.error());
      if (!*t) {
        ++env_.counters.malformed;
        return zeroed();
      }
      Counters::bump(env_.counters.requests, h.method);
      if (conn_->methods.size() < kMaxPendingMethods) conn_->methods.emplace_back(h.method);
      out = std::string(h.method) + " " + **t + " " + std::string(h.version) + "\r\n";
      for (const auto u : values_of(h, "Upgrade")) {
        if (iequal(u, "h2c")) conn_->upgrade_h2c = true;
        if (iequal(u, "websocket")) conn_->upgrade_websocket = true;
      }
      if (h.method == "CONNECT") {
        to_tls = true;
        Counters::bump(env_.counters.upgrades, "connect");
      } else if (conn_->upgrade_h2c) {
        to_h2 = true;
      }
    } else {
      client_ = false;
      const std::string method(answered_method());
      if (h.status >= 200 || h.status == 101) {
        if (!conn_->methods.empty()) conn_->methods.pop_front();
      }
      Counters::bump(env_.counters.responses, std::to_string(h.status / 100) + "xx");
      out = std::string(h.version) + " " + std::to_string(h.status) + " " + std::string(reason_phrase(h.status)) + "\r\n";
      if (h.status == 101) {
        bool h2c = false;
        bool ws = false;
        for (const auto u : values_of(h, "Upgrade")) {
          h2c = h2c || iequal(u, "h2c");
          ws = ws || iequal(u, "websocket");
        }
        if (h2c) {
          to_h2 = true;
          Counters::bump(env_.counters.upgrades, "h2c");
        } else {
          to_dead = true;
          if (ws) Counters::bump(env_.counters.upgrades, "websocket");
        }
      }
      if (pending_.plan.connect_tunnel) to_tls = true;
    }
    // The body.
    const auto& d = pending_.body;
    std::optional<std::string> body;  // rewritten body, or nullopt
    std::string reason = d.reason;
    if (d.kind == BodyDecision::Kind::rewrite) {
      std::string data;
      std::string_view raw = m.substr(h.length);
      if (pending_.dechunked) {
        const auto dc = dechunk(raw, kMaxRewrittenBody);
        if (dc.kind == Dechunked::Kind::done) data = dc.data;
        raw = data;
      }
      auto r = rewrite_body(d, raw, env_, reason);
      if (!r) return std::unexpected(r.error());
      body = std::move(*r);
    }
    const bool has_body = d.kind != BodyDecision::Kind::none;
    if (has_body) {
      const std::string ct = d.content_type.empty() ? "(none)" : d.content_type;
      if (body) Counters::bump(env_.counters.bodies, ct, d.rule ? to_string(d.rule->handling) : "rewritten");
      else Counters::bump(env_.counters.bodies, ct, "removed:" + reason);
    }
    // The fields.
    bool wrote_length = false;
    for (const auto& f : h.fields) {
      if (iequal(f.name, "Content-Length")) {
        if (wrote_length) continue;
        Counters::bump(env_.counters.headers, "Content-Length", "kept");
        if (has_body) {
          out += std::string(f.name) + ": " + std::to_string(body ? body->size() : 0) + "\r\n";
        } else {
          auto v = rewrite_field(f.name, f.value, env_);
          if (!v) return std::unexpected(v.error());
          if (*v) out += std::string(f.name) + ": " + **v + "\r\n";
        }
        wrote_length = true;
        continue;
      }
      if (has_body && iequal(f.name, "Transfer-Encoding")) {
        Counters::bump(env_.counters.headers, "Transfer-Encoding", "removed");
        continue;
      }
      if (has_body && !body && iequal(f.name, "Content-Encoding")) {
        Counters::bump(env_.counters.headers, "Content-Encoding", "removed");
        continue;
      }
      if (!body && iequal(f.name, "Trailer")) continue;
      auto v = rewrite_field(f.name, f.value, env_);
      if (!v) return std::unexpected(v.error());
      if (*v) out += std::string(f.name) + ": " + **v + "\r\n";
    }
    if (has_body && !wrote_length) out += "Content-Length: " + std::to_string(body ? body->size() : 0) + "\r\n";
    out += "\r\n";
    const std::size_t head_out = out.size();
    if (body) out += *body;
    RewrittenMessage r;
    r.bytes = std::move(out);
    // Linear spans: the output bytes stay spread over the segments that carried the input.
    r.spans.push_back(Piece{0, h.length, 0, head_out, true});
    if (m.size() > h.length || r.bytes.size() > head_out) {
      r.spans.push_back(Piece{h.length, m.size() - h.length, head_out, r.bytes.size() - head_out, true});
    }
    // What follows the message.
    if (d.kind == BodyDecision::Kind::remove && pending_.plan.kind == BodyPlan::Kind::chunked) {
      mode_ = Mode::chunk_drop;
    } else if (to_dead) {
      (void)dead("websocket");
    } else if (to_tls) {
      mode_ = Mode::tls_pending;
    } else if (to_h2) {
      if (client_) {
        mode_ = Mode::h2_pending;
      } else {
        mode_ = Mode::h2;
        h2_ = std::make_unique<H2>(env_, conn_, false, false);
        Counters::bump(env_.counters.streams, "h2");
      }
    }
    return r;
  }

  Env& env_;
  std::shared_ptr<stream::Connection> conn_;
  Mode mode_ = Mode::http1;
  bool client_ = false;
  Pending pending_;
  std::unique_ptr<H2> h2_;
  std::unique_ptr<stream::Session> inner_;
};

}  // namespace

std::unique_ptr<stream::Session> open_web_session(Env& env, std::shared_ptr<stream::Connection> connection, Start start) {
  return std::make_unique<WebSession>(env, std::move(connection), start);
}

std::optional<bool> is_h2_server_start(std::string_view b) {
  // A SETTINGS frame (type 4) on stream 0 whose length is a multiple of 6 (RFC 9113 §6.5).
  if (b.size() < 9) {
    if (!b.empty() && b[0] != 0) return false;
    if (b.size() > 3 && static_cast<unsigned char>(b[3]) != 4) return false;
    return std::nullopt;
  }
  const auto len = (static_cast<std::size_t>(static_cast<unsigned char>(b[0])) << 16) |
                   (static_cast<std::size_t>(static_cast<unsigned char>(b[1])) << 8) | static_cast<unsigned char>(b[2]);
  const bool ack = (static_cast<unsigned char>(b[4]) & 1) != 0;
  const bool zero_stream = b[5] == 0 && b[6] == 0 && b[7] == 0 && b[8] == 0;
  return static_cast<unsigned char>(b[3]) == 4 && zero_stream && len % 6 == 0 && (!ack || len == 0) && len <= 16384;
}

}  // namespace mcxanon::http
