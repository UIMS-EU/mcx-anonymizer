// SPDX-License-Identifier: GPL-3.0-or-later
#include "http/h2.hpp"

#include "http/body.hpp"
#include "http/headers.hpp"
#include "http/hpack.hpp"
#include "http/limits.hpp"
#include "http/message.hpp"
#include "http/target.hpp"

#include <array>
#include <map>
#include <string>
#include <vector>

namespace mcxanon::http {

namespace {

using stream::FrameKind;
using stream::Framed;
using stream::Piece;
using stream::RewrittenMessage;

enum Type : std::uint8_t {
  kData = 0, kHeaders = 1, kPriority = 2, kRstStream = 3, kSettings = 4,
  kPushPromise = 5, kPing = 6, kGoaway = 7, kWindowUpdate = 8, kContinuation = 9,
};
constexpr std::uint8_t kEndStream = 0x1, kEndHeaders = 0x4, kPadded = 0x8, kPriorityFlag = 0x20;

constexpr std::array<std::string_view, 10> kNames{"DATA",          "HEADERS", "PRIORITY", "RST_STREAM",   "SETTINGS",
                                                  "PUSH_PROMISE", "PING",    "GOAWAY",   "WINDOW_UPDATE", "CONTINUATION"};

struct Frame {
  std::size_t at = 0;  // offset in the unit
  std::uint32_t length = 0;
  std::uint8_t type = 0;
  std::uint8_t flags = 0;
  std::uint32_t stream = 0;
  std::string_view payload;
};

std::uint32_t be24(std::string_view b, std::size_t p) {
  return (static_cast<std::uint32_t>(static_cast<unsigned char>(b[p])) << 16) |
         (static_cast<std::uint32_t>(static_cast<unsigned char>(b[p + 1])) << 8) | static_cast<unsigned char>(b[p + 2]);
}
std::uint32_t be32(std::string_view b, std::size_t p) {
  return (static_cast<std::uint32_t>(static_cast<unsigned char>(b[p])) << 24) | (be24(b, p + 1));
}

// The frame at `p`; nullopt when incomplete, length kMaxFrame + 1 when it is over the bound.
std::optional<Frame> frame_at(std::string_view b, std::size_t p) {
  if (b.size() < p + 9) return std::nullopt;
  Frame f;
  f.at = p;
  f.length = be24(b, p);
  f.type = static_cast<std::uint8_t>(b[p + 3]);
  f.flags = static_cast<std::uint8_t>(b[p + 4]);
  f.stream = be32(b, p + 5) & 0x7FFFFFFFu;
  if (f.length > kMaxFrame) {
    f.length = kMaxFrame + 1;
    return f;
  }
  if (b.size() < p + 9 + f.length) return std::nullopt;
  f.payload = b.substr(p + 9, f.length);
  return f;
}

void put_header(std::string& out, std::size_t len, std::uint8_t type, std::uint8_t flags, std::uint32_t stream) {
  out.push_back(static_cast<char>((len >> 16) & 0xFF));
  out.push_back(static_cast<char>((len >> 8) & 0xFF));
  out.push_back(static_cast<char>(len & 0xFF));
  out.push_back(static_cast<char>(type));
  out.push_back(static_cast<char>(flags));
  out.push_back(static_cast<char>((stream >> 24) & 0x7F));
  out.push_back(static_cast<char>((stream >> 16) & 0xFF));
  out.push_back(static_cast<char>((stream >> 8) & 0xFF));
  out.push_back(static_cast<char>(stream & 0xFF));
}

// The payload without its padding (RFC 9113 §6.1, §6.2): (pad length octet count, content).
std::optional<std::pair<std::size_t, std::string_view>> unpad(const Frame& f) {
  std::string_view p = f.payload;
  if ((f.flags & kPadded) == 0) return std::make_pair(std::size_t{0}, p);
  if (p.empty()) return std::nullopt;
  const std::size_t pad = static_cast<unsigned char>(p[0]);
  if (pad + 1 > p.size()) return std::nullopt;
  return std::make_pair(pad, p.substr(1, p.size() - 1 - pad));
}

}  // namespace

struct H2::Impl {
  Env& env;
  std::shared_ptr<stream::Connection> conn;
  bool client = false;
  bool preface = false;  // the connection preface is still to come
  bool dead = false;
  HpackDecoder decoder;

  struct Stream {
    enum class Body { none, rewrite, remove } body = Body::none;
    BodyDecision decision;
    std::string collected;
    bool overflow = false;
    std::string method;
  };
  std::map<std::uint32_t, Stream> streams;

  Stream& stream_of(std::uint32_t id) {
    auto it = streams.find(id);
    if (it == streams.end()) {
      if (streams.size() >= kMaxStreams) streams.erase(streams.begin());
      it = streams.emplace(id, Stream{}).first;
    }
    return it->second;
  }

  Framed zero_rest(std::string_view why) {
    dead = true;
    Counters::bump(env.counters.zero_rest, why);
    return {FrameKind::zero_rest, 0};
  }

  // Research R14: a unit is one frame, or a header block with its CONTINUATION frames. A body
  // that is rewritten is collected in its stream across units (bounded) and leaves with the
  // stream's END_STREAM frame.
  Framed frame(std::string_view b) {
    if (dead) return {FrameKind::zero_rest, 0};
    if (preface) {
      const auto p = is_preface(b);
      if (!p) return {FrameKind::more, 0};
      if (!*p) return zero_rest("h2-preface");
      preface = false;  // a verbatim span is not passed to rewrite()
      return {FrameKind::verbatim, kPreface.size()};
    }
    auto f = frame_at(b, 0);
    if (!f) return {FrameKind::more, 0};
    if (f->length > kMaxFrame) return zero_rest("h2-frame-size");
    std::size_t end = 9 + f->length;
    if ((f->type == kHeaders || f->type == kPushPromise) && (f->flags & kEndHeaders) == 0) {
      for (;;) {
        auto c = frame_at(b, end);
        if (!c) return end > kMaxHeaderBlock + 9 ? zero_rest("h2-header-block") : Framed{FrameKind::more, 0};
        if (c->length > kMaxFrame || c->type != kContinuation || c->stream != f->stream) return zero_rest("h2-continuation");
        end += 9 + c->length;
        if (end > kMaxHeaderBlock + 9) return zero_rest("h2-header-block");
        if ((c->flags & kEndHeaders) != 0) break;
      }
      return {FrameKind::message, end};
    }
    return {FrameKind::message, end};
  }

  Result<std::optional<std::string>> rewrite_block(std::uint32_t id, std::string_view block, bool end_stream,
                                                   bool push) {
    auto list = decoder.decode(block);
    if (!list) return std::optional<std::string>{};
    ++env.counters.header_blocks;
    ++env.counters.messages;
    Stream& s = stream_of(id);
    std::vector<HeaderField> out;
    Head head;  // for the body decision: content-type and content-encoding
    std::vector<std::pair<std::string, std::string>> kept;
    kept.reserve(list->size());  // head.fields holds views into its elements
    std::string method;
    std::string path;
    bool request = false;
    int status = 0;
    for (const auto& f : *list) {
      if (f.name.empty()) continue;
      if (f.name[0] == ':') {
        if (f.name == ":method") {
          request = true;
          method = f.value;
          if (!env.rules.headers.known_method(f.value)) return std::optional<std::string>{};
          out.push_back(f);
        } else if (f.name == ":scheme") {
          if (f.value == "http" || f.value == "https") out.push_back(f);
        } else if (f.name == ":authority") {
          auto a = rewrite_authority(f.value, env);
          if (!a) return std::unexpected(a.error());
          if (*a) out.push_back({f.name, **a});
        } else if (f.name == ":path") {
          path = f.value;
        } else if (f.name == ":status") {
          if (f.value.size() == 3 && std::all_of(f.value.begin(), f.value.end(), [](char c) { return c >= '0' && c <= '9'; })) {
            status = std::stoi(f.value);
            out.push_back(f);
          }
        } else {
          Counters::bump(env.counters.removed_unknown, "http-header", counted_name(f.name));
        }
        continue;
      }
      kept.emplace_back(f.name, f.value);
      head.fields.push_back({kept.back().first, kept.back().second});
    }
    if (!path.empty()) {
      auto t = rewrite_target(path, method, env);
      if (!t) return std::unexpected(t.error());
      if (!*t) return std::optional<std::string>{};
      out.push_back({":path", **t});
    }
    if (request) {
      Counters::bump(env.counters.requests, method);
      s.method = method;
    } else if (status != 0) {
      Counters::bump(env.counters.responses, std::to_string(status / 100) + "xx");
    }
    // The body decision (FR-009): framed by END_STREAM, so no length bound applies here.
    BodyPlan plan;
    plan.kind = end_stream || push ? BodyPlan::Kind::none : BodyPlan::Kind::chunked;
    head.request = request;
    s.decision = decide_body(head, plan, env);
    s.body = s.decision.kind == BodyDecision::Kind::rewrite ? Stream::Body::rewrite
             : s.decision.kind == BodyDecision::Kind::remove ? Stream::Body::remove
                                                             : Stream::Body::none;
    s.collected.clear();
    s.overflow = false;
    if (s.body == Stream::Body::remove) {
      Counters::bump(env.counters.bodies, s.decision.content_type.empty() ? "(none)" : s.decision.content_type,
                     "removed:" + s.decision.reason);
    }
    for (const auto& [name, value] : kept) {
      if (iequal(name, "content-length") && s.body != Stream::Body::none) {
        Counters::bump(env.counters.headers, "Content-Length", "removed");  // P13
        continue;
      }
      if (s.body == Stream::Body::remove && iequal(name, "content-encoding")) continue;
      auto v = rewrite_field(name, value, env);
      if (!v) return std::unexpected(v.error());
      if (*v) out.push_back({name, **v});
    }
    return std::optional<std::string>(hpack_encode(out));
  }

  // A header block in HEADERS (or PUSH_PROMISE) + CONTINUATION frames of at most 16 384 octets.
  static void emit_block(std::string& out, std::uint8_t type, std::uint8_t flags, std::uint32_t stream,
                         std::string_view prefix, std::string_view block) {
    std::string first(prefix);
    const std::size_t room = kOutFrame - first.size();
    first.append(block.substr(0, room));
    std::string_view rest = block.size() > room ? block.substr(room) : std::string_view();
    const std::uint8_t keep = flags & static_cast<std::uint8_t>(~(kPadded | kEndHeaders));
    put_header(out, first.size(), type, static_cast<std::uint8_t>(keep | (rest.empty() ? kEndHeaders : 0)), stream);
    out += first;
    while (!rest.empty()) {
      const auto part = rest.substr(0, kOutFrame);
      rest.remove_prefix(part.size());
      put_header(out, part.size(), kContinuation, rest.empty() ? kEndHeaders : 0, stream);
      out += part;
    }
  }

  static void emit_data(std::string& out, std::uint32_t stream, std::string_view body, bool end_stream) {
    do {
      const auto part = body.substr(0, kOutFrame);
      body.remove_prefix(part.size());
      put_header(out, part.size(), kData, body.empty() && end_stream ? kEndStream : 0, stream);
      out += part;
    } while (!body.empty());
  }

  Result<RewrittenMessage> rewrite(std::string_view m) {
    RewrittenMessage r;
    if (preface) {
      preface = false;
      r.bytes.assign(m);
      r.spans.push_back(Piece{0, m.size(), 0, m.size(), true});
      return r;
    }
    std::string out;
    std::size_t p = 0;
    while (p < m.size()) {
      auto f = frame_at(m, p);
      if (!f || f->length > kMaxFrame) break;
      p += 9 + f->length;
      Counters::bump(env.counters.h2_frames, f->type < kNames.size() ? kNames[f->type] : std::string_view("unknown"));
      switch (f->type) {
        case kHeaders:
        case kPushPromise: {
          // The block: this frame's fragment and the CONTINUATION fragments of the unit.
          auto up = unpad(*f);
          if (!up) return dead_unit();
          std::string_view frag = up->second;
          std::string prefix;
          std::uint32_t promised = 0;
          if (f->type == kHeaders && (f->flags & kPriorityFlag) != 0) {
            if (frag.size() < 5) return dead_unit();
            prefix.assign(frag.substr(0, 5));
            frag.remove_prefix(5);
          }
          if (f->type == kPushPromise) {
            if (frag.size() < 4) return dead_unit();
            prefix.assign(frag.substr(0, 4));
            promised = be32(frag, 0) & 0x7FFFFFFFu;
            frag.remove_prefix(4);
          }
          std::string block(frag);
          if ((f->flags & kEndHeaders) == 0) {
            while (p < m.size()) {
              auto c = frame_at(m, p);
              if (!c) return dead_unit();
              p += 9 + c->length;
              Counters::bump(env.counters.h2_frames, "CONTINUATION");
              block.append(c->payload);
              if ((c->flags & kEndHeaders) != 0) break;
            }
          }
          const bool push = f->type == kPushPromise;
          auto nb = rewrite_block(push ? promised : f->stream, block, (f->flags & kEndStream) != 0, push);
          if (!nb) return std::unexpected(nb.error());
          if (!*nb) return dead_unit();
          emit_block(out, f->type, f->flags, f->stream, prefix, **nb);
          break;
        }
        case kData: {
          auto up = unpad(*f);
          if (!up) return dead_unit();
          const bool end = (f->flags & kEndStream) != 0;
          auto it = streams.find(f->stream);
          if (it == streams.end() || it->second.body != Stream::Body::rewrite || it->second.overflow) {
            put_header(out, 0, kData, static_cast<std::uint8_t>(f->flags & kEndStream), f->stream);  // removed
            break;
          }
          auto& s = it->second;
          s.collected.append(up->second);
          if (s.collected.size() > kMaxRewrittenBody) {
            Counters::bump(env.counters.bodies, s.decision.content_type, "removed:limit");
            s.collected.clear();
            s.overflow = true;
            put_header(out, 0, kData, static_cast<std::uint8_t>(f->flags & kEndStream), f->stream);
            break;
          }
          if (!end) break;  // the rewritten body leaves with the stream's last DATA frame (P13)
          std::string reason;
          auto body = rewrite_body(s.decision, s.collected, env, reason);
          if (!body) return std::unexpected(body.error());
          const auto ct = s.decision.content_type.empty() ? std::string("(none)") : s.decision.content_type;
          if (*body) {
            Counters::bump(env.counters.bodies, ct, to_string(s.decision.rule->handling));
            emit_data(out, f->stream, **body, true);
          } else {
            Counters::bump(env.counters.bodies, ct, "removed:" + reason);
            put_header(out, 0, kData, kEndStream, f->stream);
          }
          s.collected.clear();
          s.body = Stream::Body::none;
          break;
        }
        case kSettings: {
          std::string pl(f->payload);
          for (std::size_t i = 0; i + 6 <= pl.size(); i += 6) {
            const unsigned id = (static_cast<unsigned>(static_cast<unsigned char>(pl[i])) << 8) |
                                static_cast<unsigned>(static_cast<unsigned char>(pl[i + 1]));
            if (id < 1 || id > 6) std::fill(pl.begin() + static_cast<std::ptrdiff_t>(i), pl.begin() + static_cast<std::ptrdiff_t>(i + 6), '\0');
          }
          put_header(out, pl.size(), f->type, f->flags, f->stream);
          out += pl;
          break;
        }
        case kPing:
          put_header(out, f->length, f->type, f->flags, f->stream);
          out.append(f->length, '\0');
          break;
        case kGoaway: {
          put_header(out, f->length, f->type, f->flags, f->stream);
          const std::size_t keep = std::min<std::size_t>(8, f->length);
          out.append(f->payload.substr(0, keep));
          out.append(f->length - keep, '\0');  // debug data
          break;
        }
        case kPriority:
        case kRstStream:
        case kWindowUpdate:
          put_header(out, f->length, f->type, f->flags, f->stream);
          out.append(f->payload);
          break;
        default:  // unknown frame types and a stray CONTINUATION: header kept, payload zeroed
          put_header(out, f->length, f->type, f->flags, f->stream);
          out.append(f->length, '\0');
          break;
      }
    }
    r.bytes = std::move(out);
    r.spans.push_back(Piece{0, m.size(), 0, r.bytes.size(), true});
    return r;
  }

  RewrittenMessage dead_unit() {
    dead = true;
    ++env.counters.h2_undecodable;
    Counters::bump(env.counters.zero_rest, "h2-header-block");
    RewrittenMessage r;
    r.zeroed = true;
    return r;
  }
};

H2::H2(Env& env, std::shared_ptr<stream::Connection> connection, bool client, bool preface)
    : impl_(std::make_unique<Impl>(Impl{env, std::move(connection), client, preface, false, {}, {}})) {}
H2::~H2() = default;

stream::Framed H2::frame(std::string_view b) { return impl_->frame(b); }
Result<stream::RewrittenMessage> H2::rewrite(std::string_view m) { return impl_->rewrite(m); }

}  // namespace mcxanon::http
