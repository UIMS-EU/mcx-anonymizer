// SPDX-License-Identifier: GPL-3.0-or-later
#include "tls/session.hpp"

#include "tls/handshake.hpp"
#include "tls/limits.hpp"

#include <string>

namespace mcxanon::tls {

namespace {

using stream::FrameKind;
using stream::Framed;
using stream::Piece;
using stream::RewrittenMessage;

constexpr std::uint8_t kCcs = 20, kAlert = 21, kHandshake = 22;

std::size_t u16(std::string_view b, std::size_t p) {
  return (static_cast<std::size_t>(static_cast<unsigned char>(b[p])) << 8) | static_cast<unsigned char>(b[p + 1]);
}
std::size_t u24(std::string_view b, std::size_t p) {
  return (static_cast<std::size_t>(static_cast<unsigned char>(b[p])) << 16) | u16(b, p + 1);
}

// The end of the complete messages at the front of `hs`.
std::size_t aligned(std::string_view hs) {
  std::size_t p = 0;
  while (p + 4 <= hs.size()) {
    const auto len = u24(hs, p + 1);
    if (p + 4 + len > hs.size()) break;
    p += 4 + len;
  }
  return p;
}

class TlsSession final : public stream::Session {
 public:
  TlsSession(Env& env, std::shared_ptr<stream::Connection> c) : env_(env), conn_(std::move(c)) { ++env_.counters.connections; }

  Framed frame(std::string_view b) override {
    if (dead_) return {FrameKind::zero_rest, 0};
    std::size_t p = 0;
    std::string hs;
    for (;;) {
      if (b.size() < p + 5) return more(p);
      const auto type = static_cast<std::uint8_t>(b[p]);
      const auto* rule = env_.rules.find_record(type);
      if (rule == nullptr) return give_up("bad-record");
      if (b[p + 1] != 3 || static_cast<unsigned char>(b[p + 2]) > 4) return give_up("bad-version");
      const auto len = u16(b, p + 3);
      if (len > kMaxRecord) return give_up("record-size");
      const bool in_unit = p > 0;
      if (in_unit && type != kHandshake) return give_up("interleaved-handshake");
      if (b.size() < p + 5 + len) return more(p + 5 + len);
      if (type != kHandshake || protected_) return {FrameKind::message, 5 + len};
      hs.append(b.substr(p + 5, len));
      p += 5 + len;
      if (aligned(hs) == hs.size()) return {FrameKind::message, p};
      if (p > kMaxHandshakeUnit) return give_up("handshake-unit");
    }
  }

  Result<RewrittenMessage> rewrite(std::string_view m) override {
    RewrittenMessage r;
    const auto type = static_cast<std::uint8_t>(m[0]);
    const auto* rule = env_.rules.find_record(type);
    Counters::bump(env_.counters.records, rule != nullptr ? rule->name : "unknown");
    if (type == kHandshake && !protected_) {
      std::string hs;
      for (std::size_t p = 0; p + 5 <= m.size(); p += 5 + u16(m, p + 3)) hs.append(m.substr(p + 5, u16(m, p + 3)));
      std::string out_hs;
      for (std::size_t p = 0; p + 4 <= hs.size();) {
        const auto len = u24(hs, p + 1);
        auto msg = rewrite_handshake(static_cast<std::uint8_t>(hs[p]), std::string_view(hs).substr(p + 4, len), *conn_, env_);
        if (!msg) return std::unexpected(msg.error());
        out_hs += *msg;
        p += 4 + len;
      }
      // R16, P14: re-fragmented into records of at most 2^14 octets with the first version.
      std::string_view rest = out_hs;
      do {
        const auto part = rest.substr(0, kOutRecord);
        rest.remove_prefix(part.size());
        r.bytes.push_back(static_cast<char>(kHandshake));
        r.bytes.append(m.substr(1, 2));
        r.bytes.push_back(static_cast<char>(part.size() >> 8));
        r.bytes.push_back(static_cast<char>(part.size() & 0xFF));
        r.bytes.append(part);
      } while (!rest.empty());
      r.spans.push_back(Piece{0, m.size(), 0, r.bytes.size(), true});
      return r;
    }
    r.bytes.assign(m.substr(0, 5));
    const auto body = m.substr(5);
    const bool keep = rule != nullptr && rule->action == TlsRecordAction::keep && !protected_;
    if (keep) {
      r.bytes.append(body);
      if (type == kAlert && body.size() == 2) {
        Counters::bump(env_.counters.alerts, std::to_string(static_cast<unsigned char>(body[0])) + "/" +
                                                 std::to_string(static_cast<unsigned char>(body[1])));
      }
    } else {
      r.bytes.append(body.size(), '\0');
      ++env_.counters.protected_zeroed;
    }
    // TLS 1.2: later records of this direction are protected. TLS 1.3 (RFC 8446 §5, §D.4): a
    // change_cipher_spec is a compatibility record; protection shows as application_data records.
    if (type == kCcs && conn_->tls_version.value_or(0x0303) < 0x0304) protected_ = true;
    r.spans.push_back(Piece{0, m.size(), 0, r.bytes.size(), true});
    return r;
  }

  std::optional<bool> resync(std::string_view) override { return false; }
  [[nodiscard]] bool text() const override { return false; }

 private:
  Framed more(std::size_t need) {
    if (need > kMaxHandshakeUnit + kMaxRecord + 5) return give_up("handshake-unit");
    return {FrameKind::more, 0};
  }
  Framed give_up(std::string_view why) {
    dead_ = true;
    Counters::bump(env_.counters.zero_rest, why);
    return {FrameKind::zero_rest, 0};
  }

  Env& env_;
  std::shared_ptr<stream::Connection> conn_;
  bool protected_ = false;
  bool dead_ = false;
};

}  // namespace

std::unique_ptr<stream::Session> open_tls_session(Env& env, std::shared_ptr<stream::Connection> connection) {
  return std::make_unique<TlsSession>(env, std::move(connection));
}

std::optional<bool> is_record_start(std::string_view b) {
  if (b.empty()) return std::nullopt;
  const auto t = static_cast<unsigned char>(b[0]);
  if (t < 20 || t > 23) return false;
  if (b.size() < 5) return b.size() < 2 || b[1] == 3 ? std::nullopt : std::optional<bool>(false);
  const auto len = u16(b, 3);
  return b[1] == 3 && static_cast<unsigned char>(b[2]) <= 4 && len > 0 && len <= kMaxRecord;
}

}  // namespace mcxanon::tls
