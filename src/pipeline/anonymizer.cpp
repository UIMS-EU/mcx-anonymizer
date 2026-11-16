// SPDX-License-Identifier: GPL-3.0-or-later
#include "pipeline/anonymizer.hpp"

#include "xml/sip_bodies.hpp"

#include "media/endpoints.hpp"
#include "media/msrp.hpp"
#include "http/message.hpp"
#include "http/session.hpp"
#include "tls/session.hpp"
#include "stream/connection.hpp"
#include "media/rtcp.hpp"
#include "media/rtp.hpp"
#include "mikey/rewriter.hpp"

#include "bytes/endian.hpp"
#include "capture/pcap.hpp"
#include "capture/pcapng.hpp"
#include "pipeline/hold_queue.hpp"
#include "pipeline/mapper_adapter.hpp"
#include "policy/decide.hpp"
#include "pseudo/project_impl.hpp"
#include "pseudo/pseudonymiser.hpp"
#include "sip/message.hpp"
#include "sip/rewrite.hpp"
#include "sip/stream_framing.hpp"
#include "stream/fragments.hpp"
#include "stream/tcp.hpp"

#include <algorithm>
#include <iterator>
#include <map>
#include <optional>
#include <variant>

namespace mcxanon {
namespace {

__extension__ typedef __int128 i128;  // 64-bit timestamps times units per second

// Timestamp units per second for an if_tsresol value (pcapng-06 §4.2).
std::optional<i128> units_per_second(std::uint8_t tsresol) {
  const unsigned n = tsresol & 0x7Fu;
  if ((tsresol & 0x80u) != 0) return n <= 62 ? std::optional<i128>(i128{1} << n) : std::nullopt;
  if (n > 18) return std::nullopt;
  i128 v = 1;
  for (unsigned i = 0; i < n; ++i) v *= 10;
  return v;
}

// The time shift in units, or an error when it is not an exact multiple.
Result<i128> shift_in_units(std::int64_t shift_ns, std::uint8_t tsresol) {
  const auto ups = units_per_second(tsresol);
  if (!ups) return fail(ErrorCode::input, "unsupported timestamp resolution in the capture");
  const i128 num = static_cast<i128>(shift_ns) * *ups;
  if (num % 1000000000 != 0) {
    return fail(ErrorCode::usage,
                "the time shift is not a whole number of the capture's timestamp units");
  }
  return num / 1000000000;
}

struct Iface {
  InterfaceInfo info;
  i128 shift = 0;  // in units
};

// The media classifier tag (feature 005): what the dissector carries from
// the classification of a datagram to its rewrite, packed into the hook's int. The low byte is the
// endpoint kind + 1, then the secure and by-source flags, then the key context id (at most
// media::kMaxKeyContexts).
struct MediaTag {
  media::Kind kind = media::Kind::rtp;
  bool secure = false;
  bool by_source = false;
  std::uint32_t keys = 0;

  static constexpr int kSecure = 0x100;
  static constexpr int kBySource = 0x200;
  static constexpr int kKeysShift = 12;
  static_assert(media::kMaxKeyContexts < (std::size_t{1} << 18));

  static MediaTag of(const media::Lookup& l) { return {l.kind, l.secure, l.matched == media::Match::src, l.keys}; }
  [[nodiscard]] int pack() const {
    return (static_cast<int>(kind) + 1) | (secure ? kSecure : 0) | (by_source ? kBySource : 0) |
           static_cast<int>(keys << kKeysShift);
  }
  static MediaTag unpack(int t) {
    return {static_cast<media::Kind>((t & 0xFF) - 1), (t & kSecure) != 0, (t & kBySource) != 0,
            static_cast<std::uint32_t>(t) >> kKeysShift};
  }
};

bool recognise_sip(ByteView payload) {
  return sip::is_start_line(std::string_view(reinterpret_cast<const char*>(payload.data()), payload.size()));
}

std::optional<bool> stream_start(std::string_view d) { return sip::stream_start(d); }

stream::Framed stream_frame(std::string_view d) {
  const auto f = sip::stream_frame(d);
  switch (f.kind) {
    case sip::StreamFrame::Kind::more: return {stream::FrameKind::more, f.len};
    case sip::StreamFrame::Kind::message: return {stream::FrameKind::message, f.len};
    case sip::StreamFrame::Kind::verbatim: return {stream::FrameKind::verbatim, f.len};
    case sip::StreamFrame::Kind::oversized: return {stream::FrameKind::oversized, f.len};
    case sip::StreamFrame::Kind::invalid: break;
  }
  return {stream::FrameKind::invalid, 0};
}

stream::Framed msrp_frame(std::string_view d) {
  const auto f = media::msrp_frame(d);
  switch (f.kind) {
    case media::MsrpFrameKind::more: return {stream::FrameKind::more, 0};
    case media::MsrpFrameKind::message: return {stream::FrameKind::message, f.len};
    case media::MsrpFrameKind::invalid: break;
  }
  return {stream::FrameKind::invalid, 0};
}

std::uint64_t micros(i128 units, i128 units_per_second) {
  if (units < 0 || units_per_second <= 0) return 0;
  return static_cast<std::uint64_t>(units * 1000000 / units_per_second);
}

std::size_t bytes_of(const std::vector<Record>& v) {
  std::size_t n = 0;
  for (const auto& r : v) n += r.bytes.size();
  return n;
}

// Research R13: a rewritten SIP message may grow, so every output interface accepts at least
// 262,144 bytes per packet; 0 (no limit) stays 0.
constexpr std::uint32_t kMinSnaplen = 262144;
std::uint32_t output_snaplen(std::uint32_t snaplen) {
  return snaplen == 0 ? 0 : std::max(snaplen, kMinSnaplen);
}

// The original length of an output packet: a complete input packet stays complete at its new
// length; a truncated one keeps the 001 rule.
std::uint32_t output_origlen(bool truncated_by_drop, std::uint32_t in_caplen, std::uint32_t in_origlen,
                             std::uint32_t out_caplen) {
  if (truncated_by_drop) return out_caplen;
  if (in_caplen >= in_origlen) return out_caplen;
  return std::max(in_origlen, out_caplen);
}

}  // namespace

CaptureFormat resolve_output_format(OutputFormat requested, CaptureFormat input) {
  switch (requested) {
    case OutputFormat::pcap: return CaptureFormat::pcap;
    case OutputFormat::pcapng: return CaptureFormat::pcapng;
    case OutputFormat::same: return input;
  }
  return input;
}

struct Anonymizer::Impl {
  Impl(Project::Impl& p, const AnonymizeOptions& o, CaptureFormat in, RuleSet r, SipRuleSet sr,
       MediaRuleSet mr, XmlRuleSet xr, MikeyRuleSet kr, HttpRuleSet hr, TlsRuleSet tr)
      : project(p), options(o), rules(std::move(r)), policy(rules), sip_rules(std::move(sr)),
        media_rules(std::move(mr)), xml_rules(std::move(xr)), mikey_rules(std::move(kr)), http_rules(std::move(hr)),
        tls_rules(std::move(tr)),
        pseudonymiser(p.secret, p.mapping,
                      PseudonymiserOptions{o.prefix_preserving, o.ephemeral_lo, o.ephemeral_hi}),
        mapper(pseudonymiser),
        streams(stream::SipFns{stream_start, stream_frame,
                               [this](std::string_view m) { return rewrite_sip_stream(m); }},
                o.payload == PayloadMode::drop,
                stream::SipFns{media::msrp_is_start, msrp_frame,
                               [this](std::string_view m) { return rewrite_msrp_stream(m); }},
                [this](const Bytes& key) { return msrp_direction(key); },
                stream::WebFns{[this](const Bytes& dir, const Bytes& rev, std::string_view b, bool syn, bool resync) {
                  return web_open(dir, rev, b, syn, resync);
                }}) {
    sip_options.pseudonymise_ports = o.pseudonymise_ephemeral_ports;
    if (o.time_shift) sip_options.time_shift_s = o.time_shift->count() / 1000000000;
    hook.recognise = &recognise_sip;
    hook.classify_media = &classify_media;
    hook.classify_media_ctx = this;
    summary.media.ruleset_name = media_rules.name;
    summary.media.ruleset_version = media_rules.version;
    summary.media.ruleset_digest = media_rules.digest;
    summary.xml.ruleset_name = xml_rules.name;
    summary.xml.ruleset_version = xml_rules.version;
    summary.mikey.ruleset_name = mikey_rules.name;
    summary.mikey.ruleset_version = mikey_rules.version;
    summary.mikey.ruleset_digest = mikey_rules.digest;
    summary.xml.ruleset_digest = xml_rules.digest;
    for (const auto& seg : http_rules.paths) kept_segments.push_back(seg.segment);
    summary.http.ruleset_name = http_rules.name;
    summary.http.ruleset_version = http_rules.version;
    summary.http.ruleset_digest = http_rules.digest;
    http_sctx.emplace(sip::Context{sip_rules, mapper, sip_options, http_sip_counters, nullptr, &xml_bodies,
                                   &mikey_rewriter, &mikey_rewriter});
    http_sctx->kept_path_segments = &kept_segments;
    tls_env.emplace(tls::Env{tls_rules, *http_sctx, summary.tls.counters});
    http_env.emplace(http::Env{http_rules, *http_sctx, summary.http.counters, &tls_opener});
    summary.tls.ruleset_name = tls_rules.name;
    summary.tls.ruleset_version = tls_rules.version;
    summary.tls.ruleset_digest = tls_rules.digest;
    for (const auto& [name, ns] : xml_rules.namespaces) summary.xml.known_namespaces.insert(name);
    hook.rewrite = [this](ByteView payload, const L7Context& l7) -> Result<std::optional<Bytes>> {
      if (l7.field == Fid::payload_media) return rewrite_media(payload, l7.media_tag);
      return rewrite_sip(payload);
    };
    summary.input_format = in;
    summary.output_format = resolve_output_format(o.format, in);
    ropt.payload = o.payload == PayloadMode::drop ? PayloadPolicy::drop : PayloadPolicy::zero;
    ropt.pseudonymise_vlan = o.pseudonymise_vlan;
    ropt.pseudonymise_ports = o.pseudonymise_ephemeral_ports;
    ropt.strict = o.strict;
  }

  Project::Impl& project;
  AnonymizeOptions options;
  RuleSet rules;
  Policy policy;
  SipRuleSet sip_rules;
  MediaRuleSet media_rules;
  XmlRuleSet xml_rules;
  MikeyRuleSet mikey_rules;
  HttpRuleSet http_rules;
  TlsRuleSet tls_rules;
  std::vector<std::string> kept_segments;  // feature 007: rules/http.yaml paths, for XML web-uri values
  media::EndpointTable endpoints;
  sip::SipCounters media_sip_counters;  // URI mappings of APP fields (not part of the SIP report)
  // Turns the media descriptions of every rewritten SDP into endpoints.
  struct Sink : sip::MediaSink {
    explicit Sink(Impl* s) : self(s) {}
    Impl* self;
    void announce(const sip::SdpMedia& m) override {
      const auto a = media::from_sdp(m);
      if (const auto* r = std::get_if<media::SkipReason>(&a)) {
        self->endpoints.skip(*r);
        return;
      }
      for (const auto& x : std::get<std::vector<media::Announcement>>(a)) self->endpoints.announce(x, self->last_ts);
    }
  } media_sink{this};
  sip::TextOptions sip_options;
  L7Hook hook;
  bool test_sip_passthrough = false;
  Pseudonymiser pseudonymiser;
  MapperAdapter mapper;
  RewriteOptions ropt;
  stream::TcpStreams streams;
  pipeline::HoldQueue queue;
  std::map<stream::TcpStreams::Ticket, pipeline::HoldQueue::Id> held;  // pending segments
  stream::FragmentTable frags;
  std::map<stream::FragmentTable::Ticket, pipeline::HoldQueue::Id> held_frags;
  struct FirstFragment {
    Record rec;
    std::size_t off = 0;
    std::size_t len = 0;
    std::uint16_t lt = 0;
    std::size_t fcs = 0;
    int layer = -1;
  };
  struct FragmentJob {
    bool ok = false;  // the datagram was SIP and is cut into `chunks`
    std::vector<Bytes> chunks;
    std::vector<std::uint32_t> offsets;  // fragment offset of each chunk, in bytes
  };
  std::map<stream::FragmentTable::Datagram, FirstFragment> first_frags;
  std::map<stream::FragmentTable::Datagram, FragmentJob> frag_jobs;
  std::uint64_t last_ts = 0;
  bool queued = false;  // the current record's output already went through the queue
  RunSummary summary;
  // The XML body rewriter (feature 003); it refers to xml_rules and to
  // summary.xml.counters, so it is declared after both.
  xml::SipXmlBodies xml_bodies{xml_rules, summary.xml.counters,
                               xml::RewriteOptions{false, options.encrypted == EncryptedMode::passthrough,
                                                   options.time_shift ? options.time_shift->count() / 1000000000 : 0}};
  // The MIKEY rewriter (feature 005); it refers to mikey_rules and to
  // summary.mikey.counters, so it is declared after both.
  mikey::Rewriter mikey_rewriter{mikey_rules, mikey_options(options), summary.mikey.counters};

  // Feature 007: the HTTP layer's SIP context (its own counters: removed values become scan tokens)
  // and environment, set up in the constructor body once the SIP options are known.
  sip::SipCounters http_sip_counters;
  std::optional<sip::Context> http_sctx;
  std::optional<http::Env> http_env;
  std::optional<tls::Env> tls_env;
  // CONNECT tunnels: the web session hands the bytes after the 2xx to TLS.
  struct TlsOpener : http::TlsOpener {
    explicit TlsOpener(Impl* s) : self(s) {}
    Impl* self;
    std::unique_ptr<stream::Session> open(std::shared_ptr<stream::Connection> c) override {
      return tls::open_tls_session(*self->tls_env, std::move(c));
    }
  } tls_opener{this};
  std::map<std::pair<Bytes, Bytes>, std::weak_ptr<stream::Connection>> connections;
  bool web_passthrough = false;  // test seam: web sessions keep the original bytes

  // The test seam (pipeline/testing.hpp): a session that rewrites as usual, then returns the
  // original message, so that only the independent scan stands between it and the output.
  struct Passthrough final : stream::Session {
    explicit Passthrough(std::unique_ptr<stream::Session> s) : inner(std::move(s)) {}
    std::unique_ptr<stream::Session> inner;
    stream::Framed frame(std::string_view b) override { return inner->frame(b); }
    Result<stream::RewrittenMessage> rewrite(std::string_view m) override {
      auto r = inner->rewrite(m);
      if (!r || r->zeroed) return r;
      stream::RewrittenMessage o;
      o.bytes.assign(m);
      o.spans.push_back(stream::Piece{0, m.size(), 0, m.size(), true});
      return o;
    }
    std::optional<bool> resync(std::string_view b) override { return inner->resync(b); }
    [[nodiscard]] bool text() const override { return inner->text(); }
  };
  stream::Opened seam(stream::Opened o) {
    if (web_passthrough && o.kind == stream::Opened::Kind::session) o.session = std::make_unique<Passthrough>(std::move(o.session));
    return o;
  }

  std::shared_ptr<stream::Connection> connection(const Bytes& dir, const Bytes& rev) {
    auto key = dir < rev ? std::make_pair(dir, rev) : std::make_pair(rev, dir);
    auto& w = connections[key];
    if (auto c = w.lock()) return c;
    auto c = std::make_shared<stream::Connection>();
    w = c;
    if (connections.size() > 4096) std::erase_if(connections, [](const auto& e) { return e.second.expired(); });
    return c;
  }

  // Feature 007: a TCP direction that is not SIP is offered here: HTTP/1.1, the
  // HTTP/2 preface (or the server side of an h2 connection whose client sent it) or TLS.
  stream::Opened web_open(const Bytes& dir, const Bytes& rev, std::string_view b, bool syn, bool resync) {
    return seam(web_open_session(dir, rev, b, syn, resync));
  }
  stream::Opened web_open_session(const Bytes& dir, const Bytes& rev, std::string_view b, bool syn, bool resync) {
    (void)syn;
    using K = stream::Opened::Kind;
    auto conn = connection(dir, rev);
    auto session = [&](http::Start s) { return stream::Opened{K::session, http::open_web_session(*http_env, conn, s)}; };
    const auto start = http::is_start(b);
    if (resync) {
      if (!start) return {K::more, nullptr};
      return *start ? session(http::Start::http1) : stream::Opened{};
    }
    // TLS: a record header at the start of the direction.
    const auto t = tls::is_record_start(b);
    if (t && *t) return {K::session, tls::open_tls_session(*tls_env, conn)};
    const auto pre = http::is_preface(b);
    if (pre && *pre) {
      conn->h2_preface = true;
      return session(http::Start::h2_client);
    }
    if (start && *start) return session(http::Start::http1);
    if (conn->h2_preface) {
      const auto h = http::is_h2_server_start(b);
      if (h && *h) return session(http::Start::h2_server);
      if (!h) return {K::more, nullptr};
    }
    if (!pre || !start || !t) return {K::more, nullptr};
    return {};
  }

  static mikey::RewriterOptions mikey_options(const AnonymizeOptions& o) {
    mikey::RewriterOptions r;
    r.passthrough = o.encrypted == EncryptedMode::passthrough;
    if (o.time_shift) r.time_shift_ns = o.time_shift->count();
    for (const auto& k : o.kms_key_periods) r.kms_periods.push_back({k.kms, k.length_s, k.offset_s});
    return r;
  }

  // pcap input
  PcapFileHeader pcap_in;
  i128 pcap_shift = 0;
  // pcapng input
  std::vector<Iface> ifaces;
  Endian section_endian = Endian::little;
  // pcap output from pcapng input
  bool pcap_out_header_done = false;
  PcapFileHeader pcap_out;

  [[nodiscard]] bool to_pcap() const { return summary.output_format == CaptureFormat::pcap; }
  [[nodiscard]] std::int64_t shift_ns() const {
    return options.time_shift ? options.time_shift->count() : 0;
  }

  Result<PacketOutput> rewrite(std::uint16_t lt, ByteView data, std::size_t fcs,
                               const TcpOverride* tcp = nullptr) {
    return rewrite_packet(lt, data, fcs, policy, mapper, ropt, summary.rewrite, &hook, tcp);
  }

  void count_sip(const sip::SipRewriteResult& r) {
    auto& s = summary.sip;
    ++s.messages;
    if (r.request) {
      ++s.requests[r.method];
    } else if (r.status_code >= 100 && r.status_code <= 699) {
      ++s.responses[std::to_string(r.status_code / 100) + "xx"];
    }
    s.trailing_zeroed_bytes += r.trailing_zeroed;
    if (r.malformed == sip::Malformed::message) ++s.malformed;
  }

  // The media classifier: the endpoint of a UDP datagram, by destination, then
  // by source, at the current capture time.
  static int classify_media(const UdpFlowView& f, ByteView, void* p) {
    auto* self = static_cast<Impl*>(p);
    const auto src = media::Address::from_bytes(f.src);
    const auto dst = media::Address::from_bytes(f.dst);
    if (!src || !dst) return 0;
    const auto l = self->endpoints.lookup({*dst, f.dport, media::Transport::udp},
                                          {*src, f.sport, media::Transport::udp}, self->last_ts);
    return l ? MediaTag::of(*l).pack() : 0;
  }

  // One datagram on an announced media endpoint (feature 004): the rewritten bytes, or nullopt
  // when nothing of it can be kept (it is zeroed).
  Result<std::optional<Bytes>> rewrite_media(ByteView payload, int tag) {
    auto& mc = summary.media.counters;
    const auto t = MediaTag::unpack(tag);
    const auto kind = t.kind;
    const bool secure = t.secure;
    const sip::KeyContext* keys = endpoints.key_context(t.keys);
    // RFC 5761 §4: on a multiplexed port, the second octet 192-223 is an RTCP packet type.
    const bool rtcp_octet = payload.size() >= 2 && payload[1] >= 192 && payload[1] <= 223;
    if (kind == media::Kind::rtp || (kind == media::Kind::mux && !rtcp_octet)) {
      return media::rewrite_rtp(payload, secure, media_rules, mapper, mc, keys);
    }
    // RTCP: a declared RTCP port, a floor or transmission control channel, or the RTCP half of
    // a multiplexed port. APP URIs go through the SIP URI mapping (SC-003); its counters are
    // kept apart from the SIP report, its removed values become scan tokens.
    sip::Context sctx{sip_rules, mapper, sip_options, media_sip_counters, nullptr, nullptr, &mikey_rewriter, &mikey_rewriter};
    sctx.kept_path_segments = &kept_segments;
    media::RtcpEnv env{media_rules, mapper, sctx, mc, keys};
    return media::rewrite_rtcp(payload, secure, env);
  }

  // A TCP direction is MSRP when one of its endpoints is an announced MSRP endpoint (research
  // R10). The key is source and destination address, source and destination port, depth.
  bool msrp_direction(const Bytes& key) {
    if (key.size() != 13 && key.size() != 37) return false;
    const std::size_t a = (key.size() - 5) / 2;
    const auto src = media::Address::from_bytes(ByteView(key).subspan(0, a));
    const auto dst = media::Address::from_bytes(ByteView(key).subspan(a, a));
    if (!src || !dst) return false;
    const auto port = [&](std::size_t off) { return static_cast<std::uint16_t>((key[off] << 8) | key[off + 1]); };
    const auto l = endpoints.lookup({*dst, port(2 * a + 2), media::Transport::tcp},
                                    {*src, port(2 * a), media::Transport::tcp}, last_ts);
    return l && l->kind == media::Kind::msrp;
  }

  // One MSRP message framed on a TCP stream: the rewritten head is one span, the
  // content and end-line keep their length and map byte by byte.
  Result<stream::RewrittenMessage> rewrite_msrp_stream(std::string_view m) {
    sip::Context sctx{sip_rules, mapper, sip_options, media_sip_counters, nullptr, nullptr, &mikey_rewriter, &mikey_rewriter};
    sctx.kept_path_segments = &kept_segments;
    auto r = media::rewrite_msrp(m, media_rules, sctx, mapper, summary.media.counters);
    if (!r) return std::unexpected(r.error());
    stream::RewrittenMessage out;
    if (r->zeroed) {
      out.zeroed = true;
      return out;
    }
    out.bytes = std::move(r->bytes);
    out.spans.push_back(stream::Piece{0, r->head_orig, 0, r->head_out, false});
    const std::size_t tail = m.size() - r->head_orig;
    if (tail > 0) out.spans.push_back(stream::Piece{r->head_orig, tail, r->head_out, tail, true});
    return out;
  }

  // One SIP message in one UDP datagram (FR-025): the rewritten bytes, or nullopt when the
  // message is malformed (zeroed, or dropped in drop mode).
  Result<std::optional<Bytes>> rewrite_sip(ByteView payload) {
    sip::Context ctx{sip_rules, mapper,      sip_options,     summary.sip.counters, &media_sink, &xml_bodies,
                     &mikey_rewriter, &mikey_rewriter};
    ctx.kept_path_segments = &kept_segments;
    auto r = sip::rewrite_message(std::string_view(reinterpret_cast<const char*>(payload.data()), payload.size()),
                                  sip::Transport::datagram, ctx);
    if (!r) return std::unexpected(r.error());
    count_sip(*r);
    if (r->malformed == sip::Malformed::message) return std::optional<Bytes>{};
    if (test_sip_passthrough) return std::optional<Bytes>(Bytes(payload.begin(), payload.end()));
    return std::optional<Bytes>(Bytes(r->bytes.begin(), r->bytes.end()));
  }

  // One SIP message framed on a TCP stream (R14): the new bytes and the offset map.
  Result<stream::RewrittenMessage> rewrite_sip_stream(std::string_view m) {
    sip::Context ctx{sip_rules, mapper,      sip_options,     summary.sip.counters, &media_sink, &xml_bodies,
                     &mikey_rewriter, &mikey_rewriter};
    ctx.kept_path_segments = &kept_segments;
    auto r = sip::rewrite_message(m, sip::Transport::stream, ctx);
    if (!r) return std::unexpected(r.error());
    count_sip(*r);
    stream::RewrittenMessage out;
    if (r->malformed == sip::Malformed::message) {
      out.zeroed = true;
      return out;
    }
    if (test_sip_passthrough) {
      out.bytes.assign(m);
      out.spans.push_back(stream::Piece{0, m.size(), 0, m.size(), true});
      return out;
    }
    out.bytes = std::move(r->bytes);
    for (const auto& sp : r->offset_map) {
      out.spans.push_back(stream::Piece{sp.orig, sp.orig_len, sp.out, sp.out_len, sp.verbatim});
    }
    return out;
  }

  // --- ordered output (R2) ------------------------------------------------------------------

  using Build = std::function<Result<std::vector<Record>>(const PacketOutput&)>;

  // Records that need no future bytes: passed on, or queued behind a pending record.
  Result<std::vector<Record>> emit(std::vector<Record> recs) {
    queued = true;
    if (queue.empty()) return recs;
    const std::size_t n = bytes_of(recs);
    queue.push(last_ts, n, false, [recs = std::move(recs)](pipeline::GiveUp) -> Result<std::vector<Record>> { return recs; });
    return queue.release(last_ts);
  }

  void wake(const std::vector<stream::TcpStreams::Ticket>& tickets) {
    for (const auto t : tickets) {
      if (const auto it = held.find(t); it != held.end()) queue.mark_ready(it->second);
    }
  }

  Result<std::vector<Record>> resolve_segment(stream::TcpStreams::Ticket t, pipeline::GiveUp why, std::uint16_t lt,
                                              ByteView data, std::size_t fcs, const Build& build) {
    std::vector<stream::TcpStreams::Ticket> became;
    auto o = streams.take(t, why != pipeline::GiveUp::no, became);
    held.erase(t);
    if (!o) return std::unexpected(o.error());
    wake(became);
    const TcpOverride ov{std::move(o->payload), o->seq, o->ack, std::move(o->sack), o->sack_known, o->sip};
    auto r = rewrite(lt, data, fcs, &ov);
    if (!r) return std::unexpected(r.error());
    if (r->drop) return std::vector<Record>{};
    return build(*r);
  }

  void wake_frags(const std::vector<stream::FragmentTable::Ticket>& tickets) {
    for (const auto t : tickets) {
      if (const auto it = held_frags.find(t); it != held_frags.end()) queue.mark_ready(it->second);
    }
  }

  // R16: the reassembled datagram is rewritten once, then cut at the chunk size.
  Result<const FragmentJob*> fragment_job(stream::FragmentTable::Datagram dg) {
    if (const auto it = frag_jobs.find(dg); it != frag_jobs.end()) return &it->second;
    FragmentJob& job = frag_jobs[dg];
    const auto ff = first_frags.find(dg);
    if (ff == first_frags.end()) return &job;
    const FirstFragment& f = ff->second;
    const ByteView first = ByteView(f.rec.bytes).subspan(f.off, f.len);
    auto synth = reassembled_packet(f.lt, first, f.fcs, f.layer, frags.reassembled(dg));
    if (!synth) return &job;  // does not fit: zeroed per feature 001
    RewriteStats scratch;     // the synthetic packet is not a captured packet
    auto r = rewrite_packet(f.lt, *synth, f.fcs, policy, mapper, ropt, scratch, &hook);
    if (!r) return std::unexpected(r.error());
    for (const auto& [field, actions] : scratch.counters) {
      if (field == "payload.sip") {
        for (const auto& [a, n] : actions) summary.rewrite.counters[field][a] += n;
      }
    }
    if (!r->l7_spliced || r->drop) {
      ++summary.sip.fragmented_not_sip;  // malformed SIP: zeroed per feature 001
      return &job;
    }
    const auto reg = fragmentable_region(f.lt, r->data, f.fcs, f.layer);
    if (!reg) return &job;
    // R16 cuts at the largest original fragment size. When the rewritten datagram fits in as
    // many fragments as the input had, it is spread over that many (each a multiple of 8 and
    // no larger than the largest original), so that the packets keep their numbers (the SC-001
    // ladder oracle compares frame numbers); fewer are used only when it is too
    // short to give each one 8 bytes, more only when it does not fit.
    const std::size_t total = reg->second - reg->first;
    const std::size_t chunk = frags.chunk_size(dg);
    std::size_t n = (total + chunk - 1) / chunk;
    std::size_t size = chunk;
    if (n <= frags.ranks(dg)) {
      n = frags.ranks(dg);
      for (;;) {
        size = ((total + n - 1) / n + 7) / 8 * 8;
        if (n == 1 || size * (n - 1) < total) break;
        --n;
      }
    }
    for (std::size_t at = 0; at < total; at += size) {
      const std::size_t len = std::min(size, total - at);
      const auto from = r->data.begin() + static_cast<std::ptrdiff_t>(reg->first + at);
      job.chunks.emplace_back(from, from + static_cast<std::ptrdiff_t>(len));
      job.offsets.push_back(static_cast<std::uint32_t>(at));
    }
    job.ok = !job.chunks.empty();
    if (job.ok) ++summary.sip.fragmented_rewritten;
    return &job;
  }

  void release_fragment(stream::FragmentTable::Ticket t, stream::FragmentTable::Datagram dg) {
    held_frags.erase(t);
    frags.release(t);
    if (frags.open(dg) == 0) {
      first_frags.erase(dg);
      frag_jobs.erase(dg);
    }
  }

  Result<std::vector<Record>> resolve_fragment(stream::FragmentTable::Ticket t, stream::FragmentTable::Datagram dg,
                                               pipeline::GiveUp why, std::uint16_t lt, ByteView data, std::size_t fcs,
                                               const Build& build) {
    if (!frags.ready(t)) {
      if (why == pipeline::GiveUp::no) {
        return fail(ErrorCode::internal, "fragment resolved before its datagram is known");
      }
      using A = stream::FragmentTable::Abandon;
      std::vector<stream::FragmentTable::Ticket> became;
      frags.abandon(dg, why == pipeline::GiveUp::timeout ? A::timeout : why == pipeline::GiveUp::bound ? A::bound : A::missing,
                    became);
      wake_frags(became);
    }
    std::vector<Record> out;
    if (frags.verdict(dg) == stream::FragmentTable::Verdict::complete) {
      auto job = fragment_job(dg);
      if (!job) return std::unexpected(job.error());
      if ((*job)->ok) {
        const auto& chunks = (*job)->chunks;
        const std::size_t rank = frags.rank(t);
        const std::size_t ranks = frags.ranks(dg);
        // The slot of the last original fragment also carries surplus output fragments; slots
        // beyond the output fragments are dropped.
        const std::size_t last = rank + 1 == ranks ? chunks.size() : std::min(rank + 1, chunks.size());
        for (std::size_t k = rank; k < last; ++k) {
          const FragmentOverride fo{chunks[k], (*job)->offsets[k], k + 1 < chunks.size()};
          auto r = rewrite_packet(lt, data, fcs, policy, mapper, ropt, summary.rewrite, &hook, nullptr, &fo);
          if (!r) return std::unexpected(r.error());
          auto recs = build(*r);
          if (!recs) return std::unexpected(recs.error());
          for (auto& x : *recs) out.push_back(std::move(x));
        }
        release_fragment(t, dg);
        return out;
      }
    }
    release_fragment(t, dg);
    auto r = rewrite(lt, data, fcs);
    if (!r) return std::unexpected(r.error());
    if (r->drop) return out;
    return build(*r);
  }

  // One captured packet. A TCP segment goes through the stream layer and may wait for later
  // segments (a SIP message still arriving), a fragment of a SIP datagram waits for the rest
  // of the datagram; everything else is rewritten at once.
  Result<std::vector<Record>> packet(const Record& rec, ByteView data, std::uint16_t lt, std::size_t fcs,
                                     std::uint64_t ts_us, Build build) {
    // Records that waited past the pending timeout are given up before this packet can add the
    // bytes they waited for (R15: the timeout is a property of capture time, not of arrival).
    std::vector<Record> early;
    if (!queue.empty()) {
      auto e = queue.release(std::max(last_ts, ts_us));
      if (!e) return std::unexpected(e.error());
      early = std::move(*e);
    }
    auto r = packet_now(rec, data, lt, fcs, ts_us, std::move(build));
    if (!r || early.empty()) return r;
    early.insert(early.end(), std::make_move_iterator(r->begin()), std::make_move_iterator(r->end()));
    return early;
  }

  Result<std::vector<Record>> packet_now(const Record& rec, ByteView data, std::uint16_t lt, std::size_t fcs,
                                         std::uint64_t ts_us, Build build) {
    ++summary.frames;
    last_ts = std::max(last_ts, ts_us);
    DissectOptions dopt;
    dopt.fcs_len = lt == kLinkEthernet ? fcs : 0;
    dopt.recognise_sip = &recognise_sip;
    const Dissection d = dissect(lt, data, dopt);
    if (auto fr = stream::fragment_of(d, data, &recognise_sip)) {
      std::vector<stream::FragmentTable::Ticket> became;
      const auto a = frags.add(*fr, became);
      wake_frags(became);
      if (a.tracked) {
        queued = true;
        const auto off = static_cast<std::size_t>(data.data() - rec.bytes.data());
        const std::size_t len = data.size();
        if (fr->offset == 0) first_frags[a.datagram] = FirstFragment{rec, off, len, lt, fcs, fr->layer};
        const auto id = queue.push(last_ts, rec.bytes.size(), !a.ready,
                                   [this, copy = rec, off, len, lt, fcs, t = a.ticket, dg = a.datagram,
                                    build](pipeline::GiveUp why) {
                                     return resolve_fragment(t, dg, why, lt, ByteView(copy.bytes).subspan(off, len),
                                                             fcs, build);
                                   });
        if (!a.ready) held_frags[a.ticket] = id;
        return queue.release(last_ts);
      }
    }
    auto seg = stream::segment_of(d, data, ts_us);
    if (!seg) {
      auto r = rewrite(lt, data, fcs);
      if (!r) return std::unexpected(r.error());
      if (r->drop) return emit({});
      auto recs = build(*r);
      if (!recs) return std::unexpected(recs.error());
      return emit(std::move(*recs));
    }
    queued = true;
    std::vector<stream::TcpStreams::Ticket> became;
    auto a = streams.segment(*seg, became);
    if (!a) return std::unexpected(a.error());
    wake(became);
    if (a->ready && queue.empty()) return resolve_segment(a->ticket, pipeline::GiveUp::no, lt, data, fcs, build);
    const auto off = static_cast<std::size_t>(data.data() - rec.bytes.data());
    const std::size_t len = data.size();
    const auto t = a->ticket;
    const auto id = queue.push(last_ts, rec.bytes.size(), !a->ready,
                               [this, copy = rec, off, len, lt, fcs, t, build](pipeline::GiveUp why) {
                                 return resolve_segment(t, why, lt, ByteView(copy.bytes).subspan(off, len),
                                                        fcs, build);
                               });
    if (!a->ready) held[t] = id;
    return queue.release(last_ts);
  }

  static Record make(RecordKind k, std::uint32_t type, Endian e, Bytes b, std::uint64_t frame) {
    Record r;
    r.kind = k;
    r.block_type = type;
    r.endian = e;
    r.bytes = std::move(b);
    r.frame_number = frame;
    return r;
  }

  // Converts (units, tsresol, tsoffset) to a pcap timestamp of the output header.
  Result<std::pair<std::uint32_t, std::uint32_t>> to_pcap_ts(i128 units, const InterfaceInfo& info) {
    const auto ups = units_per_second(info.tsresol);
    if (!ups) return fail(ErrorCode::input, "unsupported timestamp resolution");
    const i128 out_ups = pcap_out.nanosecond ? 1000000000 : 1000000;
    i128 secs = units / *ups + info.tsoffset;
    const i128 frac = (units % *ups) * out_ups / *ups;
    if (secs < 0 || secs > 0xFFFFFFFF) return fail(ErrorCode::input, "timestamp out of range for pcap");
    return std::make_pair(static_cast<std::uint32_t>(secs), static_cast<std::uint32_t>(frac));
  }

  Result<std::vector<Record>> pcap_record(const Record& rec) {
    std::vector<Record> out;
    if (rec.kind == RecordKind::pcap_file_header) {
      auto h = parse_pcap_file_header(rec.bytes);
      if (!h) return std::unexpected(h.error());
      pcap_in = *h;
      if (options.time_shift) {
        auto s = shift_in_units(shift_ns(), h->nanosecond ? 9 : 6);
        if (!s) return std::unexpected(s.error());
        pcap_shift = *s;
      }
      if (!to_pcap()) {
        const Endian e = h->endian;
        out.push_back(make(RecordKind::pcapng_block, kPcapngShb, e, build_shb(e, {}), 0));
        Bytes body(8, 0);
        store16(body, 0, h->linktype, e);
        store32(body, 4, output_snaplen(h->snaplen), e);
        std::vector<PcapngOption> opts;
        if (h->nanosecond) opts.push_back({9, {9}});
        if (h->fcs_present) opts.push_back({13, {static_cast<std::uint8_t>(h->fcs_len_words * 2)}});
        out.push_back(make(RecordKind::pcapng_block, kPcapngIdb, e, build_block(kPcapngIdb, body, opts, e), 0));
      } else {
        PcapFileHeader oh = *h;
        oh.snaplen = output_snaplen(h->snaplen);
        out.push_back(make(RecordKind::pcap_file_header, 0, h->endian, build_pcap_file_header(oh), 0));
      }
      return out;
    }
    auto ph = parse_pcap_packet_header(rec.bytes, pcap_in.endian);
    if (!ph) return std::unexpected(ph.error());
    const std::size_t fcs = pcap_in.fcs_present ? pcap_in.fcs_len_words * 2u : 0u;
    const i128 ups = pcap_in.nanosecond ? 1000000000 : 1000000;
    const i128 raw = static_cast<i128>(ph->ts_sec) * ups + ph->ts_frac;
    const i128 units = raw + pcap_shift;
    if (units < 0 || units / ups > 0xFFFFFFFF) {
      return fail(ErrorCode::input, "the time shift moves a timestamp out of range");
    }
    Build build = [this, e = pcap_in.endian, units, ups, h = *ph,
                   frame = rec.frame_number](const PacketOutput& r) -> Result<std::vector<Record>> {
      std::vector<Record> o;
      const auto caplen = static_cast<std::uint32_t>(r.data.size());
      const std::uint32_t origlen = output_origlen(r.truncated, h.caplen, h.origlen, caplen);
      if (to_pcap()) {
        Bytes b(kPcapRecordHeaderSize);
        store_pcap_packet_header(b, PcapPacketHeader{static_cast<std::uint32_t>(units / ups),
                                                     static_cast<std::uint32_t>(units % ups), caplen,
                                                     origlen},
                                 e);
        b.insert(b.end(), r.data.begin(), r.data.end());
        o.push_back(make(RecordKind::pcap_packet, 0, e, std::move(b), frame));
      } else {
        Bytes body(20, 0);
        store32(body, 4, static_cast<std::uint32_t>(static_cast<std::uint64_t>(units) >> 32), e);
        store32(body, 8, static_cast<std::uint32_t>(static_cast<std::uint64_t>(units)), e);
        store32(body, 12, caplen, e);
        store32(body, 16, origlen, e);
        body.insert(body.end(), r.data.begin(), r.data.end());
        o.push_back(make(RecordKind::pcapng_block, kPcapngEpb, e, build_block(kPcapngEpb, body, {}, e), frame));
      }
      return o;
    };
    return packet(rec, pcap_packet_data(rec), pcap_in.linktype, fcs, micros(raw, ups), std::move(build));
  }

  Result<std::vector<PcapngOption>> options_of(const Record& rec) {
    auto off = option_region_offset(rec.block_type, rec.bytes, rec.endian);
    if (!off) return std::unexpected(off.error());
    if (!off->has_value()) return std::vector<PcapngOption>{};
    return parse_options(ByteView(rec.bytes).subspan(**off, rec.bytes.size() - 4 - **off), rec.endian);
  }

  std::vector<PcapngOption> filtered(const Record& rec, std::uint32_t as_type,
                                     const std::vector<PcapngOption>& opts) {
    return filter_options(as_type, opts, rec.endian, policy, summary.rewrite, summary.meta,
                          summary.removed_values);
  }

  Result<void> shift_option_ts(std::vector<PcapngOption>& opts, const Iface& ifc, Endian e) {
    for (auto& o : opts) {
      if ((o.code == 2 || o.code == 3) && o.value.size() == 8) {
        const i128 v = (static_cast<i128>(load32(o.value, 0, e)) << 32) | load32(o.value, 4, e);
        const i128 s = v + ifc.shift;
        if (s < 0 || s > static_cast<i128>(UINT64_MAX)) {
          return fail(ErrorCode::input, "the time shift moves a timestamp out of range");
        }
        store32(o.value, 0, static_cast<std::uint32_t>(static_cast<std::uint64_t>(s) >> 32), e);
        store32(o.value, 4, static_cast<std::uint32_t>(static_cast<std::uint64_t>(s)), e);
      }
    }
    return {};
  }

  Result<Iface*> iface(std::uint32_t id) {
    if (id >= ifaces.size()) {
      return fail(ErrorCode::input, "a packet block references an undefined interface");
    }
    return &ifaces[id];
  }

  // Packet block common path (EPB and the obsolete Packet Block).
  Result<std::vector<Record>> emit_packet(const Record& rec, const Iface& ifc, std::uint32_t ifid,
                                          i128 units, std::uint32_t origlen, ByteView data,
                                          std::vector<PcapngOption> opts, std::size_t fcs) {
    const i128 shifted = units + ifc.shift;
    if (shifted < 0 || shifted > static_cast<i128>(UINT64_MAX)) {
      return fail(ErrorCode::input, "the time shift moves a timestamp out of range");
    }
    const auto ups = units_per_second(ifc.info.tsresol);
    const auto in_caplen = static_cast<std::uint32_t>(data.size());
    Build build = [this, ifc, ifid, shifted, origlen, in_caplen, opts = std::move(opts), e = rec.endian,
                   frame = rec.frame_number](const PacketOutput& r) -> Result<std::vector<Record>> {
      std::vector<Record> out;
      const auto caplen = static_cast<std::uint32_t>(r.data.size());
      const std::uint32_t olen = output_origlen(r.truncated, in_caplen, origlen, caplen);
      if (to_pcap()) {
        auto ts = to_pcap_ts(shifted, ifc.info);
        if (!ts) return std::unexpected(ts.error());
        Bytes b(kPcapRecordHeaderSize);
        store_pcap_packet_header(b, PcapPacketHeader{ts->first, ts->second, caplen, olen}, pcap_out.endian);
        b.insert(b.end(), r.data.begin(), r.data.end());
        out.push_back(make(RecordKind::pcap_packet, 0, pcap_out.endian, std::move(b), frame));
        return out;
      }
      Bytes body(20, 0);
      store32(body, 0, ifid, e);
      store32(body, 4, static_cast<std::uint32_t>(static_cast<std::uint64_t>(shifted) >> 32), e);
      store32(body, 8, static_cast<std::uint32_t>(static_cast<std::uint64_t>(shifted)), e);
      store32(body, 12, caplen, e);
      store32(body, 16, olen, e);
      body.insert(body.end(), r.data.begin(), r.data.end());
      out.push_back(make(RecordKind::pcapng_block, kPcapngEpb, e, build_block(kPcapngEpb, body, opts, e), frame));
      return out;
    };
    return packet(rec, data, ifc.info.linktype, fcs, ups ? micros(units, *ups) : last_ts, std::move(build));
  }

  static std::size_t fcs_of(const Iface& ifc, const std::vector<PcapngOption>& opts, Endian e) {
    for (const auto& o : opts) {
      if (o.code == 2 && o.value.size() == 4) {
        const std::uint32_t flags = load32(o.value, 0, e);
        const std::uint32_t fcs = (flags >> 5) & 0x0Fu;  // octets (pcapng-06 §4.3.1)
        if (fcs != 0) return fcs;
      }
    }
    return ifc.info.fcslen.value_or(0);
  }

  Result<std::vector<Record>> pcapng_record(const Record& rec) {
    std::vector<Record> out;
    const Endian e = rec.endian;
    const std::uint32_t t = rec.block_type;
    if (!keep_block(t, policy, summary.rewrite, summary.meta)) {
      collect_block_values(t, rec.bytes, e, summary.removed_values);
      if (t == kPcapngShb || t == kPcapngIdb || t == kPcapngEpb || t == kPcapngSpb ||
          t == kPcapngPacketObsolete) {
        return fail(ErrorCode::internal, "the rule set removes a structural pcapng block");
      }
      return out;
    }
    auto opts = options_of(rec);
    if (!opts) return std::unexpected(opts.error());
    switch (t) {
      case kPcapngShb: {
        section_endian = e;
        ifaces.clear();
        const auto kept = filtered(rec, t, *opts);
        if (!to_pcap()) out.push_back(make(RecordKind::pcapng_block, t, e, build_shb(e, kept), 0));
        return out;
      }
      case kPcapngIdb: {
        auto info = parse_idb(rec.bytes, e);
        if (!info) return std::unexpected(info.error());
        Iface ifc{*info, 0};
        if (options.time_shift) {
          auto s = shift_in_units(shift_ns(), info->tsresol);
          if (!s) return std::unexpected(s.error());
          ifc.shift = *s;
        }
        ifaces.push_back(ifc);
        const auto kept = filtered(rec, t, *opts);
        if (to_pcap()) {
          if (!pcap_out_header_done) {
            pcap_out.endian = e;
            pcap_out.linktype = info->linktype;
            pcap_out.snaplen = info->snaplen == 0 ? kMinSnaplen : output_snaplen(info->snaplen);
            pcap_out.nanosecond = info->tsresol != 6;
            if (info->fcslen && *info->fcslen > 0) {
              pcap_out.fcs_present = true;
              pcap_out.fcs_len_words = static_cast<std::uint8_t>(*info->fcslen / 2);
            }
            pcap_out_header_done = true;
            out.push_back(make(RecordKind::pcap_file_header, 0, e, build_pcap_file_header(pcap_out), 0));
          } else if (info->linktype != pcap_out.linktype) {
            return fail(ErrorCode::usage,
                        "pcap output needs a single link type, but the capture has interfaces "
                        "with different link types; use --format pcapng");
          }
          return out;
        }
        Bytes body(8, 0);
        store16(body, 0, info->linktype, e);
        store32(body, 4, output_snaplen(info->snaplen), e);
        out.push_back(make(RecordKind::pcapng_block, t, e, build_block(t, body, kept, e), 0));
        return out;
      }
      case kPcapngEpb: {
        if (rec.bytes.size() < 32) return fail(ErrorCode::input, "Enhanced Packet Block truncated");
        const std::uint32_t ifid = load32(rec.bytes, 8, e);
        const i128 units = (static_cast<i128>(load32(rec.bytes, 12, e)) << 32) | load32(rec.bytes, 16, e);
        const std::uint32_t caplen = load32(rec.bytes, 20, e);
        const std::uint32_t origlen = load32(rec.bytes, 24, e);
        if (caplen > rec.bytes.size() - 32) return fail(ErrorCode::input, "EPB data overruns the block");
        auto ifc = iface(ifid);
        if (!ifc) return std::unexpected(ifc.error());
        const std::size_t fcs = fcs_of(**ifc, *opts, e);
        auto kept = filtered(rec, t, *opts);
        return emit_packet(rec, **ifc, ifid, units, origlen, ByteView(rec.bytes).subspan(28, caplen),
                           std::move(kept), fcs);
      }
      case kPcapngPacketObsolete: {
        if (rec.bytes.size() < 32) return fail(ErrorCode::input, "Packet Block truncated");
        const std::uint32_t ifid = load16(rec.bytes, 8, e);
        const std::uint16_t drops = load16(rec.bytes, 10, e);
        const i128 units = (static_cast<i128>(load32(rec.bytes, 12, e)) << 32) | load32(rec.bytes, 16, e);
        const std::uint32_t caplen = load32(rec.bytes, 20, e);
        const std::uint32_t origlen = load32(rec.bytes, 24, e);
        if (caplen > rec.bytes.size() - 32) return fail(ErrorCode::input, "Packet Block data overruns the block");
        auto ifc = iface(ifid);
        if (!ifc) return std::unexpected(ifc.error());
        const std::size_t fcs = fcs_of(**ifc, *opts, e);
        auto kept = filtered(rec, kPcapngPacketObsolete, *opts);
        if (drops != 0xFFFF && policy.decide(Fid::pcapng_epb_dropcount).action == Action::keep) {
          Bytes v(8, 0);
          store64(v, 0, drops, e);
          kept.push_back({4, v});
        }
        return emit_packet(rec, **ifc, ifid, units, origlen, ByteView(rec.bytes).subspan(28, caplen),
                           std::move(kept), fcs);
      }
      case kPcapngSpb: {
        if (rec.bytes.size() < 16) return fail(ErrorCode::input, "Simple Packet Block truncated");
        auto ifc = iface(0);
        if (!ifc) return std::unexpected(ifc.error());
        const std::uint32_t origlen = load32(rec.bytes, 8, e);
        std::size_t len = std::min<std::size_t>(origlen, rec.bytes.size() - 16);
        if ((*ifc)->info.snaplen != 0) len = std::min<std::size_t>(len, (*ifc)->info.snaplen);
        Build build = [this, in_len = static_cast<std::uint32_t>(len), origlen, e, t,
                       frame = rec.frame_number](const PacketOutput& r) -> Result<std::vector<Record>> {
          std::vector<Record> o;
          const auto caplen = static_cast<std::uint32_t>(r.data.size());
          const std::uint32_t olen = output_origlen(r.truncated, in_len, origlen, caplen);
          if (to_pcap()) {
            Bytes b(kPcapRecordHeaderSize);
            store_pcap_packet_header(b, PcapPacketHeader{0, 0, caplen, olen}, pcap_out.endian);
            b.insert(b.end(), r.data.begin(), r.data.end());
            o.push_back(make(RecordKind::pcap_packet, 0, pcap_out.endian, std::move(b), frame));
            return o;
          }
          Bytes body(4, 0);
          store32(body, 0, olen, e);
          body.insert(body.end(), r.data.begin(), r.data.end());
          o.push_back(make(RecordKind::pcapng_block, t, e, build_block(t, body, {}, e), frame));
          return o;
        };
        return packet(rec, ByteView(rec.bytes).subspan(12, len), (*ifc)->info.linktype,
                      (*ifc)->info.fcslen.value_or(0), last_ts, std::move(build));
      }
      case kPcapngIsb: {
        if (rec.bytes.size() < 24) return fail(ErrorCode::input, "Interface Statistics Block truncated");
        const std::uint32_t ifid = load32(rec.bytes, 8, e);
        auto ifc = iface(ifid);
        if (!ifc) return std::unexpected(ifc.error());
        auto kept = filtered(rec, t, *opts);
        if (to_pcap()) {
          ++summary.meta.removed_blocks[block_key(t)];
          return out;
        }
        if (auto s = shift_option_ts(kept, **ifc, e); !s) return std::unexpected(s.error());
        i128 units = (static_cast<i128>(load32(rec.bytes, 12, e)) << 32) | load32(rec.bytes, 16, e);
        units += (*ifc)->shift;
        if (units < 0 || units > static_cast<i128>(UINT64_MAX)) {
          return fail(ErrorCode::input, "the time shift moves a timestamp out of range");
        }
        Bytes body(12, 0);
        store32(body, 0, ifid, e);
        store32(body, 4, static_cast<std::uint32_t>(static_cast<std::uint64_t>(units) >> 32), e);
        store32(body, 8, static_cast<std::uint32_t>(static_cast<std::uint64_t>(units)), e);
        out.push_back(make(RecordKind::pcapng_block, t, e, build_block(t, body, kept, e), 0));
        return out;
      }
      default:
        return out;
    }
  }
};

Anonymizer::Anonymizer(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
Anonymizer::Anonymizer(Anonymizer&&) noexcept = default;
Anonymizer& Anonymizer::operator=(Anonymizer&&) noexcept = default;
Anonymizer::~Anonymizer() = default;

Result<Anonymizer> Anonymizer::create(Project& project, const AnonymizeOptions& options,
                                      CaptureFormat input_format, RuleSet rules,
                                      std::optional<SipRuleSet> sip_override) {
  if (options.ephemeral_lo > options.ephemeral_hi) {
    return fail(ErrorCode::usage, "invalid ephemeral port range");
  }
  auto sip_rules = sip_override ? Result<SipRuleSet>(std::move(*sip_override)) : load_embedded_sip_ruleset();
  if (!sip_rules) return std::unexpected(sip_rules.error());
  auto media_rules = load_embedded_media_ruleset();
  if (!media_rules) return std::unexpected(media_rules.error());
  auto xml_rules = load_embedded_xml_ruleset();
  if (!xml_rules) return std::unexpected(xml_rules.error());
  auto mikey_rules = load_embedded_mikey_ruleset();
  if (!mikey_rules) return std::unexpected(mikey_rules.error());
  auto http_rules = load_embedded_http_ruleset();
  if (!http_rules) return std::unexpected(http_rules.error());
  auto tls_rules = load_embedded_tls_ruleset();
  if (!tls_rules) return std::unexpected(tls_rules.error());
  // Every Content-Type of FR-001 is switched on: the check covers the whole list.
  std::vector<std::string> http_xml;
  for (const auto& b : http_rules->bodies) {
    if (b.handling == HttpBodyHandling::xml) http_xml.push_back(b.content_type);
  }
  if (auto c = check_xml_bodies(*sip_rules, *xml_rules, true, http_xml); !c) return std::unexpected(c.error());
  return Anonymizer(std::make_unique<Impl>(project.impl(), options, input_format, std::move(rules),
                                           std::move(*sip_rules), std::move(*media_rules), std::move(*xml_rules),
                                           std::move(*mikey_rules), std::move(*http_rules), std::move(*tls_rules)));
}

Result<std::vector<Record>> Anonymizer::process(const Record& record) {
  impl_->queued = false;
  auto r = record.kind == RecordKind::pcapng_block ? impl_->pcapng_record(record) : impl_->pcap_record(record);
  if (!r || impl_->queued) return r;
  return impl_->emit(std::move(*r));  // blocks and headers keep their place behind held packets
}

Result<Anonymizer::Finish> Anonymizer::finish() {
  Finish out;
  auto rest = impl_->queue.finish();
  if (!rest) return std::unexpected(rest.error());
  out.records = std::move(*rest);
  impl_->summary.sip.tcp = impl_->streams.stats();
  impl_->summary.sip.held_forced = impl_->queue.forced();
  impl_->summary.sip.fragments = impl_->frags.stats();
  {
    auto& m = impl_->summary.media;
    m.endpoints.clear();
    m.skipped.clear();
    for (const auto& [k, n] : impl_->endpoints.registered()) m.endpoints[std::string(media::to_string(k))] = n;
    for (const auto& [r, n] : impl_->endpoints.skipped()) m.skipped[std::string(media::to_string(r))] = n;
    m.max_endpoints = impl_->endpoints.max_endpoints();
    m.endpoints_evicted = impl_->endpoints.evicted();
  }
  impl_->pseudonymiser.finish_run();
  const auto& st = impl_->pseudonymiser.stats();
  impl_->summary.new_entries = st.new_entries;
  impl_->summary.reused_entries = st.reused_entries;
  impl_->summary.collisions_resolved = st.collisions_resolved;
  // Values the SIP rules removed (free text, credentials, keys) are scan tokens (FR-030).
  for (const auto& [cat, value] : impl_->summary.sip.counters.take_removed()) {
    impl_->summary.removed_values.push_back(RemovedValue{cat, Bytes(value.begin(), value.end())});
  }
  // Values the media rules removed (SDES items, BYE reasons, Reject Phrases, Participant Types,
  // unknown fields) and the URI layer's removed values: scan tokens too (FR-031).
  for (const auto& [cat, value] : impl_->media_sip_counters.take_removed()) {
    impl_->summary.removed_values.push_back(RemovedValue{cat, Bytes(value.begin(), value.end())});
  }
  // Feature 007: values the HTTP rules removed (credentials, tokens, free text).
  for (const auto& [cat, value] : impl_->http_sip_counters.take_removed()) {
    impl_->summary.removed_values.push_back(RemovedValue{cat, Bytes(value.begin(), value.end())});
  }
  for (const auto& [cat, value] : impl_->summary.media.counters.removed_values) {
    impl_->summary.removed_values.push_back(RemovedValue{cat, Bytes(value.begin(), value.end())});
  }
  out.summary = impl_->summary;
  return out;
}

const RunSummary& Anonymizer::summary() const { return impl_->summary; }

void Anonymizer::set_test_sip_passthrough(bool on) { impl_->test_sip_passthrough = on; }
void Anonymizer::set_test_xml_passthrough(bool on) { impl_->xml_bodies.set_test_passthrough(on); }
void Anonymizer::set_test_web_passthrough(bool on) { impl_->web_passthrough = on; }

}  // namespace mcxanon
