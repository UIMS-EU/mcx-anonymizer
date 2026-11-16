// SPDX-License-Identifier: GPL-3.0-or-later
// Rewriter in both payload modes over arbitrary packets, with the SIP layer attached: no
// crash, and in zero mode the length never changes unless the packet carries a recognised SIP
// message.
#include "dissect/fields.hpp"
#include "policy/decide.hpp"
#include "policy/ruleset.hpp"
#include "policy/sip_rules.hpp"
#include "rewrite/apply.hpp"
#include "stream/tcp.hpp"
#include "sip/message.hpp"
#include "sip/rewrite.hpp"

#include <array>
#include <cstdlib>
#include <optional>

namespace {
class Mapper final : public mcxanon::AddressMapper {
 public:
  mcxanon::Result<mcxanon::MacAddr> mac(const mcxanon::MacAddr& a) override { auto m = a; m[0] = 0x02; return m; }
  mcxanon::Result<std::uint32_t> ipv4(std::uint32_t v) override { return 0xF0000000u | (v & 0x0FFFFFFFu); }
  mcxanon::Result<mcxanon::Ipv6Addr> ipv6(const mcxanon::Ipv6Addr& a) override { auto o = a; o[0] = 0x20; return o; }
  mcxanon::Result<std::uint16_t> vlan(std::uint16_t v) override { return v; }
  mcxanon::Result<std::uint16_t> port(std::uint16_t p) override { return p; }
  mcxanon::Result<std::string> text(mcxanon::Category, std::string_view) override { return std::string("x"); }
  mcxanon::Result<std::string> domain(std::string_view) override { return std::string("d.invalid"); }
  mcxanon::Result<std::string> tel(std::string_view v) override { return std::string(v); }
  mcxanon::Result<std::string> sdp_version(std::string_view, std::string_view v) override { return std::string(v); }
  mcxanon::Result<std::uint32_t> spi(std::uint32_t v) override { return v; }
  mcxanon::Result<std::uint32_t> ssrc(std::uint32_t v) override { return v; }
  mcxanon::Result<std::uint32_t> binary(mcxanon::Category, std::uint32_t v) override { return v; }
};
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  static const auto rules = mcxanon::load_embedded_ruleset();
  if (!rules || size < 1) return 0;
  static const mcxanon::Policy policy(*rules);
  constexpr std::array<std::uint16_t, 4> kLinks{1, 101, 113, 276};
  const std::uint16_t lt = kLinks[data[0] % kLinks.size()];
  Mapper m;
  mcxanon::RewriteStats stats;
  mcxanon::RewriteOptions o;
  static const auto sip_rules = mcxanon::load_embedded_sip_ruleset();
  if (!sip_rules) return 0;
  mcxanon::sip::SipCounters counters;
  mcxanon::L7Hook hook;
  hook.recognise = [](mcxanon::ByteView p) {
    return mcxanon::sip::is_start_line(std::string_view(reinterpret_cast<const char*>(p.data()), p.size()));
  };
  hook.rewrite = [&](mcxanon::ByteView p, const mcxanon::L7Context&) -> mcxanon::Result<std::optional<mcxanon::Bytes>> {
    mcxanon::sip::Context ctx{*sip_rules, m, {}, counters};
    auto r = mcxanon::sip::rewrite_message(std::string_view(reinterpret_cast<const char*>(p.data()), p.size()),
                                           mcxanon::sip::Transport::datagram, ctx);
    if (!r) return std::unexpected(r.error());
    if (r->malformed == mcxanon::sip::Malformed::message) return std::optional<mcxanon::Bytes>{};
    return std::optional<mcxanon::Bytes>(mcxanon::Bytes(r->bytes.begin(), r->bytes.end()));
  };
  const mcxanon::ByteView pkt(data + 1, size - 1);
  const std::size_t fcs = (data[0] & 0x80) ? 4 : 0;
  // The TCP stream layer's override, as the pipeline computes it (without SIP framing here).
  const auto tcp_for = [&](bool drop) -> std::optional<mcxanon::TcpOverride> {
    mcxanon::DissectOptions dopt;
    dopt.fcs_len = lt == 1 ? fcs : 0;
    auto seg = mcxanon::stream::segment_of(mcxanon::dissect(lt, pkt, dopt), pkt, 0);
    if (!seg) return std::nullopt;
    mcxanon::stream::TcpStreams streams({}, drop);
    std::vector<mcxanon::stream::TcpStreams::Ticket> ready;
    auto a = streams.segment(*seg, ready);
    if (!a) return std::nullopt;
    auto t = streams.take(a->ticket, true, ready);
    if (!t) std::abort();
    return mcxanon::TcpOverride{t->payload, t->seq, t->ack, t->sack, t->sack_known, t->sip};
  };
  const auto zt = tcp_for(false);
  auto z = mcxanon::rewrite_packet(lt, pkt, fcs, policy, m, o, stats, &hook, zt ? &*zt : nullptr);
  const bool sip = stats.counters.contains("payload.sip");
  if (z && !z->drop && !sip && z->data.size() != pkt.size()) std::abort();
  o.payload = mcxanon::PayloadPolicy::drop;
  const auto dt = tcp_for(true);
  (void)mcxanon::rewrite_packet(lt, pkt, 0, policy, m, o, stats, &hook, dt ? &*dt : nullptr);
  return 0;
}
