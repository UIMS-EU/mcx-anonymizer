// SPDX-License-Identifier: GPL-3.0-or-later
#include "media/app.hpp"

#include "media/wire.hpp"
#include "sip/rewrite.hpp"

#include <algorithm>
#include <cctype>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace mcxanon::media {
namespace {

std::string_view as_text(ByteView v) { return {reinterpret_cast<const char*>(v.data()), v.size()}; }
Bytes as_bytes(std::string_view s) { return Bytes(s.begin(), s.end()); }

bool printable(ByteView v) {
  return !v.empty() && std::all_of(v.begin(), v.end(), [](std::uint8_t c) { return c >= 0x20 && c < 0x7F; });
}

// The fixed value size of an encoding, 0 for variable-size encodings.
std::size_t fixed_size(AppEncoding e) {
  switch (e) {
    case AppEncoding::u8: return 1;
    case AppEncoding::u16:
    case AppEncoding::u8_spare: return 2;
    case AppEncoding::ssrc_spare:
    case AppEncoding::message_name: return 6;
    default: return 0;
  }
}

// The outcome of one field: the new value, or removed.
struct FieldOut {
  bool keep = false;  // emit the field with `value`
  Bytes value;
  std::string action;  // counted under app.fields: keep, pseudonymise, zero, remove, malformed
};

FieldOut removed(const char* action = "remove") { return {false, {}, action}; }
FieldOut kept(Bytes v, const char* action) { return {true, std::move(v), action}; }

class App {
 public:
  explicit App(RtcpEnv& env) : env_(env) {}

  Result<FieldOut> field(const AppFieldRule& r, ByteView v) {
    if (r.action == MediaAction::remove) {
      note_removed(v);
      return removed();
    }
    if (r.action == MediaAction::zero) return kept(Bytes(v.size(), 0), "zero");
    if (const auto n = fixed_size(r.encoding); n != 0) return fixed(r, v, n);
    switch (r.encoding) {
      case AppEncoding::uri: {
        auto u = uri(v);
        if (!u) return std::unexpected(u.error());
        if (!*u) return removed("malformed");
        return kept(std::move(**u), "pseudonymise");
      }
      case AppEncoding::uri_list: return uri_list(v);
      case AppEncoding::ssrc_list: return ssrc_list(v);
      case AppEncoding::reject_cause: return reject_cause(v);
      case AppEncoding::session_identity: {
        if (v.size() < 2) return removed("malformed");
        auto u = uri(v.subspan(1));
        if (!u) return std::unexpected(u.error());
        if (!*u) return removed("malformed");
        Bytes out{v[0]};
        out.insert(out.end(), (*u)->begin(), (*u)->end());
        return kept(std::move(out), "pseudonymise");
      }
      case AppEncoding::track_info: return track_info(v);
      case AppEncoding::location: return location(v);
      case AppEncoding::location_list: return location_list(v);
      case AppEncoding::subchannel:
      case AppEncoding::mbs_subchannel:
      case AppEncoding::mcvideo_subchannel:
      case AppEncoding::mcvideo_mbs_subchannel:
      case AppEncoding::mcdm_subchannel: return subchannel(r.encoding, v);
      case AppEncoding::mikey: return mikey(v);
      default: return kept(Bytes(v.size(), 0), "zero");
    }
  }

 private:
  // The PCK I_MESSAGE field (TS 24.380 §8.3.3.10, feature 005): the MIKEY carrier rewrites it in
  // its own form (binary or base64); on its fallback, or without one, the field is zeroed with its
  // length (FR-020 d). The field length is 16 bits (§8.1.3), so the result must fit.
  Result<FieldOut> mikey(ByteView v) {
    if (env_.sip.mikey == nullptr) return kept(Bytes(v.size(), 0), "zero");
    sip::MikeyOutcome outcome;
    auto r = env_.sip.mikey->rewrite(sip::MikeyCarrierKind::mcpc, as_text(v), {}, outcome, env_.sip);
    if (!r) return std::unexpected(r.error());
    if (!*r || (*r)->size() > 0xFFFF) return kept(Bytes(v.size(), 0), "zero");
    return kept(as_bytes(**r), outcome.kind == sip::MikeyOutcome::Kind::passed_through ? "keep" : "pseudonymise");
  }

  void note_removed(ByteView v) {
    if (printable(v)) env_.counters.removed(as_text(v));
  }

  // Fixed-size values (A11): shorter is malformed; longer keeps the defined octets and zeroes
  // the rest, which a later version of the protocol may define.
  Result<FieldOut> fixed(const AppFieldRule& r, ByteView v, std::size_t n) {
    if (v.size() < n) return removed("malformed");
    Bytes out(v.begin(), v.end());
    zero(out, n, out.size());
    if (r.encoding == AppEncoding::ssrc_spare) {
      auto m = env_.mapper.ssrc(get32(out, 0));
      if (!m) return std::unexpected(m.error());
      set32(out, 0, *m);
      zero(out, 4, out.size());  // spare
      return kept(std::move(out), "pseudonymise");
    }
    if (r.encoding == AppEncoding::message_name) {
      // The 4-octet name of the acknowledged message (TS 24.581 §9.2.3.18): kept only when it
      // is a name the rules know.
      if (env_.rules.family_by_name(as_text(ByteView(out).first(4))) == nullptr) zero(out, 0, 4);
      zero(out, 4, out.size());
    }
    return kept(std::move(out), "keep");
  }

  // A URI value: the SIP URI mapping, so that it gets the pseudonym SIP gives it (SC-003); the
  // anonymous identity of TS 24.380 §8.3.4 too, as SIP treats it.
  Result<std::optional<Bytes>> uri(ByteView v) {
    if (!printable(v)) return std::optional<Bytes>{};
    const auto text = as_text(v);
    auto r = sip::rewrite_uri_text(text, env_.sip);
    if (!r) return std::unexpected(r.error());
    if (!*r) {
      env_.counters.removed(text);
      return std::optional<Bytes>{};
    }
    return std::optional<Bytes>(as_bytes(**r));
  }

  // count(1), then (length, URI) pairs; the entry length is 1 octet (TS 24.380 §8.1.3), or 2
  // octets as the List of Queued Users figure draws it (A5): the width that consumes the value
  // exactly (up to 3 trailing zero octets) is used, and kept on output.
  Result<FieldOut> uri_list(ByteView v) {
    if (v.empty()) return removed("malformed");
    for (const std::size_t w : {std::size_t{1}, std::size_t{2}}) {
      std::vector<ByteView> items;
      std::size_t i = 1;
      bool ok = true;
      for (std::size_t k = 0; k < v[0] && ok; ++k) {
        if (i + w > v.size()) {
          ok = false;
          break;
        }
        const std::size_t len = w == 1 ? v[i] : get16(v, i);
        if (len == 0 || i + w + len > v.size()) {
          ok = false;
          break;
        }
        items.push_back(v.subspan(i + w, len));
        i += w + len;
      }
      if (!ok || v.size() - i > 3 || !std::all_of(v.begin() + static_cast<std::ptrdiff_t>(i), v.end(),
                                                  [](std::uint8_t b) { return b == 0; })) {
        continue;
      }
      Bytes out{v[0]};
      for (const auto item : items) {
        auto u = uri(item);
        if (!u) return std::unexpected(u.error());
        if (!*u || (w == 1 && (*u)->size() > 255) || (*u)->size() > 0xFFFF) return removed("malformed");
        if (w == 1) {
          out.push_back(static_cast<std::uint8_t>((*u)->size()));
        } else {
          put16(out, static_cast<std::uint16_t>((*u)->size()));
        }
        out.insert(out.end(), (*u)->begin(), (*u)->end());
      }
      return kept(std::move(out), "pseudonymise");
    }
    return removed("malformed");
  }

  // count(1), spare(1), count x 32-bit SSRC (TS 24.380 §8.2.3.18).
  Result<FieldOut> ssrc_list(ByteView v) {
    if (v.size() < 2 || v.size() != 2 + 4 * std::size_t{v[0]}) return removed("malformed");
    Bytes out(v.begin(), v.end());
    out[1] = 0;
    for (std::size_t o = 2; o < out.size(); o += 4) {
      auto m = env_.mapper.ssrc(get32(out, o));
      if (!m) return std::unexpected(m.error());
      set32(out, o, *m);
    }
    return kept(std::move(out), "pseudonymise");
  }

  // 16-bit cause + optional Reject Phrase (TS 24.380 §8.2.3.4): the phrase is free text and is
  // removed; "If the length field is set to '2', there is no <Reject Phrase>" (P5).
  Result<FieldOut> reject_cause(ByteView v) {
    if (v.size() < 2) return removed("malformed");
    if (v.size() > 2) note_removed(v.subspan(2));
    return kept(Bytes(v.begin(), v.begin() + 2), "keep");
  }

  // Track Info (TS 24.380 §8.2.3.13, TS 24.581 §9.2.3.13): Queueing Capability, Participant
  // Type Length, Participant Type padded to a multiple of 4, then 32-bit references. Both
  // length conventions are accepted (A4, B7) and the input's is kept. Participant Type becomes
  // "unknown" (TS 24.380 §6.5.4.2, FR-019); references use the fc_ref mapping.
  Result<FieldOut> track_info(ByteView v) {
    if (v.size() < 2) return removed("malformed");
    const std::size_t ptl = v[1];
    const std::size_t padded = (ptl + 3) / 4 * 4;
    std::size_t refs = 0;
    bool padded_convention = true;
    if (v.size() >= 2 + padded && (v.size() - 2 - padded) % 4 == 0) {
      refs = 2 + padded;
    } else if (v.size() >= 2 + ptl && (v.size() - 2 - ptl) % 4 == 0) {
      refs = 2 + ptl;
      padded_convention = false;
    } else {
      return removed("malformed");
    }
    if (ptl > 0) note_removed(v.subspan(2, ptl));
    constexpr std::string_view kUnknown = "unknown";
    Bytes out{v[0], static_cast<std::uint8_t>(kUnknown.size())};
    out.insert(out.end(), kUnknown.begin(), kUnknown.end());
    if (padded_convention) {
      while (out.size() < 2 + (kUnknown.size() + 3) / 4 * 4) out.push_back(0);
    }
    for (std::size_t o = refs; o + 4 <= v.size(); o += 4) {
      auto m = env_.mapper.binary(Category::fc_ref, get32(v, o));
      if (!m) return std::unexpected(m.error());
      put32(out, *m);
    }
    return kept(std::move(out), "pseudonymise");
  }

  // A 32-bit port container (TS 24.380 §8.4.3.3: "a 32-bit binary value"): the 001 port policy on
  // the low 16 bits; non-zero high bits are not a port (A8).
  Result<bool> port32(Bytes& b, std::size_t off) {
    const std::uint32_t v = get32(b, off);
    if ((v >> 16) != 0) return false;
    if (env_.sip.options.pseudonymise_ports) {
      auto p = env_.mapper.port(static_cast<std::uint16_t>(v));
      if (!p) return std::unexpected(p.error());
      set32(b, off, *p);
    }
    return true;
  }

  // MBMS / MBS Subchannel fields (TS 24.380 §8.4.3.3, §8.6.3.3; TS 24.581 §9.3.3.3, §9.5.3.3;
  // TS 24.582 §11.2.3.3): m-line numbers and IP version kept, ports by the port policy, the
  // floor or transmission control SSRC by the SSRC mapping, the address by the 001 address
  // mapping (FR-022). A layout that does not match its m-line numbers is zeroed.
  Result<FieldOut> subchannel(AppEncoding e, ByteView v) {
    Bytes out(v.begin(), v.end());
    std::size_t o = 0;
    std::vector<std::size_t> ports;
    std::optional<std::size_t> ssrc_at;
    unsigned ipv = 0;
    const auto need = [&](std::size_t n) { return o + n <= out.size(); };
    switch (e) {
      case AppEncoding::subchannel:
      case AppEncoding::mbs_subchannel: {
        if (!need(2)) return kept(Bytes(v.size(), 0), "zero");
        const unsigned floor = out[0] & 0x0Fu;
        ipv = out[1] >> 4;
        o = 2;
        if (floor > 0) {
          ports.push_back(o);
          o += 4;
        }
        if (e == AppEncoding::mbs_subchannel) {
          ssrc_at = o;
          o += 4;
        }
        ports.push_back(o);  // media port
        o += 4;
        break;
      }
      case AppEncoding::mcvideo_subchannel:
      case AppEncoding::mcvideo_mbs_subchannel: {
        if (!need(6)) return kept(Bytes(v.size(), 0), "zero");
        const unsigned audio = out[0] & 0x0Fu, control = out[1] >> 4, fec = out[1] & 0x0Fu;
        ipv = out[2] >> 4;
        o = 6;
        if (control > 0) {
          ports.push_back(o);
          o += 4;
        }
        if (e == AppEncoding::mcvideo_mbs_subchannel) {
          ssrc_at = o;
          o += 4;
        }
        ports.push_back(o);  // video media port
        o += 4;
        if (audio > 0) {
          ports.push_back(o);
          o += 4;
        }
        if (fec > 0) {
          ports.push_back(o);
          o += 4;
        }
        break;
      }
      case AppEncoding::mcdm_subchannel:
        if (!need(2)) return kept(Bytes(v.size(), 0), "zero");
        ipv = out[1] >> 4;
        o = 2;
        ports.push_back(o);
        o += 4;
        break;
      default: return kept(Bytes(v.size(), 0), "zero");
    }
    const std::size_t addr = ipv == 0 ? 4 : ipv == 1 ? 16 : 0;
    if (addr == 0 || o + addr != out.size()) return kept(Bytes(v.size(), 0), "zero");
    for (const auto at : ports) {
      auto ok = port32(out, at);
      if (!ok) return std::unexpected(ok.error());
      if (!*ok) return kept(Bytes(v.size(), 0), "zero");
    }
    if (ssrc_at) {
      auto m = env_.mapper.ssrc(get32(out, *ssrc_at));
      if (!m) return std::unexpected(m.error());
      set32(out, *ssrc_at, *m);
    }
    if (addr == 4) {
      auto m = env_.mapper.ipv4(get32(out, o));
      if (!m) return std::unexpected(m.error());
      set32(out, o, *m);
    } else {
      Ipv6Addr a{};
      std::copy(out.begin() + static_cast<std::ptrdiff_t>(o), out.end(), a.begin());
      auto m = env_.mapper.ipv6(a);
      if (!m) return std::unexpected(m.error());
      std::copy(m->begin(), m->end(), out.begin() + static_cast<std::ptrdiff_t>(o));
    }
    return kept(std::move(out), "pseudonymise");
  }

  // Location (TS 24.380 §8.2.3.21): one item exactly; anything else is zeroed with its length.
  Result<FieldOut> location(ByteView v) {
    Bytes out(v.begin(), v.end());
    auto n = rewrite_location_item(out, 0, out.size(), env_.mapper);
    if (!n) return std::unexpected(n.error());
    if (!*n || **n != out.size()) return kept(Bytes(v.size(), 0), "zero");
    return kept(std::move(out), "pseudonymise");
  }

  // List of Locations (TS 24.380 §8.2.3.22): count, then items without a per-item length; an
  // item that cannot be decoded zeroes the rest of the value (A6).
  Result<FieldOut> location_list(ByteView v) {
    if (v.empty()) return removed("malformed");
    Bytes out(v.begin(), v.end());
    std::size_t i = 1;
    for (std::size_t k = 0; k < v[0]; ++k) {
      auto n = rewrite_location_item(out, i, out.size(), env_.mapper);
      if (!n) return std::unexpected(n.error());
      if (!*n) {
        zero(out, i, out.size());
        return kept(std::move(out), "pseudonymise");
      }
      i += **n;
    }
    zero(out, i, out.size());
    return kept(std::move(out), "pseudonymise");
  }

  RtcpEnv& env_;
};

void emit_field(Bytes& out, std::uint16_t id, const Bytes& value) {
  const std::size_t start = out.size();
  out.push_back(static_cast<std::uint8_t>(id));
  if (id < 192) {
    out.push_back(static_cast<std::uint8_t>(value.size()));
  } else {
    put16(out, static_cast<std::uint16_t>(value.size()));
  }
  out.insert(out.end(), value.begin(), value.end());
  while ((out.size() - start) % 4 != 0) out.push_back(0);
}

}  // namespace

Result<Bytes> rewrite_app(ByteView packet, RtcpEnv& env) {
  Bytes b(packet.begin(), packet.end());
  auto& c = env.counters;
  if (b.size() >= 8) {
    auto m = env.mapper.ssrc(get32(b, 4));
    if (!m) return std::unexpected(m.error());
    set32(b, 4, *m);
  }
  if (b.size() < 12 || (b[0] & 0x20) != 0) {  // P is '0' (TS 24.380 §8.1.2)
    ++c.app_unknown["malformed"];
    zero(b, std::min<std::size_t>(8, b.size()), b.size());
    return b;
  }
  const std::string name(reinterpret_cast<const char*>(b.data() + 8), 4);
  const AppFamily* fam = env.rules.family_by_name(name);
  if (fam == nullptr) {
    // FR-014: an APP packet with another name is removed; its name (4 octets of the input) and
    // data do not leave the tool, and the datagram stays decodable.
    ++c.app_unknown["name"];
    return Bytes{};
  }
  const std::uint8_t subtype = b[0] & 0x1F;
  if (fam->message(subtype) == nullptr) {
    // TS 24.380 §8.1.4: "ignore the whole message, if the subtype is unknown" (FR-015).
    ++c.app_unknown["subtype"];
    zero(b, 12, b.size());
    return b;
  }
  ++c.app_messages[name + "/" + std::to_string(subtype)];
  App a(env);
  Bytes out(b.begin(), b.begin() + 12);
  std::size_t i = 12;
  while (i < b.size()) {
    const std::uint8_t id = b[i];
    const std::size_t h = id < 192 ? 2 : 3;
    if (b.size() - i < h) {
      ++c.app_unknown["malformed"];
      break;
    }
    const std::size_t len = id < 192 ? b[i + 1] : get16(b, i + 1);
    if (len > b.size() - i - h) {
      // A field that overruns the packet: nothing after it can be framed (FR-016, FR-030).
      ++c.app_unknown["malformed"];
      break;
    }
    const ByteView v = ByteView(b).subspan(i + h, len);
    i = std::min(b.size(), i + (h + len + 3) / 4 * 4);
    const AppFieldRule* rule = fam->field(id);
    if (rule == nullptr) {
      // TS 24.380 §8.1.4: unspecified fields are ignored; here they are removed (FR-016).
      ++c.app_unknown["field"];
      if (printable(v)) c.removed(as_text(v));
      continue;
    }
    auto f = a.field(*rule, v);
    if (!f) return std::unexpected(f.error());
    c.count(c.app_fields, fam->id + "/" + std::to_string(id), f->action);
    if (f->keep) {
      if (id < 192 && f->value.size() > 255) {
        c.count(c.app_fields, fam->id + "/" + std::to_string(id), "malformed");
        continue;
      }
      emit_field(out, id, f->value);
    }
  }
  // FR-023: the APP length in 32-bit words minus one.
  set16(out, 2, static_cast<std::uint16_t>(out.size() / 4 - 1));
  return out;
}

}  // namespace mcxanon::media
