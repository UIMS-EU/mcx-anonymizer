// SPDX-License-Identifier: GPL-3.0-or-later
#include "policy/media_rules.hpp"

#include "bytes/hex.hpp"
#include "mcxanon/version.hpp"
#include "policy/ruleset_embedded.hpp"
#include "policy/yaml_util.hpp"

#include <openssl/sha.h>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <initializer_list>
#include <set>

namespace mcxanon {
namespace {

using yaml::key;
using yaml::str;

// The documents the media rule set may cite: the "Media plane" section of rules/SOURCES.md.
// Keep both lists in sync.
constexpr std::array<std::string_view, 16> kDocuments{
    "RFC 3550", "RFC 5285", "RFC 5761", "RFC 5506", "RFC 4585", "RFC 3611", "RFC 3711", "RFC 4733",
    "RFC 4975", "TS 24.380", "TS 24.581", "TS 24.582", "TS 24.282", "TS 33.180", "TS 23.003", "TS 23.032"};

constexpr std::array<std::pair<MediaAction, std::string_view>, 4> kActions{{
    {MediaAction::keep, "keep"},
    {MediaAction::pseudonymise, "pseudonymise"},
    {MediaAction::remove, "remove"},
    {MediaAction::zero, "zero"},
}};

constexpr std::array<std::pair<AppEncoding, std::string_view>, 20> kEncodings{{
    {AppEncoding::u8, "u8"},
    {AppEncoding::u16, "u16"},
    {AppEncoding::u8_spare, "u8+spare"},
    {AppEncoding::ssrc_spare, "ssrc+spare"},
    {AppEncoding::uri, "uri"},
    {AppEncoding::uri_list, "uri-list"},
    {AppEncoding::ssrc_list, "ssrc-list"},
    {AppEncoding::reject_cause, "reject-cause"},
    {AppEncoding::session_identity, "session-identity"},
    {AppEncoding::track_info, "track-info"},
    {AppEncoding::location, "location"},
    {AppEncoding::location_list, "location-list"},
    {AppEncoding::subchannel, "subchannel"},
    {AppEncoding::mbs_subchannel, "mbs-subchannel"},
    {AppEncoding::mcvideo_subchannel, "mcvideo-subchannel"},
    {AppEncoding::mcvideo_mbs_subchannel, "mcvideo-mbs-subchannel"},
    {AppEncoding::mcdm_subchannel, "mcdm-subchannel"},
    {AppEncoding::message_name, "message-name"},
    {AppEncoding::mikey, "mikey"},
    {AppEncoding::opaque, "opaque"},
}};

// § RTP and RTCP inventory: every RTP element and its only action.
constexpr std::array<std::pair<std::string_view, MediaAction>, 18> kRtpElements{{
    {"version", MediaAction::keep},
    {"padding-bit", MediaAction::keep},
    {"extension-bit", MediaAction::keep},
    {"csrc-count", MediaAction::keep},
    {"marker", MediaAction::keep},
    {"payload-type", MediaAction::keep},
    {"sequence-number", MediaAction::keep},
    {"timestamp", MediaAction::keep},
    {"ssrc", MediaAction::pseudonymise},
    {"csrc", MediaAction::pseudonymise},
    {"extension-profile", MediaAction::keep},
    {"extension-length", MediaAction::keep},
    {"extension-element-header", MediaAction::keep},
    {"extension-element-data", MediaAction::zero},
    {"payload", MediaAction::zero},
    {"padding-count", MediaAction::keep},
    {"padding-octets", MediaAction::zero},
    {"srtp-trailer", MediaAction::zero},
}};

// MSRP elements other than methods and headers, with their only action (FR-027, FR-028).
constexpr std::array<std::pair<std::string_view, MediaAction>, 3> kMsrpElements{{
    {"tid", MediaAction::pseudonymise},
    {"content", MediaAction::zero},
    {"comment", MediaAction::remove},
}};

template <typename T, std::size_t N>
std::optional<T> lookup(const std::array<std::pair<T, std::string_view>, N>& table, std::string_view name) {
  for (const auto& [v, n] : table) {
    if (n == name) return v;
  }
  return std::nullopt;
}

template <typename T, std::size_t N>
std::string_view name_of(const std::array<std::pair<T, std::string_view>, N>& table, T v) {
  for (const auto& [x, n] : table) {
    if (x == v) return n;
  }
  return "?";
}

bool action_allowed(AppEncoding e, MediaAction a) {
  if (a == MediaAction::zero || a == MediaAction::remove) return true;
  switch (e) {
    case AppEncoding::u8:
    case AppEncoding::u16:
    case AppEncoding::u8_spare:
    case AppEncoding::message_name:
    case AppEncoding::reject_cause:  // the cause is kept; the Reject Phrase is always removed
      return a == MediaAction::keep;
    case AppEncoding::opaque:
      return false;
    default:  // identities, SSRCs, locations, subchannels
      return a == MediaAction::pseudonymise;
  }
}

std::string lower(std::string_view s) {
  std::string out(s);
  for (auto& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return out;
}

std::string sha256_hex(const std::string& data) {
  std::array<unsigned char, SHA256_DIGEST_LENGTH> d{};
  SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), d.data());
  return to_hex(ByteView(d.data(), d.size()));
}

class Loader {
 public:
  explicit Loader(MediaRuleSet& rs) : rs_(rs) {}

  Result<void> file(const RuleFile& f, bool first) {
    file_ = &f;
    ryml::Tree tree = ryml::parse_in_arena(ryml::to_csubstr(f.name), ryml::to_csubstr(f.text));
    const auto root = tree.crootref();
    if (!root.is_map()) return err("top level must be a mapping");
    for (const auto c : root.children()) {
      const auto k = key(c);
      if (k != "ruleset" && k != "version" && k != "rtp" && k != "rtcp" && k != "app" && k != "msrp") {
        return err("unknown key '" + k + "'");
      }
    }
    if (!root.has_child("ruleset") || !root.has_child("version")) {
      return err("'ruleset' and 'version' are required");
    }
    const std::string name = scalar(root["ruleset"]);
    const std::string version = scalar(root["version"]);
    if (name != "mcxanon-media") return err("ruleset must be 'mcxanon-media'");
    if (version.empty()) return err("'version' must be non-empty");
    if (first) {
      rs_.name = name;
      rs_.version = version;
    } else if (version != rs_.version) {
      return err("rule set version differs from the other rule files");
    }
    if (root.has_child("rtp")) {
      if (auto r = rtp(root["rtp"]); !r) return r;
    }
    if (root.has_child("rtcp")) {
      if (auto r = rtcp(root["rtcp"]); !r) return r;
    }
    if (root.has_child("app")) {
      if (auto r = app(root["app"]); !r) return r;
    }
    if (root.has_child("msrp")) {
      if (auto r = msrp(root["msrp"]); !r) return r;
    }
    return {};
  }

  // Load-time completeness checks over all files.
  Result<void> finish() const {
    if (saw_rtp_) {
      for (const auto& [name, action] : kRtpElements) {
        if (!rs_.rtp.contains(std::string(name))) {
          return fail(ErrorCode::internal,
                      "media rule set: RTP element '" + std::string(name) + "' has no rule");
        }
      }
    }
    return {};
  }

 private:
  std::unexpected<Error> err(const std::string& msg) const {
    return std::unexpected(Error{ErrorCode::internal, "rule file " + file_->name + ": " + msg});
  }

  static std::string scalar(ryml::ConstNodeRef n) { return n.is_keyval() || n.is_val() ? str(n) : ""; }

  Result<void> only_keys(ryml::ConstNodeRef n, std::initializer_list<std::string_view> keys,
                         const std::string& what) const {
    if (!n.is_map()) return err(what + " must be a mapping");
    for (const auto c : n.children()) {
      const auto k = key(c);
      if (std::find(keys.begin(), keys.end(), k) == keys.end()) {
        return err("unknown key '" + k + "' in " + what);
      }
    }
    return {};
  }

  Result<std::string> text(ryml::ConstNodeRef n, std::string_view k, const std::string& what,
                           bool required = true) const {
    if (!n.has_child(ryml::to_csubstr(std::string(k)))) {
      if (required) return err(what + " needs '" + std::string(k) + "'");
      return std::string();
    }
    const auto c = n[ryml::to_csubstr(std::string(k))];
    if (!c.is_keyval()) return err("'" + std::string(k) + "' of " + what + " must be a scalar");
    return str(c);
  }

  Result<unsigned> number(ryml::ConstNodeRef n, std::string_view k, const std::string& what,
                          unsigned max) const {
    auto t = text(n, k, what);
    if (!t) return std::unexpected(t.error());
    unsigned v = 0;
    const auto* end = t->data() + t->size();
    const auto [p, ec] = std::from_chars(t->data(), end, v);
    if (t->empty() || ec != std::errc{} || p != end || v > max) {
      return err("'" + std::string(k) + "' of " + what + " must be a number from 0 to " +
                 std::to_string(max));
    }
    return v;
  }

  Result<bool> flag(ryml::ConstNodeRef n, std::string_view k, const std::string& what) const {
    auto t = text(n, k, what, false);
    if (!t) return std::unexpected(t.error());
    if (t->empty() || *t == "false") return false;
    if (*t == "true") return true;
    return err("'" + std::string(k) + "' of " + what + " must be true or false");
  }

  Result<Source> source(ryml::ConstNodeRef n, const std::string& what) const {
    if (!n.has_child("source") || !n["source"].is_map()) return err(what + ": rule without source");
    const auto s = n["source"];
    if (auto r = only_keys(s, {"spec", "version", "clause"}, what + " source"); !r) {
      return std::unexpected(r.error());
    }
    Source src;
    for (auto [k, dst] : {std::pair{"spec", &src.spec}, std::pair{"version", &src.version},
                          std::pair{"clause", &src.clause}}) {
      auto v = text(s, k, what + " source");
      if (!v) return std::unexpected(v.error());
      if (v->empty()) return err(what + ": empty source field '" + std::string(k) + "'");
      *dst = *v;
    }
    if (std::find(kDocuments.begin(), kDocuments.end(), src.spec) == kDocuments.end()) {
      return err(what + ": source '" + src.spec + "' is not in the list of indexed documents");
    }
    return src;
  }

  Result<MediaAction> action(ryml::ConstNodeRef n, const std::string& what) const {
    auto a = text(n, "action", what);
    if (!a) return std::unexpected(a.error());
    const auto v = lookup(kActions, *a);
    if (!v) return err("unknown action '" + *a + "' for " + what);
    return *v;
  }

  // An item with {name, action, source} and a set of allowed actions.
  Result<MediaItemRule> item(ryml::ConstNodeRef n, const std::string& what,
                             std::initializer_list<std::string_view> extra_keys,
                             std::initializer_list<MediaAction> allowed) const {
    std::vector<std::string_view> keys{"name", "action", "source"};
    keys.insert(keys.end(), extra_keys.begin(), extra_keys.end());
    if (!n.is_map()) return err(what + " must be a mapping");
    for (const auto c : n.children()) {
      if (std::find(keys.begin(), keys.end(), key(c)) == keys.end()) {
        return err("unknown key '" + key(c) + "' in " + what);
      }
    }
    MediaItemRule r;
    auto nm = text(n, "name", what, false);
    if (!nm) return std::unexpected(nm.error());
    r.name = *nm;
    auto a = action(n, what);
    if (!a) return std::unexpected(a.error());
    if (std::find(allowed.begin(), allowed.end(), *a) == allowed.end()) {
      return err("action '" + std::string(to_string(*a)) + "' not allowed for " + what);
    }
    r.action = *a;
    auto s = source(n, what);
    if (!s) return std::unexpected(s.error());
    r.source = *s;
    return r;
  }

  Result<void> rtp(ryml::ConstNodeRef n) {
    if (!n.is_seq()) return err("'rtp' must be a sequence");
    saw_rtp_ = true;
    for (const auto e : n.children()) {
      auto nm = text(e, "name", "RTP element rule");
      if (!nm) return std::unexpected(nm.error());
      const auto it = std::find_if(kRtpElements.begin(), kRtpElements.end(),
                                   [&](const auto& x) { return x.first == *nm; });
      if (it == kRtpElements.end()) return err("unknown RTP element '" + *nm + "'");
      auto r = item(e, "RTP element " + *nm, {}, {it->second});
      if (!r) return std::unexpected(r.error());
      if (!rs_.rtp.emplace(*nm, *r).second) return err("duplicate RTP element '" + *nm + "'");
    }
    return {};
  }

  Result<void> rtcp(ryml::ConstNodeRef n) {
    if (auto r = only_keys(n, {"packet_types", "sdes_items", "feedback", "xr_blocks", "bye_reason"},
                           "'rtcp'");
        !r) {
      return r;
    }
    if (n.has_child("packet_types")) {
      for (const auto e : n["packet_types"].children()) {
        auto pt = number(e, "pt", "RTCP packet type rule", 255);
        if (!pt) return std::unexpected(pt.error());
        auto r = item(e, "RTCP packet type " + std::to_string(*pt), {"pt"}, {MediaAction::keep, MediaAction::zero});
        if (!r) return std::unexpected(r.error());
        if (!rs_.rtcp.packet_types.emplace(static_cast<std::uint8_t>(*pt), *r).second) {
          return err("duplicate RTCP packet type " + std::to_string(*pt));
        }
      }
    }
    if (n.has_child("sdes_items")) {
      for (const auto e : n["sdes_items"].children()) {
        auto t = number(e, "type", "SDES item rule", 255);
        if (!t) return std::unexpected(t.error());
        // FR-010: CNAME (type 1) is pseudonymised, every other item is removed.
        const auto only = *t == 1 ? MediaAction::pseudonymise : MediaAction::remove;
        auto r = item(e, "SDES item " + std::to_string(*t), {"type"}, {only});
        if (!r) return std::unexpected(r.error());
        if (!rs_.rtcp.sdes_items.emplace(static_cast<std::uint8_t>(*t), *r).second) {
          return err("duplicate SDES item " + std::to_string(*t));
        }
      }
    }
    if (n.has_child("feedback")) {
      for (const auto e : n["feedback"].children()) {
        auto pt = number(e, "pt", "feedback rule", 255);
        if (!pt) return std::unexpected(pt.error());
        auto fmt = number(e, "fmt", "feedback rule", 31);
        if (!fmt) return std::unexpected(fmt.error());
        auto r = item(e, "feedback " + std::to_string(*pt) + "/" + std::to_string(*fmt), {"pt", "fmt"},
                      {MediaAction::keep, MediaAction::zero});
        if (!r) return std::unexpected(r.error());
        if (!rs_.rtcp.feedback.emplace(std::pair{static_cast<std::uint8_t>(*pt), static_cast<std::uint8_t>(*fmt)}, *r)
                 .second) {
          return err("duplicate feedback format " + std::to_string(*pt) + "/" + std::to_string(*fmt));
        }
      }
    }
    if (n.has_child("xr_blocks")) {
      for (const auto e : n["xr_blocks"].children()) {
        auto bt = number(e, "bt", "XR block rule", 255);
        if (!bt) return std::unexpected(bt.error());
        auto r = item(e, "XR block " + std::to_string(*bt), {"bt"}, {MediaAction::keep, MediaAction::zero});
        if (!r) return std::unexpected(r.error());
        if (!rs_.rtcp.xr_blocks.emplace(static_cast<std::uint8_t>(*bt), *r).second) {
          return err("duplicate XR block " + std::to_string(*bt));
        }
      }
    }
    if (n.has_child("bye_reason")) {
      auto r = item(n["bye_reason"], "BYE reason", {}, {MediaAction::remove});
      if (!r) return std::unexpected(r.error());
      rs_.rtcp.bye_reason = *r;
    }
    return {};
  }

  Result<void> app(ryml::ConstNodeRef n) {
    if (!n.is_seq()) return err("'app' must be a sequence");
    for (const auto e : n.children()) {
      if (auto r = only_keys(e, {"family", "names", "source", "messages", "fields"}, "APP family"); !r) return r;
      AppFamily fam;
      auto id = text(e, "family", "APP family");
      if (!id) return std::unexpected(id.error());
      if (id->empty()) return err("APP family needs a non-empty 'family'");
      fam.id = *id;
      const std::string what = "APP family " + fam.id;
      if (rs_.family_by_id(fam.id) != nullptr) return err("duplicate family '" + fam.id + "'");
      if (!e.has_child("names") || !e["names"].is_seq()) return err(what + " needs a 'names' sequence");
      for (const auto nm : e["names"].children()) {
        const std::string s = str(nm);
        if (s.size() != 4 || !std::all_of(s.begin(), s.end(), [](char c) { return c > 0x20 && c < 0x7F; })) {
          return err("APP name '" + s + "' must be 4 characters");
        }
        if (rs_.family_by_name(s) != nullptr) return err("APP name '" + s + "' is used by two families");
        fam.names.push_back({s[0], s[1], s[2], s[3]});
      }
      auto src = source(e, what);
      if (!src) return std::unexpected(src.error());
      fam.source = *src;
      if (e.has_child("messages")) {
        for (const auto m : e["messages"].children()) {
          if (auto r = only_keys(m, {"name", "subtype", "ack_variant", "source"}, what + " message"); !r) return r;
          AppMessageRule mr;
          auto nm = text(m, "name", what + " message");
          if (!nm) return std::unexpected(nm.error());
          mr.name = *nm;
          auto st = number(m, "subtype", what + " message " + mr.name, 31);
          if (!st) return std::unexpected(st.error());
          mr.subtype = static_cast<std::uint8_t>(*st);
          auto ack = flag(m, "ack_variant", what + " message " + mr.name);
          if (!ack) return std::unexpected(ack.error());
          mr.ack_variant = *ack;
          if (mr.ack_variant && mr.subtype >= 16) {
            return err(what + " message " + mr.name + ": an acknowledgement variant needs a subtype below 16");
          }
          auto ms = source(m, what + " message " + mr.name);
          if (!ms) return std::unexpected(ms.error());
          mr.source = *ms;
          for (const unsigned s : {unsigned{mr.subtype}, mr.ack_variant ? unsigned{mr.subtype} + 16u : 256u}) {
            if (s > 31) continue;
            if (!fam.messages.emplace(static_cast<std::uint8_t>(s), mr).second) {
              return err(what + ": duplicate subtype " + std::to_string(s));
            }
          }
        }
      }
      if (e.has_child("fields")) {
        for (const auto fnode : e["fields"].children()) {
          if (auto r = only_keys(fnode, {"id", "name", "encoding", "action", "source"}, what + " field"); !r) return r;
          AppFieldRule fr;
          auto fid = number(fnode, "id", what + " field", 255);
          if (!fid) return std::unexpected(fid.error());
          fr.id = static_cast<std::uint16_t>(*fid);
          auto nm = text(fnode, "name", what + " field");
          if (!nm) return std::unexpected(nm.error());
          fr.name = *nm;
          const std::string fwhat = what + " field " + std::to_string(fr.id);
          auto enc = text(fnode, "encoding", fwhat);
          if (!enc) return std::unexpected(enc.error());
          const auto e2 = lookup(kEncodings, *enc);
          if (!e2) return err("unknown encoding '" + *enc + "' for " + fwhat);
          fr.encoding = *e2;
          auto a = action(fnode, fwhat);
          if (!a) return std::unexpected(a.error());
          if (!action_allowed(fr.encoding, *a)) {
            return err("action '" + std::string(to_string(*a)) + "' not allowed for encoding '" + *enc +
                       "' (" + fwhat + ")");
          }
          fr.action = *a;
          auto fs = source(fnode, fwhat);
          if (!fs) return std::unexpected(fs.error());
          fr.source = *fs;
          if (!fam.fields.emplace(fr.id, fr).second) {
            return err(what + ": duplicate field ID " + std::to_string(fr.id));
          }
        }
      }
      rs_.app.push_back(std::move(fam));
    }
    return {};
  }

  Result<void> msrp(ryml::ConstNodeRef n) {
    if (auto r = only_keys(n, {"methods", "headers", "elements"}, "'msrp'"); !r) return r;
    if (n.has_child("methods")) {
      for (const auto e : n["methods"].children()) {
        auto r = item(e, "MSRP method", {}, {MediaAction::keep});
        if (!r) return std::unexpected(r.error());
        // RFC 4975 §9: method = mSEND / mREPORT / other-method; other-method = 1*UPALPHA.
        if (r->name.empty() ||
            !std::all_of(r->name.begin(), r->name.end(), [](char c) { return c >= 'A' && c <= 'Z'; })) {
          return err("MSRP method '" + r->name + "' must be upper-case letters");
        }
        if (!rs_.msrp.methods.emplace(r->name, *r).second) return err("duplicate MSRP method '" + r->name + "'");
      }
    }
    if (n.has_child("headers")) {
      for (const auto e : n["headers"].children()) {
        auto r = item(e, "MSRP header", {}, {MediaAction::keep, MediaAction::pseudonymise, MediaAction::remove});
        if (!r) return std::unexpected(r.error());
        if (r->name.empty()) return err("MSRP header rule needs a name");
        if (!rs_.msrp.headers.emplace(lower(r->name), MsrpHeaderRule{r->name, r->action, r->source}).second) {
          return err("duplicate MSRP header '" + r->name + "'");
        }
      }
    }
    if (n.has_child("elements")) {
      for (const auto e : n["elements"].children()) {
        auto nm = text(e, "name", "MSRP element rule");
        if (!nm) return std::unexpected(nm.error());
        const auto it = std::find_if(kMsrpElements.begin(), kMsrpElements.end(),
                                     [&](const auto& x) { return x.first == *nm; });
        if (it == kMsrpElements.end()) return err("unknown MSRP element '" + *nm + "'");
        auto r = item(e, "MSRP element " + *nm, {}, {it->second});
        if (!r) return std::unexpected(r.error());
        if (!rs_.msrp.elements.emplace(*nm, *r).second) return err("duplicate MSRP element '" + *nm + "'");
      }
    }
    return {};
  }

  MediaRuleSet& rs_;
  const RuleFile* file_ = nullptr;
  bool saw_rtp_ = false;
};

}  // namespace

const AppMessageRule* AppFamily::message(std::uint8_t subtype) const {
  const auto it = messages.find(subtype);
  return it == messages.end() ? nullptr : &it->second;
}

const AppFieldRule* AppFamily::field(std::uint16_t field_id) const {
  const auto it = fields.find(field_id);
  return it == fields.end() ? nullptr : &it->second;
}

const AppFamily* MediaRuleSet::family_by_name(std::string_view name4) const {
  if (name4.size() != 4) return nullptr;
  for (const auto& f : app) {
    for (const auto& n : f.names) {
      if (std::string_view(n.data(), 4) == name4) return &f;
    }
  }
  return nullptr;
}

const AppFamily* MediaRuleSet::family_by_id(std::string_view family) const {
  for (const auto& f : app) {
    if (f.id == family) return &f;
  }
  return nullptr;
}

std::span<const std::pair<std::string_view, MediaAction>> rtp_elements() { return kRtpElements; }

std::string_view to_string(MediaAction a) { return name_of(kActions, a); }
std::string_view to_string(AppEncoding e) { return name_of(kEncodings, e); }

Result<MediaRuleSet> load_media_ruleset(std::span<const RuleFile> files) {
  if (files.empty()) return fail(ErrorCode::internal, "media rule set has no files");
  std::vector<const RuleFile*> ordered;
  for (const auto& f : files) ordered.push_back(&f);
  std::sort(ordered.begin(), ordered.end(),
            [](const RuleFile* a, const RuleFile* b) { return a->name < b->name; });
  MediaRuleSet rs;
  Loader loader(rs);
  std::string combined;
  yaml::ScopedCallbacks callbacks;
  for (std::size_t i = 0; i < ordered.size(); ++i) {
    combined += ordered[i]->text;
    try {
      if (auto r = loader.file(*ordered[i], i == 0); !r) return std::unexpected(r.error());
    } catch (const yaml::YamlError& e) {
      return fail(ErrorCode::internal, "rule file " + ordered[i]->name + ": " + e.what());
    }
  }
  if (auto r = loader.finish(); !r) return std::unexpected(r.error());
  rs.digest = sha256_hex(combined);
  return rs;
}

Result<MediaRuleSet> load_embedded_media_ruleset() {
  std::vector<RuleFile> files;
  for (const auto& f : embedded_media_rule_files()) {
    files.push_back(RuleFile{std::string(f.name), std::string(f.text)});
  }
  return load_media_ruleset(files);
}

std::string_view embedded_media_ruleset_digest() { return media_ruleset_digest; }

}  // namespace mcxanon
