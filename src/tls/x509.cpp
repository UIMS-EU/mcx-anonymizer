// SPDX-License-Identifier: GPL-3.0-or-later
#include "tls/x509.hpp"

#include "sip/rewrite.hpp"
#include "tls/limits.hpp"
#include "xml/categories.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <functional>

namespace mcxanon::tls {

namespace {

using der::Node;
using Opt = Result<std::optional<std::string>>;
const auto kNone = std::optional<std::string>{};

bool printable_char(char c) {
  return std::isalnum(static_cast<unsigned char>(c)) != 0 || std::string_view(" '()+,-./:=?").find(c) != std::string_view::npos;
}

bool domain_shaped(std::string_view v) {
  if (v.size() < 3 || v.find('.') == std::string_view::npos || v.front() == '.' || v.back() == '.') return false;
  return std::all_of(v.begin(), v.end(), [](char c) { return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '-' || c == '.'; });
}

// Text of a DirectoryString-like value and back, keeping the string type (BMPString as UTF-16BE,
// ASCII only; UniversalString is not rewritten).
std::optional<std::string> text_of(const Node& n) {
  if (n.tag == der::kBmp) {
    if (n.content.size() % 2 != 0) return std::nullopt;
    std::string t;
    for (std::size_t i = 0; i < n.content.size(); i += 2) {
      if (n.content[i] != 0 || static_cast<unsigned char>(n.content[i + 1]) >= 0x80) return std::nullopt;
      t.push_back(n.content[i + 1]);
    }
    return t;
  }
  if (n.tag == der::kUniversal) return std::nullopt;
  return n.content;
}

bool set_text(Node& n, const std::string& t) {
  if (n.tag == der::kPrintable && !std::all_of(t.begin(), t.end(), printable_char)) return false;
  if (n.tag == der::kBmp) {
    std::string c;
    for (char ch : t) {
      c.push_back('\0');
      c.push_back(ch);
    }
    n.content = std::move(c);
    return true;
  }
  n.content = t;
  return true;
}

void zero(Node& n) {
  if (n.constructed()) {
    for (auto& c : n.children) zero(c);
  } else {
    std::fill(n.content.begin(), n.content.end(), '\0');
  }
}

Result<bool> map_bytes(std::string& content, Env& env) {
  if (content.empty() || content.size() > 255) return content.empty();
  auto b = env.sip.mapper.bytes(Category::nonce, ByteView(reinterpret_cast<const std::uint8_t*>(content.data()), content.size()));
  if (!b) return std::unexpected(b.error());
  content.assign(b->begin(), b->end());
  return true;
}

// A positive, minimal INTEGER of the same length (RFC 5280 §4.1.2.2): the serial number.
Result<bool> map_serial(std::string& c, Env& env) {
  if (c.empty()) return false;
  const bool lead = c.size() > 1 && c[0] == '\0';
  std::string body = lead ? c.substr(1) : c;
  auto ok = map_bytes(body, env);
  if (!ok || !*ok) return ok;
  if (lead) {
    body[0] = static_cast<char>(static_cast<unsigned char>(body[0]) | 0x80);
  } else {
    body[0] = static_cast<char>(static_cast<unsigned char>(body[0]) & 0x7F);
    if (body.size() > 1 && body[0] == '\0') body[0] = 1;
  }
  c = lead ? std::string(1, '\0') + body : body;
  return true;
}

Opt general_uri(std::string_view v, Env& env) {
  auto m = xml::map_category(XmlCategory::web_uri, v, env.sip);
  if (!m || *m) return m;
  return map_opaque(v, env);
}

// GeneralName (RFC 5280 §4.2.1.6) by kind, in place: false when it must be zeroed.
Result<bool> general_name(Node& g, Env& env) {
  switch (g.tag) {
    case 0x81: {  // rfc822Name
      const auto at = g.content.find('@');
      Opt m = at == std::string::npos ? Opt(kNone) : xml::map_category(XmlCategory::user_at_host, g.content, env.sip);
      if (!m) return std::unexpected(m.error());
      if (!*m) return false;
      g.content = **m;
      return true;
    }
    case 0x82: {  // dNSName, a wildcard label kept
      const bool wild = g.content.starts_with("*.");
      auto m = sip::map_host(wild ? std::string_view(g.content).substr(2) : std::string_view(g.content), env.sip);
      if (!m) return std::unexpected(m.error());
      if (!*m) return false;
      g.content = (wild ? "*." : "") + **m;
      return true;
    }
    case 0x86: {  // uniformResourceIdentifier
      auto m = general_uri(g.content, env);
      if (!m) return std::unexpected(m.error());
      if (!*m) return false;
      g.content = **m;
      return true;
    }
    case 0x87: {  // iPAddress (address, or address and mask in name constraints)
      if (g.content.size() == 4) {
        const auto* p = reinterpret_cast<const std::uint8_t*>(g.content.data());
        auto a = env.sip.mapper.ipv4((std::uint32_t{p[0]} << 24) | (std::uint32_t{p[1]} << 16) | (std::uint32_t{p[2]} << 8) | p[3]);
        if (!a) return std::unexpected(a.error());
        for (int i = 0; i < 4; ++i) g.content[static_cast<std::size_t>(i)] = static_cast<char>((*a >> (24 - 8 * i)) & 0xFF);
        return true;
      }
      if (g.content.size() == 16) {
        Ipv6Addr in{};
        std::copy(g.content.begin(), g.content.end(), in.begin());
        auto a = env.sip.mapper.ipv6(in);
        if (!a) return std::unexpected(a.error());
        g.content.assign(a->begin(), a->end());
        return true;
      }
      return false;
    }
    case 0xa4: {  // directoryName
      if (g.children.size() != 1) return false;
      return rewrite_name(g.children[0], env);
    }
    default: return false;  // otherName, x400Address, ediPartyName, registeredID: zeroed
  }
}

// Every GeneralName below `n` (SAN, IAN, AIA, CRL distribution points, AKI issuer). `names`: the
// children of `n` are GeneralNames themselves (SAN, IAN, AKI issuer), so an otherName [0] and the
// other constructed kinds are zeroed; otherwise constructed context tags are structure (the
// [0] distributionPoint and [0] fullName of a CRL distribution point) and are walked.
Result<void> general_names(Node& n, Env& env, bool names, std::uint8_t parent = 0) {
  for (auto& c : n.children) {
    const auto t = c.tag;
    const bool primitive_name = t == 0x81 || t == 0x82 || t == 0x86 || t == 0x87 || t == 0x88;
    if (primitive_name || t == 0xa4 || (names && (t == 0xa0 || t == 0xa3 || t == 0xa5))) {
      auto ok = general_name(c, env);
      if (!ok) return std::unexpected(ok.error());
      if (!*ok) zero(c);
      continue;
    }
    if (c.constructed()) {
      // CRL distribution point: [0] distributionPoint { [0] fullName GeneralNames }, [2] cRLIssuer.
      const bool inner_names = (t == 0xa0 && parent == 0xa0) || t == 0xa2;
      if (auto r = general_names(c, env, inner_names, t); !r) return r;
    } else if (der::is_string_type(t)) {
      zero(c);  // a string outside a name kind: not classified
    }
  }
  return {};
}

std::string ext_name(const TlsRuleSet& rules, const std::string& oid) {
  const auto* r = rules.find_x509_extension(oid);
  return r != nullptr ? r->name : "unknown";
}

Result<void> extension(Node& ext, Env& env) {
  // Extension ::= SEQUENCE { extnID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }
  if (ext.tag != der::kSequence || ext.children.size() < 2 || ext.children.front().tag != der::kOid ||
      ext.children.back().tag != der::kOctetString) {
    zero(ext);
    return {};
  }
  const auto oid = der::oid_text(ext.children.front().content);
  const auto* rule = env.rules.find_x509_extension(oid);
  Node& value = ext.children.back();
  const auto action = rule != nullptr ? rule->action : X509ExtensionAction::zero;
  Counters::bump(env.counters.x509, ext_name(env.rules, oid), action == X509ExtensionAction::keep ? "kept" : action == X509ExtensionAction::zero ? "zeroed" : "pseudonymised");
  if (action == X509ExtensionAction::keep) return {};
  if (action == X509ExtensionAction::zero) {
    std::fill(value.content.begin(), value.content.end(), '\0');
    return {};
  }
  auto inner = der::parse(value.content);
  if (!inner) {
    std::fill(value.content.begin(), value.content.end(), '\0');
    return {};
  }
  switch (action) {
    case X509ExtensionAction::general_names:
      if (auto r = general_names(*inner, env, true); !r) return r;
      break;
    case X509ExtensionAction::uri_access:
      if (auto r = general_names(*inner, env, false); !r) return r;
      break;
    case X509ExtensionAction::key_identifier: {
      if (inner->tag != der::kOctetString) {
        zero(*inner);
        break;
      }
      auto ok = map_bytes(inner->content, env);
      if (!ok) return std::unexpected(ok.error());
      break;
    }
    case X509ExtensionAction::authority_key_identifier:
      for (auto& c : inner->children) {
        if (c.tag == 0x80) {
          auto ok = map_bytes(c.content, env);
          if (!ok) return std::unexpected(ok.error());
        } else if (c.tag == 0xa1) {
          if (auto r = general_names(c, env, true); !r) return r;
        } else if (c.tag == 0x82) {
          auto ok = map_serial(c.content, env);
          if (!ok) return std::unexpected(ok.error());
        } else {
          zero(c);
        }
      }
      break;
    case X509ExtensionAction::policies: {
      // PolicyInformation: OIDs kept; CPS URIs (IA5String) mapped; user notice texts zeroed.
      std::function<Result<void>(Node&)> walk = [&](Node& n) -> Result<void> {
        for (auto& c : n.children) {
          if (c.tag == der::kIa5) {
            auto m = general_uri(c.content, env);
            if (!m) return std::unexpected(m.error());
            if (*m) c.content = **m;
            else zero(c);
          } else if (der::is_string_type(c.tag) || c.tag == der::kInteger) {
            if (c.tag != der::kInteger) zero(c);
          } else if (c.constructed()) {
            if (auto r = walk(c); !r) return r;
          }
        }
        return {};
      };
      if (auto r = walk(*inner); !r) return r;
      break;
    }
    default: break;
  }
  value.content = der::write(*inner);
  return {};
}

Result<void> public_key(Node& spki, Env& env) {
  // SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
  if (spki.children.size() != 2 || spki.children[0].children.empty() || spki.children[1].tag != der::kBitString ||
      spki.children[1].content.empty()) {
    zero(spki);
    return {};
  }
  const auto oid = der::oid_text(spki.children[0].children[0].content);
  const auto* rule = env.rules.find_public_key(oid);
  auto& bits = spki.children[1].content;
  const auto action = rule != nullptr ? rule->action : PublicKeyAction::zero;
  Counters::bump(env.counters.x509, rule != nullptr ? rule->name : "unknown-key", "zeroed");
  if (action == PublicKeyAction::rsa) {
    // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER } (RFC 3279 §2.3.1)
    auto k = der::parse(std::string_view(bits).substr(1));
    if (k && k->children.size() == 2 && k->children[0].tag == der::kInteger && !k->children[0].content.empty()) {
      auto& m = k->children[0].content;
      const bool lead = m.size() > 1 && m[0] == '\0';
      std::fill(m.begin(), m.end(), '\0');
      if (lead) m[1] = static_cast<char>(0x80);
      else m[0] = static_cast<char>(0x40);
      bits = bits.substr(0, 1) + der::write(*k);
      return {};
    }
  } else if (action == PublicKeyAction::ec && bits.size() > 2) {
    // ECPoint: the format octet (RFC 5480 §2.2) kept, coordinates zeroed.
    std::fill(bits.begin() + 2, bits.end(), '\0');
    return {};
  }
  std::fill(bits.begin() + 1, bits.end(), '\0');
  return {};
}

}  // namespace

Result<std::optional<std::string>> map_opaque(std::string_view v, Env& env) {
  if (v.empty()) return std::optional<std::string>(std::string());
  if (v.size() < 4 && std::all_of(v.begin(), v.end(), [](char c) {
        return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '.' || c == '_' || c == '-';
      })) {
    return std::optional<std::string>(std::string(v));
  }
  auto p = env.sip.mapper.text(Category::opaque, v);
  if (!p) return std::unexpected(p.error());
  return std::optional<std::string>(std::move(*p));
}

Result<std::optional<std::string>> map_identity(std::string_view v, Env& env) {
  if (v.starts_with("sip:") || v.starts_with("sips:") || v.starts_with("tel:") || v.starts_with("http://") ||
      v.starts_with("https://")) {
    auto m = xml::map_category(XmlCategory::web_uri, v, env.sip);
    if (!m || *m) return m;
  } else if (v.find('@') != std::string_view::npos && v.find(':') == std::string_view::npos) {
    auto m = xml::map_category(XmlCategory::user_at_host, v, env.sip);
    if (!m || *m) return m;
  } else if (domain_shaped(v) || v.starts_with("*.")) {
    const bool wild = v.starts_with("*.");
    auto m = sip::map_host(wild ? v.substr(2) : v, env.sip);
    if (!m) return m;
    if (*m) return std::optional<std::string>((wild ? "*." : "") + **m);
  }
  return map_opaque(v, env);
}

Result<bool> rewrite_name(Node& name, Env& env) {
  // Name ::= RDNSequence ::= SEQUENCE OF SET OF AttributeTypeAndValue
  if (name.tag != der::kSequence) return false;
  for (auto& rdn : name.children) {
    if (rdn.tag != der::kSet) return false;
    for (auto& atv : rdn.children) {
      if (atv.tag != der::kSequence || atv.children.size() != 2 || atv.children[0].tag != der::kOid) return false;
      const auto oid = der::oid_text(atv.children[0].content);
      const auto* rule = env.rules.find_attribute(oid);
      const auto action = rule != nullptr ? rule->action : X509AttributeAction::opaque;
      Node& v = atv.children[1];
      Counters::bump(env.counters.x509, rule != nullptr ? rule->name : "unknown-attribute",
                     action == X509AttributeAction::keep ? "kept" : "pseudonymised");
      if (action == X509AttributeAction::keep) continue;
      const auto text = der::is_string_type(v.tag) ? text_of(v) : std::nullopt;
      if (!text) {
        zero(v);
        continue;
      }
      Result<std::optional<std::string>> m = kNone;
      switch (action) {
        case X509AttributeAction::identity: m = map_identity(*text, env); break;
        case X509AttributeAction::email: m = xml::map_category(XmlCategory::user_at_host, *text, env.sip); break;
        case X509AttributeAction::domain_label: m = map_opaque(*text, env); break;
        default: m = map_opaque(*text, env); break;
      }
      if (!m) return std::unexpected(m.error());
      if (!*m || !set_text(v, **m)) zero(v);
    }
  }
  return true;
}

Result<std::optional<std::string>> rewrite_certificate(std::string_view der_bytes, Env& env) {
  if (der_bytes.size() > kMaxCertificate) return kNone;
  auto cert = der::parse(der_bytes);
  // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue BIT STRING }
  if (!cert || cert->tag != der::kSequence || cert->children.size() != 3 || cert->children[0].tag != der::kSequence ||
      cert->children[2].tag != der::kBitString) {
    return kNone;
  }
  auto& tbs = cert->children[0].children;
  std::size_t i = 0;
  if (i < tbs.size() && tbs[i].tag == 0xa0) ++i;  // version
  if (i + 6 > tbs.size() || tbs[i].tag != der::kInteger) return kNone;
  if (auto ok = map_serial(tbs[i].content, env); !ok) return std::unexpected(ok.error());
  i += 2;                                          // serialNumber, signature
  if (auto ok = rewrite_name(tbs[i], env); !ok) return std::unexpected(ok.error());
  else if (!*ok) return kNone;
  i += 2;                                          // issuer, validity (kept, R24)
  if (auto ok = rewrite_name(tbs[i], env); !ok) return std::unexpected(ok.error());
  else if (!*ok) return kNone;
  ++i;
  if (auto r = public_key(tbs[i], env); !r) return std::unexpected(r.error());
  for (++i; i < tbs.size(); ++i) {
    if (tbs[i].tag == 0x81 || tbs[i].tag == 0x82) {
      zero(tbs[i]);  // unique identifiers
    } else if (tbs[i].tag == 0xa3 && tbs[i].children.size() == 1) {
      if (tbs[i].children[0].children.size() > kMaxExtensions) return kNone;
      for (auto& ext : tbs[i].children[0].children) {
        if (auto r = extension(ext, env); !r) return std::unexpected(r.error());
      }
    } else {
      return kNone;
    }
  }
  auto& sig = cert->children[2].content;
  if (!sig.empty()) std::fill(sig.begin() + 1, sig.end(), '\0');
  ++env.counters.certificates_rewritten;
  return std::optional<std::string>(der::write(*cert));
}

}  // namespace mcxanon::tls
