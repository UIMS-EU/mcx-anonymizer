// SPDX-License-Identifier: GPL-3.0-or-later
//
// Encrypted XML content in ciphertext mode (spec FR-016, US4).
// xenc:EncryptedData keeps its allowlisted structure, the XPK-ID in ds:KeyName takes the key
// identifier pseudonym (base64) and the CipherValue is kept byte for byte; anything outside the
// allowlist is removed and counted.
#include "bytes/base64.hpp"
#include "pipeline/mapper_adapter.hpp"
#include "policy/sip_rules.hpp"
#include "policy/xml_rules.hpp"
#include "pseudo/pseudonymiser.hpp"
#include "xml/rewrite.hpp"
#include "xml/sip_bodies.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace mcxanon;

namespace {

constexpr const char* kInfoCt = "application/vnd.3gpp.mcptt-info+xml";
constexpr const char* kXenc = "http://www.w3.org/2001/04/xmlenc#";
constexpr std::uint32_t kXpk = 0x2A0B0C0Du;  // a CSK-ID (purpose tag 2)

Secret secret() {
  Secret s{};
  for (std::size_t i = 0; i < s.size(); ++i) s[i] = static_cast<std::uint8_t>(i * 29 + 7);
  return s;
}

std::string b64(std::uint32_t v) {
  const Bytes b{static_cast<std::uint8_t>(v >> 24), static_cast<std::uint8_t>(v >> 16), static_cast<std::uint8_t>(v >> 8),
                static_cast<std::uint8_t>(v)};
  return base64::encode(b);
}

const std::string kCipher = "q83vEjRWeJq83vEjRWeJq83vEjRWeJq8\n  3vEjRWeJ+/0=";

std::string enc_data(const std::string& type = "http://www.w3.org/2001/04/xmlenc#Content",
                     const std::string& alg = "http://www.w3.org/2009/xmlenc11#aes128-gcm",
                     const std::string& key_name = b64(kXpk), const std::string& extra = "") {
  return "<xenc:EncryptedData xmlns:xenc=\"" + std::string(kXenc) + "\" Type=\"" + type + "\"" + extra + ">" +
         "<xenc:EncryptionMethod Algorithm=\"" + alg + "\"/>" +
         "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:KeyName>" + key_name +
         "</ds:KeyName></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>" + kCipher +
         "</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>";
}

std::string info(const std::string& inner) {
  return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<mcpttinfo xmlns=\"urn:3gpp:ns:mcpttInfo:1.0\"><mcptt-Params>"
         "<mcptt-access-token type=\"Encrypted\">" + inner + "</mcptt-access-token></mcptt-Params></mcpttinfo>\n";
}

struct Fixture {
  XmlRuleSet rules = *load_embedded_xml_ruleset();
  SipRuleSet sip_rules = *load_embedded_sip_ruleset();
  Secret key = secret();
  Mapping mapping;
  Pseudonymiser p{key, mapping};
  MapperAdapter mapper{p};
  sip::SipCounters sip_counters;
  sip::Context ctx{sip_rules, mapper, {}, sip_counters};
  xml::Counters counters;
  xml::BodyRewriter rewriter{rules, counters, xml::RewriteOptions{true}};
  xml::ContextMapper values{ctx, &counters};

  std::string run(const std::string& body, const char* ct = kInfoCt) {
    auto r = rewriter.rewrite(ct, "", body, values);
    REQUIRE(r.has_value());
    REQUIRE(r->rewritten);
    return r->bytes;
  }
  std::string xpk(std::uint32_t v) { return b64(*mapper.key_id(v)); }
};

bool has(const std::string& s, const std::string& part) { return s.find(part) != std::string::npos; }

}  // namespace

TEST_CASE("xenc: the allowlisted structure is kept, the XPK-ID pseudonymised, the cipher value kept",
          "[xml][xenc]") {
  Fixture f;
  const auto out = f.run(info(enc_data()));
  CHECK(has(out, "<mcptt-access-token type=\"Encrypted\"><xenc:EncryptedData"));
  CHECK(has(out, "Type=\"http://www.w3.org/2001/04/xmlenc#Content\""));
  CHECK(has(out, "Algorithm=\"http://www.w3.org/2009/xmlenc11#aes128-gcm\""));
  CHECK(has(out, "<ds:KeyName>" + f.xpk(kXpk) + "</ds:KeyName>"));
  CHECK_FALSE(has(out, b64(kXpk)));
  CHECK(has(out, "<xenc:CipherValue>" + kCipher + "</xenc:CipherValue>"));
  CHECK(f.counters.encrypted_kept == 1);
  CHECK(f.counters.encrypted_removed_parts == 0);
  CHECK(f.counters.encrypted == 0);  // nothing removed whole any more
}

TEST_CASE("xenc: protected key material (EncryptedKey, kw-aes256) is kept the same way", "[xml][xenc]") {
  Fixture f;
  const auto out = f.run(info(enc_data("http://www.w3.org/2001/04/xmlenc#EncryptedKey",
                                       "http://www.w3.org/2001/04/xmlenc#kw-aes256")));
  CHECK(has(out, "Type=\"http://www.w3.org/2001/04/xmlenc#EncryptedKey\""));
  CHECK(has(out, "Algorithm=\"http://www.w3.org/2001/04/xmlenc#kw-aes256\""));
  CHECK(has(out, kCipher));
}

TEST_CASE("xenc: an unknown child, attribute or algorithm is removed and counted", "[xml][xenc]") {
  Fixture f;
  std::string body = enc_data("http://www.w3.org/2001/04/xmlenc#Content", "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
                              b64(kXpk), " Id=\"secret-id\"");
  body.insert(body.find("<xenc:CipherData>"), "<xenc:EncryptionProperties><x>leak</x></xenc:EncryptionProperties>");
  const auto out = f.run(info(body));
  CHECK_FALSE(has(out, "aes256-cbc"));
  CHECK_FALSE(has(out, "secret-id"));
  CHECK_FALSE(has(out, "EncryptionProperties"));
  CHECK_FALSE(has(out, "leak"));
  CHECK(has(out, kCipher));
  CHECK(f.counters.encrypted_removed_parts == 3);
}

TEST_CASE("xenc: a KeyName that is not the base64 of 4 octets is removed", "[xml][xenc]") {
  Fixture f;
  const auto out = f.run(info(enc_data("http://www.w3.org/2001/04/xmlenc#Content",
                                       "http://www.w3.org/2009/xmlenc11#aes128-gcm", "base64XpkId")));
  CHECK_FALSE(has(out, "base64XpkId"));
  CHECK_FALSE(has(out, "<ds:KeyName"));
  CHECK(has(out, "<ds:KeyInfo"));
}

TEST_CASE("xenc: a cipher value that is not base64 is emptied", "[xml][xenc]") {
  Fixture f;
  std::string body = enc_data();
  body.replace(body.find(kCipher), kCipher.size(), "CANARY-not-base64");
  const auto out = f.run(info(body));
  CHECK_FALSE(has(out, "CANARY"));
  CHECK(has(out, "<xenc:CipherValue></xenc:CipherValue>"));
}

TEST_CASE("xenc: a wholly encrypted body is rewritten by the same rules", "[xml][xenc]") {
  Fixture f;
  const auto out = f.run("<?xml version=\"1.0\"?>\n" + enc_data());
  CHECK(has(out, "<ds:KeyName>" + f.xpk(kXpk) + "</ds:KeyName>"));
  CHECK(has(out, kCipher));
  CHECK(f.counters.encrypted_kept == 1);
}

TEST_CASE("xenc: the KeyName of a signed body takes the same key identifier pseudonym (P2)", "[xml][xenc]") {
  Fixture f;
  const std::string body =
      "<?xml version=\"1.0\"?>\n<signatures xmlns=\"urn:3gpp:ns:mcpttSignedDoc:1.0\">"
      "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo>"
      "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>"
      "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256\"/></ds:SignedInfo>"
      "<ds:SignatureValue>c2ln</ds:SignatureValue><ds:KeyInfo><ds:KeyName>" + b64(kXpk) +
      "</ds:KeyName></ds:KeyInfo></ds:Signature></signatures>\n";
  const auto out = f.run(body, "application/vnd.3gpp.mcptt-signed+xml");
  CHECK(has(out, "<ds:KeyName>" + f.xpk(kXpk) + "</ds:KeyName>"));
}
