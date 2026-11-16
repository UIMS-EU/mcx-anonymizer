// SPDX-License-Identifier: GPL-3.0-or-later
//
// JSON, OAuth parameters, JWTs and header credentials.
#include "bytes/base64.hpp"
#include "http/headers.hpp"
#include "http/json.hpp"
#include "http/jwt.hpp"
#include "http/params.hpp"
#include "sip/rewrite.hpp"

#include "web_env.hpp"

using namespace mcxanon;
using namespace mcxanon::http;

namespace {
std::string b64url(const std::string& s) {
  base64::Layout l;
  l.padded = false;
  return base64::encode(ByteView(reinterpret_cast<const std::uint8_t*>(s.data()), s.size()), l, base64::Alphabet::url);
}
std::string unb64url(const std::string& s) {
  auto d = base64::decode(s, base64::Alphabet::url);
  REQUIRE(d.has_value());
  return std::string(d->bytes.begin(), d->bytes.end());
}
}  // namespace

TEST_CASE("json: reader bounds and canonical writer", "[http][json]") {
  auto j = parse_json(R"( {"a": [1, 2.5e3, true, null], "b": "x\u00e9\/y", "a": 7} )");
  REQUIRE(j);
  CHECK(write_json(*j) == "{\"a\":[1,2.5e3,true,null],\"b\":\"x\xc3\xa9/y\"}");
  CHECK_FALSE(parse_json("{\"a\":01}"));
  CHECK_FALSE(parse_json("{\"a\":\"\\ud800\"}"));
  CHECK_FALSE(parse_json(std::string(40, '[') + std::string(40, ']')));
  CHECK_FALSE(parse_json("{\"a\":1} x"));
  CHECK_FALSE(parse_json("\"\xff\""));
}

TEST_CASE("oauth: token response JSON", "[http][oauth]") {
  web_test::Env e;
  auto r = rewrite_json_body(R"({"access_token":"SlAV32hkKG7GzZ9","token_type":"Bearer","expires_in":3600,)"
                             R"("refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA","scope":"openid 3gpp:mc:ptt_service private-x",)"
                             R"("error_description":"free text","custom":"zzzz"})", *e);
  REQUIRE(r.has_value());
  REQUIRE(r->has_value());
  const auto& s = **r;
  CHECK(s.find("SlAV32hkKG7GzZ9") == std::string::npos);
  CHECK(s.find("\"token_type\":\"Bearer\"") != std::string::npos);
  CHECK(s.find("\"expires_in\":3600") != std::string::npos);
  CHECK(s.find("\"refresh_token\":\"\"") != std::string::npos);
  CHECK(s.find("openid 3gpp:mc:ptt_service ") != std::string::npos);
  CHECK(s.find("private-x") == std::string::npos);
  CHECK(s.find("custom") == std::string::npos);
  CHECK(s.find("free text") == std::string::npos);
  CHECK(e.removed("tGzv3JOkF0XG5Qx2TlKWIA"));
  CHECK(e.counters.removed_unknown["json-member"]["custom"] == 1);
  CHECK_FALSE(rewrite_json_body("[1,2]", *e)->has_value());
}

TEST_CASE("jwt: decomposed, claims mapped and shifted, signature zeroed", "[http][jwt]") {
  web_test::Env e(100);
  const std::string h = b64url(R"({"alg":"ES256","typ":"JWT","kid":"key-2026-abc","x5u":"https://x"})");
  const std::string c = b64url(R"({"iss":"https://idms.example.org","sub":"sip:dave@example.org","mcptt_id":"sip:dave@example.org",)"
                               R"("exp":1700000000,"scope":"openid","auth_time":5})");
  const std::string sig = b64url(std::string(64, '\x42'));
  auto t = rewrite_token(h + "." + c + "." + sig, *e);
  REQUIRE(t.has_value());
  CHECK(t->kind == "jwt");
  const auto d1 = t->text.find('.');
  const auto d2 = t->text.find('.', d1 + 1);
  const auto hj = unb64url(t->text.substr(0, d1));
  const auto cj = unb64url(t->text.substr(d1 + 1, d2 - d1 - 1));
  CHECK(hj.find("\"alg\":\"ES256\"") != std::string::npos);
  CHECK(hj.find("key-2026-abc") == std::string::npos);
  CHECK(hj.find("https://x") == std::string::npos);  // x5u: the name stays, the value leaves
  CHECK(cj.find("dave") == std::string::npos);
  CHECK(cj.find("\"exp\":1700000100") != std::string::npos);
  CHECK(cj.find("auth_time") == std::string::npos);  // no corpus source (D5)
  CHECK(unb64url(t->text.substr(d2 + 1)) == std::string(64, '\0'));
  CHECK(e.removed(sig));
  // The MCPTT ID of the token equals the SIP pseudonym.
  const auto sip = sip::rewrite_uri_text("sip:dave@example.org", *e.sctx);
  CHECK(cj.find(**sip) != std::string::npos);
  // Not a JWT: a consistent opaque pseudonym of the same length.
  auto o1 = rewrite_token("abcdefghijklmnop.qrst", *e);
  auto o2 = rewrite_token("abcdefghijklmnop.qrst", *e);
  REQUIRE((o1 && o2));
  CHECK(o1->text == o2->text);
  CHECK(o1->text.size() == 21);
  CHECK(o1->text != "abcdefghijklmnop.qrst");
  CHECK(rewrite_token("a.b.c.d.e", *e)->kind == "jwe");
  CHECK(rewrite_token("eyJhbGciOiJub25lIn0.!!!.x", *e)->kind == "malformed-jwt");
}

TEST_CASE("http headers: credentials, cookies and dates", "[http][auth]") {
  web_test::Env e(3600);
  const auto f = [&](const char* n, const char* v) {
    auto r = rewrite_field(n, v, *e);
    REQUIRE(r.has_value());
    return r->value_or("<removed>");
  };
  CHECK(f("Authorization", "Basic dXNlcjpwYXNzd29yZA==") == "Basic");
  CHECK(e.removed("dXNlcjpwYXNzd29yZA=="));
  const auto b = f("Authorization", "Bearer opaque-token-value-123");
  CHECK(b.starts_with("Bearer "));
  CHECK(b.find("opaque-token-value-123") == std::string::npos);
  const auto d = f("Authorization", R"(Digest username="erin", realm="example.org", nonce="abc123def", uri="/x", response="0123456789abcdef", qop=auth, nc=00000001, cnonce="zzzz1111")");
  CHECK(d.find("erin") == std::string::npos);
  CHECK(d.find("0123456789abcdef") == std::string::npos);
  CHECK(d.find("qop=auth") != std::string::npos);
  CHECK(f("Cookie", "SESSIONID=s3cr3tvalue; theme=dark").find("s3cr3tvalue") == std::string::npos);
  CHECK(e.removed("s3cr3tvalue"));
  const auto sc = f("Set-Cookie", "SESSIONID=s3cr3t2; Path=/app; Domain=.example.org; Expires=Sun, 15 Nov 2026 10:00:00 GMT; HttpOnly; SameSite=Lax");
  CHECK(sc.find("s3cr3t2") == std::string::npos);
  CHECK(sc.find("Expires=Sun, 15 Nov 2026 11:00:00 GMT") != std::string::npos);
  CHECK(sc.find("HttpOnly") != std::string::npos);
  CHECK(sc.find("SameSite") == std::string::npos);
  CHECK(sc.find("Domain=.") != std::string::npos);
  CHECK(sc.find("example.org") == std::string::npos);
  CHECK(f("Date", "Sun, 15 Nov 2026 10:00:00 GMT") == "Sun, 15 Nov 2026 11:00:00 GMT");
  CHECK(f("ETag", "W/\"xyz-etag-1\"").starts_with("W/\""));
  CHECK(f("ETag", "W/\"xyz-etag-1\"").find("xyz-etag-1") == std::string::npos);
  CHECK(f("Cache-Control", "max-age=60, private=\"Set-Cookie\", foo") == "max-age=60, private");
  CHECK(f("User-Agent", "SecretClient/1.0") == "<removed>");
  CHECK(f("X-Unknown", "v") == "<removed>");
  CHECK(f("Host", "kms.example.org:8080").ends_with(":8080"));
}

TEST_CASE("D20: values without room for an opaque pseudonym leave the output", "[http][oauth][d20]") {
  web_test::Env e;
  // A scope token with fewer than four ASCII letters or digits is left out, the rest kept.
  auto r = rewrite_json_body("{\"scope\":\"openid \xd0\x98\xd0\xb2\xd0\xb0\xd0\xbd 3gpp:mc:ptt_service\"}", *e);
  REQUIRE(r.has_value());
  REQUIRE(r->has_value());
  CHECK(**r == "{\"scope\":\"openid 3gpp:mc:ptt_service\"}");
  // A Bearer token of punctuation leaves as zeros of its length.
  auto t = rewrite_token("-._~-._~", *e);
  REQUIRE(t.has_value());
  CHECK(t->text == "00000000");
  // A cookie pair whose name has no pseudonym is left out; its value is removed as a credential.
  auto c = rewrite_field("Cookie", "----=secretvalue1; sessionid=abcdef123456", *e);
  REQUIRE(c.has_value());
  REQUIRE(c->has_value());
  CHECK((*c)->find("----") == std::string::npos);
  CHECK((*c)->find("secretvalue1") == std::string::npos);
  CHECK(e.removed("secretvalue1"));
}
