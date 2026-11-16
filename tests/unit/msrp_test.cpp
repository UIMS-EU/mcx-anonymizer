// SPDX-License-Identifier: GPL-3.0-or-later
//
// MSRP framing and rewrite (RFC 4975 §7.1, §9; FR-026 to FR-028).
#include "media/msrp.hpp"
#include "media_env.hpp"
#include "sip/sdp.hpp"

#include <algorithm>

using namespace mcxanon;
using namespace mcxanon::test;

namespace {
const std::string kTo = "msrp://10.0.0.2:7002/s7002abcd;tcp";
const std::string kFrom = "msrp://alice@10.0.0.1:7001/s7001wxyz;tcp";

std::string send(const std::string& tid, const std::string& content, const std::string& extra = "",
                 const std::string& ctype = "application/vnd.3gpp.mcdata-signalling", char flag = '$') {
  std::string m = "MSRP " + tid + " SEND\r\nTo-Path: " + kTo + "\r\nFrom-Path: " + kFrom +
                  "\r\nMessage-ID: msg-0001\r\nByte-Range: 1-" + std::to_string(content.size()) + "/" +
                  std::to_string(content.size()) + "\r\nSuccess-Report: yes\r\n" + extra;
  if (content.empty()) return m + "-------" + tid + flag + "\r\n";
  return m + "Content-Type: " + ctype + "\r\n\r\n" + content + "\r\n-------" + tid + flag + "\r\n";
}

media::MsrpRewrite run(MediaEnv& e, const std::string& m) {
  auto r = media::rewrite_msrp(m, e.rules, e.sip, e.mapper, e.counters);
  REQUIRE(r.has_value());
  return *r;
}

std::string path(MediaEnv& e, const std::string& u) { return **sip::map_msrp_uri(u, e.sip); }
}  // namespace

TEST_CASE("MSRP framing: start line, end-line with $, + and #", "[media][msrp]") {
  for (char flag : {'$', '+', '#'}) {
    const auto m = send("tid0001", "hello", "", "text/plain", flag);
    CHECK(media::msrp_is_start(m) == std::optional<bool>(true));
    const auto f = media::msrp_frame(m + "MSRP next");
    CHECK(f.kind == media::MsrpFrameKind::message);
    CHECK(f.len == m.size());
  }
  CHECK(media::msrp_is_start("MSR") == std::nullopt);
  CHECK(media::msrp_is_start("SIP/2.0 200 OK\r\n") == std::optional<bool>(false));
  const auto half = send("tid0001", "hello");
  CHECK(media::msrp_frame(half.substr(0, half.size() - 5)).kind == media::MsrpFrameKind::more);
  // An end-line with another transaction id does not end the message.
  const auto other = send("tid0001", "x").substr(0, send("tid0001", "x").find("-------")) + "-------tid9999$\r\n";
  CHECK(media::msrp_frame(other).kind == media::MsrpFrameKind::more);
  CHECK(media::msrp_frame("MSRP bad id with spaces\r\n").kind == media::MsrpFrameKind::invalid);
}

TEST_CASE("SEND: paths, Message-ID and transaction id pseudonymised; content zeroed", "[media][msrp]") {
  MediaEnv e;
  const std::string content = "CANARY-SDS-CONTENT";
  const auto m = send("tid0001", content);
  const auto r = run(e, m);
  REQUIRE_FALSE(r.zeroed);
  const std::string& o = r.bytes;
  const std::string tid = *e.mapper.text(Category::msrp_tid, "tid0001");
  CHECK(o.starts_with("MSRP " + tid + " SEND\r\n"));
  CHECK(o.find("To-Path: " + path(e, kTo) + "\r\n") != std::string::npos);
  CHECK(o.find("From-Path: " + path(e, kFrom) + "\r\n") != std::string::npos);
  CHECK(o.find("Message-ID: " + *e.mapper.text(Category::msrp_msgid, "msg-0001") + "\r\n") != std::string::npos);
  CHECK(o.find("Byte-Range: 1-18/18\r\n") != std::string::npos);
  CHECK(o.find("Success-Report: yes\r\n") != std::string::npos);
  CHECK(o.find("Content-Type: application/vnd.3gpp.mcdata-signalling\r\n\r\n") != std::string::npos);
  CHECK(o.find(content) == std::string::npos);
  CHECK(o.find(std::string(content.size(), '\0')) != std::string::npos);
  CHECK(o.ends_with("\r\n-------" + tid + "$\r\n"));
  // The tail (content, CRLF, end-line) keeps its length: only the head changes size.
  CHECK(o.size() - r.head_out == m.size() - r.head_orig);
  CHECK(e.counters.msrp_requests.at("SEND") == 1);
  CHECK(o.find("10.0.0.1") == std::string::npos);
}

TEST_CASE("REPORT and the response keep their match with the SEND", "[media][msrp]") {
  MediaEnv e;
  run(e, send("tid0001", "x"));
  const auto rep = run(e, "MSRP tid0002 REPORT\r\nTo-Path: " + kFrom + "\r\nFrom-Path: " + kTo +
                              "\r\nMessage-ID: msg-0001\r\nByte-Range: 1-1/1\r\nStatus: 000 200 OK delivered\r\n-------tid0002$\r\n");
  CHECK(rep.bytes.find("Message-ID: " + *e.mapper.text(Category::msrp_msgid, "msg-0001")) != std::string::npos);
  CHECK(rep.bytes.find("Status: 000 200\r\n") != std::string::npos);  // the comment is removed (B14)
  const auto resp = run(e, "MSRP tid0001 200 OK fine\r\nTo-Path: " + kFrom + "\r\nFrom-Path: " + kTo + "\r\n-------tid0001$\r\n");
  const std::string tid = *e.mapper.text(Category::msrp_tid, "tid0001");
  CHECK(resp.bytes.starts_with("MSRP " + tid + " 200\r\n"));
  CHECK(resp.bytes.ends_with("-------" + tid + "$\r\n"));
  CHECK(e.counters.msrp_responses.at("2xx") == 1);
  CHECK(e.counters.msrp_requests.at("REPORT") == 1);
}

TEST_CASE("headers without a rule, MIME headers and RFC 4976 headers are removed", "[media][msrp]") {
  MediaEnv e;
  const auto r = run(e, send("tid0001", "x",
                             "Content-ID: <CANARY-CID@example.net>\r\nContent-Description: CANARY-DESC\r\n"
                             "Use-Path: msrp://relay.example.net:2855/r;tcp\r\nX-Vendor: CANARY-X\r\n"
                             "Content-Disposition: attachment; filename=CANARY-FILE.txt\r\n"));
  CHECK(r.bytes.find("CANARY") == std::string::npos);
  CHECK(r.bytes.find("Use-Path") == std::string::npos);
  CHECK(r.bytes.find("Content-Disposition: attachment\r\n") != std::string::npos);
  CHECK(e.counters.msrp_headers.at("other").at("remove") >= 2);
  CHECK(std::any_of(e.counters.removed_values.begin(), e.counters.removed_values.end(),
                    [](const auto& x) { return x.second.find("CANARY-DESC") != std::string::npos; }));
}

TEST_CASE("Content-Type keeps the media type; boundary pseudonymised, other parameters removed", "[media][msrp]") {
  MediaEnv e;
  const auto r = run(e, send("tid0001", "--bnd\r\n\r\nx\r\n--bnd--", "", "multipart/mixed;boundary=bnd;x-param=CANARY"));
  const std::string b = *e.mapper.text(Category::boundary, "bnd");
  CHECK(r.bytes.find("Content-Type: multipart/mixed;boundary=" + b + "\r\n") != std::string::npos);
  CHECK(r.bytes.find("CANARY") == std::string::npos);
}

TEST_CASE("AUTH and unknown methods, and malformed messages, are zeroed", "[media][msrp]") {
  MediaEnv e;
  CHECK(run(e, "MSRP tid0001 AUTH\r\nTo-Path: " + kTo + "\r\nFrom-Path: " + kFrom + "\r\n-------tid0001$\r\n").zeroed);
  CHECK(run(e, "MSRP tid0001 SEND\r\nbroken header line\r\n-------tid0001$\r\n").zeroed);
  CHECK(run(e, "MSRP tid0001 SEND\r\nTo-Path: not a uri\r\nFrom-Path: " + kFrom + "\r\n-------tid0001$\r\n").zeroed);
  CHECK(e.counters.msrp_zeroed.at("method") == 1);
  CHECK(e.counters.msrp_zeroed.at("malformed") == 2);
}

TEST_CASE("an empty binding SEND has no Content-Type and keeps its framing", "[media][msrp]") {
  MediaEnv e;
  const auto r = run(e, send("tid0001", ""));
  REQUIRE_FALSE(r.zeroed);
  CHECK(r.bytes.find("Content-Type") == std::string::npos);
  CHECK(r.bytes.ends_with("$\r\n"));
}
