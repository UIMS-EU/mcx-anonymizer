// SPDX-License-Identifier: GPL-3.0-or-later
//
// The ordered hold queue: output order equals input order while records wait
// for future bytes; bounds and timeouts resolve the oldest pending record by zeroing.
#include "pipeline/hold_queue.hpp"
#include "stream/limits.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using namespace mcxanon;
using namespace mcxanon::pipeline;

namespace {
Record rec(std::uint64_t frame) {
  Record r;
  r.kind = RecordKind::pcap_packet;
  r.frame_number = frame;
  return r;
}

// A held record whose resolution yields its frame number, marked with the reason when it is
// given up: B (the held-bytes bound), T (the pending timeout), E (the end of the capture).
struct Probe {
  std::vector<std::string>* log;
  std::uint64_t frame;
  HoldQueue::Resolve fn() {
    return [log = log, frame = frame](GiveUp why) -> Result<std::vector<Record>> {
      const char* mark = why == GiveUp::bound ? "B" : why == GiveUp::timeout ? "T" : why == GiveUp::end ? "E" : "";
      log->push_back(std::to_string(frame) + mark);
      return std::vector<Record>{rec(frame)};
    };
  }
};

std::vector<std::uint64_t> frames(const std::vector<Record>& v) {
  std::vector<std::uint64_t> out;
  for (const auto& r : v) out.push_back(r.frame_number);
  return out;
}
}  // namespace

TEST_CASE("ready records pass through in order", "[hold]") {
  std::vector<std::string> log;
  HoldQueue q;
  for (std::uint64_t f = 1; f <= 3; ++f) q.push(f * 1000, 10, false, Probe{&log, f}.fn());
  auto out = q.release(3000);
  REQUIRE(out.has_value());
  CHECK(frames(*out) == std::vector<std::uint64_t>{1, 2, 3});
  CHECK(q.empty());
}

TEST_CASE("a pending head blocks later records until it is ready", "[hold]") {
  std::vector<std::string> log;
  HoldQueue q;
  const auto a = q.push(1000, 10, true, Probe{&log, 1}.fn());
  q.push(2000, 10, false, Probe{&log, 2}.fn());
  const auto c = q.push(3000, 10, true, Probe{&log, 3}.fn());
  q.push(4000, 10, false, Probe{&log, 4}.fn());
  CHECK(q.release(4000)->empty());
  q.mark_ready(c);  // a later record becoming ready changes nothing while the head waits
  CHECK(q.release(4000)->empty());
  q.mark_ready(a);
  auto out = q.release(4000);
  REQUIRE(out.has_value());
  CHECK(frames(*out) == std::vector<std::uint64_t>{1, 2, 3, 4});
  CHECK(log == std::vector<std::string>{"1", "2", "3", "4"});
}

TEST_CASE("the held-bytes bound resolves the oldest pending record by zeroing", "[hold][bounds]") {
  std::vector<std::string> log;
  HoldQueue q;
  const std::size_t half = stream::kMaxHeldBytes / 2 - stream::kHeldEntryOverhead;
  q.push(1000, half, true, Probe{&log, 1}.fn());
  q.push(2000, half, true, Probe{&log, 2}.fn());
  CHECK(q.release(2000)->empty());
  CHECK(q.held_bytes() == stream::kMaxHeldBytes);
  q.push(3000, 0, false, Probe{&log, 3}.fn());  // its entry overhead is over the bound
  auto out = q.release(3000);
  REQUIRE(out.has_value());
  CHECK(frames(*out) == std::vector<std::uint64_t>{1});
  CHECK(log.front() == "1B");
  CHECK(q.forced() == 1);
  CHECK(q.held_bytes() <= stream::kMaxHeldBytes);
}

TEST_CASE("every entry counts its overhead against the bound", "[hold][bounds]") {
  std::vector<std::string> log;
  HoldQueue q;
  q.push(1000, 0, true, Probe{&log, 1}.fn());
  for (std::uint64_t f = 2; f < 10; ++f) q.push(1000, 0, false, Probe{&log, f}.fn());
  CHECK(q.held_bytes() == 9 * stream::kHeldEntryOverhead);
  // Small records behind a stalled one reach the bound by their number alone.
  std::size_t n = 9;
  while (q.held_bytes() <= stream::kMaxHeldBytes) {
    q.push(1000, 0, false, Probe{&log, ++n}.fn());
  }
  auto out = q.release(1000);
  REQUIRE(out.has_value());
  CHECK(log.front() == "1B");
  CHECK(n < stream::kMaxHeldBytes / stream::kHeldEntryOverhead + 2);
}

TEST_CASE("a pending record is given up after 10 s of capture time", "[hold][bounds]") {
  std::vector<std::string> log;
  HoldQueue q;
  q.push(1'000'000, 10, true, Probe{&log, 1}.fn());
  q.push(1'500'000, 10, false, Probe{&log, 2}.fn());
  CHECK(q.release(1'000'000 + stream::kPendingTimeoutMs * 1000 - 1)->empty());
  auto out = q.release(1'000'000 + stream::kPendingTimeoutMs * 1000);
  REQUIRE(out.has_value());
  CHECK(frames(*out) == std::vector<std::uint64_t>{1, 2});
  CHECK(log == std::vector<std::string>{"1T", "2"});
}

TEST_CASE("finish resolves everything, forcing what is still pending", "[hold]") {
  std::vector<std::string> log;
  HoldQueue q;
  q.push(1000, 10, false, Probe{&log, 1}.fn());
  q.push(2000, 10, true, Probe{&log, 2}.fn());
  q.push(3000, 10, true, Probe{&log, 3}.fn());
  auto out = q.finish();
  REQUIRE(out.has_value());
  CHECK(frames(*out) == std::vector<std::uint64_t>{1, 2, 3});
  CHECK(log == std::vector<std::string>{"1", "2E", "3E"});
  CHECK(q.empty());
}

TEST_CASE("a forced resolution may make later records ready (shared dependency)", "[hold]") {
  std::vector<std::string> log;
  HoldQueue q;
  HoldQueue::Id second = 0;
  const auto first = q.push(1000, 10, true, [&](GiveUp why) -> Result<std::vector<Record>> {
    log.push_back(why != GiveUp::no ? "1F" : "1");
    q.mark_ready(second);  // the stream gave up the message both segments belong to
    return std::vector<Record>{rec(1)};
  });
  (void)first;
  second = q.push(2000, 10, true, Probe{&log, 2}.fn());
  auto out = q.finish();
  REQUIRE(out.has_value());
  CHECK(log == std::vector<std::string>{"1F", "2"});
}

TEST_CASE("the queue is deterministic", "[hold]") {
  const auto run = [] {
    std::vector<std::string> log;
    HoldQueue q;
    for (std::uint64_t f = 1; f <= 50; ++f) q.push(f * 997, 100, f % 7 == 0, Probe{&log, f}.fn());
    (void)q.release(30 * 997);
    (void)q.finish();
    return log;
  };
  CHECK(run() == run());
}
