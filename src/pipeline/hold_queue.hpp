// SPDX-License-Identifier: GPL-3.0-or-later
//
// Ordered hold queue: output order equals input order while a record waits
// for future bytes (a SIP message over TCP, a fragmented datagram). A record leaves the queue
// only from the head. A pending head is given up (resolved with force, which zero-fills) when
// the queue holds more than kMaxHeldBytes, when it has waited kPendingTimeoutMs of capture time,
// or at finish(). Time is capture time only, so output is deterministic (FR-034).
#pragma once

#include "mcxanon/error.hpp"

#include "capture/record.hpp"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <vector>

namespace mcxanon::pipeline {

// Why a pending record is resolved without waiting longer (no: it is ready).
enum class GiveUp { no, bound, timeout, end };

class HoldQueue {
 public:
  using Id = std::uint64_t;
  // Produces the output records of one input record; anything but GiveUp::no means give up
  // waiting, for that reason.
  using Resolve = std::function<Result<std::vector<Record>>(GiveUp why)>;

  // ts_us: capture time; bytes: what the entry holds (for the bound, which also counts
  // stream::kHeldEntryOverhead per entry); pending: waits for a mark_ready().
  Id push(std::uint64_t ts_us, std::size_t bytes, bool pending, Resolve resolve);
  void mark_ready(Id id);
  // Releases ready heads; gives up pending heads past the bound or the timeout at `now_us`.
  Result<std::vector<Record>> release(std::uint64_t now_us);
  // Resolves everything, forcing what is still pending.
  Result<std::vector<Record>> finish();

  [[nodiscard]] bool empty() const { return entries_.empty(); }
  [[nodiscard]] std::size_t held_bytes() const { return held_; }
  [[nodiscard]] std::uint64_t forced() const { return forced_; }

 private:
  struct Entry {
    Id id = 0;
    std::uint64_t ts_us = 0;
    std::size_t bytes = 0;
    bool pending = false;
    Resolve resolve;
  };
  Result<void> pop_head(GiveUp why, std::vector<Record>& out);

  std::deque<Entry> entries_;
  Id next_ = 1;
  std::size_t held_ = 0;
  std::uint64_t forced_ = 0;
};

}  // namespace mcxanon::pipeline
