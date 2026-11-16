// SPDX-License-Identifier: GPL-3.0-or-later
#include "pipeline/hold_queue.hpp"

#include "stream/limits.hpp"

#include <algorithm>

namespace mcxanon::pipeline {

HoldQueue::Id HoldQueue::push(std::uint64_t ts_us, std::size_t bytes, bool pending, Resolve resolve) {
  const Id id = next_++;
  bytes += stream::kHeldEntryOverhead;
  entries_.push_back(Entry{id, ts_us, bytes, pending, std::move(resolve)});
  held_ += bytes;
  return id;
}

void HoldQueue::mark_ready(Id id) {
  // Ids increase along the queue: a binary search finds the entry.
  const auto it = std::lower_bound(entries_.begin(), entries_.end(), id,
                                   [](const Entry& e, Id v) { return e.id < v; });
  if (it != entries_.end() && it->id == id) it->pending = false;
}

Result<void> HoldQueue::pop_head(GiveUp why, std::vector<Record>& out) {
  Entry e = std::move(entries_.front());
  entries_.pop_front();
  held_ -= e.bytes;
  if (!e.pending) why = GiveUp::no;
  if (why != GiveUp::no) ++forced_;
  auto r = e.resolve(why);
  if (!r) return std::unexpected(r.error());
  for (auto& rec : *r) out.push_back(std::move(rec));
  return {};
}

Result<std::vector<Record>> HoldQueue::release(std::uint64_t now_us) {
  std::vector<Record> out;
  const std::uint64_t timeout = stream::kPendingTimeoutMs * 1000;
  while (!entries_.empty()) {
    const Entry& h = entries_.front();
    GiveUp why = GiveUp::no;
    if (h.pending && held_ > stream::kMaxHeldBytes) {
      why = GiveUp::bound;
    } else if (h.pending && now_us >= h.ts_us && now_us - h.ts_us >= timeout) {
      why = GiveUp::timeout;
    } else if (h.pending) {
      break;
    }
    if (auto r = pop_head(why, out); !r) return std::unexpected(r.error());
  }
  return out;
}

Result<std::vector<Record>> HoldQueue::finish() {
  std::vector<Record> out;
  while (!entries_.empty()) {
    if (auto r = pop_head(GiveUp::end, out); !r) return std::unexpected(r.error());
  }
  return out;
}

}  // namespace mcxanon::pipeline
