// SPDX-License-Identifier: GPL-3.0-or-later
//
// Bounds of the hold queue, the TCP stream table and the fragment table. Each
// bound leads to zeroing, never to pass-through or unbounded memory. Reported in
// the report's sip.limits object.
#pragma once

#include <cstddef>
#include <cstdint>

namespace mcxanon::stream {

inline constexpr std::size_t kMaxTcpDirections = 65536;
inline constexpr std::size_t kMaxHeldBytes = 64u * 1024 * 1024;
// What one held record costs beyond its bytes (queue entry, resolver, record copy), counted
// against kMaxHeldBytes so that many small records cannot exceed the memory budget (SC-005).
inline constexpr std::size_t kHeldEntryOverhead = 512;
inline constexpr std::uint64_t kPendingTimeoutMs = 10000;  // capture time
inline constexpr std::size_t kRetransCacheBytes = 256u * 1024;
inline constexpr std::size_t kMaxOffsetBreakpoints = 65536;
inline constexpr std::size_t kMaxPendingDatagrams = 4096;
inline constexpr std::size_t kMaxDatagramBytes = 64u * 1024;
// A SIP message over TCP (sip/limits.hpp kMaxMessageBytes), bytes held beyond a sequence gap,
// and bytes searched for a start line before a direction counts as non-SIP (R14).
inline constexpr std::size_t kMaxStreamMessageBytes = 1024u * 1024;
inline constexpr std::size_t kMaxOutOfOrderBytes = 1024u * 1024;
inline constexpr std::size_t kMaxSearchBytes = 1024u * 1024;

}  // namespace mcxanon::stream
