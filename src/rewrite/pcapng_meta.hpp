// SPDX-License-Identifier: GPL-3.0-or-later
//
// pcapng metadata policy (FR-007..FR-010): blocks and options are kept only
// when the rule set says so and the block's structure is understood; removed
// identity-bearing values are collected (in memory) for the leak scanner.
#pragma once

#include "bytes/bytes.hpp"
#include "capture/pcapng.hpp"
#include "dissect/fields.hpp"
#include "policy/decide.hpp"
#include "rewrite/apply.hpp"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace mcxanon {

struct RemovedValue {
  std::string category;  // mac, ipv4, ipv6, string
  Bytes value;
  bool operator==(const RemovedValue&) const = default;
};

struct MetaStats {
  std::map<std::string, std::uint64_t> removed_blocks;   // "0x%08x"
  std::map<std::string, std::uint64_t> removed_options;  // "0x%08x/<code>"
};

Fid block_fid(std::uint32_t block_type);
Fid option_fid(std::uint32_t block_type, std::uint16_t code);
// Blocks whose structure the tool rewrites; every other block is always removed.
bool block_structure_known(std::uint32_t block_type);
std::string block_key(std::uint32_t block_type);

// True when the block is kept (and counts the decision).
bool keep_block(std::uint32_t block_type, const Policy& policy, RewriteStats& stats,
                MetaStats& meta);

std::vector<PcapngOption> filter_options(std::uint32_t block_type,
                                         const std::vector<PcapngOption>& options, Endian e,
                                         const Policy& policy, RewriteStats& stats,
                                         MetaStats& meta, std::vector<RemovedValue>& removed);

// Identity-bearing values of a removed block (Name Resolution Block records
// and options).
void collect_block_values(std::uint32_t block_type, ByteView block, Endian e,
                          std::vector<RemovedValue>& removed);

}  // namespace mcxanon
