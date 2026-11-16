// SPDX-License-Identifier: GPL-3.0-or-later
// FR-029: the mapping is durable before the output becomes visible.
#include "mcxanon/project.hpp"

#include "capture/pcap.hpp"
#include "packet_builder.hpp"
#include "pipeline/testing.hpp"
#include "temp_dir.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>

using namespace mcxanon;
using namespace mcxanon::test;
namespace fs = std::filesystem;

namespace {
void write_pcap(const fs::path& p, const Bytes& packet) {
  PcapFileHeader h;
  h.linktype = kLinkEthernet;
  Bytes file = build_pcap_file_header(h);
  Bytes rec(16);
  store_pcap_packet_header(rec, PcapPacketHeader{1, 0, static_cast<std::uint32_t>(packet.size()),
                                                 static_cast<std::uint32_t>(packet.size())},
                           Endian::little);
  file = file + rec + packet;
  std::ofstream(p, std::ios::binary).write(reinterpret_cast<const char*>(file.data()),
                                           static_cast<std::streamsize>(file.size()));
}
}  // namespace

TEST_CASE("a failure after the mapping is saved publishes nothing", "[pipeline]") {
  TempDir tmp;
  const DataDirResolution where{tmp.path() / "data", DataDirSource::flag};
  REQUIRE(Project::create(where, "p").has_value());
  const fs::path in = tmp.path() / "in.pcap";
  write_pcap(in, eth(kMacB, kMacA, 0x0800, udp4(kIpA, kIpB, 1, 2, text("x"))));
  AnonymizeFileRequest req;
  req.input = in;
  req.output = tmp.path() / "out.pcap";
  {
    auto project = Project::open(where, "p", false);
    REQUIRE(project.has_value());
    testing::Hooks hooks;
    hooks.fail_before_publish = true;
    auto r = testing::anonymize_file_with_hooks(*project, req, hooks);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().code == ErrorCode::internal);
  }
  CHECK_FALSE(fs::exists(req.output));
  for (const auto& e : fs::directory_iterator(tmp.path())) {
    INFO(e.path().filename().string());
    CHECK(e.path().filename().string().find("mcxanon-tmp") == std::string::npos);
  }
  CHECK(fs::exists(fs::path(req.output.string() + ".report.json")));
  auto reopened = Project::open(where, "p", false);
  REQUIRE(reopened.has_value());
  CHECK(reopened->mapping_size() == 4);  // two MACs and two IPv4 addresses
}

TEST_CASE("a successful run publishes the output after saving the mapping", "[pipeline]") {
  TempDir tmp;
  const DataDirResolution where{tmp.path() / "data", DataDirSource::flag};
  REQUIRE(Project::create(where, "p").has_value());
  const fs::path in = tmp.path() / "in.pcap";
  write_pcap(in, eth(kMacB, kMacA, 0x0800, udp4(kIpA, kIpB, 1, 2, text("x"))));
  AnonymizeFileRequest req;
  req.input = in;
  req.output = tmp.path() / "out.pcap";
  auto project = Project::open(where, "p", false);
  REQUIRE(project.has_value());
  auto r = anonymize_file(*project, req);
  REQUIRE(r.has_value());
  CHECK(fs::exists(req.output));
  CHECK(fs::file_size(req.output) == fs::file_size(in));
  CHECK(r->status.exit_code == 0);
  CHECK(r->files.frames == 1);
}
