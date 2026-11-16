// SPDX-License-Identifier: GPL-3.0-or-later
// One RTCP APP packet through the field decoder of every family (FR-015 to FR-023). The first
// byte picks the APP name written over octets 9 to 12, so that arbitrary field bytes reach each
// family's rules; the rest is the packet.
#include "fuzz_media_common.hpp"
#include "media/app.hpp"

#include <array>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size < 1) return 0;
  static constexpr std::array<std::string_view, 13> kNames{"MCPT", "MCPC", "MCMC", "MCNC", "MCSC", "MCV0", "MCV1",
                                                           "MCV2", "MCV3", "MCV4", "MCV5", "MCDM", "XXXX"};
  mcxanon::Bytes p(data + 1, data + size);
  if (p.size() >= 12) {
    const auto name = kNames[data[0] % kNames.size()];
    std::copy(name.begin(), name.end(), p.begin() + 8);
  }
  fuzz::MediaEnv env;
  (void)mcxanon::media::rewrite_app(p, env.rtcp);
  return 0;
}
