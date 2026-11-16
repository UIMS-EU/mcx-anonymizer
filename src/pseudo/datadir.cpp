// SPDX-License-Identifier: GPL-3.0-or-later
#include "pseudo/datadir.hpp"

#include "pseudo/fsutil.hpp"

#include <cstdlib>
#include <unistd.h>

namespace mcxanon {

std::string_view to_string(DataDirSource s) {
  switch (s) {
    case DataDirSource::flag: return "--data-dir";
    case DataDirSource::env: return "MCXANON_DATA_DIR";
    case DataDirSource::portable: return "portable mcxanon-data next to the executable";
    case DataDirSource::platform: return "platform default";
  }
  return "?";
}

Result<DataDirResolution> resolve_data_dir(const DataDirOptions& o) {
  if (o.explicit_dir && !o.explicit_dir->empty()) {
    return DataDirResolution{*o.explicit_dir, DataDirSource::flag};
  }
  if (o.env_dir && !o.env_dir->empty()) {
    return DataDirResolution{std::filesystem::path(*o.env_dir), DataDirSource::env};
  }
  if (o.executable_dir) {
    const auto portable = *o.executable_dir / "mcxanon-data";
    if (fsutil::is_directory(portable)) {
      if (::access(portable.c_str(), W_OK | X_OK) != 0) {
        return fail(ErrorCode::input,
                    "portable data directory " + portable.string() +
                        " exists but is not writable; fix its permissions or use --data-dir");
      }
      return DataDirResolution{portable, DataDirSource::portable};
    }
  }
  switch (o.platform) {
    case Platform::windows:
      if (o.appdata && !o.appdata->empty()) {
        return DataDirResolution{std::filesystem::path(*o.appdata) / "mcxanon",
                                 DataDirSource::platform};
      }
      break;
    case Platform::macos:
      if (o.home && !o.home->empty()) {
        return DataDirResolution{
            std::filesystem::path(*o.home) / "Library" / "Application Support" / "mcxanon",
            DataDirSource::platform};
      }
      break;
    case Platform::linux_like:
      if (o.xdg_data_home && !o.xdg_data_home->empty()) {
        return DataDirResolution{std::filesystem::path(*o.xdg_data_home) / "mcxanon",
                                 DataDirSource::platform};
      }
      if (o.home && !o.home->empty()) {
        return DataDirResolution{
            std::filesystem::path(*o.home) / ".local" / "share" / "mcxanon",
            DataDirSource::platform};
      }
      break;
  }
  return fail(ErrorCode::usage,
              "cannot determine a data directory (no home directory); use --data-dir");
}

DataDirOptions data_dir_options_from_environment() {
  const auto env = [](const char* name) -> std::optional<std::string> {
    const char* v = std::getenv(name);  // NOLINT(concurrency-mt-unsafe): read once at start-up
    if (v == nullptr || *v == '\0') return std::nullopt;
    return std::string(v);
  };
  DataDirOptions o;
  o.env_dir = env("MCXANON_DATA_DIR");
  o.xdg_data_home = env("XDG_DATA_HOME");
  o.home = env("HOME");
  o.appdata = env("APPDATA");
#if defined(_WIN32)
  o.platform = Platform::windows;
#elif defined(__APPLE__)
  o.platform = Platform::macos;
#else
  o.platform = Platform::linux_like;
  o.executable_dir = fsutil::executable_dir();
#endif
  return o;
}

}  // namespace mcxanon
