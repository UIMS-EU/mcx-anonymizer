// SPDX-License-Identifier: GPL-3.0-or-later
//
// The reveal report, the stderr summary and the
// file-level driver (FR-006, FR-018).
#include "mcxanon/version.hpp"
#include "pseudo/atomic_file.hpp"
#include "pseudo/fsutil.hpp"
#include "reveal/engine.hpp"

#include <nlohmann/json.hpp>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <random>
#include <sys/stat.h>
#include <unistd.h>

namespace mcxanon {
namespace {

// Valid UTF-8 is kept; every byte of an invalid sequence becomes U+00XX (Latin-1 view), so the
// JSON is always valid; the dump escapes everything outside ASCII as \uXXXX.
std::string utf8_safe(std::string_view s) {
  std::string out;
  out.reserve(s.size());
  std::size_t i = 0;
  const auto latin1 = [&](unsigned char c) {
    out.push_back(static_cast<char>(0xC0 | (c >> 6)));
    out.push_back(static_cast<char>(0x80 | (c & 0x3F)));
  };
  while (i < s.size()) {
    const auto c = static_cast<unsigned char>(s[i]);
    std::size_t n = c < 0x80 ? 1 : (c >> 5) == 6 ? 2 : (c >> 4) == 14 ? 3 : (c >> 3) == 30 ? 4 : 0;
    bool ok = n > 0 && i + n <= s.size();
    for (std::size_t k = 1; ok && k < n; ++k) ok = (static_cast<unsigned char>(s[i + k]) & 0xC0) == 0x80;
    if (ok && n == 1 && c < 0x80) {
      out.push_back(static_cast<char>(c));
    } else if (ok) {
      out.append(s.substr(i, n));
    } else {
      latin1(c);
      n = 1;
    }
    i += n;
  }
  return out;
}

const char* kind_name(RevealKind k) {
  switch (k) {
    case RevealKind::revealed: return "revealed";
    case RevealKind::ambiguous: return "ambiguous";
    case RevealKind::unknown: return "unknown";
  }
  return "?";
}

std::string counts(const std::map<std::string, std::uint64_t>& m) {
  std::string o;
  for (const auto& [k, v] : m) o += (o.empty() ? "" : ", ") + k + " " + std::to_string(v);
  return o;
}

std::uint64_t total(const std::map<std::string, std::uint64_t>& m) {
  std::uint64_t t = 0;
  for (const auto& [k, v] : m) t += v;
  return t;
}

bool is_stdio(const std::optional<std::filesystem::path>& p) { return !p || p->empty() || *p == "-"; }

}  // namespace

std::string reveal_report_json(const RevealSummary& s, std::string_view project_name, const RevealOptions& options) {
  nlohmann::ordered_json doc;
  doc["format"] = 1;
  doc["kind"] = "reveal";
  doc["tool"] = {{"name", "mcxanon"}, {"version", std::string(tool_version)}};
  doc["project"] = utf8_safe(project_name);
  doc["options"] = {{"replace_ambiguous", options.replace_ambiguous}, {"annotate", options.annotate}};
  doc["bytes"] = {{"in", s.bytes_in}, {"out", s.bytes_out}};
  const auto obj = [](const std::map<std::string, std::uint64_t>& m) {
    nlohmann::ordered_json o = nlohmann::ordered_json::object();
    for (const auto& [k, v] : m) {
      if (v) o[k] = v;
    }
    return o;
  };
  doc["revealed"] = obj(s.revealed);
  doc["ambiguous"] = obj(s.ambiguous);
  doc["unknown"] = obj(s.unknown);
  doc["not_searchable"] = s.not_searchable;
  auto list = nlohmann::ordered_json::array();
  for (const auto& c : s.candidates) {
    list.push_back({{"kind", kind_name(c.kind)},
                    {"ambiguity", c.ambiguity},
                    {"line", c.line},
                    {"column", c.column},
                    {"category", c.category},
                    {"matched", utf8_safe(c.matched)},
                    {"original", utf8_safe(c.original)}});
  }
  doc["candidates"] = std::move(list);
  return doc.dump(2, ' ', true) + "\n";
}

namespace reveal {

std::string summary_text(const RevealSummary& s, std::size_t max_lines) {
  std::string o = "mcxanon: revealed " + std::to_string(total(s.revealed)) + " values";
  if (!s.revealed.empty()) o += " (" + counts(s.revealed) + ")";
  o += "\n";
  o += "mcxanon: left " + std::to_string(total(s.ambiguous)) + " ambiguous";
  if (!s.ambiguous.empty()) o += " (" + counts(s.ambiguous) + ")";
  o += ", " + std::to_string(total(s.unknown)) + " unknown";
  if (!s.unknown.empty()) o += " (" + counts(s.unknown) + ")";
  o += "; " + std::to_string(s.not_searchable) + " mapping entries not searchable\n";
  std::size_t shown = 0;
  char buf[64];
  for (const auto& c : s.candidates) {
    if (shown == max_lines) break;
    std::snprintf(buf, sizeof buf, "  %llu:%llu", static_cast<unsigned long long>(c.line),
                  static_cast<unsigned long long>(c.column));
    std::string line = buf;
    line.resize(std::max<std::size_t>(line.size() + 1, 9), ' ');
    std::string kind = kind_name(c.kind);
    kind.resize(std::max<std::size_t>(kind.size() + 1, 11), ' ');
    std::string cat = c.category;
    cat.resize(std::max<std::size_t>(cat.size() + 1, 10), ' ');
    std::string matched = c.matched;
    for (auto& ch : matched) {
      if (static_cast<unsigned char>(ch) < 0x20) ch = '?';
    }
    o += line + kind + cat + matched;
    if (!c.original.empty()) o += "  -> " + c.original;
    o += "\n";
    ++shown;
  }
  if (s.candidates.size() > shown) {
    o += "  ... and " + std::to_string(s.candidates.size() - shown) + " more (see --report)\n";
  }
  return o;
}

}  // namespace reveal

Result<RevealSummary> reveal_file(Revealer& revealer, const RevealFileRequest& request) {
  try {
    namespace fs = std::filesystem;
    const bool in_stdin = is_stdio(request.input);
    const bool out_stdout = is_stdio(request.output);
    if (!in_stdin && !fsutil::is_regular_file(*request.input) && !fsutil::exists(*request.input)) {
      return fail(ErrorCode::input, "cannot read " + request.input->string() + ": no such file");
    }
    if (!out_stdout) {
      if (!in_stdin && fsutil::exists(*request.output) && fsutil::same_file(*request.input, *request.output)) {
        return fail(ErrorCode::usage, "the output would overwrite the input");
      }
      if (fsutil::exists(*request.output) && !request.overwrite) {
        return fail(ErrorCode::usage, request.output->string() + " exists; use --overwrite to replace it");
      }
    }
    if (request.report_path) {
      if (!in_stdin && fsutil::exists(*request.report_path) && fsutil::same_file(*request.input, *request.report_path)) {
        return fail(ErrorCode::usage, "the report would overwrite the input");
      }
      if (fsutil::exists(*request.report_path) && !request.overwrite) {
        return fail(ErrorCode::usage, request.report_path->string() + " exists; use --overwrite to replace it");
      }
    }
    std::FILE* in = in_stdin ? stdin : std::fopen(request.input->c_str(), "rb");
    if (!in) return fail(ErrorCode::input, "cannot read " + request.input->string() + ": " + std::strerror(errno));
    // The output goes to a temporary owner-only file that replaces the target at the end, so an
    // error never leaves a partial file behind.
    fs::path tmp;
    int fd = -1;
    if (!out_stdout) {
      std::random_device rd;
      tmp = request.output->string() + ".tmp-" + std::to_string(rd());
      fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
      if (fd < 0) {
        if (!in_stdin) std::fclose(in);
        return fail(ErrorCode::input, "cannot write " + request.output->string() + ": " + std::strerror(errno));
      }
    }
    const auto cleanup = [&] {
      if (!in_stdin) std::fclose(in);
      if (fd >= 0) {
        ::close(fd);
        ::unlink(tmp.c_str());
      }
    };
    const RevealSink sink = [&](std::span<const std::uint8_t> b) -> Result<void> {
      if (out_stdout) {
        if (std::fwrite(b.data(), 1, b.size(), stdout) != b.size()) {
          return fail(ErrorCode::input, "cannot write the output: " + std::string(std::strerror(errno)));
        }
        return {};
      }
      std::size_t done = 0;
      while (done < b.size()) {
        const auto n = ::write(fd, b.data() + done, b.size() - done);
        if (n < 0) {
          if (errno == EINTR) continue;
          return fail(ErrorCode::input, "cannot write " + request.output->string() + ": " + std::strerror(errno));
        }
        done += static_cast<std::size_t>(n);
      }
      return {};
    };
    std::vector<std::uint8_t> chunk(1 << 16);
    while (true) {
      const std::size_t n = std::fread(chunk.data(), 1, chunk.size(), in);
      if (n > 0) {
        if (auto r = revealer.feed(std::span(chunk.data(), n), sink); !r) {
          cleanup();
          return std::unexpected(r.error());
        }
      }
      if (n < chunk.size()) {
        if (std::ferror(in)) {
          cleanup();
          return fail(ErrorCode::input, "cannot read the input: " + std::string(std::strerror(errno)));
        }
        break;
      }
    }
    if (auto r = revealer.finish(sink); !r) {
      cleanup();
      return std::unexpected(r.error());
    }
    if (out_stdout) std::fflush(stdout);
    if (!in_stdin) std::fclose(in);
    if (fd >= 0) {
      if (::fsync(fd) != 0 || ::close(fd) != 0) {
        ::unlink(tmp.c_str());
        return fail(ErrorCode::input, "cannot write " + request.output->string() + ": " + std::strerror(errno));
      }
      fd = -1;
      if (::rename(tmp.c_str(), request.output->c_str()) != 0) {
        ::unlink(tmp.c_str());
        return fail(ErrorCode::input, "cannot write " + request.output->string() + ": " + std::strerror(errno));
      }
    }
    if (request.report_path) {
      const auto json = reveal_report_json(revealer.summary(), request.project_name, request.options);
      if (auto r = atomic_write(*request.report_path, json); !r) return std::unexpected(r.error());
    }
    return revealer.summary();
  } catch (const std::exception& e) {
    return fail(ErrorCode::internal, std::string("internal error: ") + e.what());
  }
}

Result<RevealSummary> reveal_file(const Project& project, const RevealFileRequest& request) {
  auto r = Revealer::create(project, request.options);
  if (!r) return std::unexpected(r.error());
  RevealFileRequest req = request;
  req.project_name = project.name();
  return reveal_file(*r, req);
}

}  // namespace mcxanon
