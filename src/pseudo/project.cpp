// SPDX-License-Identifier: GPL-3.0-or-later
#include "mcxanon/project.hpp"

#include "bytes/hex.hpp"
#include "pseudo/atomic_file.hpp"
#include "pseudo/fsutil.hpp"
#include "pseudo/project_impl.hpp"

#include <nlohmann/json.hpp>
#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <sys/stat.h>

namespace mcxanon {
namespace {

constexpr const char* kProjectJson = "project.json";
constexpr const char* kSecret = "project.secret";
constexpr const char* kMapping = "mapping.map.json";
constexpr const char* kLock = "lock";

template <class F>
auto guarded(F&& f) -> decltype(f()) {
  try {
    return f();
  } catch (const std::exception& e) {
    return fail(ErrorCode::internal, std::string("internal error: ") + e.what());
  }
}

Result<void> make_private_dir(const std::filesystem::path& p) {
  if (::mkdir(p.c_str(), 0700) == 0) return {};
  if (errno == EEXIST) return {};
  return fail(ErrorCode::input, "cannot create directory " + p.string() + ": " + std::strerror(errno));
}

Result<void> require_owner_only(const std::filesystem::path& p) {
  auto ok = is_owner_only(p);
  if (!ok) return std::unexpected(ok.error());
  if (!*ok) {
    return fail(ErrorCode::input, p.filename().string() + " is accessible by group or others; run: chmod go-rwx '" +
                                      p.string() + "'");
  }
  return {};
}

std::string project_json(std::string_view name, const Project::Impl& impl) {
  nlohmann::json doc = {{"format", 1}, {"name", std::string(name)}, {"encrypted", impl.encrypted}, {"kdf", nullptr}};
  if (impl.encrypted) {
    doc["kdf"] = {{"algorithm", "argon2id"}, {"m_kib", impl.kdf.m_kib}, {"t", impl.kdf.t},
                  {"p", impl.kdf.p}, {"salt", to_hex(impl.kdf.salt)}};
  }
  return doc.dump(2) + "\n";
}

struct Meta {
  bool encrypted = false;
  KdfParams kdf;
};

Result<Meta> parse_project_json(const std::string& text) {
  const auto doc = nlohmann::json::parse(text, nullptr, false);
  const auto bad = [] { return fail(ErrorCode::input, "project.json is corrupt or of an unsupported format"); };
  if (doc.is_discarded() || !doc.is_object() || !doc.contains("format") || doc["format"] != 1) return bad();
  Meta m;
  if (!doc.contains("encrypted") || !doc["encrypted"].is_boolean()) return bad();
  m.encrypted = doc["encrypted"].get<bool>();
  if (m.encrypted) {
    const auto& k = doc.value("kdf", nlohmann::json());
    if (!k.is_object() || k.value("algorithm", "") != "argon2id") return bad();
    for (const char* f : {"m_kib", "t", "p"}) {
      if (!k.contains(f) || !k[f].is_number_unsigned()) return bad();
    }
    m.kdf.m_kib = k["m_kib"].get<std::uint32_t>();
    m.kdf.t = k["t"].get<std::uint32_t>();
    m.kdf.p = k["p"].get<std::uint32_t>();
    if (!k.contains("salt") || !k["salt"].is_string()) return bad();
    auto salt = from_hex(k["salt"].get<std::string>());
    if (!salt || salt->size() != m.kdf.salt.size()) return bad();
    std::copy(salt->begin(), salt->end(), m.kdf.salt.begin());
  }
  return m;
}

Result<void> write_protected(const Project::Impl& impl, const char* file, const char* role, ByteView data) {
  if (!impl.encrypted) {
    return atomic_write(impl.file(file), std::string_view(reinterpret_cast<const char*>(data.data()), data.size()));
  }
  auto sealed = seal(impl.key, impl.kdf, role, data);
  if (!sealed) return std::unexpected(sealed.error());
  return atomic_write(impl.file(file), std::string_view(reinterpret_cast<const char*>(sealed->data()), sealed->size()));
}

Result<Bytes> read_protected(const Project::Impl& impl, const char* file, const char* role) {
  auto text = read_small_file(impl.file(file));
  if (!text) return std::unexpected(text.error());
  Bytes raw(text->begin(), text->end());
  OPENSSL_cleanse(text->data(), text->size());
  if (!impl.encrypted) return raw;
  auto plain = open_sealed(impl.key, role, raw);
  if (!plain) return std::unexpected(plain.error());
  return plain;
}

// Text values as UTF-8; bytes that are not valid UTF-8, control characters and the
// backslash itself are written as \xNN.
std::string fmt_text(ByteView b) {
  std::string out;
  char buf[8];
  const auto esc = [&](std::uint8_t v) {
    std::snprintf(buf, sizeof buf, "\\x%02x", v);
    out += buf;
  };
  for (std::size_t i = 0; i < b.size();) {
    const std::uint8_t c = b[i];
    std::size_t n = 0;
    std::uint32_t cp = 0;
    if (c < 0x80) {
      n = 1;
      cp = c;
    } else if ((c & 0xE0) == 0xC0) {
      n = 2;
      cp = c & 0x1Fu;
    } else if ((c & 0xF0) == 0xE0) {
      n = 3;
      cp = c & 0x0Fu;
    } else if ((c & 0xF8) == 0xF0) {
      n = 4;
      cp = c & 0x07u;
    }
    bool ok = n > 0 && i + n <= b.size();
    for (std::size_t k = 1; ok && k < n; ++k) {
      ok = (b[i + k] & 0xC0) == 0x80;
      cp = (cp << 6) | (b[i + k] & 0x3Fu);
    }
    // Reject overlong forms, surrogates and values beyond U+10FFFF.
    if (ok && ((n == 2 && cp < 0x80) || (n == 3 && cp < 0x800) || (n == 4 && cp < 0x10000) ||
               (cp >= 0xD800 && cp <= 0xDFFF) || cp > 0x10FFFF)) {
      ok = false;
    }
    if (!ok) {
      esc(c);
      ++i;
      continue;
    }
    if (n == 1 && (c < 0x20 || c == 0x7F || c == '\\')) {
      esc(c);
    } else {
      out.append(reinterpret_cast<const char*>(b.data() + i), n);
    }
    i += n;
  }
  return out;
}

std::string fmt_value(Category c, ByteView b) {
  char buf[64];
  if (c == Category::key_id || is_byte_category(c)) return to_hex(b);  // feature 005: 8 hex digits, hex
  if (is_binary_category(c)) {
    if (b.size() >= 1 && b.size() <= 4) {
      std::uint32_t v = 0;
      for (auto x : b) v = (v << 8) | x;
      return std::to_string(v);
    }
    return to_hex(b);
  }
  if (is_text_category(c)) return fmt_text(b);
  if (b.size() == 4 && (c == Category::ipv4 || c == Category::ipv4_pp || c == Category::ipv4_mcast)) {
    std::snprintf(buf, sizeof buf, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
    return buf;
  }
  if (b.size() == 6 && c == Category::mac) {
    std::snprintf(buf, sizeof buf, "%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5]);
    return buf;
  }
  if (b.size() == 16) {
    std::string o;
    for (std::size_t i = 0; i < 16; i += 2) {
      if (i) o += ":";
      std::snprintf(buf, sizeof buf, "%x", (b[i] << 8) | b[i + 1]);
      o += buf;
    }
    return o;
  }
  if (b.size() == 2) return std::to_string((b[0] << 8) | b[1]);
  return to_hex(b);
}

}  // namespace

std::string format_mapping_value(Category c, ByteView b) { return fmt_value(c, b); }

bool is_mapping_category(std::string_view name) { return category_from_string(name).has_value(); }

bool is_valid_project_name(std::string_view name) {
  if (name.empty() || name.size() > 64 || name == "." || name == "..") return false;
  return std::all_of(name.begin(), name.end(), [](char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' ||
           c == '_' || c == '-';
  });
}

Project::Impl::~Impl() {
  OPENSSL_cleanse(secret.data(), secret.size());
  OPENSSL_cleanse(key.data(), key.size());
}

Result<void> Project::Impl::save_mapping() const {
  const std::string json = mapping.to_json();
  return write_protected(*this, kMapping, "mapping",
                         ByteView(reinterpret_cast<const std::uint8_t*>(json.data()), json.size()));
}

Project::Project(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
Project::Project(Project&&) noexcept = default;
Project& Project::operator=(Project&&) noexcept = default;
Project::~Project() = default;

const std::string& Project::name() const { return impl_->name; }
const std::filesystem::path& Project::directory() const { return impl_->dir; }
std::size_t Project::mapping_size() const { return impl_->mapping.size(); }
bool Project::encrypted() const { return impl_->encrypted; }

std::vector<MappingRow> Project::mapping_rows() const {
  std::vector<MappingRow> rows;
  for (const auto& [k, e] : impl_->mapping.entries()) {
    rows.push_back({std::string(to_string(e.category)), fmt_value(e.category, e.original),
                    fmt_value(e.category, e.pseudonym), e.counter, e.runs_seen});
  }
  std::sort(rows.begin(), rows.end(), [](const MappingRow& a, const MappingRow& b) {
    return std::tie(a.category, a.original) < std::tie(b.category, b.original);
  });
  return rows;
}

Result<Project> Project::create(const DataDirResolution& where, std::string_view name,
                                std::optional<std::string_view> passphrase) {
  return guarded([&] { return create_unguarded(where, name, passphrase); });
}

Result<Project> Project::open(const DataDirResolution& where, std::string_view name, bool wait_for_lock,
                              std::optional<std::string_view> passphrase) {
  return guarded([&] { return open_unguarded(where, name, wait_for_lock, passphrase); });
}

Result<bool> Project::is_encrypted(const DataDirResolution& where, std::string_view name) {
  return guarded([&]() -> Result<bool> {
    if (!is_valid_project_name(name)) return fail(ErrorCode::usage, "invalid project name");
    auto text = read_small_file(where.path / "projects" / std::string(name) / kProjectJson);
    if (!text) {
      return fail(ErrorCode::input, "project '" + std::string(name) + "' not found in " + where.path.string() +
                                        "; create it with: mcxanon project init " + std::string(name));
    }
    auto m = parse_project_json(*text);
    if (!m) return std::unexpected(m.error());
    return m->encrypted;
  });
}

Result<std::vector<ProjectInfo>> Project::list(const DataDirResolution& where) {
  return guarded([&]() -> Result<std::vector<ProjectInfo>> {
    std::vector<ProjectInfo> out;
    const auto dir = where.path / "projects";
    DIR* d = ::opendir(dir.c_str());
    if (d == nullptr) return out;
    while (const dirent* e = ::readdir(d)) {
      const std::string n = e->d_name;
      if (!is_valid_project_name(n) || !fsutil::is_directory(dir / n)) continue;
      ProjectInfo info{n, false, std::nullopt};
      if (auto t = read_small_file(dir / n / kProjectJson)) {
        if (auto m = parse_project_json(*t)) info.encrypted = m->encrypted;
      }
      if (!info.encrypted) {
        if (auto mt = read_small_file(dir / n / kMapping)) {
          if (auto mp = Mapping::from_json(*mt)) info.entries = mp->size();
        }
      }
      out.push_back(std::move(info));
    }
    ::closedir(d);
    std::sort(out.begin(), out.end(), [](const auto& a, const auto& b) { return a.name < b.name; });
    return out;
  });
}

Result<Project> Project::create_unguarded(const DataDirResolution& where, std::string_view name,
                                          std::optional<std::string_view> passphrase) {
  if (!is_valid_project_name(name)) {
    return fail(ErrorCode::usage, "invalid project name; use 1-64 characters from A-Z a-z 0-9 . _ -");
  }
  if (passphrase && passphrase->empty()) return fail(ErrorCode::usage, "the passphrase must not be empty");
  if (auto r = fsutil::make_directories(where.path, 0700); !r) return std::unexpected(r.error());
  const auto projects = where.path / "projects";
  if (auto r = make_private_dir(projects); !r) return std::unexpected(r.error());
  const auto dir = projects / std::string(name);
  if (::mkdir(dir.c_str(), 0700) != 0) {
    if (errno == EEXIST) return fail(ErrorCode::usage, "project '" + std::string(name) + "' already exists");
    return fail(ErrorCode::input, "cannot create project directory: " + std::string(std::strerror(errno)));
  }
  auto lock = ProjectLock::acquire(dir / kLock, false);
  if (!lock) return std::unexpected(lock.error());
  auto impl = std::make_unique<Impl>(std::string(name), dir, std::move(*lock));
  if (RAND_bytes(impl->secret.data(), static_cast<int>(impl->secret.size())) != 1) {
    return fail(ErrorCode::internal, "random number generator failed");
  }
  if (passphrase) {
    auto kp = new_kdf_params();
    if (!kp) return std::unexpected(kp.error());
    impl->kdf = *kp;
    auto key = derive_key(*passphrase, impl->kdf);
    if (!key) return std::unexpected(key.error());
    impl->key = *key;
    impl->encrypted = true;
  }
  auto ok = write_protected(*impl, kSecret, "secret", impl->secret);
  if (ok) ok = atomic_write(impl->file(kProjectJson), project_json(name, *impl));
  if (ok) ok = impl->save_mapping();
  if (!ok) return std::unexpected(ok.error());
  return Project(std::move(impl));
}

Result<Project> Project::open_unguarded(const DataDirResolution& where, std::string_view name, bool wait_for_lock,
                                        std::optional<std::string_view> passphrase) {
  if (!is_valid_project_name(name)) return fail(ErrorCode::usage, "invalid project name");
  const auto dir = where.path / "projects" / std::string(name);
  if (!fsutil::is_directory(dir)) {
    return fail(ErrorCode::input, "project '" + std::string(name) + "' not found in " + where.path.string() +
                                      "; create it with: mcxanon project init " + std::string(name));
  }
  if (auto r = require_owner_only(dir); !r) return std::unexpected(r.error());
  auto lock = ProjectLock::acquire(dir / kLock, wait_for_lock);
  if (!lock) return std::unexpected(lock.error());
  auto impl = std::make_unique<Impl>(std::string(name), dir, std::move(*lock));
  for (const char* f : {kProjectJson, kSecret, kMapping}) {
    if (auto r = require_owner_only(impl->file(f)); !r) return std::unexpected(r.error());
  }
  auto pj = read_small_file(impl->file(kProjectJson));
  if (!pj) return std::unexpected(pj.error());
  auto meta = parse_project_json(*pj);
  if (!meta) return std::unexpected(meta.error());
  if (meta->encrypted) {
    if (!passphrase) return fail(ErrorCode::input, "this project is encrypted; a passphrase is needed");
    impl->encrypted = true;
    impl->kdf = meta->kdf;
    auto key = derive_key(*passphrase, impl->kdf);
    if (!key) return std::unexpected(key.error());
    impl->key = *key;
  }
  auto secret = read_protected(*impl, kSecret, "secret");
  if (!secret) return std::unexpected(secret.error());
  if (secret->size() != impl->secret.size()) {
    OPENSSL_cleanse(secret->data(), secret->size());
    return fail(ErrorCode::input, "project.secret is corrupt (wrong size)");
  }
  std::memcpy(impl->secret.data(), secret->data(), impl->secret.size());
  OPENSSL_cleanse(secret->data(), secret->size());
  auto mtext = read_protected(*impl, kMapping, "mapping");
  if (!mtext) return std::unexpected(mtext.error());
  auto mapping = Mapping::from_json(std::string_view(reinterpret_cast<const char*>(mtext->data()), mtext->size()));
  OPENSSL_cleanse(mtext->data(), mtext->size());
  if (!mapping) return std::unexpected(mapping.error());
  impl->mapping = std::move(*mapping);
  return Project(std::move(impl));
}

}  // namespace mcxanon
