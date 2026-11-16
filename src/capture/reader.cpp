// SPDX-License-Identifier: GPL-3.0-or-later
#include "capture/reader.hpp"

#include "capture/detect.hpp"

#include <cerrno>
#include <cstring>
#include <string>

namespace mcxanon {

// Sequential byte source. read() returns the number of bytes actually read,
// which is less than requested only at the end of the data.
class ByteSource {
 public:
  virtual ~ByteSource() = default;
  virtual Result<std::size_t> read(std::uint8_t* out, std::size_t n) = 0;
};

namespace {

class FileSource final : public ByteSource {
 public:
  explicit FileSource(std::FILE* f) : f_(f) { std::setvbuf(f_, nullptr, _IOFBF, 1u << 20); }
  FileSource(const FileSource&) = delete;
  FileSource& operator=(const FileSource&) = delete;
  ~FileSource() override { std::fclose(f_); }
  Result<std::size_t> read(std::uint8_t* out, std::size_t n) override {
    const std::size_t got = std::fread(out, 1, n, f_);
    if (got < n && std::ferror(f_)) return fail(ErrorCode::input, "read error on input file");
    return got;
  }

 private:
  std::FILE* f_;
};

class MemorySource final : public ByteSource {
 public:
  explicit MemorySource(Bytes data) : data_(std::move(data)) {}
  Result<std::size_t> read(std::uint8_t* out, std::size_t n) override {
    const std::size_t got = std::min(n, data_.size() - pos_);
    if (got == 0) return std::size_t{0};  // memcpy with a null pointer is undefined even for 0 bytes
    std::memcpy(out, data_.data() + pos_, got);
    pos_ += got;
    return got;
  }

 private:
  Bytes data_;
  std::size_t pos_ = 0;
};

// Reads exactly n bytes into buf (appending). Returns the number read; fewer
// than n means end of data.
Result<std::size_t> read_into(ByteSource& src, Bytes& buf, std::size_t n) {
  if (n == 0) return std::size_t{0};
  const std::size_t at = buf.size();
  buf.resize(at + n);
  auto got = src.read(buf.data() + at, n);
  if (!got) return std::unexpected(got.error());
  buf.resize(at + *got);
  return *got;
}

}  // namespace

CaptureReader::CaptureReader(std::unique_ptr<ByteSource> src) : src_(std::move(src)) {}
CaptureReader::CaptureReader(CaptureReader&&) noexcept = default;
CaptureReader& CaptureReader::operator=(CaptureReader&&) noexcept = default;
CaptureReader::~CaptureReader() = default;

Result<CaptureReader> CaptureReader::open(const std::filesystem::path& path) {
  std::FILE* f = std::fopen(path.c_str(), "rb");
  if (f == nullptr) {
    return fail(ErrorCode::input,
                "cannot open input file " + path.filename().string() + ": " + std::strerror(errno));
  }
  CaptureReader r(std::make_unique<FileSource>(f));
  if (auto ok = r.init(); !ok) return std::unexpected(ok.error());
  return r;
}

Result<CaptureReader> CaptureReader::from_memory(Bytes data) {
  CaptureReader r(std::make_unique<MemorySource>(std::move(data)));
  if (auto ok = r.init(); !ok) return std::unexpected(ok.error());
  return r;
}

// Peeks the format: the first bytes are kept in a pending buffer by re-reading
// through a small prefix source.
namespace {
class PrefixSource final : public ByteSource {
 public:
  PrefixSource(Bytes prefix, std::unique_ptr<ByteSource> rest)
      : prefix_(std::move(prefix)), rest_(std::move(rest)) {}
  Result<std::size_t> read(std::uint8_t* out, std::size_t n) override {
    std::size_t done = 0;
    if (pos_ < prefix_.size() && n > 0) {
      done = std::min(n, prefix_.size() - pos_);
      std::memcpy(out, prefix_.data() + pos_, done);
      pos_ += done;
    }
    if (done < n) {
      auto more = rest_->read(out + done, n - done);
      if (!more) return std::unexpected(more.error());
      done += *more;
    }
    return done;
  }

 private:
  Bytes prefix_;
  std::size_t pos_ = 0;
  std::unique_ptr<ByteSource> rest_;
};
}  // namespace

Result<void> CaptureReader::init() {
  Bytes head;
  auto got = read_into(*src_, head, 8);
  if (!got) return std::unexpected(got.error());
  auto fmt = detect_format(head);
  if (!fmt) return std::unexpected(fmt.error());
  format_ = *fmt;
  src_ = std::make_unique<PrefixSource>(std::move(head), std::move(src_));
  return {};
}

Result<std::optional<Record>> CaptureReader::next() {
  if (ended_) return std::optional<Record>();
  auto r = format_ == CaptureFormat::pcap ? next_pcap() : next_pcapng();
  if (r && !r->has_value()) ended_ = true;
  return r;
}

Result<std::optional<Record>> CaptureReader::next_pcap() {
  Record rec;
  rec.file_offset = offset_;
  if (!header_done_) {
    auto got = read_into(*src_, rec.bytes, kPcapFileHeaderSize);
    if (!got) return std::unexpected(got.error());
    auto h = parse_pcap_file_header(rec.bytes);
    if (!h) return std::unexpected(h.error());
    pcap_header_ = *h;
    header_done_ = true;
    rec.kind = RecordKind::pcap_file_header;
    rec.endian = h->endian;
    offset_ += rec.bytes.size();
    return std::optional<Record>(std::move(rec));
  }
  auto got = read_into(*src_, rec.bytes, kPcapRecordHeaderSize);
  if (!got) return std::unexpected(got.error());
  if (*got == 0) return std::optional<Record>();
  if (*got < kPcapRecordHeaderSize) {
    tail_ = *got;
    return std::optional<Record>();
  }
  const auto ph = parse_pcap_packet_header(rec.bytes, pcap_header_.endian);
  if (!ph) return std::unexpected(ph.error());
  if (ph->caplen > kPcapngMaxBlockSize) {
    return fail(ErrorCode::input,
                "pcap record at offset " + std::to_string(offset_) + " is larger than 64 MiB");
  }
  auto data = read_into(*src_, rec.bytes, ph->caplen);
  if (!data) return std::unexpected(data.error());
  if (*data < ph->caplen) {
    tail_ = rec.bytes.size();
    return std::optional<Record>();
  }
  rec.kind = RecordKind::pcap_packet;
  rec.endian = pcap_header_.endian;
  rec.frame_number = ++frames_;
  offset_ += rec.bytes.size();
  return std::optional<Record>(std::move(rec));
}

Result<std::optional<Record>> CaptureReader::next_pcapng() {
  Record rec;
  rec.file_offset = offset_;
  rec.kind = RecordKind::pcapng_block;
  auto got = read_into(*src_, rec.bytes, 8);
  if (!got) return std::unexpected(got.error());
  if (*got == 0) return std::optional<Record>();
  if (*got < 8) {
    tail_ = *got;
    return std::optional<Record>();
  }
  const std::uint32_t raw_type = load32(rec.bytes, 0, Endian::little);
  if (raw_type == kPcapngShb) {
    // Byte order comes from the byte-order magic that follows the length.
    auto magic = read_into(*src_, rec.bytes, 4);
    if (!magic) return std::unexpected(magic.error());
    if (*magic < 4) {
      tail_ = rec.bytes.size();
      return std::optional<Record>();
    }
    const std::uint32_t m = load32(rec.bytes, 8, Endian::little);
    if (m == kPcapngByteOrderMagic) {
      section_endian_ = Endian::little;
    } else if (load32(rec.bytes, 8, Endian::big) == kPcapngByteOrderMagic) {
      section_endian_ = Endian::big;
    } else {
      return fail(ErrorCode::input, "pcapng SHB has an invalid byte-order magic");
    }
    seen_shb_ = true;
    interfaces_.clear();
  } else if (!seen_shb_) {
    return fail(ErrorCode::input, "pcapng file does not start with a Section Header Block");
  }
  const Endian e = section_endian_;
  rec.endian = e;
  rec.block_type = load32(rec.bytes, 0, e);
  const std::uint32_t total = load32(rec.bytes, 4, e);
  if (total < 12 || total % 4 != 0) {
    return fail(ErrorCode::input, "pcapng block at offset " + std::to_string(offset_) +
                                      " has an invalid total length");
  }
  if (total > kPcapngMaxBlockSize) {
    return fail(ErrorCode::input, "pcapng block at offset " + std::to_string(offset_) +
                                      " is larger than 64 MiB");
  }
  const std::size_t have = rec.bytes.size();
  auto body = read_into(*src_, rec.bytes, total - have);
  if (!body) return std::unexpected(body.error());
  if (*body < total - have) {
    tail_ = rec.bytes.size();
    return std::optional<Record>();
  }
  if (load32(rec.bytes, total - 4, e) != total) {
    return fail(ErrorCode::input, "pcapng block at offset " + std::to_string(offset_) +
                                      " has mismatched leading and trailing lengths");
  }
  if (rec.block_type == kPcapngShb) {
    const std::uint16_t major = load16(rec.bytes, 12, e);
    if (major != 1) return fail(ErrorCode::input, "unsupported pcapng major version");
  } else if (rec.block_type == kPcapngIdb) {
    auto info = parse_idb(rec.bytes, e);
    if (!info) return std::unexpected(info.error());
    interfaces_.push_back(*info);
  } else if (rec.block_type == kPcapngEpb || rec.block_type == kPcapngSpb ||
             rec.block_type == kPcapngPacketObsolete) {
    rec.frame_number = ++frames_;
  }
  offset_ += rec.bytes.size();
  return std::optional<Record>(std::move(rec));
}

}  // namespace mcxanon
