// SPDX-License-Identifier: GPL-3.0-or-later
#include "pseudo/crypto.hpp"

#include "bytes/endian.hpp"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include <cstring>
#include <memory>

namespace mcxanon {
namespace {

constexpr std::size_t kHeader = 48;
constexpr std::size_t kTag = 16;
constexpr char kMagic[] = "MCXENC01";

struct CtxFree {
  void operator()(EVP_CIPHER_CTX* c) const { EVP_CIPHER_CTX_free(c); }
};

Result<void> crypto_fail() { return fail(ErrorCode::internal, "cryptographic library failure"); }

Bytes aad(ByteView header, std::string_view role) {
  Bytes a(header.begin(), header.begin() + kHeader);
  a.insert(a.end(), role.begin(), role.end());
  return a;
}

}  // namespace

Result<KdfParams> new_kdf_params() {
  KdfParams p;
  if (RAND_bytes(p.salt.data(), static_cast<int>(p.salt.size())) != 1) {
    return fail(ErrorCode::internal, "random number generator failed");
  }
  return p;
}

Result<Key> derive_key(std::string_view passphrase, const KdfParams& kp) {
  EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "ARGON2ID", nullptr);
  if (kdf == nullptr) return fail(ErrorCode::internal, "Argon2id is not available");
  EVP_KDF_CTX* ctx = EVP_KDF_CTX_new(kdf);
  EVP_KDF_free(kdf);
  if (ctx == nullptr) return fail(ErrorCode::internal, "Argon2id is not available");
  std::uint32_t iter = kp.t;
  std::uint32_t mem = kp.m_kib;
  std::uint32_t lanes = kp.p;
  std::uint32_t threads = 1;
  auto salt = kp.salt;
  const OSSL_PARAM params[] = {
      OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, const_cast<char*>(passphrase.data()),
                                        passphrase.size()),
      OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt.data(), salt.size()),
      OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &iter),
      OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &mem),
      OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &lanes),
      OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS, &threads),
      OSSL_PARAM_construct_end()};
  Key key{};
  const int rc = EVP_KDF_derive(ctx, key.data(), key.size(), params);
  EVP_KDF_CTX_free(ctx);
  if (rc != 1) return fail(ErrorCode::internal, "key derivation failed");
  return key;
}

Result<Bytes> seal(const Key& key, const KdfParams& kp, std::string_view role, ByteView plaintext) {
  Bytes out(kHeader, 0);
  std::memcpy(out.data(), kMagic, 8);
  store32(out, 8, kp.m_kib, Endian::big);
  store32(out, 12, kp.t, Endian::big);
  store32(out, 16, kp.p, Endian::big);
  std::memcpy(out.data() + 20, kp.salt.data(), 16);
  if (RAND_bytes(out.data() + 36, 12) != 1) return fail(ErrorCode::internal, "random number generator failed");
  std::unique_ptr<EVP_CIPHER_CTX, CtxFree> ctx(EVP_CIPHER_CTX_new());
  if (!ctx) return std::unexpected(crypto_fail().error());
  const Bytes a = aad(out, role);
  int len = 0;
  if (EVP_EncryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr, key.data(), out.data() + 36) != 1 ||
      EVP_EncryptUpdate(ctx.get(), nullptr, &len, a.data(), static_cast<int>(a.size())) != 1) {
    return std::unexpected(crypto_fail().error());
  }
  out.resize(kHeader + plaintext.size() + kTag);
  if (EVP_EncryptUpdate(ctx.get(), out.data() + kHeader, &len, plaintext.data(),
                        static_cast<int>(plaintext.size())) != 1 ||
      EVP_EncryptFinal_ex(ctx.get(), out.data() + kHeader + len, &len) != 1 ||
      EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, kTag, out.data() + kHeader + plaintext.size()) != 1) {
    return std::unexpected(crypto_fail().error());
  }
  return out;
}

Result<KdfParams> container_params(ByteView c) {
  if (c.size() < kHeader + kTag || std::memcmp(c.data(), kMagic, 8) != 0) {
    return fail(ErrorCode::input, "not an encrypted project file");
  }
  KdfParams p;
  p.m_kib = load32(c, 8, Endian::big);
  p.t = load32(c, 12, Endian::big);
  p.p = load32(c, 16, Endian::big);
  std::memcpy(p.salt.data(), c.data() + 20, 16);
  if (p.m_kib < 8 || p.m_kib > (4u << 20) || p.t < 1 || p.t > 64 || p.p < 1 || p.p > 64) {
    return fail(ErrorCode::input, "encrypted project file has unsupported parameters");
  }
  return p;
}

Result<Bytes> open_sealed(const Key& key, std::string_view role, ByteView c) {
  auto params = container_params(c);
  if (!params) return std::unexpected(params.error());
  const std::size_t n = c.size() - kHeader - kTag;
  std::unique_ptr<EVP_CIPHER_CTX, CtxFree> ctx(EVP_CIPHER_CTX_new());
  if (!ctx) return std::unexpected(crypto_fail().error());
  const Bytes a = aad(c, role);
  Bytes plain(n);
  int len = 0;
  Bytes tag(c.end() - kTag, c.end());
  const bool ok =
      EVP_DecryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr, key.data(), c.data() + 36) == 1 &&
      EVP_DecryptUpdate(ctx.get(), nullptr, &len, a.data(), static_cast<int>(a.size())) == 1 &&
      EVP_DecryptUpdate(ctx.get(), plain.data(), &len, c.data() + kHeader, static_cast<int>(n)) == 1 &&
      EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, kTag, tag.data()) == 1 &&
      EVP_DecryptFinal_ex(ctx.get(), plain.data() + len, &len) == 1;
  if (!ok) {
    OPENSSL_cleanse(plain.data(), plain.size());
    return fail(ErrorCode::input, "wrong passphrase or tampered file");
  }
  return plain;
}

}  // namespace mcxanon
