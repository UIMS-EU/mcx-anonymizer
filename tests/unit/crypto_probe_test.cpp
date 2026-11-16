// SPDX-License-Identifier: GPL-3.0-or-later
//
// Early verification: the linked OpenSSL provides Argon2id through EVP_KDF and
// reproduces the Argon2id test vector of RFC 9106, Section 5.3.

#include <catch2/catch_test_macros.hpp>

#include <openssl/core_names.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

#include <array>
#include <cstdint>

TEST_CASE("OpenSSL Argon2id reproduces RFC 9106 section 5.3", "[crypto][probe]") {
  std::array<unsigned char, 32> password{};
  password.fill(0x01);
  std::array<unsigned char, 16> salt{};
  salt.fill(0x02);
  std::array<unsigned char, 8> secret{};
  secret.fill(0x03);
  std::array<unsigned char, 12> ad{};
  ad.fill(0x04);
  const std::array<unsigned char, 32> expected{
      0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, 0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b, 0x53, 0xc9,
      0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e, 0xb5, 0x25, 0x20, 0xe9, 0x6b, 0x01, 0xe6, 0x59};

  EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "ARGON2ID", nullptr);
  REQUIRE(kdf != nullptr);
  EVP_KDF_CTX* ctx = EVP_KDF_CTX_new(kdf);
  EVP_KDF_free(kdf);
  REQUIRE(ctx != nullptr);

  std::uint32_t iterations = 3;
  std::uint32_t memory_kib = 32;
  std::uint32_t lanes = 4;
  std::uint32_t threads = 1;  // lanes set the parallelism; one thread is enough
  std::uint32_t version = 0x13;
  const std::array<OSSL_PARAM, 10> params{
      OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, password.data(), password.size()),
      OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt.data(), salt.size()),
      OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET, secret.data(), secret.size()),
      OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_ARGON2_AD, ad.data(), ad.size()),
      OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &iterations),
      OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &memory_kib),
      OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &lanes),
      OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS, &threads),
      OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_VERSION, &version),
      OSSL_PARAM_construct_end()};

  std::array<unsigned char, 32> tag{};
  const int rc = EVP_KDF_derive(ctx, tag.data(), tag.size(), params.data());
  EVP_KDF_CTX_free(ctx);
  REQUIRE(rc == 1);
  CHECK(tag == expected);
}
