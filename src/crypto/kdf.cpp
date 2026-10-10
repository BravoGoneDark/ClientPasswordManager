#include "crypto/kdf.hpp"
#include <stdexcept>

#if __has_include(<sodium.h>)
#include <sodium.h>
#define HAS_SODIUM 1
#else
#define HAS_SODIUM 0
#endif

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#endif

namespace pwdmgr::crypto {

SecureBuffer KDF::derive_key(
    std::string_view password,
    std::span<const uint8_t> salt,
    const Params& params
) {
    if (salt.size() < SALT_LEN) {
        throw std::invalid_argument("Salt size is too small; must be at least 16 bytes");
    }

    SecureBuffer key(KEY_LEN);

#if HAS_SODIUM
    if (crypto_pwhash(
            key.data(),
            key.size(),
            password.data(),
            password.size(),
            salt.data(),
            params.ops_limit,
            params.mem_limit,
            crypto_pwhash_ALG_ARGON2ID13
        ) != 0) {
        throw std::runtime_error("Argon2id key derivation failed (insufficient memory or invalid params)");
    }
#elif defined(_WIN32)
    // Windows CNG PBKDF2-HMAC-SHA256 fallback when libsodium is not yet linked
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_SHA256_ALGORITHM,
        nullptr,
        BCRYPT_ALG_HANDLE_HMAC_FLAG
    );

    if (!BCRYPT_SUCCESS(status)) {
        throw std::runtime_error("Failed to open BCrypt SHA256 HMAC algorithm provider");
    }

    // Work factor iterations for PBKDF2 fallback (600,000 iterations standard)
    const uint64_t iterations = 600000;

    status = BCryptDeriveKeyPBKDF2(
        hAlg,
        reinterpret_cast<PUCHAR>(const_cast<char*>(password.data())),
        static_cast<ULONG>(password.size()),
        reinterpret_cast<PUCHAR>(const_cast<uint8_t*>(salt.data())),
        static_cast<ULONG>(salt.size()),
        iterations,
        key.data(),
        static_cast<ULONG>(key.size()),
        0
    );

    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!BCRYPT_SUCCESS(status)) {
        throw std::runtime_error("Windows CNG PBKDF2 key derivation failed");
    }
#else
    throw std::runtime_error("No cryptographic KDF implementation available on this platform");
#endif

    return key;
}

} // namespace pwdmgr::crypto
