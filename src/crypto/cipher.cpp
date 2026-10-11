#include "crypto/cipher.hpp"
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
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

#ifndef STATUS_AUTH_TAG_MISMATCH
#define STATUS_AUTH_TAG_MISMATCH ((NTSTATUS)0xC000A002L)
#endif
#endif

namespace pwdmgr::crypto {

CiphertextPackage Cipher::encrypt(
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> key,
    std::span<const uint8_t> nonce,
    std::span<const uint8_t> aad
) {
    if (key.size() != KEY_LEN) {
        throw std::invalid_argument("Invalid key length for AEAD encryption; must be 32 bytes");
    }

    CiphertextPackage pkg;
    pkg.ciphertext.resize(plaintext.size());
    pkg.tag.resize(TAG_LEN);

#if HAS_SODIUM
    unsigned long long mac_len = 0;
    int res = crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
        pkg.ciphertext.data(),
        pkg.tag.data(),
        &mac_len,
        plaintext.data(),
        plaintext.size(),
        aad.empty() ? nullptr : aad.data(),
        aad.size(),
        nullptr,
        nonce.data(),
        key.data()
    );

    if (res != 0) {
        throw std::runtime_error("Libsodium XChaCha20-Poly1305 encryption failed");
    }
#elif defined(_WIN32)
    // Windows CNG AES-256-GCM
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) {
        throw std::runtime_error("Failed to open BCrypt AES algorithm provider");
    }

    status = BCryptSetProperty(
        hAlg,
        BCRYPT_CHAINING_MODE,
        reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
        sizeof(BCRYPT_CHAIN_MODE_GCM),
        0
    );
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("Failed to set GCM chaining mode in BCrypt");
    }

    BCRYPT_KEY_HANDLE hKey = nullptr;
    status = BCryptGenerateSymmetricKey(
        hAlg,
        &hKey,
        nullptr,
        0,
        const_cast<PUCHAR>(key.data()),
        static_cast<ULONG>(key.size()),
        0
    );
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("Failed to generate symmetric key in BCrypt");
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = const_cast<PUCHAR>(nonce.data());
    authInfo.cbNonce = static_cast<ULONG>(nonce.size() >= 12 ? 12 : nonce.size());
    authInfo.pbAuthData = aad.empty() ? nullptr : const_cast<PUCHAR>(aad.data());
    authInfo.cbAuthData = static_cast<ULONG>(aad.size());
    authInfo.pbTag = pkg.tag.data();
    authInfo.cbTag = static_cast<ULONG>(pkg.tag.size());

    ULONG bytesWritten = 0;
    status = BCryptEncrypt(
        hKey,
        const_cast<PUCHAR>(plaintext.data()),
        static_cast<ULONG>(plaintext.size()),
        &authInfo,
        nullptr,
        0,
        pkg.ciphertext.data(),
        static_cast<ULONG>(pkg.ciphertext.size()),
        &bytesWritten,
        0
    );

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!BCRYPT_SUCCESS(status)) {
        throw std::runtime_error("Windows CNG AES-GCM encryption failed");
    }
#else
    throw std::runtime_error("No cryptographic AEAD implementation available on this platform");
#endif

    return pkg;
}

SecureBuffer Cipher::decrypt(
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t> tag,
    std::span<const uint8_t> key,
    std::span<const uint8_t> nonce,
    std::span<const uint8_t> aad
) {
    if (key.size() != KEY_LEN) {
        throw std::invalid_argument("Invalid key length for AEAD decryption; must be 32 bytes");
    }
    if (tag.size() != TAG_LEN) {
        throw std::invalid_argument("Invalid tag length for AEAD decryption; must be 16 bytes");
    }

    SecureBuffer plaintext(ciphertext.size());

#if HAS_SODIUM
    int res = crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
        plaintext.data(),
        nullptr,
        ciphertext.data(),
        ciphertext.size(),
        tag.data(),
        aad.empty() ? nullptr : aad.data(),
        aad.size(),
        nonce.data(),
        key.data()
    );

    if (res != 0) {
        throw AuthenticationError("Authentication failed: invalid master password or corrupted/tampered vault data");
    }
#elif defined(_WIN32)
    // Windows CNG AES-256-GCM
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) {
        throw std::runtime_error("Failed to open BCrypt AES algorithm provider");
    }

    status = BCryptSetProperty(
        hAlg,
        BCRYPT_CHAINING_MODE,
        reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
        sizeof(BCRYPT_CHAIN_MODE_GCM),
        0
    );
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("Failed to set GCM chaining mode in BCrypt");
    }

    BCRYPT_KEY_HANDLE hKey = nullptr;
    status = BCryptGenerateSymmetricKey(
        hAlg,
        &hKey,
        nullptr,
        0,
        const_cast<PUCHAR>(key.data()),
        static_cast<ULONG>(key.size()),
        0
    );
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("Failed to generate symmetric key in BCrypt");
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = const_cast<PUCHAR>(nonce.data());
    authInfo.cbNonce = static_cast<ULONG>(nonce.size() >= 12 ? 12 : nonce.size());
    authInfo.pbAuthData = aad.empty() ? nullptr : const_cast<PUCHAR>(aad.data());
    authInfo.cbAuthData = static_cast<ULONG>(aad.size());
    authInfo.pbTag = const_cast<PUCHAR>(tag.data());
    authInfo.cbTag = static_cast<ULONG>(tag.size());

    ULONG bytesWritten = 0;
    status = BCryptDecrypt(
        hKey,
        const_cast<PUCHAR>(ciphertext.data()),
        static_cast<ULONG>(ciphertext.size()),
        &authInfo,
        nullptr,
        0,
        plaintext.data(),
        static_cast<ULONG>(plaintext.size()),
        &bytesWritten,
        0
    );

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (status == STATUS_AUTH_TAG_MISMATCH || !BCRYPT_SUCCESS(status)) {
        throw AuthenticationError("Authentication failed: invalid master password or corrupted/tampered vault data");
    }
#else
    throw std::runtime_error("No cryptographic AEAD implementation available on this platform");
#endif

    return plaintext;
}

} // namespace pwdmgr::crypto
