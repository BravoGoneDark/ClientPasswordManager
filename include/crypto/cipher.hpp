#pragma once

#include "crypto/secure_memory.hpp"
#include <cstdint>
#include <cstddef>
#include <span>
#include <stdexcept>

namespace pwdmgr::crypto {

/**
 * @brief Exception thrown when ciphertext has been tampered with or key is incorrect.
 */
class AuthenticationError : public std::runtime_error {
public:
    explicit AuthenticationError(const std::string& msg) : std::runtime_error(msg) {}
};

/**
 * @brief Container holding encrypted data and its authentication tag (MAC).
 */
struct CiphertextPackage {
    SecureBuffer ciphertext;
    SecureBuffer tag;    // 16-byte MAC authentication tag
};

/**
 * @brief Authenticated Encryption with Associated Data (AEAD).
 *        Uses XChaCha20-Poly1305 (Libsodium) or AES-256-GCM (Windows CNG).
 *        Guarantees both confidentiality (encryption) and authenticity/integrity (tamper detection).
 */
class Cipher {
public:
    static constexpr size_t KEY_LEN   = 32;  // 256-bit symmetric key
    static constexpr size_t NONCE_LEN = 24;  // 192-bit nonce for XChaCha20 (or 12 bytes for GCM)
    static constexpr size_t TAG_LEN   = 16;  // 128-bit authentication tag

    /**
     * @brief Encrypts plaintext using AEAD and generates an authentication tag.
     * @param plaintext Data to encrypt.
     * @param key 256-bit derived key.
     * @param nonce Unique random nonce/IV (must never be reused with same key).
     * @param aad Additional Authenticated Data (header metadata verified but not encrypted).
     * @return CiphertextPackage containing ciphertext and authentication tag.
     */
    static CiphertextPackage encrypt(
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t> key,
        std::span<const uint8_t> nonce,
        std::span<const uint8_t> aad = {}
    );

    /**
     * @brief Decrypts ciphertext and verifies authentication tag integrity.
     * @throws AuthenticationError If MAC check fails (wrong password or corrupted/tampered bytes).
     * @return Decrypted plaintext in a SecureBuffer.
     */
    static SecureBuffer decrypt(
        std::span<const uint8_t> ciphertext,
        std::span<const uint8_t> tag,
        std::span<const uint8_t> key,
        std::span<const uint8_t> nonce,
        std::span<const uint8_t> aad = {}
    );
};

} // namespace pwdmgr::crypto
