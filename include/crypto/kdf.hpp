#pragma once

#include "crypto/secure_memory.hpp"
#include <cstdint>
#include <cstddef>
#include <span>
#include <string_view>

namespace pwdmgr::crypto {

/**
 * @brief Key Derivation Function (KDF) using Argon2id.
 *        Stretches a master password into a 256-bit cryptographic key
 *        with configurable memory and CPU cost to defeat GPU/ASIC cracking.
 */
class KDF {
public:
    // Standard sizes (in bytes)
    static constexpr size_t SALT_LEN = 16;       // 128-bit salt
    static constexpr size_t KEY_LEN  = 32;       // 256-bit symmetric encryption key

    // Standard Argon2id difficulty parameters (Security profiles)
    struct Params {
        uint32_t ops_limit;   // Number of computational passes
        size_t   mem_limit;   // Memory limit in bytes (memory hardness)

        // Balanced profile for standard interactive desktop vaults
        static constexpr Params interactive() {
            return {3, 64 * 1024 * 1024}; // 3 passes, 64 MB RAM
        }

        // High-security profile (slower, maximum offline defense)
        static constexpr Params moderate() {
            return {4, 128 * 1024 * 1024}; // 4 passes, 128 MB RAM
        }
    };

    /**
     * @brief Derives a 256-bit key from a password and salt using Argon2id.
     * @param password User-supplied master password.
     * @param salt Cryptographically secure random salt (must be at least SALT_LEN).
     * @param params Memory and CPU work factors.
     * @return SecureBuffer containing the derived 256-bit key.
     */
    static SecureBuffer derive_key(
        std::string_view password,
        std::span<const uint8_t> salt,
        const Params& params = Params::interactive()
    );
};

} // namespace pwdmgr::crypto
