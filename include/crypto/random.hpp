#pragma once

#include "crypto/secure_memory.hpp"
#include <cstdint>
#include <cstddef>
#include <span>

namespace pwdmgr::crypto {

/**
 * @brief Cryptographically Secure Pseudo-Random Number Generator (CSPRNG) wrapper.
 *        Sources entropy from OS kernel pools (BCryptGenRandom / sodium_randombytes).
 */
class Random {
public:
    /**
     * @brief Fills the provided buffer with cryptographically secure random bytes.
     */
    static void fill(std::span<uint8_t> buffer);

    /**
     * @brief Allocates and returns a SecureBuffer of specified size with random bytes.
     */
    static SecureBuffer get_bytes(size_t size);

    /**
     * @brief Generates an unbiased random integer in the range [min, max] inclusive.
     *        Uses rejection sampling to prevent modulo bias.
     */
    static uint32_t get_uniform_u32(uint32_t min, uint32_t max);
};

} // namespace pwdmgr::crypto
