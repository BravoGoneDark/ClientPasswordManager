#include "crypto/random.hpp"
#include <stdexcept>
#include <limits>

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

void Random::fill(std::span<uint8_t> buffer) {
    if (buffer.empty()) return;

#if HAS_SODIUM
    randombytes_buf(buffer.data(), buffer.size());
#elif defined(_WIN32)
    NTSTATUS status = BCryptGenRandom(
        nullptr,
        buffer.data(),
        static_cast<ULONG>(buffer.size()),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );
    if (!BCRYPT_SUCCESS(status)) {
        throw std::runtime_error("BCryptGenRandom failed to generate secure random bytes");
    }
#else
    throw std::runtime_error("No cryptographic random source available on this platform");
#endif
}

SecureBuffer Random::get_bytes(size_t size) {
    SecureBuffer buf(size);
    fill(buf.span());
    return buf;
}

uint32_t Random::get_uniform_u32(uint32_t min, uint32_t max) {
    if (min > max) {
        throw std::invalid_argument("min cannot be greater than max in get_uniform_u32");
    }
    if (min == max) {
        return min;
    }

    const uint64_t range = static_cast<uint64_t>(max) - min + 1;

    // Rejection sampling to prevent modulo bias:
    // Any sample >= (2^32 - (2^32 % range)) is rejected and re-drawn.
    const uint64_t limit = (uint64_t{1} << 32) - ((uint64_t{1} << 32) % range);

    uint32_t random_val = 0;
    do {
        fill(std::span<uint8_t>(reinterpret_cast<uint8_t*>(&random_val), sizeof(random_val)));
    } while (random_val >= limit);

    return static_cast<uint32_t>(min + (random_val % range));
}

} // namespace pwdmgr::crypto
