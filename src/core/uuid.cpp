#include "core/uuid.hpp"
#include "crypto/random.hpp"

#include <array>
#include <cstdio>
#include <cctype>

namespace pwdmgr::core {

std::string Uuid::generate() {
    std::array<uint8_t, 16> bytes{};
    crypto::Random::fill(bytes);

    // RFC 4122 Section 4.4:
    // Set the two most significant bits (bits 6 and 7) of clock_seq_hi_and_reserved to zero and one (variant 1: 0b10xxxxxx)
    bytes[8] = static_cast<uint8_t>((bytes[8] & 0x3F) | 0x80);

    // Set the four most significant bits (bits 12 through 15) of time_hi_and_version to 4 (version 4: 0b0100xxxx)
    bytes[6] = static_cast<uint8_t>((bytes[6] & 0x0F) | 0x40);

    char buffer[37];
    std::snprintf(
        buffer, sizeof(buffer),
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    );

    return std::string(buffer, 36);
}

bool Uuid::is_valid(std::string_view uuid) noexcept {
    if (uuid.length() != 36) {
        return false;
    }

    // Hyphens check
    if (uuid[8] != '-' || uuid[13] != '-' || uuid[18] != '-' || uuid[23] != '-') {
        return false;
    }

    // Version 4 check
    if (uuid[14] != '4') {
        return false;
    }

    // Variant 1 check (8, 9, a, b, A, B)
    char variant = uuid[19];
    if (variant != '8' && variant != '9' &&
        variant != 'a' && variant != 'b' &&
        variant != 'A' && variant != 'B') {
        return false;
    }

    // Hexadecimal check for all non-hyphen positions
    for (size_t i = 0; i < 36; ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            continue;
        }
        if (!std::isxdigit(static_cast<unsigned char>(uuid[i]))) {
            return false;
        }
    }

    return true;
}

} // namespace pwdmgr::core
