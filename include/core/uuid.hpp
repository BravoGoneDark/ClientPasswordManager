#pragma once

#include <string>
#include <string_view>

namespace pwdmgr::core {

/**
 * @brief RFC 4122 Version 4 (Random) UUID Generator and Validator.
 *        Generates cryptographically random UUIDs using the CSPRNG subsystem.
 */
class Uuid {
public:
    /**
     * @brief Generates a canonical RFC 4122 v4 UUID string.
     *        Format: "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx"
     * @return Canonical 36-character UUID string in lowercase.
     */
    [[nodiscard]] static std::string generate();

    /**
     * @brief Validates if the given string is a valid RFC 4122 v4 UUID.
     * @param uuid The string view to test.
     * @return true if valid canonical v4 UUID, false otherwise.
     */
    [[nodiscard]] static bool is_valid(std::string_view uuid) noexcept;
};

} // namespace pwdmgr::core
