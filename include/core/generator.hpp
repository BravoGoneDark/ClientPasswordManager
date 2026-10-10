#pragma once

#include "crypto/secure_memory.hpp"

#include <string>
#include <string_view>
#include <vector>
#include <cstdint>

namespace pwdmgr::core {

/**
 * @brief Configuration options for password generation.
 */
struct PasswordOptions {
    size_t length{20};
    bool use_lowercase{true};
    bool use_uppercase{true};
    bool use_digits{true};
    bool use_symbols{true};
    bool exclude_ambiguous{false};  // Filters 0, O, o, 1, l, I, |
    bool require_each_type{true};   // Guarantees at least one char from each selected set

    static PasswordOptions strong() noexcept {
        return {20, true, true, true, true, false, true};
    }

    static PasswordOptions pin(size_t len = 6) noexcept {
        return {len, false, false, true, false, false, false};
    }

    static PasswordOptions alphanumeric(size_t len = 16) noexcept {
        return {len, true, true, true, false, false, true};
    }
};

/**
 * @brief Classification levels for password strength based on entropy.
 */
enum class StrengthLevel {
    VeryWeak,   // < 40 bits
    Weak,       // 40 - 59 bits
    Moderate,   // 60 - 79 bits
    Strong,     // 80 - 99 bits
    VeryStrong  // >= 100 bits
};

/**
 * @brief Detailed breakdown of password entropy and brute-force resistance.
 */
struct EntropyScore {
    double pool_entropy_bits{0.0};       // E = L * log2(R)
    double shannon_entropy_bits{0.0};    // Information-theoretic Shannon entropy
    double effective_entropy_bits{0.0};  // Penalized for repeats and sequential patterns
    StrengthLevel strength{StrengthLevel::VeryWeak};
    std::string crack_time_offline;      // Estimated time against 10^10 hashes/sec (GPU rig)
    std::string crack_time_online;       // Estimated time against 100 attempts/sec (rate-limited)
    std::vector<std::string> suggestions;
};

/**
 * @brief CSPRNG-backed password and passphrase generator.
 *        Eliminates modulo bias using rejection sampling and stores secrets in SecureString.
 */
class PasswordGenerator {
public:
    static constexpr const char* LOWERCASE_CHARS = "abcdefghijklmnopqrstuvwxyz";
    static constexpr const char* UPPERCASE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    static constexpr const char* DIGIT_CHARS     = "0123456789";
    static constexpr const char* SYMBOL_CHARS    = "!@#$%^&*()-_=+[]{}|;:,.<>?";
    static constexpr const char* AMBIGUOUS_CHARS = "0Oo1lI|";

    /**
     * @brief Generates a cryptographically strong random password matching the options.
     * @param options Character pools, length, and requirements.
     * @throws std::invalid_argument If length is 0 or no character pools are enabled.
     * @return SecureString containing the generated password.
     */
    [[nodiscard]] static crypto::SecureString generate(
        const PasswordOptions& options = PasswordOptions::strong()
    );

    /**
     * @brief Generates a multi-word Diceware passphrase from cryptographically selected words.
     * @param word_count Number of words in the passphrase (default 5).
     * @param separator Separator character between words (default '-').
     * @return SecureString containing the passphrase.
     */
    [[nodiscard]] static crypto::SecureString generate_passphrase(
        size_t word_count = 5,
        char separator = '-'
    );
};

/**
 * @brief Information-theoretic entropy evaluator and password strength analyzer.
 */
class EntropyMeter {
public:
    /**
     * @brief Performs a full cryptographic entropy analysis on a given password.
     * @param password Password to evaluate.
     * @return Detailed EntropyScore struct.
     */
    [[nodiscard]] static EntropyScore evaluate(std::string_view password);

    /**
     * @brief Calculates pool-based entropy in bits: E = L * log2(R).
     * @param password Password string.
     * @return Raw pool entropy in bits.
     */
    [[nodiscard]] static double calculate_pool_entropy(std::string_view password) noexcept;

    /**
     * @brief Calculates Shannon information entropy H = -sum(p * log2(p)).
     * @param password Password string.
     * @return Shannon entropy per character.
     */
    [[nodiscard]] static double calculate_shannon_entropy(std::string_view password) noexcept;

    /**
     * @brief Converts a StrengthLevel enum into a user-friendly string.
     */
    [[nodiscard]] static const char* level_to_string(StrengthLevel level) noexcept;

    /**
     * @brief Formats estimated crack time in seconds into human-readable text.
     */
    [[nodiscard]] static std::string format_crack_time(double seconds);
};

} // namespace pwdmgr::core
