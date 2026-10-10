#include "core/generator.hpp"
#include "crypto/random.hpp"
#include "crypto/secure_memory.hpp"

#include <cmath>
#include <array>
#include <algorithm>
#include <unordered_map>
#include <sstream>
#include <iomanip>
#include <cctype>

namespace pwdmgr::core {

namespace {

// Curated Diceware wordlist of 128 distinct memorable words (7 bits of entropy per word)
constexpr std::array<const char*, 128> DICEWARE_WORDS = {
    "anchor", "apollo", "archer", "aurora", "badger", "banner", "beacon", "breeze",
    "bridge", "cactus", "canyon", "castle", "cedar",  "cipher", "clover", "cobalt",
    "comet",  "copper", "crater", "dagger", "desert", "delta",  "diablo", "dragon",
    "falcon", "fathom", "flame",  "forest", "fossil", "frost",  "galaxy", "garden",
    "geyser", "glacier","goblet", "granite","harbor", "hazard", "helix",  "helmet",
    "hunter", "hybrid", "island", "jaguar", "javelin","jungle", "knight", "lagoon",
    "lantern","legend", "leopard","lynx",   "magnet", "marble", "matrix", "meteor",
    "mirage", "monarch","mosaic", "nebula", "nexus",  "nomad",  "oasis",  "orbit",
    "palace", "panther","parade", "phoenix","pillow", "planet", "plasma", "portal",
    "prism",  "pulse",  "python", "quasar", "quiver", "radius", "raptor", "raven",
    "rebel",  "rescue", "rhino",  "ribbon", "river",  "rocket", "safari", "sailor",
    "shadow", "shield", "silver", "siren",  "solar",  "sphinx", "spiral", "spring",
    "stride", "summit", "sunset", "talon",  "tempo",  "tensor", "thunder","tiger",
    "timber", "titan",  "topaz",  "torque", "tower",  "tracer", "tunnel", "turtle",
    "vector", "velvet", "vessel", "viking", "viper",  "vortex", "walnut", "winter",
    "wizard", "wolf",   "wombat", "zenith", "zephyr", "zigzag", "zodiac", "zone"
};

bool is_char_ambiguous(char c) noexcept {
    for (const char* p = PasswordGenerator::AMBIGUOUS_CHARS; *p != '\0'; ++p) {
        if (c == *p) {
            return true;
        }
    }
    return false;
}

std::string filter_pool(const char* raw_pool, bool exclude_ambiguous) {
    std::string result;
    for (const char* p = raw_pool; *p != '\0'; ++p) {
        if (exclude_ambiguous && is_char_ambiguous(*p)) {
            continue;
        }
        result.push_back(*p);
    }
    return result;
}

} // anonymous namespace

crypto::SecureString PasswordGenerator::generate(const PasswordOptions& options) {
    if (options.length == 0) {
        throw std::invalid_argument("Password length must be greater than zero");
    }

    std::vector<std::string> enabled_pools;
    std::string total_pool;

    if (options.use_lowercase) {
        std::string p = filter_pool(LOWERCASE_CHARS, options.exclude_ambiguous);
        if (!p.empty()) {
            enabled_pools.push_back(p);
            total_pool += p;
        }
    }
    if (options.use_uppercase) {
        std::string p = filter_pool(UPPERCASE_CHARS, options.exclude_ambiguous);
        if (!p.empty()) {
            enabled_pools.push_back(p);
            total_pool += p;
        }
    }
    if (options.use_digits) {
        std::string p = filter_pool(DIGIT_CHARS, options.exclude_ambiguous);
        if (!p.empty()) {
            enabled_pools.push_back(p);
            total_pool += p;
        }
    }
    if (options.use_symbols) {
        std::string p = filter_pool(SYMBOL_CHARS, options.exclude_ambiguous);
        if (!p.empty()) {
            enabled_pools.push_back(p);
            total_pool += p;
        }
    }

    if (total_pool.empty()) {
        throw std::invalid_argument("No character pools available for password generation");
    }

    if (options.require_each_type && options.length < enabled_pools.size()) {
        throw std::invalid_argument(
            "Password length is too short to include all required character types"
        );
    }

    std::string password;
    password.reserve(options.length);

    // 1. If require_each_type is enabled, draw one character from each selected pool
    if (options.require_each_type) {
        for (const auto& pool : enabled_pools) {
            uint32_t idx = crypto::Random::get_uniform_u32(0, static_cast<uint32_t>(pool.size() - 1));
            password.push_back(pool[idx]);
        }
    }

    // 2. Fill the remaining length uniformly from the combined pool
    while (password.size() < options.length) {
        uint32_t idx = crypto::Random::get_uniform_u32(0, static_cast<uint32_t>(total_pool.size() - 1));
        password.push_back(total_pool[idx]);
    }

    // 3. Cryptographically shuffle characters using Fisher-Yates algorithm to eliminate positional bias
    if (password.size() > 1) {
        for (size_t i = password.size() - 1; i > 0; --i) {
            uint32_t j = crypto::Random::get_uniform_u32(0, static_cast<uint32_t>(i));
            std::swap(password[i], password[j]);
        }
    }

    // 4. Wrap into SecureString and securely wipe intermediate plaintext string from stack/heap
    crypto::SecureString result(password);
    crypto::SecureMemory::zero(password.data(), password.size());
    password.clear();

    return result;
}

crypto::SecureString PasswordGenerator::generate_passphrase(size_t word_count, char separator) {
    if (word_count == 0) {
        throw std::invalid_argument("Passphrase word count must be greater than zero");
    }

    std::string passphrase;
    const uint32_t max_idx = static_cast<uint32_t>(DICEWARE_WORDS.size() - 1);

    for (size_t i = 0; i < word_count; ++i) {
        uint32_t word_idx = crypto::Random::get_uniform_u32(0, max_idx);
        passphrase += DICEWARE_WORDS[word_idx];
        if (i + 1 < word_count) {
            passphrase += separator;
        }
    }

    crypto::SecureString result(passphrase);
    crypto::SecureMemory::zero(passphrase.data(), passphrase.size());
    passphrase.clear();

    return result;
}

double EntropyMeter::calculate_pool_entropy(std::string_view password) noexcept {
    if (password.empty()) {
        return 0.0;
    }

    bool has_lower = false;
    bool has_upper = false;
    bool has_digit = false;
    bool has_symbol = false;

    for (char c : password) {
        if (std::islower(static_cast<unsigned char>(c))) {
            has_lower = true;
        } else if (std::isupper(static_cast<unsigned char>(c))) {
            has_upper = true;
        } else if (std::isdigit(static_cast<unsigned char>(c))) {
            has_digit = true;
        } else {
            has_symbol = true;
        }
    }

    size_t pool_size = 0;
    if (has_lower)  pool_size += 26;
    if (has_upper)  pool_size += 26;
    if (has_digit)  pool_size += 10;
    if (has_symbol) pool_size += 33; // Standard printable punctuation

    if (pool_size == 0) {
        return 0.0;
    }

    // E = L * log2(R)
    return static_cast<double>(password.length()) * (std::log(static_cast<double>(pool_size)) / std::log(2.0));
}

double EntropyMeter::calculate_shannon_entropy(std::string_view password) noexcept {
    if (password.empty()) {
        return 0.0;
    }

    std::unordered_map<char, size_t> frequencies;
    for (char c : password) {
        frequencies[c]++;
    }

    const double len = static_cast<double>(password.length());
    double entropy = 0.0;

    // H = -sum(p * log2(p))
    for (const auto& [ch, count] : frequencies) {
        double p = static_cast<double>(count) / len;
        entropy -= p * (std::log(p) / std::log(2.0));
    }

    return entropy;
}

EntropyScore EntropyMeter::evaluate(std::string_view password) {
    EntropyScore score;
    if (password.empty()) {
        score.strength = StrengthLevel::VeryWeak;
        score.crack_time_offline = "Instant";
        score.crack_time_online = "Instant";
        score.suggestions.push_back("Password cannot be empty.");
        return score;
    }

    const size_t len = password.length();
    score.pool_entropy_bits = calculate_pool_entropy(password);
    score.shannon_entropy_bits = calculate_shannon_entropy(password) * static_cast<double>(len);

    // Baseline effective entropy starts at the lesser of pool and shannon entropy
    double effective = std::min(score.pool_entropy_bits, score.shannon_entropy_bits);

    // 1. Repetitive character penalty
    size_t repeat_count = 0;
    for (size_t i = 1; i < len; ++i) {
        if (password[i] == password[i - 1]) {
            repeat_count++;
        }
    }
    if (repeat_count > 0) {
        effective -= static_cast<double>(repeat_count) * 2.5;
        score.suggestions.push_back("Avoid repeated consecutive characters.");
    }

    // 2. Sequential character penalty (e.g. "abc", "123")
    size_t sequence_count = 0;
    if (len >= 3) {
        for (size_t i = 2; i < len; ++i) {
            char c1 = password[i - 2];
            char c2 = password[i - 1];
            char c3 = password[i];
            if ((c2 == c1 + 1 && c3 == c2 + 1) || (c2 == c1 - 1 && c3 == c2 - 1)) {
                sequence_count++;
            }
        }
    }
    if (sequence_count > 0) {
        effective -= static_cast<double>(sequence_count) * 4.0;
        score.suggestions.push_back("Avoid sequential patterns (e.g. abc, 123).");
    }

    score.effective_entropy_bits = std::max(0.0, effective);

    // 3. Classify Strength Level
    if (score.effective_entropy_bits < 40.0) {
        score.strength = StrengthLevel::VeryWeak;
    } else if (score.effective_entropy_bits < 60.0) {
        score.strength = StrengthLevel::Weak;
    } else if (score.effective_entropy_bits < 80.0) {
        score.strength = StrengthLevel::Moderate;
    } else if (score.effective_entropy_bits < 100.0) {
        score.strength = StrengthLevel::Strong;
    } else {
        score.strength = StrengthLevel::VeryStrong;
    }

    // 4. Estimate Crack Times
    // Offline: 10^10 hashes per second (high-end GPU cluster)
    // Online: 100 attempts per second (rate-limited network login)
    double combinations = std::pow(2.0, score.effective_entropy_bits);
    double offline_seconds = combinations / 1e10;
    double online_seconds = combinations / 100.0;

    score.crack_time_offline = format_crack_time(offline_seconds);
    score.crack_time_online = format_crack_time(online_seconds);

    // 5. Improvement Suggestions
    if (len < 12) {
        score.suggestions.push_back("Increase length to at least 14-16 characters.");
    }

    bool has_symbol = false, has_digit = false, has_upper = false, has_lower = false;
    for (char c : password) {
        if (std::islower(static_cast<unsigned char>(c))) has_lower = true;
        else if (std::isupper(static_cast<unsigned char>(c))) has_upper = true;
        else if (std::isdigit(static_cast<unsigned char>(c))) has_digit = true;
        else has_symbol = true;
    }

    if (!has_symbol) score.suggestions.push_back("Add special symbols (e.g. !, @, #, $).");
    if (!has_digit)  score.suggestions.push_back("Add numbers.");
    if (!has_upper)  score.suggestions.push_back("Include uppercase letters.");
    if (!has_lower)  score.suggestions.push_back("Include lowercase letters.");

    return score;
}

const char* EntropyMeter::level_to_string(StrengthLevel level) noexcept {
    switch (level) {
        case StrengthLevel::VeryWeak:   return "Very Weak";
        case StrengthLevel::Weak:       return "Weak";
        case StrengthLevel::Moderate:   return "Moderate";
        case StrengthLevel::Strong:     return "Strong";
        case StrengthLevel::VeryStrong: return "Very Strong";
    }
    return "Unknown";
}

std::string EntropyMeter::format_crack_time(double seconds) {
    if (seconds <= 0.001)   return "Instant";
    if (seconds < 1.0)      return "< 1 second";
    if (seconds < 60.0)     return std::to_string(static_cast<uint64_t>(seconds)) + " seconds";

    double minutes = seconds / 60.0;
    if (minutes < 60.0)     return std::to_string(static_cast<uint64_t>(minutes)) + " minutes";

    double hours = minutes / 60.0;
    if (hours < 24.0)       return std::to_string(static_cast<uint64_t>(hours)) + " hours";

    double days = hours / 24.0;
    if (days < 30.0)        return std::to_string(static_cast<uint64_t>(days)) + " days";

    double months = days / 30.4375;
    if (months < 12.0)      return std::to_string(static_cast<uint64_t>(months)) + " months";

    double years = days / 365.25;
    if (years < 1000.0)     return std::to_string(static_cast<uint64_t>(years)) + " years";
    if (years < 1e6)        return std::to_string(static_cast<uint64_t>(years / 1000.0)) + " thousand years";
    if (years < 1e9)        return std::to_string(static_cast<uint64_t>(years / 1e6)) + " million years";
    if (years < 1e12)       return std::to_string(static_cast<uint64_t>(years / 1e9)) + " billion years";

    return "Trillions of years";
}

} // namespace pwdmgr::core
