#include "core/generator.hpp"
#include "crypto/secure_memory.hpp"

#include <iostream>
#include <cassert>
#include <string>
#include <sstream>
#include <cctype>

using namespace pwdmgr::core;

void test_password_generator_basic() {
    std::cout << "[*] Testing PasswordGenerator Basic Generation..." << std::endl;

    auto pwd = PasswordGenerator::generate();
    assert(pwd.length() == 20);

    bool has_lower = false, has_upper = false, has_digit = false, has_symbol = false;
    for (char c : pwd.view()) {
        if (std::islower(static_cast<unsigned char>(c))) has_lower = true;
        else if (std::isupper(static_cast<unsigned char>(c))) has_upper = true;
        else if (std::isdigit(static_cast<unsigned char>(c))) has_digit = true;
        else has_symbol = true;
    }

    assert(has_lower);
    assert(has_upper);
    assert(has_digit);
    assert(has_symbol);

    std::cout << "  [+] Default 20-character password generated with all character sets." << std::endl;
}

void test_password_generator_options() {
    std::cout << "[*] Testing PasswordGenerator Configurations..." << std::endl;

    // 1. PIN Generation
    PasswordOptions pin_opts = PasswordOptions::pin(8);
    auto pin = PasswordGenerator::generate(pin_opts);
    assert(pin.length() == 8);
    for (char c : pin.view()) {
        assert(std::isdigit(static_cast<unsigned char>(c)));
    }

    // 2. Alphanumeric Generation
    PasswordOptions alpha_opts = PasswordOptions::alphanumeric(16);
    auto alpha = PasswordGenerator::generate(alpha_opts);
    assert(alpha.length() == 16);
    for (char c : alpha.view()) {
        assert(std::isalnum(static_cast<unsigned char>(c)));
    }

    // 3. Ambiguous Characters Exclusion
    PasswordOptions no_ambig;
    no_ambig.length = 50;
    no_ambig.exclude_ambiguous = true;

    for (int run = 0; run < 10; ++run) {
        auto clean_pwd = PasswordGenerator::generate(no_ambig);
        for (char c : clean_pwd.view()) {
            assert(c != '0' && c != 'O' && c != 'o');
            assert(c != '1' && c != 'l' && c != 'I');
            assert(c != '|');
        }
    }

    std::cout << "  [+] Configurations (PIN, Alphanumeric, Ambiguity filtering) verified." << std::endl;
}

void test_passphrase_generation() {
    std::cout << "[*] Testing Diceware Passphrase Generation..." << std::endl;

    auto phrase = PasswordGenerator::generate_passphrase(5, '-');
    assert(!phrase.empty());

    // Count hyphen-separated words
    std::string s(phrase.view());
    std::stringstream ss(s);
    std::string word;
    int word_count = 0;
    while (std::getline(ss, word, '-')) {
        assert(!word.empty());
        word_count++;
    }
    assert(word_count == 5);

    // Test custom separator
    auto phrase_under = PasswordGenerator::generate_passphrase(4, '_');
    int under_count = 0;
    for (char c : phrase_under.view()) {
        if (c == '_') under_count++;
    }
    assert(under_count == 3); // 4 words separated by 3 underscores

    std::cout << "  [+] Diceware passphrase generation verified." << std::endl;
}

void test_entropy_meter_evaluation() {
    std::cout << "[*] Testing EntropyMeter & Shannon Calculations..." << std::endl;

    // 1. Very Weak Passwords
    auto empty_eval = EntropyMeter::evaluate("");
    assert(empty_eval.strength == StrengthLevel::VeryWeak);

    auto weak_pin = EntropyMeter::evaluate("123456");
    assert(weak_pin.strength == StrengthLevel::VeryWeak);

    auto repeating = EntropyMeter::evaluate("aaaaaaaaaaaa");
    // Repeating characters must be heavily penalized
    assert(repeating.effective_entropy_bits < repeating.pool_entropy_bits);

    // 2. Sequential vs Non-Sequential Penalties
    auto sequential = EntropyMeter::evaluate("abcdef123456");
    auto non_sequential = EntropyMeter::evaluate("a9b8c7d6e5f4");
    assert(non_sequential.effective_entropy_bits > sequential.effective_entropy_bits);

    // 3. Strong Passwords
    auto generated_strong = PasswordGenerator::generate(PasswordOptions::strong());
    auto strong_eval = EntropyMeter::evaluate(generated_strong.view());
    assert(strong_eval.strength == StrengthLevel::VeryStrong ||
           strong_eval.strength == StrengthLevel::Strong);
    assert(strong_eval.effective_entropy_bits >= 80.0);
    assert(!strong_eval.crack_time_offline.empty());

    std::cout << "  [+] Entropy calculations & pattern penalties verified." << std::endl;
}

void test_generator_invalid_inputs() {
    std::cout << "[*] Testing Exception Handling for Invalid Generator Inputs..." << std::endl;

    PasswordOptions zero_len;
    zero_len.length = 0;
    bool caught_zero = false;
    try {
        PasswordGenerator::generate(zero_len);
    } catch (const std::invalid_argument&) {
        caught_zero = true;
    }
    assert(caught_zero);

    PasswordOptions no_pools;
    no_pools.use_lowercase = false;
    no_pools.use_uppercase = false;
    no_pools.use_digits = false;
    no_pools.use_symbols = false;
    bool caught_no_pools = false;
    try {
        PasswordGenerator::generate(no_pools);
    } catch (const std::invalid_argument&) {
        caught_no_pools = true;
    }
    assert(caught_no_pools);

    bool caught_zero_words = false;
    try {
        PasswordGenerator::generate_passphrase(0);
    } catch (const std::invalid_argument&) {
        caught_zero_words = true;
    }
    assert(caught_zero_words);

    std::cout << "  [+] Invalid inputs properly rejected." << std::endl;
}

int main() {
    std::cout << "======================================================" << std::endl;
    std::cout << " ClientPasswordManager - Phase 6 Generator Test Suite " << std::endl;
    std::cout << "======================================================" << std::endl;

    try {
        test_password_generator_basic();
        test_password_generator_options();
        test_passphrase_generation();
        test_entropy_meter_evaluation();
        test_generator_invalid_inputs();

        std::cout << "\n>>> ALL PHASE 6 GENERATOR TEST SUITES PASSED! <<<\n" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "[-] Generator test failed with exception: " << e.what() << std::endl;
        return 1;
    }
}
