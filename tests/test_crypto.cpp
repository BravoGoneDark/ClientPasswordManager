#include "crypto/secure_memory.hpp"
#include "crypto/random.hpp"
#include "crypto/kdf.hpp"
#include "crypto/cipher.hpp"

#include <iostream>
#include <cassert>
#include <string>
#include <vector>

using namespace pwdmgr::crypto;

void test_secure_memory() {
    std::cout << "[*] Testing SecureMemory & SecureBuffer..." << std::endl;
    {
        SecureBuffer buf(32);
        assert(buf.size() == 32);
        assert(!buf.empty());

        // Fill with dummy secret
        for (size_t i = 0; i < buf.size(); ++i) {
            buf[i] = static_cast<uint8_t>(i + 1);
        }

        // Test move semantics
        SecureBuffer moved = std::move(buf);
        assert(buf.empty());
        assert(moved.size() == 32);
        assert(moved[0] == 1);
        assert(moved[31] == 32);
    }
    std::cout << "  [+] SecureMemory tests passed." << std::endl;
}

void test_random() {
    std::cout << "[*] Testing CSPRNG & Rejection Sampling..." << std::endl;
    SecureBuffer r1 = Random::get_bytes(16);
    SecureBuffer r2 = Random::get_bytes(16);

    assert(r1.size() == 16);
    assert(r2.size() == 16);

    // Two CSPRNG draws must not be identical
    bool identical = true;
    for (size_t i = 0; i < 16; ++i) {
        if (r1[i] != r2[i]) {
            identical = false;
            break;
        }
    }
    assert(!identical);

    // Test uniform distribution bounds
    for (int i = 0; i < 100; ++i) {
        uint32_t val = Random::get_uniform_u32(10, 50);
        assert(val >= 10 && val <= 50);
    }

    std::cout << "  [+] CSPRNG tests passed." << std::endl;
}

void test_kdf_and_cipher() {
    std::cout << "[*] Testing KDF and Authenticated Encryption (AEAD)..." << std::endl;

    std::string master_pass = "SuperSecureMasterPassw0rd!";
    SecureBuffer salt = Random::get_bytes(KDF::SALT_LEN);
    SecureBuffer nonce = Random::get_bytes(Cipher::NONCE_LEN);

    // 1. Derive key
    SecureBuffer key = KDF::derive_key(master_pass, salt.span(), KDF::Params::interactive());
    assert(key.size() == Cipher::KEY_LEN);

    // 2. Encrypt plaintext
    std::string raw_plaintext = R"({"vault": [{"title": "GitHub", "password": "gh_secret_token"}]})";
    std::vector<uint8_t> plaintext_bytes(raw_plaintext.begin(), raw_plaintext.end());
    std::string aad_header = "CPWM\x01\x00";
    std::vector<uint8_t> aad_bytes(aad_header.begin(), aad_header.end());

    CiphertextPackage encrypted = Cipher::encrypt(
        plaintext_bytes,
        key.span(),
        nonce.span(),
        aad_bytes
    );

    assert(encrypted.ciphertext.size() == plaintext_bytes.size());
    assert(encrypted.tag.size() == Cipher::TAG_LEN);

    // 3. Decrypt plaintext successfully
    SecureBuffer decrypted = Cipher::decrypt(
        encrypted.ciphertext.span(),
        encrypted.tag.span(),
        key.span(),
        nonce.span(),
        aad_bytes
    );

    std::string decrypted_str(reinterpret_cast<char*>(decrypted.data()), decrypted.size());
    assert(decrypted_str == raw_plaintext);
    std::cout << "  [+] Encryption/Decryption roundtrip verified." << std::endl;

    // 4. Tamper Test: Modify 1 bit in ciphertext (must throw AuthenticationError)
    bool tamper_caught = false;
    encrypted.ciphertext[0] ^= 0x01; // Bit flip attack
    try {
        Cipher::decrypt(
            encrypted.ciphertext.span(),
            encrypted.tag.span(),
            key.span(),
            nonce.span(),
            aad_bytes
        );
    } catch (const AuthenticationError&) {
        tamper_caught = true;
    }
    assert(tamper_caught);
    std::cout << "  [+] Tamper detection (Bit-flip attack) successfully rejected." << std::endl;

    // 5. Wrong Password Test: Derive key with wrong password
    encrypted.ciphertext[0] ^= 0x01; // Restore bit
    SecureBuffer wrong_key = KDF::derive_key("WrongPassw0rd", salt.span(), KDF::Params::interactive());
    bool wrong_pass_caught = false;
    try {
        Cipher::decrypt(
            encrypted.ciphertext.span(),
            encrypted.tag.span(),
            wrong_key.span(),
            nonce.span(),
            aad_bytes
        );
    } catch (const AuthenticationError&) {
        wrong_pass_caught = true;
    }
    assert(wrong_pass_caught);
    std::cout << "  [+] Wrong master password successfully rejected." << std::endl;
}

int main() {
    std::cout << "==================================================" << std::endl;
    std::cout << " ClientPasswordManager - Cryptographic Test Suite " << std::endl;
    std::cout << "==================================================" << std::endl;

    try {
        test_secure_memory();
        test_random();
        test_kdf_and_cipher();
        std::cout << "\n>>> ALL CRYPTOGRAPHIC TEST SUITES PASSED! <<<\n" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "[-] Test failed with unhandled exception: " << e.what() << std::endl;
        return 1;
    }
}
