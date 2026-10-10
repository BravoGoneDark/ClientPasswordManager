#include "storage/vault_file.hpp"
#include "core/vault.hpp"
#include "core/credential.hpp"
#include "crypto/secure_memory.hpp"
#include "crypto/cipher.hpp"

#include <iostream>
#include <cassert>
#include <filesystem>
#include <fstream>
#include <string>

using namespace pwdmgr::core;
using namespace pwdmgr::crypto;
using namespace pwdmgr::storage;

const std::filesystem::path TEST_FILE = "storage_test_sandbox.vault";

void cleanup_test_files() {
    std::error_code ec;
    std::filesystem::remove(TEST_FILE, ec);
    std::filesystem::path tmp_path = TEST_FILE;
    tmp_path += ".tmp";
    std::filesystem::remove(tmp_path, ec);
}

void test_save_and_load_roundtrip() {
    std::cout << "[*] Testing VaultFile Save & Load Roundtrip..." << std::endl;
    cleanup_test_files();

    Vault original_vault("storage-test-vault-uuid");
    original_vault.add_entry(CredentialEntry(
        "GitHub",
        "bravo_user",
        SecureString("ghp_SecretTokenXYZ123!"),
        "https://github.com",
        "Primary developer account"
    ));
    original_vault.add_entry(CredentialEntry(
        "ProtonMail",
        "bravo@proton.me",
        SecureString("ProtonEncryptedEmailPass#99"),
        "https://mail.proton.me"
    ));

    std::string master_pass = "MyUltraSecureMasterPassword2026!";

    // 1. Save vault to disk
    VaultFile::save(TEST_FILE, original_vault, master_pass);
    assert(std::filesystem::exists(TEST_FILE));
    auto file_size = std::filesystem::file_size(TEST_FILE);
    assert(file_size > VaultFile::HEADER_SIZE);

    // 2. Load vault from disk with correct password
    Vault loaded_vault = VaultFile::load(TEST_FILE, master_pass);
    assert(loaded_vault.vault_id() == "storage-test-vault-uuid");
    assert(loaded_vault.size() == 2);

    auto gh = loaded_vault.find_by_title("github");
    assert(gh.size() == 1);
    assert(gh[0]->username() == "bravo_user");
    assert(gh[0]->password().view() == "ghp_SecretTokenXYZ123!");
    assert(gh[0]->notes() == "Primary developer account");

    auto proton = loaded_vault.find_by_title("proton");
    assert(proton.size() == 1);
    assert(proton[0]->password().view() == "ProtonEncryptedEmailPass#99");

    std::cout << "  [+] Save & Load roundtrip verified." << std::endl;
}

void test_header_inspection() {
    std::cout << "[*] Testing Vault Header Inspection..." << std::endl;

    assert(VaultFile::is_vault_file(TEST_FILE));

    VaultHeaderMetadata meta = VaultFile::read_header(TEST_FILE);
    assert(std::memcmp(meta.magic, "CPWM", 4) == 0);
    assert(meta.version == 1);
    assert(meta.kdf_id == VaultFile::KDF_ARGON2ID);
    assert(meta.cipher_id == VaultFile::CIPHER_AEAD);
    assert(meta.salt.size() == 16);
    assert(meta.nonce.size() == 24);
    assert(meta.auth_tag.size() == 16);

    // Test non-vault file check
    std::filesystem::path dummy_file = "dummy_non_vault.txt";
    {
        std::ofstream out(dummy_file);
        out << "This is plain text, not a vault!";
    }
    assert(!VaultFile::is_vault_file(dummy_file));
    std::filesystem::remove(dummy_file);

    std::cout << "  [+] Header inspection verified." << std::endl;
}

void test_atomic_write_replace() {
    std::cout << "[*] Testing Atomic Write-Replace Persistence..." << std::endl;

    std::string master_pass = "MyUltraSecureMasterPassword2026!";

    // Load existing vault, add a 3rd entry, and re-save
    Vault vault = VaultFile::load(TEST_FILE, master_pass);
    assert(vault.size() == 2);

    vault.add_entry(CredentialEntry(
        "Bitwarden Backup",
        "backup_user",
        SecureString("EmergencyBackupPass42$")
    ));

    VaultFile::save(TEST_FILE, vault, master_pass);

    // Verify no temporary file was left dangling
    std::filesystem::path tmp_path = TEST_FILE;
    tmp_path += ".tmp";
    assert(!std::filesystem::exists(tmp_path));

    // Re-load and verify 3 entries
    Vault updated_vault = VaultFile::load(TEST_FILE, master_pass);
    assert(updated_vault.size() == 3);
    assert(!updated_vault.find_by_title("bitwarden").empty());

    std::cout << "  [+] Atomic write-replace persistence verified." << std::endl;
}

void test_wrong_password_rejection() {
    std::cout << "[*] Testing Wrong Master Password Rejection..." << std::endl;

    bool caught_wrong_pass = false;
    try {
        VaultFile::load(TEST_FILE, "IncorrectMasterPassw0rd!");
    } catch (const AuthenticationError&) {
        caught_wrong_pass = true;
    }
    assert(caught_wrong_pass);

    std::cout << "  [+] Wrong master password successfully rejected." << std::endl;
}

void test_tamper_detection_ciphertext() {
    std::cout << "[*] Testing Bit-Flip Attack Detection in Ciphertext..." << std::endl;

    // Read raw file bytes
    std::ifstream in(TEST_FILE, std::ios::binary);
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(in)),
                                std::istreambuf_iterator<char>());
    in.close();

    // Flip 1 bit in the ciphertext (offset 72 or later)
    assert(bytes.size() > 75);
    bytes[75] ^= 0x01; // Bit flip

    std::filesystem::path tampered_file = "tampered_ciphertext.vault";
    {
        std::ofstream out(tampered_file, std::ios::binary);
        out.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    }

    bool caught_tamper = false;
    try {
        VaultFile::load(tampered_file, "MyUltraSecureMasterPassword2026!");
    } catch (const AuthenticationError&) {
        caught_tamper = true;
    }
    assert(caught_tamper);

    std::filesystem::remove(tampered_file);
    std::cout << "  [+] Ciphertext bit-flip tampering caught and rejected." << std::endl;
}

void test_tamper_detection_header_aad() {
    std::cout << "[*] Testing Header AAD Tampering Detection..." << std::endl;

    // Read raw file bytes
    std::ifstream in(TEST_FILE, std::ios::binary);
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(in)),
                                std::istreambuf_iterator<char>());
    in.close();

    // Flip 1 bit in the Salt (offset 16..31) which is part of AAD
    bytes[20] ^= 0x01;

    std::filesystem::path tampered_header_file = "tampered_header.vault";
    {
        std::ofstream out(tampered_header_file, std::ios::binary);
        out.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    }

    bool caught_header_tamper = false;
    try {
        VaultFile::load(tampered_header_file, "MyUltraSecureMasterPassword2026!");
    } catch (const AuthenticationError&) {
        caught_header_tamper = true;
    }
    assert(caught_header_tamper);

    std::filesystem::remove(tampered_header_file);
    std::cout << "  [+] Header AAD tampering caught and rejected." << std::endl;
}

void test_corrupted_header_size() {
    std::cout << "[*] Testing Truncated / Corrupted Header Detection..." << std::endl;

    std::filesystem::path truncated_file = "truncated.vault";
    {
        std::ofstream out(truncated_file, std::ios::binary);
        out << "CPWM"; // Only 4 bytes, header requires 72 bytes
    }

    bool caught_truncated = false;
    try {
        VaultFile::load(truncated_file, "MyUltraSecureMasterPassword2026!");
    } catch (const InvalidHeaderError&) {
        caught_truncated = true;
    }
    assert(caught_truncated);

    std::filesystem::remove(truncated_file);
    cleanup_test_files();

    std::cout << "  [+] Truncated file caught and rejected." << std::endl;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << " ClientPasswordManager - Phase 5 Storage Test Suite " << std::endl;
    std::cout << "====================================================" << std::endl;

    try {
        test_save_and_load_roundtrip();
        test_header_inspection();
        test_atomic_write_replace();
        test_wrong_password_rejection();
        test_tamper_detection_ciphertext();
        test_tamper_detection_header_aad();
        test_corrupted_header_size();

        std::cout << "\n>>> ALL PHASE 5 STORAGE TEST SUITES PASSED! <<<\n" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "[-] Storage test failed with exception: " << e.what() << std::endl;
        cleanup_test_files();
        return 1;
    }
}
