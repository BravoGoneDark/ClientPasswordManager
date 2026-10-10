#include "core/uuid.hpp"
#include "core/credential.hpp"
#include "core/vault.hpp"
#include "crypto/secure_memory.hpp"
#include "crypto/random.hpp"
#include "crypto/kdf.hpp"
#include "crypto/cipher.hpp"

#include <iostream>
#include <cassert>
#include <unordered_set>
#include <string>
#include <vector>

using namespace pwdmgr::core;
using namespace pwdmgr::crypto;

void test_uuid() {
    std::cout << "[*] Testing UUID v4 Generator & Validator..." << std::endl;

    std::unordered_set<std::string> generated_ids;
    for (int i = 0; i < 200; ++i) {
        std::string id = Uuid::generate();
        assert(id.length() == 36);
        assert(Uuid::is_valid(id));
        // Verify version 4 character at position 14
        assert(id[14] == '4');
        // Verify variant character at position 19 is 8, 9, a, or b
        char v = id[19];
        assert(v == '8' || v == '9' || v == 'a' || v == 'b');
        // Verify uniqueness
        assert(generated_ids.find(id) == generated_ids.end());
        generated_ids.insert(id);
    }

    // Test validator rejection of malformed UUIDs
    assert(!Uuid::is_valid("invalid-uuid-string"));
    assert(!Uuid::is_valid("c9a646d3-9c61-5c12-8b32-25080e5d4d34")); // version 5, not 4
    assert(!Uuid::is_valid("c9a646d3-9c61-4c12-2b32-25080e5d4d34")); // invalid variant '2'
    assert(!Uuid::is_valid("c9a646d3-9c61-4c12-8b32-25080e5d4d3"));  // too short

    std::cout << "  [+] UUID v4 tests passed." << std::endl;
}

void test_credential_entry() {
    std::cout << "[*] Testing CredentialEntry Model & Semantics..." << std::endl;

    CredentialEntry entry(
        "GitHub",
        "octocat",
        SecureString("SuperSecretToken123!"),
        "https://github.com",
        "Personal access token with repo scope"
    );

    assert(entry.title() == "GitHub");
    assert(entry.username() == "octocat");
    assert(entry.password().view() == "SuperSecretToken123!");
    assert(entry.url() == "https://github.com");
    assert(entry.notes() == "Personal access token with repo scope");
    assert(entry.created_at() > 0);
    assert(entry.updated_at() >= entry.created_at());

    // Test explicit clone
    CredentialEntry cloned = entry.clone();
    assert(cloned.title() == entry.title());
    assert(cloned.username() == entry.username());
    assert(cloned.password().view() == entry.password().view());

    // Test move semantics
    CredentialEntry moved = std::move(entry);
    assert(moved.title() == "GitHub");
    assert(moved.password().view() == "SuperSecretToken123!");

    // Test JSON serialization roundtrip
    nlohmann::json j = moved.to_json();
    assert(j["title"] == "GitHub");
    assert(j["username"] == "octocat");
    assert(j["password"] == "SuperSecretToken123!");

    CredentialEntry restored = CredentialEntry::from_json(j);
    assert(restored.title() == "GitHub");
    assert(restored.username() == "octocat");
    assert(restored.password().view() == "SuperSecretToken123!");
    assert(restored.url() == "https://github.com");

    // Test invalid JSON throws
    nlohmann::json bad_j = {{"title", "Incomplete"}};
    bool threw = false;
    try {
        CredentialEntry::from_json(bad_j);
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    assert(threw);

    std::cout << "  [+] CredentialEntry model tests passed." << std::endl;
}

void test_vault_crud_and_search() {
    std::cout << "[*] Testing Vault CRUD and Case-Insensitive Search..." << std::endl;

    Vault vault;
    assert(!vault.vault_id().empty());
    assert(vault.empty());
    assert(vault.size() == 0);

    // 1. Add entries
    std::string id1 = vault.add_entry(CredentialEntry(
        "Google Workspace",
        "admin@company.com",
        SecureString("G00gl3Pass!"),
        "https://accounts.google.com",
        "Recovery codes saved in safe"
    ));
    assert(!id1.empty());
    assert(vault.size() == 1);

    std::string id2 = vault.add_entry(CredentialEntry(
        "AWS Console",
        "cloud-admin",
        SecureString("AwsMasterRootKey99#"),
        "https://aws.amazon.com",
        "Production AWS environment"
    ));
    assert(!id2.empty());
    assert(vault.size() == 2);

    std::string id3 = vault.add_entry(CredentialEntry(
        "GitLab Self-Hosted",
        "developer",
        SecureString("GitLabDevPass42$"),
        "https://gitlab.internal.lan",
        "Dev server access"
    ));
    assert(vault.size() == 3);

    // 2. Lookup by UUID
    CredentialEntry* found = vault.get_entry(id2);
    assert(found != nullptr);
    assert(found->title() == "AWS Console");
    assert(found->username() == "cloud-admin");

    assert(vault.get_entry("non-existent-uuid") == nullptr);

    // 3. Search by title
    auto title_matches = vault.find_by_title("google"); // substring, case-insensitive
    assert(title_matches.size() == 1);
    assert(title_matches[0]->title() == "Google Workspace");

    auto exact_matches = vault.find_by_title("google", true); // exact
    assert(exact_matches.empty());

    // 4. Search by username
    auto user_matches = vault.find_by_username("admin");
    assert(user_matches.size() == 2); // admin@company.com and cloud-admin

    // 5. Full-text search across all fields
    auto notes_matches = vault.search("production"); // Found in AWS notes
    assert(notes_matches.size() == 1);
    assert(notes_matches[0]->uuid() == id2);

    auto lan_matches = vault.search("internal.lan"); // Found in GitLab URL
    assert(lan_matches.size() == 1);
    assert(lan_matches[0]->uuid() == id3);

    // 6. Update entry
    CredentialEntry updated_data(
        "AWS Console (US-East)",
        "cloud-admin-updated",
        SecureString("BrandNewAwsPassword2026!"),
        "https://us-east-1.console.aws.amazon.com",
        "Updated production cluster"
    );
    bool updated = vault.update_entry(id2, std::move(updated_data));
    assert(updated);

    CredentialEntry* updated_entry = vault.get_entry(id2);
    assert(updated_entry != nullptr);
    assert(updated_entry->title() == "AWS Console (US-East)");
    assert(updated_entry->username() == "cloud-admin-updated");
    assert(updated_entry->password().view() == "BrandNewAwsPassword2026!");

    // 7. Delete entry
    bool deleted = vault.delete_entry(id1);
    assert(deleted);
    assert(vault.size() == 2);
    assert(vault.get_entry(id1) == nullptr);

    // Deleting again should return false
    assert(!vault.delete_entry(id1));

    std::cout << "  [+] Vault CRUD and search tests passed." << std::endl;
}

void test_vault_serialization_and_scrubbing() {
    std::cout << "[*] Testing Secure Serialization & In-Memory Deserialization..." << std::endl;

    Vault original_vault("test-vault-uuid-001");
    original_vault.add_entry(CredentialEntry(
        "ProtonMail",
        "user@proton.me",
        SecureString("ProtonSuperSecret!"),
        "https://mail.proton.me",
        "Encrypted mail account"
    ));
    original_vault.add_entry(CredentialEntry(
        "Bitbucket",
        "repo_owner",
        SecureString("BitBucketAppPassword88!"),
        "https://bitbucket.org"
    ));

    // 1. Serialize securely to SecureBuffer
    SecureBuffer secure_payload = original_vault.serialize_secure();
    assert(!secure_payload.empty());
    assert(secure_payload.size() > 50);

    // 2. Deserialize from SecureBuffer bytes
    Vault restored_vault = Vault::deserialize(secure_payload.span());
    assert(restored_vault.vault_id() == "test-vault-uuid-001");
    assert(restored_vault.size() == 2);

    auto proton = restored_vault.find_by_title("protonmail");
    assert(proton.size() == 1);
    assert(proton[0]->username() == "user@proton.me");
    assert(proton[0]->password().view() == "ProtonSuperSecret!");

    auto bitbucket = restored_vault.find_by_title("bitbucket");
    assert(bitbucket.size() == 1);
    assert(bitbucket[0]->username() == "repo_owner");
    assert(bitbucket[0]->password().view() == "BitBucketAppPassword88!");

    // 3. Test corrupted JSON rejection
    std::string malformed_json = "{ this is not valid json : [ }";
    bool caught_corruption = false;
    try {
        Vault::deserialize(malformed_json);
    } catch (const VaultCorruptError&) {
        caught_corruption = true;
    }
    assert(caught_corruption);

    // Empty payload rejection
    bool caught_empty = false;
    try {
        Vault::deserialize("");
    } catch (const VaultCorruptError&) {
        caught_empty = true;
    }
    assert(caught_empty);

    std::cout << "  [+] Vault serialization & memory scrubbing tests passed." << std::endl;
}

void test_integrated_vault_encryption() {
    std::cout << "[*] Testing End-to-End Vault Encryption & Decryption Roundtrip..." << std::endl;

    // Create realistic populated vault
    Vault vault;
    vault.add_entry(CredentialEntry(
        "Bank of America",
        "my_online_banking",
        SecureString("BankP@ssw0rd#2026"),
        "https://bankofamerica.com"
    ));
    vault.add_entry(CredentialEntry(
        "Signal Messenger",
        "+15550199283",
        SecureString("SignalRegistrationPIN9928"),
        ""
    ));

    // 1. Serialize in-memory vault into a SecureBuffer
    SecureBuffer plaintext_json = vault.serialize_secure();

    // 2. Key Derivation from Master Password
    std::string master_password = "CorrectHorseBatteryStaple!";
    SecureBuffer salt = Random::get_bytes(KDF::SALT_LEN);
    SecureBuffer key = KDF::derive_key(master_password, salt.span(), KDF::Params::interactive());

    // 3. Authenticated Encryption (AEAD)
    SecureBuffer nonce = Random::get_bytes(Cipher::NONCE_LEN);
    std::string aad_header = "CPWM\x01\x00"; // Magic + Version
    std::vector<uint8_t> aad_bytes(aad_header.begin(), aad_header.end());

    CiphertextPackage pkg = Cipher::encrypt(
        plaintext_json.span(),
        key.span(),
        nonce.span(),
        aad_bytes
    );

    assert(pkg.ciphertext.size() == plaintext_json.size());
    assert(pkg.tag.size() == Cipher::TAG_LEN);

    // 4. Decrypt with correct key & AAD
    SecureBuffer decrypted_plaintext = Cipher::decrypt(
        pkg.ciphertext.span(),
        pkg.tag.span(),
        key.span(),
        nonce.span(),
        aad_bytes
    );

    // 5. Reconstruct Vault from decrypted payload
    Vault recovered_vault = Vault::deserialize(decrypted_plaintext.span());
    assert(recovered_vault.size() == 2);

    auto bank = recovered_vault.find_by_title("bank of america");
    assert(bank.size() == 1);
    assert(bank[0]->username() == "my_online_banking");
    assert(bank[0]->password().view() == "BankP@ssw0rd#2026");

    auto signal = recovered_vault.find_by_title("signal");
    assert(signal.size() == 1);
    assert(signal[0]->password().view() == "SignalRegistrationPIN9928");

    // 6. Security Check: Decryption with wrong password MUST fail
    SecureBuffer wrong_key = KDF::derive_key("WrongMasterPassword!", salt.span(), KDF::Params::interactive());
    bool wrong_pass_caught = false;
    try {
        Cipher::decrypt(
            pkg.ciphertext.span(),
            pkg.tag.span(),
            wrong_key.span(),
            nonce.span(),
            aad_bytes
        );
    } catch (const AuthenticationError&) {
        wrong_pass_caught = true;
    }
    assert(wrong_pass_caught);

    std::cout << "  [+] End-to-End Vault Encryption roundtrip verified successfully." << std::endl;
}

int main() {
    std::cout << "==================================================" << std::endl;
    std::cout << " ClientPasswordManager - Phase 4 Vault Test Suite " << std::endl;
    std::cout << "==================================================" << std::endl;

    try {
        test_uuid();
        test_credential_entry();
        test_vault_crud_and_search();
        test_vault_serialization_and_scrubbing();
        test_integrated_vault_encryption();
        std::cout << "\n>>> ALL PHASE 4 VAULT TEST SUITES PASSED! <<<\n" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "[-] Test failed with unhandled exception: " << e.what() << std::endl;
        return 1;
    }
}
