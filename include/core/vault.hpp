#pragma once

#include "core/credential.hpp"
#include "core/uuid.hpp"
#include "crypto/secure_memory.hpp"
#include <nlohmann/json.hpp>

#include <string>
#include <string_view>
#include <vector>
#include <span>
#include <stdexcept>
#include <cstdint>

namespace pwdmgr::core {

/**
 * @brief Exception thrown when vault serialization payload is corrupted or invalid.
 */
class VaultCorruptError : public std::runtime_error {
public:
    explicit VaultCorruptError(const std::string& msg) : std::runtime_error(msg) {}
};

/**
 * @brief In-memory collection of CredentialEntry objects with CRUD and search operations.
 *        Serializes to/from structured JSON and ensures intermediate strings are securely
 *        scrubbed from RAM.
 */
class Vault {
public:
    static constexpr uint32_t CURRENT_SCHEMA_VERSION = 1;

    /**
     * @brief Creates a new empty Vault with a randomly generated UUID v4.
     */
    Vault();

    /**
     * @brief Creates a new empty Vault with a specific UUID.
     */
    explicit Vault(std::string vault_id);

    // Disable copy semantics to prevent duplicating the entire database of secrets in memory
    Vault(const Vault&) = delete;
    Vault& operator=(const Vault&) = delete;

    // Enable move semantics for ownership transfer
    Vault(Vault&& other) noexcept = default;
    Vault& operator=(Vault&& other) noexcept = default;

    ~Vault() = default;

    // --- Metadata Accessors ---
    [[nodiscard]] const std::string& vault_id() const noexcept { return vault_id_; }
    [[nodiscard]] uint32_t schema_version() const noexcept { return schema_version_; }
    [[nodiscard]] uint64_t created_at() const noexcept { return created_at_; }
    [[nodiscard]] uint64_t updated_at() const noexcept { return updated_at_; }
    [[nodiscard]] size_t size() const noexcept { return entries_.size(); }
    [[nodiscard]] bool empty() const noexcept { return entries_.empty(); }

    void set_vault_id(std::string id) { vault_id_ = std::move(id); }
    void set_schema_version(uint32_t ver) noexcept { schema_version_ = ver; }
    void set_created_at(uint64_t ts) noexcept { created_at_ = ts; }
    void set_updated_at(uint64_t ts) noexcept { updated_at_ = ts; }

    // --- CRUD Operations ---

    /**
     * @brief Adds a credential entry to the vault.
     *        If entry's UUID is empty, automatically generates a new UUID v4.
     * @param entry Move-only credential entry to add.
     * @return Reference to the generated or assigned UUID.
     */
    const std::string& add_entry(CredentialEntry entry);

    /**
     * @brief Retrieves a pointer to an entry by its unique UUID.
     * @return Pointer to CredentialEntry, or nullptr if not found.
     */
    [[nodiscard]] CredentialEntry* get_entry(std::string_view uuid) noexcept;
    [[nodiscard]] const CredentialEntry* get_entry(std::string_view uuid) const noexcept;

    /**
     * @brief Updates an existing entry by its UUID.
     * @param uuid Unique ID of the entry to update.
     * @param updated_entry New entry data.
     * @return true if updated, false if entry was not found.
     */
    bool update_entry(std::string_view uuid, CredentialEntry updated_entry);

    /**
     * @brief Deletes an entry by its UUID.
     * @param uuid Unique ID of the entry to remove.
     * @return true if entry was removed, false if not found.
     */
    bool delete_entry(std::string_view uuid);

    // --- Search & Queries ---

    /**
     * @brief Searches entries by service title.
     * @param query Search string.
     * @param exact If true, requires exact match; if false, case-insensitive substring search.
     * @return List of non-owning pointers to matching entries.
     */
    [[nodiscard]] std::vector<const CredentialEntry*> find_by_title(
        std::string_view query, bool exact = false) const;

    /**
     * @brief Searches entries by login username / email.
     * @param query Search string.
     * @param exact If true, requires exact match; if false, case-insensitive substring search.
     * @return List of non-owning pointers to matching entries.
     */
    [[nodiscard]] std::vector<const CredentialEntry*> find_by_username(
        std::string_view query, bool exact = false) const;

    /**
     * @brief Full-text search across title, username, URL, and notes fields (case-insensitive).
     * @param query Search substring.
     * @return List of non-owning pointers to matching entries.
     */
    [[nodiscard]] std::vector<const CredentialEntry*> search(std::string_view query) const;

    /**
     * @brief Direct read-only access to all entries in the vault.
     */
    [[nodiscard]] const std::vector<CredentialEntry>& entries() const noexcept { return entries_; }

    /**
     * @brief Wipes all entries and resets the vault.
     */
    void clear() noexcept;

    // --- Serialization & Memory Scrubbing ---

    /**
     * @brief Serializes the vault into a structured nlohmann::json object.
     */
    [[nodiscard]] nlohmann::json to_json() const;

    /**
     * @brief Serializes the entire vault to JSON and packages it in a SecureBuffer.
     *        Intermediate plaintext JSON strings in memory are immediately scrubbed
     *        with SecureMemory::zero before return.
     * @return SecureBuffer containing the serialized plaintext JSON payload.
     */
    [[nodiscard]] crypto::SecureBuffer serialize_secure() const;

    /**
     * @brief Deserializes a Vault from plaintext JSON bytes.
     * @param json_bytes Raw JSON byte span.
     * @throws VaultCorruptError If JSON syntax is invalid or schema is violated.
     * @return Reconstructed Vault instance.
     */
    static Vault deserialize(std::span<const uint8_t> json_bytes);

    /**
     * @brief Deserializes a Vault from a plaintext JSON string view.
     * @throws VaultCorruptError If JSON syntax is invalid or schema is violated.
     */
    static Vault deserialize(std::string_view json_str);

private:
    std::string vault_id_;
    uint32_t schema_version_{CURRENT_SCHEMA_VERSION};
    uint64_t created_at_{0};
    uint64_t updated_at_{0};
    std::vector<CredentialEntry> entries_;

    void touch() noexcept;
};

} // namespace pwdmgr::core
