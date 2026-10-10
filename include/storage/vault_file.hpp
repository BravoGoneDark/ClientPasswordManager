#pragma once

#include "core/vault.hpp"
#include "crypto/kdf.hpp"
#include "crypto/cipher.hpp"

#include <filesystem>
#include <string_view>
#include <vector>
#include <cstdint>
#include <stdexcept>

namespace pwdmgr::storage {

/**
 * @brief Base exception for storage and file operations.
 */
class StorageError : public std::runtime_error {
public:
    explicit StorageError(const std::string& msg) : std::runtime_error(msg) {}
};

/**
 * @brief Exception thrown when file header is corrupt, missing, or unsupported.
 */
class InvalidHeaderError : public StorageError {
public:
    explicit InvalidHeaderError(const std::string& msg) : StorageError(msg) {}
};

/**
 * @brief Exception thrown when file format or body is corrupt.
 */
class CorruptedFileError : public StorageError {
public:
    explicit CorruptedFileError(const std::string& msg) : StorageError(msg) {}
};

/**
 * @brief Decoded metadata of a .vault binary file header.
 */
struct VaultHeaderMetadata {
    char magic[4]{};
    uint16_t version{0};
    uint8_t kdf_id{0};
    uint8_t cipher_id{0};
    uint32_t ops_limit{0};
    uint32_t mem_limit_kb{0};
    std::vector<uint8_t> salt;
    std::vector<uint8_t> nonce;
    std::vector<uint8_t> auth_tag;
};

/**
 * @brief Storage engine managing atomic disk persistence, header validation,
 *        and encrypted packaging of .vault files.
 */
class VaultFile {
public:
    // File Format Specification Constants
    static constexpr const char* MAGIC_BYTES     = "CPWM";
    static constexpr uint16_t CURRENT_VERSION    = 1;
    static constexpr uint8_t KDF_ARGON2ID        = 1;
    static constexpr uint8_t KDF_PBKDF2          = 2;
    static constexpr uint8_t CIPHER_AEAD         = 1;

    static constexpr size_t HEADER_SIZE          = 72;  // Total header size in bytes
    static constexpr size_t AAD_SIZE             = 56;  // Header bytes authenticated in AAD
    static constexpr size_t SALT_SIZE            = 16;  // 128-bit salt
    static constexpr size_t NONCE_SIZE           = 24;  // 192-bit nonce
    static constexpr size_t TAG_SIZE             = 16;  // 128-bit MAC tag

    /**
     * @brief Encrypts and saves an in-memory Vault to a .vault binary file on disk.
     *        Uses atomic write-replace semantics and flushes hardware buffers to
     *        prevent corruption on power loss.
     * @param file_path Destination file path.
     * @param vault The in-memory vault to save.
     * @param master_password The master password used to derive the encryption key.
     * @param kdf_params Argon2id work factor parameters (defaults to interactive profile).
     * @throws StorageError If disk write or atomic replacement fails.
     */
    static void save(
        const std::filesystem::path& file_path,
        const core::Vault& vault,
        std::string_view master_password,
        const crypto::KDF::Params& kdf_params = crypto::KDF::Params::interactive()
    );

    /**
     * @brief Reads, verifies, decrypts, and deserializes a .vault binary file from disk.
     * @param file_path Source file path.
     * @param master_password The master password used to decrypt the vault.
     * @throws InvalidHeaderError If header magic or version is invalid.
     * @throws crypto::AuthenticationError If password is wrong or file was tampered with.
     * @throws core::VaultCorruptError If decrypted payload is not valid JSON.
     * @return Decrypted and fully initialized Vault instance.
     */
    static core::Vault load(
        const std::filesystem::path& file_path,
        std::string_view master_password
    );

    /**
     * @brief Reads and inspects the 72-byte header of a .vault file without decrypting it.
     * @param file_path Source file path.
     * @throws InvalidHeaderError If header magic or version is invalid.
     * @return Decoded VaultHeaderMetadata struct.
     */
    static VaultHeaderMetadata read_header(const std::filesystem::path& file_path);

    /**
     * @brief Quickly checks if a file exists and has valid CPWM magic bytes.
     * @param file_path Path to test.
     * @return true if valid CPWM vault file, false otherwise.
     */
    static bool is_vault_file(const std::filesystem::path& file_path) noexcept;

private:
    static void atomic_replace(
        const std::filesystem::path& temp_path,
        const std::filesystem::path& target_path
    );

    static void flush_disk(const std::filesystem::path& file_path);
};

} // namespace pwdmgr::storage
