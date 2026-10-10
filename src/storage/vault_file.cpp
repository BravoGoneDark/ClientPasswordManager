#include "storage/vault_file.hpp"
#include "crypto/random.hpp"
#include "crypto/secure_memory.hpp"

#include <fstream>
#include <cstring>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace pwdmgr::storage {

namespace {

inline void write_u16_le(uint8_t* dst, uint16_t val) noexcept {
    dst[0] = static_cast<uint8_t>(val & 0xFF);
    dst[1] = static_cast<uint8_t>((val >> 8) & 0xFF);
}

inline uint16_t read_u16_le(const uint8_t* src) noexcept {
    return static_cast<uint16_t>(src[0]) |
           (static_cast<uint16_t>(src[1]) << 8);
}

inline void write_u32_le(uint8_t* dst, uint32_t val) noexcept {
    dst[0] = static_cast<uint8_t>(val & 0xFF);
    dst[1] = static_cast<uint8_t>((val >> 8) & 0xFF);
    dst[2] = static_cast<uint8_t>((val >> 16) & 0xFF);
    dst[3] = static_cast<uint8_t>((val >> 24) & 0xFF);
}

inline uint32_t read_u32_le(const uint8_t* src) noexcept {
    return static_cast<uint32_t>(src[0]) |
           (static_cast<uint32_t>(src[1]) << 8) |
           (static_cast<uint32_t>(src[2]) << 16) |
           (static_cast<uint32_t>(src[3]) << 24);
}

} // anonymous namespace

void VaultFile::flush_disk(const std::filesystem::path& file_path) {
#ifdef _WIN32
    HANDLE hFile = CreateFileW(
        file_path.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    if (hFile != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(hFile);
        CloseHandle(hFile);
    }
#endif
}

void VaultFile::atomic_replace(
    const std::filesystem::path& temp_path,
    const std::filesystem::path& target_path
) {
#ifdef _WIN32
    if (std::filesystem::exists(target_path)) {
        if (!ReplaceFileW(
                target_path.c_str(),
                temp_path.c_str(),
                nullptr,
                REPLACEFILE_WRITE_THROUGH | REPLACEFILE_IGNORE_MERGE_ERRORS,
                nullptr,
                nullptr)) {
            // If ReplaceFileW fails, fallback to MoveFileExW
            if (!MoveFileExW(
                    temp_path.c_str(),
                    target_path.c_str(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
                // Final fallback
                std::filesystem::rename(temp_path, target_path);
            }
        }
    } else {
        if (!MoveFileExW(
                temp_path.c_str(),
                target_path.c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            std::filesystem::rename(temp_path, target_path);
        }
    }
#else
    std::filesystem::rename(temp_path, target_path);
#endif
}

void VaultFile::save(
    const std::filesystem::path& file_path,
    const core::Vault& vault,
    std::string_view master_password,
    const crypto::KDF::Params& kdf_params
) {
    if (master_password.empty()) {
        throw StorageError("Master password cannot be empty");
    }

    // 1. Serialize in-memory vault into a SecureBuffer (plaintext JSON)
    crypto::SecureBuffer plaintext = vault.serialize_secure();

    // 2. Generate cryptographically random salt and nonce
    crypto::SecureBuffer salt = crypto::Random::get_bytes(SALT_SIZE);
    crypto::SecureBuffer nonce = crypto::Random::get_bytes(NONCE_SIZE);

    // 3. Derive 256-bit symmetric encryption key using Argon2id / PBKDF2
    crypto::SecureBuffer key = crypto::KDF::derive_key(master_password, salt.span(), kdf_params);

    // 4. Construct 72-byte binary header
    std::vector<uint8_t> header(HEADER_SIZE, 0);

    // Offset 0x00: Magic "CPWM"
    std::memcpy(&header[0], MAGIC_BYTES, 4);

    // Offset 0x04: Version
    write_u16_le(&header[4], CURRENT_VERSION);

    // Offset 0x06: KDF ID
    header[6] = KDF_ARGON2ID;

    // Offset 0x07: Cipher ID
    header[7] = CIPHER_AEAD;

    // Offset 0x08: OpsLimit
    write_u32_le(&header[8], kdf_params.ops_limit);

    // Offset 0x0C: MemLimit in KB
    uint32_t mem_limit_kb = static_cast<uint32_t>(kdf_params.mem_limit / 1024);
    write_u32_le(&header[12], mem_limit_kb);

    // Offset 0x10: Salt (16 bytes)
    std::memcpy(&header[16], salt.data(), SALT_SIZE);

    // Offset 0x20: Nonce (24 bytes)
    std::memcpy(&header[32], nonce.data(), NONCE_SIZE);

    // 5. Encrypt payload with Additional Authenticated Data (AAD = first 56 bytes of header)
    std::span<const uint8_t> aad_span(header.data(), AAD_SIZE);

    crypto::CiphertextPackage pkg = crypto::Cipher::encrypt(
        plaintext.span(),
        key.span(),
        nonce.span(),
        aad_span
    );

    // Offset 0x38: Authentication Tag (16 bytes)
    std::memcpy(&header[56], pkg.tag.data(), TAG_SIZE);

    // 6. Write to temporary file (.tmp)
    if (file_path.has_parent_path()) {
        std::filesystem::create_directories(file_path.parent_path());
    }

    std::filesystem::path temp_path = file_path;
    temp_path += ".tmp";

    {
        std::ofstream out(temp_path, std::ios::binary | std::ios::trunc);
        if (!out.is_open()) {
            throw StorageError("Failed to create temporary vault file: " + temp_path.string());
        }

        // Write 72-byte header
        out.write(reinterpret_cast<const char*>(header.data()), header.size());

        // Write encrypted ciphertext payload
        out.write(
            reinterpret_cast<const char*>(pkg.ciphertext.data()),
            pkg.ciphertext.size()
        );

        if (!out.good()) {
            out.close();
            std::filesystem::remove(temp_path);
            throw StorageError("I/O error occurred while writing vault data");
        }

        out.flush();
    }

    // 7. Flush OS buffers to physical disk
    flush_disk(temp_path);

    // 8. Atomically replace the destination file
    try {
        atomic_replace(temp_path, file_path);
    } catch (const std::exception& e) {
        std::filesystem::remove(temp_path);
        throw StorageError(std::string("Atomic file replacement failed: ") + e.what());
    }
}

core::Vault VaultFile::load(
    const std::filesystem::path& file_path,
    std::string_view master_password
) {
    if (!std::filesystem::exists(file_path)) {
        throw StorageError("Vault file not found: " + file_path.string());
    }

    std::ifstream in(file_path, std::ios::binary | std::ios::ate);
    if (!in.is_open()) {
        throw StorageError("Unable to open vault file: " + file_path.string());
    }

    auto file_size = in.tellg();
    if (file_size < static_cast<std::streamoff>(HEADER_SIZE)) {
        throw InvalidHeaderError("File is smaller than the minimum header size (72 bytes)");
    }

    in.seekg(0, std::ios::beg);
    std::vector<uint8_t> file_bytes(static_cast<size_t>(file_size));
    in.read(reinterpret_cast<char*>(file_bytes.data()), file_size);

    if (!in.good()) {
        throw StorageError("Failed to read complete vault file bytes");
    }
    in.close();

    // 1. Verify Magic Bytes
    if (std::memcmp(file_bytes.data(), MAGIC_BYTES, 4) != 0) {
        throw InvalidHeaderError("Invalid magic header bytes: not a CPWM vault file");
    }

    // 2. Verify Version
    uint16_t version = read_u16_le(&file_bytes[4]);
    if (version == 0 || version > CURRENT_VERSION) {
        throw InvalidHeaderError("Unsupported vault format version: " + std::to_string(version));
    }

    // 3. Extract KDF and Cipher Identifiers
    // file_bytes[6] = kdf_id, file_bytes[7] = cipher_id
    uint32_t ops_limit = read_u32_le(&file_bytes[8]);
    uint32_t mem_limit_kb = read_u32_le(&file_bytes[12]);

    // 4. Extract Salt, Nonce, Tag
    std::span<const uint8_t> salt_span(&file_bytes[16], SALT_SIZE);
    std::span<const uint8_t> nonce_span(&file_bytes[32], NONCE_SIZE);
    std::span<const uint8_t> tag_span(&file_bytes[56], TAG_SIZE);

    // 5. AAD is the first 56 bytes
    std::span<const uint8_t> aad_span(file_bytes.data(), AAD_SIZE);

    // 6. Ciphertext is everything past the 72-byte header
    size_t ciphertext_len = file_bytes.size() - HEADER_SIZE;
    std::span<const uint8_t> ciphertext_span(file_bytes.data() + HEADER_SIZE, ciphertext_len);

    // 7. Derive Key using KDF parameters from header
    crypto::KDF::Params kdf_params{
        ops_limit,
        static_cast<size_t>(mem_limit_kb) * 1024
    };

    crypto::SecureBuffer key = crypto::KDF::derive_key(master_password, salt_span, kdf_params);

    // 8. Authenticated Decryption (Throws AuthenticationError on bit-flips or wrong password)
    crypto::SecureBuffer decrypted = crypto::Cipher::decrypt(
        ciphertext_span,
        tag_span,
        key.span(),
        nonce_span,
        aad_span
    );

    // 9. Deserialize decrypted plaintext JSON into Vault
    return core::Vault::deserialize(decrypted.span());
}

VaultHeaderMetadata VaultFile::read_header(const std::filesystem::path& file_path) {
    if (!std::filesystem::exists(file_path)) {
        throw StorageError("Vault file not found: " + file_path.string());
    }

    std::ifstream in(file_path, std::ios::binary);
    if (!in.is_open()) {
        throw StorageError("Unable to open vault file: " + file_path.string());
    }

    std::vector<uint8_t> header(HEADER_SIZE);
    in.read(reinterpret_cast<char*>(header.data()), HEADER_SIZE);

    if (in.gcount() < static_cast<std::streamsize>(HEADER_SIZE)) {
        throw InvalidHeaderError("File is smaller than the required 72-byte header");
    }

    if (std::memcmp(header.data(), MAGIC_BYTES, 4) != 0) {
        throw InvalidHeaderError("Invalid magic header bytes: not a CPWM vault file");
    }

    VaultHeaderMetadata meta;
    std::memcpy(meta.magic, &header[0], 4);
    meta.version = read_u16_le(&header[4]);
    meta.kdf_id = header[6];
    meta.cipher_id = header[7];
    meta.ops_limit = read_u32_le(&header[8]);
    meta.mem_limit_kb = read_u32_le(&header[12]);

    meta.salt.assign(header.begin() + 16, header.begin() + 32);
    meta.nonce.assign(header.begin() + 32, header.begin() + 56);
    meta.auth_tag.assign(header.begin() + 56, header.begin() + 72);

    return meta;
}

bool VaultFile::is_vault_file(const std::filesystem::path& file_path) noexcept {
    try {
        if (!std::filesystem::exists(file_path)) {
            return false;
        }
        std::ifstream in(file_path, std::ios::binary);
        if (!in.is_open()) {
            return false;
        }
        char magic[4]{};
        in.read(magic, 4);
        if (in.gcount() < 4) {
            return false;
        }
        return std::memcmp(magic, MAGIC_BYTES, 4) == 0;
    } catch (...) {
        return false;
    }
}

} // namespace pwdmgr::storage
