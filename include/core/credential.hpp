#pragma once

#include "crypto/secure_memory.hpp"
#include <nlohmann/json.hpp>

#include <string>
#include <string_view>
#include <cstdint>

namespace pwdmgr::core {

/**
 * @brief Represents a single stored account / credential record.
 *        The password secret is protected inside a SecureString container,
 *        guaranteeing zeroization on destruction. Copy operations are explicitly
 *        deleted to prevent unintentional secret duplication in memory.
 */
class CredentialEntry {
public:
    CredentialEntry();

    /**
     * @brief Constructs a new CredentialEntry.
     * @param title Name of the service/platform (e.g. "GitHub", "ProtonMail").
     * @param username Login username, email, or account ID.
     * @param password Password encapsulated in a SecureString.
     * @param url Website URL or service address.
     * @param notes Optional notes, backup codes, or context.
     * @param uuid Optional UUID; if empty, will be generated upon vault insertion.
     */
    CredentialEntry(
        std::string title,
        std::string username,
        crypto::SecureString password,
        std::string url = "",
        std::string notes = "",
        std::string uuid = ""
    );

    // Disable copy semantics to prevent secret duplication in volatile RAM
    CredentialEntry(const CredentialEntry&) = delete;
    CredentialEntry& operator=(const CredentialEntry&) = delete;

    // Enable move semantics for zero-copy ownership transfer
    CredentialEntry(CredentialEntry&& other) noexcept = default;
    CredentialEntry& operator=(CredentialEntry&& other) noexcept = default;

    ~CredentialEntry() = default;

    /**
     * @brief Creates a deliberate deep copy of the credential entry.
     *        Requires an explicit method call to ensure the developer is aware
     *        that secret material is being duplicated.
     */
    [[nodiscard]] CredentialEntry clone() const;

    // --- Accessors ---
    [[nodiscard]] const std::string& uuid() const noexcept { return uuid_; }
    [[nodiscard]] const std::string& title() const noexcept { return title_; }
    [[nodiscard]] const std::string& username() const noexcept { return username_; }
    [[nodiscard]] const crypto::SecureString& password() const noexcept { return password_; }
    [[nodiscard]] const std::string& url() const noexcept { return url_; }
    [[nodiscard]] const std::string& notes() const noexcept { return notes_; }
    [[nodiscard]] uint64_t created_at() const noexcept { return created_at_; }
    [[nodiscard]] uint64_t updated_at() const noexcept { return updated_at_; }

    // --- Mutators ---
    void set_uuid(std::string uuid) { uuid_ = std::move(uuid); }
    void set_title(std::string title) { title_ = std::move(title); touch(); }
    void set_username(std::string username) { username_ = std::move(username); touch(); }
    void set_password(crypto::SecureString password) { password_ = std::move(password); touch(); }
    void set_password(std::string_view password) { password_ = crypto::SecureString(password); touch(); }
    void set_url(std::string url) { url_ = std::move(url); touch(); }
    void set_notes(std::string notes) { notes_ = std::move(notes); touch(); }
    void set_created_at(uint64_t ts) noexcept { created_at_ = ts; }
    void set_updated_at(uint64_t ts) noexcept { updated_at_ = ts; }

    /**
     * @brief Updates updated_at to the current UTC epoch timestamp.
     */
    void touch() noexcept;

    /**
     * @brief Serializes this credential entry into a JSON object.
     */
    [[nodiscard]] nlohmann::json to_json() const;

    /**
     * @brief Deserializes a CredentialEntry from a JSON object.
     * @throws std::invalid_argument If required fields are missing or corrupted.
     */
    static CredentialEntry from_json(const nlohmann::json& j);

private:
    std::string uuid_;
    std::string title_;
    std::string username_;
    crypto::SecureString password_;
    std::string url_;
    std::string notes_;
    uint64_t created_at_{0};
    uint64_t updated_at_{0};
};

} // namespace pwdmgr::core
