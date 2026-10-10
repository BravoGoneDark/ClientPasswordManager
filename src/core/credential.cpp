#include "core/credential.hpp"
#include "crypto/secure_memory.hpp"

#include <chrono>
#include <stdexcept>

namespace pwdmgr::core {

namespace {
uint64_t get_current_epoch_seconds() noexcept {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );
}
} // anonymous namespace

CredentialEntry::CredentialEntry()
    : created_at_(get_current_epoch_seconds()),
      updated_at_(created_at_) {}

CredentialEntry::CredentialEntry(
    std::string title,
    std::string username,
    crypto::SecureString password,
    std::string url,
    std::string notes,
    std::string uuid
)
    : uuid_(std::move(uuid)),
      title_(std::move(title)),
      username_(std::move(username)),
      password_(std::move(password)),
      url_(std::move(url)),
      notes_(std::move(notes)),
      created_at_(get_current_epoch_seconds()),
      updated_at_(created_at_) {}

CredentialEntry CredentialEntry::clone() const {
    CredentialEntry copy;
    copy.uuid_ = uuid_;
    copy.title_ = title_;
    copy.username_ = username_;
    copy.password_ = crypto::SecureString(password_.view());
    copy.url_ = url_;
    copy.notes_ = notes_;
    copy.created_at_ = created_at_;
    copy.updated_at_ = updated_at_;
    return copy;
}

void CredentialEntry::touch() noexcept {
    updated_at_ = get_current_epoch_seconds();
}

nlohmann::json CredentialEntry::to_json() const {
    nlohmann::json j;
    j["uuid"] = uuid_;
    j["title"] = title_;
    j["username"] = username_;
    j["password"] = std::string(password_.view());
    j["url"] = url_;
    j["notes"] = notes_;
    j["created_at"] = created_at_;
    j["updated_at"] = updated_at_;
    return j;
}

CredentialEntry CredentialEntry::from_json(const nlohmann::json& j) {
    if (!j.is_object()) {
        throw std::invalid_argument("CredentialEntry JSON payload must be an object");
    }

    if (!j.contains("title") || !j.contains("username") || !j.contains("password")) {
        throw std::invalid_argument("CredentialEntry JSON missing required fields (title, username, password)");
    }

    std::string title = j.value("title", "");
    std::string username = j.value("username", "");
    std::string url = j.value("url", "");
    std::string notes = j.value("notes", "");
    std::string uuid = j.value("uuid", "");
    uint64_t created_at = j.value("created_at", get_current_epoch_seconds());
    uint64_t updated_at = j.value("updated_at", created_at);

    // Extract password and securely wipe intermediate plaintext string from RAM
    std::string temp_pwd = j.value("password", "");
    crypto::SecureString secure_pwd(temp_pwd);
    if (!temp_pwd.empty()) {
        crypto::SecureMemory::zero(temp_pwd.data(), temp_pwd.size());
    }

    CredentialEntry entry(
        std::move(title),
        std::move(username),
        std::move(secure_pwd),
        std::move(url),
        std::move(notes),
        std::move(uuid)
    );

    entry.set_created_at(created_at);
    entry.set_updated_at(updated_at);

    return entry;
}

} // namespace pwdmgr::core
