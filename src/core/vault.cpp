#include "core/vault.hpp"
#include "crypto/secure_memory.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <cctype>

namespace pwdmgr::core {

namespace {

uint64_t get_current_epoch_seconds() noexcept {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );
}

bool contains_ci(std::string_view haystack, std::string_view needle) noexcept {
    if (needle.empty()) {
        return true;
    }
    if (haystack.size() < needle.size()) {
        return false;
    }
    auto it = std::search(
        haystack.begin(), haystack.end(),
        needle.begin(), needle.end(),
        [](char c1, char c2) {
            return std::tolower(static_cast<unsigned char>(c1)) ==
                   std::tolower(static_cast<unsigned char>(c2));
        }
    );
    return it != haystack.end();
}

bool equals_ci(std::string_view s1, std::string_view s2) noexcept {
    if (s1.size() != s2.size()) {
        return false;
    }
    return std::equal(
        s1.begin(), s1.end(),
        s2.begin(), s2.end(),
        [](char c1, char c2) {
            return std::tolower(static_cast<unsigned char>(c1)) ==
                   std::tolower(static_cast<unsigned char>(c2));
        }
    );
}

} // anonymous namespace

Vault::Vault()
    : vault_id_(Uuid::generate()),
      schema_version_(CURRENT_SCHEMA_VERSION),
      created_at_(get_current_epoch_seconds()),
      updated_at_(created_at_) {}

Vault::Vault(std::string vault_id)
    : vault_id_(std::move(vault_id)),
      schema_version_(CURRENT_SCHEMA_VERSION),
      created_at_(get_current_epoch_seconds()),
      updated_at_(created_at_) {}

void Vault::touch() noexcept {
    updated_at_ = get_current_epoch_seconds();
}

const std::string& Vault::add_entry(CredentialEntry entry) {
    if (entry.uuid().empty()) {
        entry.set_uuid(Uuid::generate());
    }
    if (entry.created_at() == 0) {
        entry.set_created_at(get_current_epoch_seconds());
    }
    if (entry.updated_at() == 0) {
        entry.set_updated_at(entry.created_at());
    }

    entries_.push_back(std::move(entry));
    touch();
    return entries_.back().uuid();
}

CredentialEntry* Vault::get_entry(std::string_view uuid) noexcept {
    for (auto& entry : entries_) {
        if (entry.uuid() == uuid) {
            return &entry;
        }
    }
    return nullptr;
}

const CredentialEntry* Vault::get_entry(std::string_view uuid) const noexcept {
    for (const auto& entry : entries_) {
        if (entry.uuid() == uuid) {
            return &entry;
        }
    }
    return nullptr;
}

bool Vault::update_entry(std::string_view uuid, CredentialEntry updated_entry) {
    for (auto& existing : entries_) {
        if (existing.uuid() == uuid) {
            uint64_t orig_created_at = existing.created_at();
            existing = std::move(updated_entry);
            existing.set_uuid(std::string(uuid));
            if (existing.created_at() == 0) {
                existing.set_created_at(orig_created_at);
            }
            existing.touch();
            touch();
            return true;
        }
    }
    return false;
}

bool Vault::delete_entry(std::string_view uuid) {
    auto it = std::find_if(
        entries_.begin(), entries_.end(),
        [&](const CredentialEntry& e) { return e.uuid() == uuid; }
    );
    if (it != entries_.end()) {
        entries_.erase(it);
        touch();
        return true;
    }
    return false;
}

std::vector<const CredentialEntry*> Vault::find_by_title(
    std::string_view query, bool exact) const {
    std::vector<const CredentialEntry*> results;
    for (const auto& entry : entries_) {
        bool match = exact ? equals_ci(entry.title(), query)
                           : contains_ci(entry.title(), query);
        if (match) {
            results.push_back(&entry);
        }
    }
    return results;
}

std::vector<const CredentialEntry*> Vault::find_by_username(
    std::string_view query, bool exact) const {
    std::vector<const CredentialEntry*> results;
    for (const auto& entry : entries_) {
        bool match = exact ? equals_ci(entry.username(), query)
                           : contains_ci(entry.username(), query);
        if (match) {
            results.push_back(&entry);
        }
    }
    return results;
}

std::vector<const CredentialEntry*> Vault::search(std::string_view query) const {
    std::vector<const CredentialEntry*> results;
    for (const auto& entry : entries_) {
        if (contains_ci(entry.title(), query) ||
            contains_ci(entry.username(), query) ||
            contains_ci(entry.url(), query) ||
            contains_ci(entry.notes(), query)) {
            results.push_back(&entry);
        }
    }
    return results;
}

void Vault::clear() noexcept {
    entries_.clear();
    touch();
}

nlohmann::json Vault::to_json() const {
    nlohmann::json root;
    root["vault_id"] = vault_id_;
    root["schema_version"] = schema_version_;
    root["created_at"] = created_at_;
    root["updated_at"] = updated_at_;

    nlohmann::json entries_arr = nlohmann::json::array();
    for (const auto& entry : entries_) {
        entries_arr.push_back(entry.to_json());
    }
    root["entries"] = entries_arr;
    return root;
}

crypto::SecureBuffer Vault::serialize_secure() const {
    nlohmann::json root = to_json();
    std::string serialized = root.dump();

    crypto::SecureBuffer sec_buf(serialized.size());
    if (!serialized.empty()) {
        std::memcpy(sec_buf.data(), serialized.data(), serialized.size());
        // Defensively sanitize intermediate plaintext string in heap RAM
        crypto::SecureMemory::zero(serialized.data(), serialized.size());
    }
    serialized.clear();
    return sec_buf;
}

Vault Vault::deserialize(std::span<const uint8_t> json_bytes) {
    if (json_bytes.empty()) {
        throw VaultCorruptError("Cannot deserialize empty vault payload");
    }

    try {
        nlohmann::json root = nlohmann::json::parse(json_bytes.begin(), json_bytes.end());
        if (!root.is_object()) {
            throw VaultCorruptError("Root JSON payload must be a valid JSON object");
        }

        std::string v_id = root.value("vault_id", "");
        if (v_id.empty()) {
            v_id = Uuid::generate();
        }

        Vault vault(v_id);
        vault.set_schema_version(root.value("schema_version", CURRENT_SCHEMA_VERSION));
        vault.set_created_at(root.value("created_at", get_current_epoch_seconds()));
        vault.set_updated_at(root.value("updated_at", vault.created_at()));

        if (root.contains("entries") && root["entries"].is_array()) {
            for (const auto& item : root["entries"]) {
                CredentialEntry entry = CredentialEntry::from_json(item);
                vault.add_entry(std::move(entry));
            }
        }

        return vault;
    } catch (const nlohmann::json::exception& e) {
        throw VaultCorruptError(std::string("Vault JSON parse error: ") + e.what());
    }
}

Vault Vault::deserialize(std::string_view json_str) {
    return deserialize(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(json_str.data()),
        json_str.size()
    ));
}

} // namespace pwdmgr::core
