#pragma once

#include "core/vault.hpp"
#include "core/generator.hpp"
#include "storage/vault_file.hpp"
#include "crypto/secure_memory.hpp"

#include <filesystem>
#include <string>
#include <string_view>
#include <optional>
#include <memory>

namespace pwdmgr::cli {

/**
 * @brief Manages secure clipboard operations with automated background scrub timers.
 */
class ClipboardManager {
public:
    /**
     * @brief Copies text to the OS clipboard and launches an asynchronous timer
     *        to automatically erase it after the specified duration.
     * @param text The secret text to copy.
     * @param auto_clear_seconds Number of seconds before clipboard is wiped (default 30).
     * @return true if successfully copied, false otherwise.
     */
    static bool copy_to_clipboard(std::string_view text, uint32_t auto_clear_seconds = 30);

    /**
     * @brief Immediately wipes the OS clipboard contents.
     */
    static bool clear_clipboard();
};

/**
 * @brief Hardened terminal user interface and interactive REPL shell.
 */
class CliInterface {
public:
    CliInterface();
    ~CliInterface();

    /**
     * @brief Main entrypoint to process CLI flags or start the interactive REPL shell.
     */
    int run(int argc, char* argv[]);

    /**
     * @brief Reads a password from console with echo suppression (shoulder-surfing defense).
     * @param prompt Text prompt displayed to the user.
     * @param mask_char Character to echo on keypress (e.g. '*' or '\0' for total silence).
     * @return SecureString containing the typed password.
     */
    static crypto::SecureString read_password_hidden(
        std::string_view prompt = "Enter master password: ",
        char mask_char = '*'
    );

private:
    enum class State {
        Locked,
        Unlocked
    };

    State state_{State::Locked};
    std::optional<core::Vault> vault_;
    std::filesystem::path current_vault_path_;
    crypto::SecureString master_password_;
    bool is_dirty_{false};

    void repl_loop();
    void print_banner() const;
    void print_help() const;
    void print_status() const;

    // --- Commands ---
    void cmd_init(std::string_view path_arg);
    void cmd_open(std::string_view path_arg);
    void cmd_add();
    void cmd_list();
    void cmd_get(std::string_view query);
    void cmd_copy(std::string_view query);
    void cmd_edit(std::string_view query);
    void cmd_delete(std::string_view query);
    void cmd_search(std::string_view query);
    void cmd_generate();
    void cmd_strength(std::string_view pwd_arg);
    void cmd_save();
    void cmd_lock();

    // Helper methods
    bool prompt_save_if_dirty();
    const core::CredentialEntry* resolve_entry(std::string_view query) const;
    static std::string format_epoch_date(uint64_t epoch_sec);
};

} // namespace pwdmgr::cli
