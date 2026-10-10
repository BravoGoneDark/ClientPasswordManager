#include "cli/cli_interface.hpp"
#include "crypto/secure_memory.hpp"
#include "crypto/cipher.hpp"

#include <iostream>
#include <iomanip>
#include <sstream>
#include <thread>
#include <chrono>
#include <ctime>
#include <cctype>

#ifdef _WIN32
#include <conio.h>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace pwdmgr::cli {

namespace {

std::string trim(std::string_view s) {
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string_view::npos) return "";
    auto end = s.find_last_not_of(" \t\r\n");
    return std::string(s.substr(start, end - start + 1));
}

} // anonymous namespace

// ==============================================================================
// Clipboard Manager Implementation
// ==============================================================================

bool ClipboardManager::copy_to_clipboard(std::string_view text, uint32_t auto_clear_seconds) {
#ifdef _WIN32
    if (!OpenClipboard(nullptr)) {
        return false;
    }
    EmptyClipboard();

    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);
    if (!hMem) {
        CloseClipboard();
        return false;
    }

    void* pMem = GlobalLock(hMem);
    if (!pMem) {
        GlobalFree(hMem);
        CloseClipboard();
        return false;
    }

    std::memcpy(pMem, text.data(), text.size());
    static_cast<char*>(pMem)[text.size()] = '\0';
    GlobalUnlock(hMem);

    SetClipboardData(CF_TEXT, hMem);
    CloseClipboard();

    if (auto_clear_seconds > 0) {
        std::thread([auto_clear_seconds]() {
            std::this_thread::sleep_for(std::chrono::seconds(auto_clear_seconds));
            ClipboardManager::clear_clipboard();
        }).detach();
    }
    return true;
#else
    // Fallback notice for non-Windows builds
    (void)text;
    (void)auto_clear_seconds;
    return false;
#endif
}

bool ClipboardManager::clear_clipboard() {
#ifdef _WIN32
    if (OpenClipboard(nullptr)) {
        EmptyClipboard();
        CloseClipboard();
        return true;
    }
    return false;
#else
    return false;
#endif
}

// ==============================================================================
// Hidden Password Input Implementation
// ==============================================================================

crypto::SecureString CliInterface::read_password_hidden(
    std::string_view prompt,
    char mask_char
) {
    std::cout << prompt << std::flush;
    std::string password;

#ifdef _WIN32
    while (true) {
        int ch = _getch();
        if (ch == '\r' || ch == '\n') {
            std::cout << "\n";
            break;
        }
        if (ch == '\b' || ch == 127) {
            if (!password.empty()) {
                password.pop_back();
                if (mask_char != '\0') {
                    std::cout << "\b \b" << std::flush;
                }
            }
            continue;
        }
        if (ch == 3) { // Ctrl+C
            std::cout << "^C\n";
            crypto::SecureMemory::zero(password.data(), password.size());
            password.clear();
            throw std::runtime_error("Password input interrupted");
        }
        if (ch == 0 || ch == 224) {
            // Extended prefix (arrow keys, function keys) - consume second byte
            _getch();
            continue;
        }
        if (std::isprint(ch)) {
            password.push_back(static_cast<char>(ch));
            if (mask_char != '\0') {
                std::cout << mask_char << std::flush;
            }
        }
    }
#else
    std::getline(std::cin, password);
#endif

    crypto::SecureString secure_pwd(password);
    crypto::SecureMemory::zero(password.data(), password.size());
    password.clear();
    return secure_pwd;
}

// ==============================================================================
// CliInterface Implementation
// ==============================================================================

CliInterface::CliInterface() = default;

CliInterface::~CliInterface() {
    master_password_.clear();
    if (vault_) {
        vault_->clear();
    }
}

std::string CliInterface::format_epoch_date(uint64_t epoch_sec) {
    if (epoch_sec == 0) return "Never";
    std::time_t t = static_cast<std::time_t>(epoch_sec);
    std::tm tm_buf{};
#ifdef _WIN32
    localtime_s(&tm_buf, &t);
#else
    localtime_r(&t, &tm_buf);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_buf);
    return std::string(buf);
}

void CliInterface::print_banner() const {
    std::cout << R"(
========================================================================
   ____ _ _            _   ____                                    _ 
  / ___| (_) ___ _ __ | |_|  _ \ __ _ ___ _____      _____  _ __ __| |
 | |   | | |/ _ \ '_ \| __| |_) / _` / __/ __\ \ /\ / / _ \| '__/ _` |
 | |___| | |  __/ | | | |_|  __/ (_| \__ \__ \\ V  V / (_) | | | (_| |
  \____|_|_|\___|_| |_|\__|_|   \__,_|___/___/ \_/\_/ \___/|_|  \__,_|
                  Manager v1.0.0 (Zero-Knowledge C++)
========================================================================
)" << std::endl;
}

void CliInterface::print_help() const {
    std::cout << R"(
Available Commands:
  Vault Management:
    init [path]         Create a new encrypted vault file
    open [path]         Unlock an existing vault file
    save                Persist vault changes to disk (atomic write-replace)
    lock                Lock vault and scrub keys/passwords from RAM
    status              Display current vault state and metadata

  Credential Operations:
    add                 Add a new credential entry (interactive)
    list                List all credentials (passwords hidden for safety)
    get <title|uuid>    View details of a credential entry
    copy <title|uuid>   Copy password to clipboard (auto-clears in 30s)
    edit <title|uuid>   Update credential details
    delete <title|uuid> Remove a credential entry
    search <keyword>    Full-text search across all fields

  Utilities:
    generate            Generate high-entropy passwords or Diceware passphrases
    strength [pwd]      Evaluate password entropy and brute-force resistance
    help                Show this command reference
    exit | quit         Exit application (prompts to save if modified)
)" << std::endl;
}

void CliInterface::print_status() const {
    std::cout << "\n--- Vault Status ---" << std::endl;
    if (state_ == State::Locked) {
        std::cout << "State:      [LOCKED]" << std::endl;
        std::cout << "Path:       " << (current_vault_path_.empty() ? "(none)" : current_vault_path_.string()) << std::endl;
    } else {
        std::cout << "State:      [UNLOCKED]" << std::endl;
        std::cout << "Vault ID:   " << vault_->vault_id() << std::endl;
        std::cout << "File:       " << current_vault_path_.string() << std::endl;
        std::cout << "Entries:    " << vault_->size() << std::endl;
        std::cout << "Modified:   " << (is_dirty_ ? "Yes (unsaved changes)" : "Clean") << std::endl;
        std::cout << "Last Touch: " << format_epoch_date(vault_->updated_at()) << std::endl;
    }
    std::cout << "--------------------\n" << std::endl;
}

bool CliInterface::prompt_save_if_dirty() {
    if (state_ == State::Unlocked && is_dirty_) {
        std::cout << "\n[!] You have unsaved changes. Save to disk now? (Y/n): " << std::flush;
        std::string ans;
        std::getline(std::cin, ans);
        ans = trim(ans);
        if (ans.empty() || ans == "y" || ans == "Y") {
            cmd_save();
            return true;
        }
    }
    return false;
}

const core::CredentialEntry* CliInterface::resolve_entry(std::string_view query) const {
    if (!vault_) return nullptr;

    // 1. Try exact UUID lookup
    auto* entry = vault_->get_entry(query);
    if (entry) return entry;

    // 2. Try exact title lookup
    auto title_exact = vault_->find_by_title(query, true);
    if (title_exact.size() == 1) return title_exact[0];

    // 3. Try case-insensitive substring title lookup
    auto title_matches = vault_->find_by_title(query, false);
    if (title_matches.size() == 1) return title_matches[0];
    if (title_matches.size() > 1) {
        std::cout << "[!] Multiple entries match '" << query << "':\n";
        for (const auto* e : title_matches) {
            std::cout << "    - " << e->title() << " (" << e->username() << ") [UUID: " << e->uuid() << "]\n";
        }
        std::cout << "Please specify the full title or exact UUID.\n";
        return nullptr;
    }

    return nullptr;
}

// ==============================================================================
// Command Implementations
// ==============================================================================

void CliInterface::cmd_init(std::string_view path_arg) {
    prompt_save_if_dirty();

    std::filesystem::path target_path = path_arg;
    if (target_path.empty()) {
        std::cout << "Enter target vault file path (default: my_passwords.vault): " << std::flush;
        std::string input;
        std::getline(std::cin, input);
        input = trim(input);
        target_path = input.empty() ? "my_passwords.vault" : input;
    }

    if (std::filesystem::exists(target_path)) {
        std::cout << "[!] File '" << target_path.string() << "' already exists. Overwrite? (y/N): " << std::flush;
        std::string confirm;
        std::getline(std::cin, confirm);
        if (trim(confirm) != "y" && trim(confirm) != "Y") {
            std::cout << "[-] Vault creation aborted.\n";
            return;
        }
    }

    crypto::SecureString pwd1 = read_password_hidden("Set master password: ");
    if (pwd1.empty()) {
        std::cout << "[-] Master password cannot be empty.\n";
        return;
    }

    crypto::SecureString pwd2 = read_password_hidden("Confirm master password: ");
    if (pwd1.view() != pwd2.view()) {
        std::cout << "[-] Passwords do not match. Vault creation aborted.\n";
        return;
    }

    // Evaluate password strength
    auto eval = core::EntropyMeter::evaluate(pwd1.view());
    std::cout << "[*] Master password strength: " << core::EntropyMeter::level_to_string(eval.strength)
              << " (" << std::fixed << std::setprecision(1) << eval.effective_entropy_bits << " bits of entropy)\n";

    core::Vault new_vault;
    storage::VaultFile::save(target_path, new_vault, pwd1.view());

    current_vault_path_ = std::move(target_path);
    master_password_ = std::move(pwd1);
    vault_ = std::move(new_vault);
    state_ = State::Unlocked;
    is_dirty_ = false;

    std::cout << "[+] New vault created and unlocked at: " << current_vault_path_.string() << "\n";
}

void CliInterface::cmd_open(std::string_view path_arg) {
    prompt_save_if_dirty();

    std::filesystem::path target_path = path_arg;
    if (target_path.empty()) {
        std::cout << "Enter vault file path to unlock: " << std::flush;
        std::string input;
        std::getline(std::cin, input);
        target_path = trim(input);
    }

    if (!std::filesystem::exists(target_path)) {
        std::cout << "[-] Vault file does not exist: " << target_path.string() << "\n";
        return;
    }

    if (!storage::VaultFile::is_vault_file(target_path)) {
        std::cout << "[-] File is not a valid ClientPasswordManager vault.\n";
        return;
    }

    crypto::SecureString master_pwd = read_password_hidden("Enter master password: ");

    try {
        core::Vault loaded = storage::VaultFile::load(target_path, master_pwd.view());
        current_vault_path_ = std::move(target_path);
        master_password_ = std::move(master_pwd);
        vault_ = std::move(loaded);
        state_ = State::Unlocked;
        is_dirty_ = false;

        std::cout << "[+] Vault unlocked successfully! Contains " << vault_->size() << " credential entries.\n";
    } catch (const crypto::AuthenticationError&) {
        std::cout << "[-] Authentication failed: Incorrect master password or tampered file.\n";
    } catch (const std::exception& e) {
        std::cout << "[-] Failed to open vault: " << e.what() << "\n";
    }
}

void CliInterface::cmd_add() {
    if (state_ != State::Unlocked) {
        std::cout << "[-] Vault is locked. Use 'open' or 'init' first.\n";
        return;
    }

    std::string title, username, url, notes;
    std::cout << "Enter service title (e.g. GitHub, AWS): " << std::flush;
    std::getline(std::cin, title);
    title = trim(title);
    if (title.empty()) {
        std::cout << "[-] Title cannot be empty.\n";
        return;
    }

    std::cout << "Enter username / login identifier: " << std::flush;
    std::getline(std::cin, username);
    username = trim(username);

    std::cout << "\nPassword Options:\n"
              << "  [1] Enter password manually (hidden)\n"
              << "  [2] Generate strong random password (20 chars)\n"
              << "  [3] Generate Diceware passphrase (5 words)\n"
              << "Select option [1-3] (default 2): " << std::flush;

    std::string opt_str;
    std::getline(std::cin, opt_str);
    opt_str = trim(opt_str);

    crypto::SecureString password;
    if (opt_str == "1") {
        password = read_password_hidden("Enter password: ");
    } else if (opt_str == "3") {
        password = core::PasswordGenerator::generate_passphrase(5, '-');
        std::cout << "[*] Generated passphrase: " << password.view() << "\n";
    } else {
        password = core::PasswordGenerator::generate(core::PasswordOptions::strong());
        std::cout << "[*] Generated password: " << password.view() << "\n";
    }

    auto eval = core::EntropyMeter::evaluate(password.view());
    std::cout << "[*] Strength: " << core::EntropyMeter::level_to_string(eval.strength)
              << " (" << std::fixed << std::setprecision(1) << eval.effective_entropy_bits << " bits)\n";

    std::cout << "Enter URL (optional): " << std::flush;
    std::getline(std::cin, url);
    url = trim(url);

    std::cout << "Enter notes (optional): " << std::flush;
    std::getline(std::cin, notes);
    notes = trim(notes);

    core::CredentialEntry entry(
        std::move(title),
        std::move(username),
        std::move(password),
        std::move(url),
        std::move(notes)
    );

    const std::string& new_uuid = vault_->add_entry(std::move(entry));
    is_dirty_ = true;

    std::cout << "[+] Credential added successfully! [UUID: " << new_uuid << "]\n";
    std::cout << "    (Remember to 'save' changes to disk)\n";
}

void CliInterface::cmd_list() {
    if (state_ != State::Unlocked) {
        std::cout << "[-] Vault is locked. Use 'open' or 'init' first.\n";
        return;
    }

    if (vault_->empty()) {
        std::cout << "[*] Vault is empty. Use 'add' to create a credential.\n";
        return;
    }

    std::cout << "\n"
              << std::left
              << std::setw(4)  << "#"
              << std::setw(24) << "Title"
              << std::setw(24) << "Username"
              << std::setw(26) << "URL"
              << std::setw(20) << "Modified"
              << "\n"
              << std::string(98, '-')
              << "\n";

    size_t idx = 1;
    for (const auto& entry : vault_->entries()) {
        std::string display_url = entry.url();
        if (display_url.length() > 24) {
            display_url = display_url.substr(0, 21) + "...";
        }
        std::cout << std::left
                  << std::setw(4)  << idx++
                  << std::setw(24) << entry.title()
                  << std::setw(24) << entry.username()
                  << std::setw(26) << display_url
                  << std::setw(20) << format_epoch_date(entry.updated_at())
                  << "\n";
    }
    std::cout << std::string(98, '-') << "\n"
              << "Total: " << vault_->size() << " entries (Passwords hidden for security. Use 'get' to view/copy).\n\n";
}

void CliInterface::cmd_get(std::string_view query) {
    if (state_ != State::Unlocked) {
        std::cout << "[-] Vault is locked. Use 'open' or 'init' first.\n";
        return;
    }

    std::string q = trim(query);
    if (q.empty()) {
        std::cout << "Enter title or UUID to view: " << std::flush;
        std::getline(std::cin, q);
        q = trim(q);
    }

    const auto* entry = resolve_entry(q);
    if (!entry) {
        std::cout << "[-] Entry not found matching '" << q << "'.\n";
        return;
    }

    std::cout << "\n================ Credential Details ================\n"
              << "Title:       " << entry->title() << "\n"
              << "Username:    " << entry->username() << "\n"
              << "URL:         " << (entry->url().empty() ? "(none)" : entry->url()) << "\n"
              << "Notes:       " << (entry->notes().empty() ? "(none)" : entry->notes()) << "\n"
              << "Created:     " << format_epoch_date(entry->created_at()) << "\n"
              << "Modified:    " << format_epoch_date(entry->updated_at()) << "\n"
              << "UUID:        " << entry->uuid() << "\n"
              << "----------------------------------------------------\n"
              << "Actions:\n"
              << "  [1] Show password in console\n"
              << "  [2] Copy password to clipboard (auto-clears in 30s)\n"
              << "  [3] Back\n"
              << "Select [1-3] (default 2): " << std::flush;

    std::string act;
    std::getline(std::cin, act);
    act = trim(act);

    if (act == "1") {
        std::cout << "Password:    " << entry->password().view() << "\n";
        auto eval = core::EntropyMeter::evaluate(entry->password().view());
        std::cout << "Strength:    " << core::EntropyMeter::level_to_string(eval.strength)
                  << " (" << std::fixed << std::setprecision(1) << eval.effective_entropy_bits << " bits)\n";
    } else if (act == "3") {
        return;
    } else {
        if (ClipboardManager::copy_to_clipboard(entry->password().view(), 30)) {
            std::cout << "[+] Password copied to clipboard! Will automatically clear in 30 seconds.\n";
        } else {
            std::cout << "[-] Failed to access system clipboard.\n";
        }
    }
}

void CliInterface::cmd_copy(std::string_view query) {
    if (state_ != State::Unlocked) {
        std::cout << "[-] Vault is locked. Use 'open' or 'init' first.\n";
        return;
    }

    std::string q = trim(query);
    if (q.empty()) {
        std::cout << "Enter title or UUID to copy: " << std::flush;
        std::getline(std::cin, q);
        q = trim(q);
    }

    const auto* entry = resolve_entry(q);
    if (!entry) {
        std::cout << "[-] Entry not found matching '" << q << "'.\n";
        return;
    }

    if (ClipboardManager::copy_to_clipboard(entry->password().view(), 30)) {
        std::cout << "[+] Password for '" << entry->title() << "' copied to clipboard!\n"
                  << "    (System clipboard will be automatically wiped in 30 seconds)\n";
    } else {
        std::cout << "[-] Failed to access clipboard.\n";
    }
}

void CliInterface::cmd_edit(std::string_view query) {
    if (state_ != State::Unlocked) {
        std::cout << "[-] Vault is locked.\n";
        return;
    }

    std::string q = trim(query);
    if (q.empty()) {
        std::cout << "Enter title or UUID to edit: " << std::flush;
        std::getline(std::cin, q);
        q = trim(q);
    }

    const auto* entry = resolve_entry(q);
    if (!entry) {
        std::cout << "[-] Entry not found matching '" << q << "'.\n";
        return;
    }

    std::string uuid = entry->uuid();
    core::CredentialEntry updated = entry->clone();

    std::cout << "Editing '" << entry->title() << "' (Press Enter to keep current value):\n";

    std::cout << "Title [" << updated.title() << "]: " << std::flush;
    std::string t;
    std::getline(std::cin, t);
    if (!trim(t).empty()) updated.set_title(trim(t));

    std::cout << "Username [" << updated.username() << "]: " << std::flush;
    std::string u;
    std::getline(std::cin, u);
    if (!trim(u).empty()) updated.set_username(trim(u));

    std::cout << "Update password? (y/N): " << std::flush;
    std::string change_p;
    std::getline(std::cin, change_p);
    if (trim(change_p) == "y" || trim(change_p) == "Y") {
        std::cout << "  [1] Type manually\n"
                  << "  [2] Generate strong random password\n"
                  << "Select [1-2] (default 2): " << std::flush;
        std::string p_opt;
        std::getline(std::cin, p_opt);
        if (trim(p_opt) == "1") {
            updated.set_password(read_password_hidden("Enter new password: "));
        } else {
            auto generated = core::PasswordGenerator::generate();
            std::cout << "[*] New generated password: " << generated.view() << "\n";
            updated.set_password(std::move(generated));
        }
    }

    std::cout << "URL [" << updated.url() << "]: " << std::flush;
    std::string url_in;
    std::getline(std::cin, url_in);
    if (!trim(url_in).empty()) updated.set_url(trim(url_in));

    std::cout << "Notes [" << updated.notes() << "]: " << std::flush;
    std::string notes_in;
    std::getline(std::cin, notes_in);
    if (!trim(notes_in).empty()) updated.set_notes(trim(notes_in));

    vault_->update_entry(uuid, std::move(updated));
    is_dirty_ = true;
    std::cout << "[+] Entry updated successfully! (Remember to 'save')\n";
}

void CliInterface::cmd_delete(std::string_view query) {
    if (state_ != State::Unlocked) {
        std::cout << "[-] Vault is locked.\n";
        return;
    }

    std::string q = trim(query);
    if (q.empty()) {
        std::cout << "Enter title or UUID to delete: " << std::flush;
        std::getline(std::cin, q);
        q = trim(q);
    }

    const auto* entry = resolve_entry(q);
    if (!entry) {
        std::cout << "[-] Entry not found matching '" << q << "'.\n";
        return;
    }

    std::cout << "[!] Are you sure you want to delete '" << entry->title() << "'? (y/N): " << std::flush;
    std::string confirm;
    std::getline(std::cin, confirm);
    if (trim(confirm) == "y" || trim(confirm) == "Y") {
        std::string uuid = entry->uuid();
        vault_->delete_entry(uuid);
        is_dirty_ = true;
        std::cout << "[+] Entry deleted successfully.\n";
    } else {
        std::cout << "[*] Deletion cancelled.\n";
    }
}

void CliInterface::cmd_search(std::string_view query) {
    if (state_ != State::Unlocked) {
        std::cout << "[-] Vault is locked.\n";
        return;
    }

    std::string q = trim(query);
    if (q.empty()) {
        std::cout << "Enter search keyword: " << std::flush;
        std::getline(std::cin, q);
        q = trim(q);
    }

    auto results = vault_->search(q);
    if (results.empty()) {
        std::cout << "[*] No entries matched keyword: '" << q << "'.\n";
        return;
    }

    std::cout << "\n[+] Found " << results.size() << " matching entries for '" << q << "':\n";
    for (const auto* e : results) {
        std::cout << "  - " << e->title() << " (" << e->username() << ") [UUID: " << e->uuid() << "]\n";
    }
    std::cout << std::endl;
}

void CliInterface::cmd_generate() {
    std::cout << "\n--- Password Generator ---" << std::endl;
    std::cout << "  [1] Strong Password (20 chars, mixed symbols)\n"
              << "  [2] Custom Character Password\n"
              << "  [3] Diceware Multi-Word Passphrase\n"
              << "  [4] Numeric PIN\n"
              << "Select [1-4] (default 1): " << std::flush;

    std::string opt;
    std::getline(std::cin, opt);
    opt = trim(opt);

    crypto::SecureString pwd;

    if (opt == "2") {
        core::PasswordOptions custom;
        std::cout << "Enter length (default 16): " << std::flush;
        std::string len_str;
        std::getline(std::cin, len_str);
        if (!trim(len_str).empty()) {
            try { custom.length = std::stoul(len_str); } catch (...) { custom.length = 16; }
        } else {
            custom.length = 16;
        }

        std::cout << "Exclude ambiguous characters (0, O, 1, l, etc.)? (y/N): " << std::flush;
        std::string amb;
        std::getline(std::cin, amb);
        custom.exclude_ambiguous = (trim(amb) == "y" || trim(amb) == "Y");

        pwd = core::PasswordGenerator::generate(custom);
    } else if (opt == "3") {
        std::cout << "Enter number of words (default 5): " << std::flush;
        std::string w_str;
        std::getline(std::cin, w_str);
        size_t words = 5;
        if (!trim(w_str).empty()) {
            try { words = std::stoul(w_str); } catch (...) { words = 5; }
        }
        pwd = core::PasswordGenerator::generate_passphrase(words, '-');
    } else if (opt == "4") {
        std::cout << "Enter PIN length (default 6): " << std::flush;
        std::string pin_str;
        std::getline(std::cin, pin_str);
        size_t len = 6;
        if (!trim(pin_str).empty()) {
            try { len = std::stoul(pin_str); } catch (...) { len = 6; }
        }
        pwd = core::PasswordGenerator::generate(core::PasswordOptions::pin(len));
    } else {
        pwd = core::PasswordGenerator::generate(core::PasswordOptions::strong());
    }

    std::cout << "\n============================================\n"
              << "Generated Secret: " << pwd.view() << "\n";

    auto eval = core::EntropyMeter::evaluate(pwd.view());
    std::cout << "Entropy:          " << std::fixed << std::setprecision(1)
              << eval.effective_entropy_bits << " bits ("
              << core::EntropyMeter::level_to_string(eval.strength) << ")\n"
              << "Crack (Offline):  " << eval.crack_time_offline << "\n"
              << "Crack (Online):   " << eval.crack_time_online << "\n"
              << "============================================\n";

    std::cout << "Copy to clipboard? (Y/n): " << std::flush;
    std::string copy_ans;
    std::getline(std::cin, copy_ans);
    if (trim(copy_ans).empty() || trim(copy_ans) == "y" || trim(copy_ans) == "Y") {
        ClipboardManager::copy_to_clipboard(pwd.view(), 30);
        std::cout << "[+] Copied to clipboard! (Auto-clears in 30 seconds)\n";
    }
}

void CliInterface::cmd_strength(std::string_view pwd_arg) {
    crypto::SecureString target_pwd;
    std::string p = trim(pwd_arg);
    if (p.empty()) {
        target_pwd = read_password_hidden("Enter password to evaluate: ");
    } else {
        target_pwd = crypto::SecureString(p);
    }

    auto eval = core::EntropyMeter::evaluate(target_pwd.view());
    std::cout << "\n--- Entropy Analysis ---" << std::endl;
    std::cout << "Length:            " << target_pwd.length() << " characters\n"
              << "Pool Entropy:      " << std::fixed << std::setprecision(1) << eval.pool_entropy_bits << " bits\n"
              << "Shannon Entropy:   " << eval.shannon_entropy_bits << " bits\n"
              << "Effective Entropy: " << eval.effective_entropy_bits << " bits\n"
              << "Rating:            " << core::EntropyMeter::level_to_string(eval.strength) << "\n"
              << "Estimated Crack:   " << eval.crack_time_offline << " (10^10 hashes/sec offline GPU)\n"
              << "                   " << eval.crack_time_online << " (100 attempts/sec online login)\n";

    if (!eval.suggestions.empty()) {
        std::cout << "Recommendations:\n";
        for (const auto& s : eval.suggestions) {
            std::cout << "  - " << s << "\n";
        }
    }
    std::cout << "------------------------\n" << std::endl;
}

void CliInterface::cmd_save() {
    if (state_ != State::Unlocked) {
        std::cout << "[-] Vault is locked.\n";
        return;
    }

    if (current_vault_path_.empty()) {
        std::cout << "[-] No vault path configured. Use 'init' first.\n";
        return;
    }

    try {
        storage::VaultFile::save(current_vault_path_, *vault_, master_password_.view());
        is_dirty_ = false;
        std::cout << "[+] Vault saved and encrypted successfully to: " << current_vault_path_.string() << "\n";
    } catch (const std::exception& e) {
        std::cout << "[-] Failed to save vault: " << e.what() << "\n";
    }
}

void CliInterface::cmd_lock() {
    if (state_ == State::Locked) {
        std::cout << "[*] Vault is already locked.\n";
        return;
    }

    prompt_save_if_dirty();

    master_password_.clear();
    if (vault_) {
        vault_->clear();
        vault_.reset();
    }
    state_ = State::Locked;
    is_dirty_ = false;
    std::cout << "[*] Vault locked. Master key and decrypted credentials securely wiped from RAM.\n";
}

void CliInterface::repl_loop() {
    print_banner();
    print_help();

    std::string line;
    while (true) {
        std::string prompt = (state_ == State::Unlocked)
            ? ("cpwm [" + current_vault_path_.filename().string() + (is_dirty_ ? "*" : "") + "]> ")
            : "cpwm (locked)> ";

        std::cout << prompt << std::flush;
        if (!std::getline(std::cin, line)) {
            break;
        }

        std::string trimmed_line = trim(line);
        if (trimmed_line.empty()) {
            continue;
        }

        std::istringstream iss(trimmed_line);
        std::string cmd;
        iss >> cmd;
        std::string remainder;
        std::getline(iss, remainder);
        remainder = trim(remainder);

        if (cmd == "exit" || cmd == "quit") {
            prompt_save_if_dirty();
            cmd_lock();
            std::cout << "[*] Exiting ClientPasswordManager. Stay safe!\n";
            break;
        } else if (cmd == "help") {
            print_help();
        } else if (cmd == "status") {
            print_status();
        } else if (cmd == "init") {
            cmd_init(remainder);
        } else if (cmd == "open" || cmd == "unlock") {
            cmd_open(remainder);
        } else if (cmd == "add") {
            cmd_add();
        } else if (cmd == "list") {
            cmd_list();
        } else if (cmd == "get") {
            cmd_get(remainder);
        } else if (cmd == "copy") {
            cmd_copy(remainder);
        } else if (cmd == "edit") {
            cmd_edit(remainder);
        } else if (cmd == "delete" || cmd == "del" || cmd == "rm") {
            cmd_delete(remainder);
        } else if (cmd == "search" || cmd == "find") {
            cmd_search(remainder);
        } else if (cmd == "generate" || cmd == "gen") {
            cmd_generate();
        } else if (cmd == "strength" || cmd == "eval") {
            cmd_strength(remainder);
        } else if (cmd == "save") {
            cmd_save();
        } else if (cmd == "lock") {
            cmd_lock();
        } else if (cmd == "clear" || cmd == "cls") {
#ifdef _WIN32
            system("cls");
#else
            system("clear");
#endif
        } else {
            std::cout << "[-] Unknown command: '" << cmd << "'. Type 'help' for available commands.\n";
        }
    }
}

int CliInterface::run(int argc, char* argv[]) {
    try {
        if (argc > 1) {
            std::string arg1 = argv[1];
            if (arg1 == "--help" || arg1 == "-h") {
                print_banner();
                print_help();
                return 0;
            }
            if (arg1 == "--version" || arg1 == "-v") {
                std::cout << "ClientPasswordManager v1.0.0 (C++20 Zero-Knowledge Vault)\n";
                return 0;
            }
            // If argument is a vault file path, open it directly
            if (std::filesystem::exists(arg1)) {
                cmd_open(arg1);
            }
        }

        repl_loop();
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "[-] Fatal error: " << e.what() << std::endl;
        return 1;
    }
}

} // namespace pwdmgr::cli
