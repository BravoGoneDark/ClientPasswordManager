#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <string_view>
#include <span>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace pwdmgr::crypto {

/**
 * @brief Memory security utilities ensuring zeroization and memory page locking.
 */
class SecureMemory {
public:
    /**
     * @brief Securely zeroes memory, immune to compiler dead-code elimination.
     */
    static void zero(void* ptr, size_t size) noexcept;

    /**
     * @brief Locks virtual memory pages into physical RAM, preventing them
     *        from being paged/swapped to disk (e.g. pagefile.sys).
     * @return true if successfully locked, false otherwise.
     */
    static bool lock(void* ptr, size_t size) noexcept;

    /**
     * @brief Unlocks previously locked virtual memory pages.
     */
    static void unlock(void* ptr, size_t size) noexcept;
};

/**
 * @brief RAII buffer for sensitive byte arrays (keys, nonces, plaintext secrets).
 *        Automatically zeroes memory upon destruction and forbids copying to
 *        prevent unintentional copies lingering across the heap.
 */
class SecureBuffer {
public:
    SecureBuffer() = default;
    explicit SecureBuffer(size_t size);
    SecureBuffer(const uint8_t* data, size_t size);
    explicit SecureBuffer(std::span<const uint8_t> data);
    ~SecureBuffer();

    // Disable copy semantics to prevent secret duplication in memory
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    // Enable move semantics for zero-copy ownership transfer
    SecureBuffer(SecureBuffer&& other) noexcept;
    SecureBuffer& operator=(SecureBuffer&& other) noexcept;

    [[nodiscard]] uint8_t* data() noexcept { return data_.data(); }
    [[nodiscard]] const uint8_t* data() const noexcept { return data_.data(); }
    [[nodiscard]] size_t size() const noexcept { return data_.size(); }
    [[nodiscard]] bool empty() const noexcept { return data_.empty(); }

    [[nodiscard]] std::span<uint8_t> span() noexcept { return {data_.data(), data_.size()}; }
    [[nodiscard]] std::span<const uint8_t> span() const noexcept { return {data_.data(), data_.size()}; }

    void resize(size_t new_size);
    void clear() noexcept;

    uint8_t& operator[](size_t index) { return data_[index]; }
    const uint8_t& operator[](size_t index) const { return data_[index]; }

private:
    std::vector<uint8_t> data_;
    bool locked_{false};
};

/**
 * @brief RAII string container for sensitive text (master password, entry passwords).
 *        Guarantees zeroization upon destruction and suppresses copies.
 */
class SecureString {
public:
    SecureString() = default;
    explicit SecureString(std::string_view str);
    ~SecureString();

    SecureString(const SecureString&) = delete;
    SecureString& operator=(const SecureString&) = delete;

    SecureString(SecureString&& other) noexcept;
    SecureString& operator=(SecureString&& other) noexcept;

    [[nodiscard]] const char* c_str() const noexcept { return data_.c_str(); }
    [[nodiscard]] size_t length() const noexcept { return data_.length(); }
    [[nodiscard]] bool empty() const noexcept { return data_.empty(); }
    [[nodiscard]] std::string_view view() const noexcept { return data_; }

    void clear() noexcept;

private:
    std::string data_;
};

} // namespace pwdmgr::crypto
