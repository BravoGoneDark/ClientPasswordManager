#include "crypto/secure_memory.hpp"
#include <algorithm>

#if __has_include(<sodium.h>)
#include <sodium.h>
#define HAS_SODIUM 1
#else
#define HAS_SODIUM 0
#endif

namespace pwdmgr::crypto {

void SecureMemory::zero(void* ptr, size_t size) noexcept {
    if (!ptr || size == 0) return;

#if HAS_SODIUM
    sodium_memzero(ptr, size);
#elif defined(_WIN32)
    SecureZeroMemory(ptr, size);
#else
    // Volatile pointer loop to prevent compiler dead-code elimination
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    while (size--) {
        *p++ = 0;
    }
#endif
}

bool SecureMemory::lock(void* ptr, size_t size) noexcept {
    if (!ptr || size == 0) return false;
#ifdef _WIN32
    return VirtualLock(ptr, size) != 0;
#else
    return false;
#endif
}

void SecureMemory::unlock(void* ptr, size_t size) noexcept {
    if (!ptr || size == 0) return;
#ifdef _WIN32
    VirtualUnlock(ptr, size);
#endif
}

// ============================================================================
// SecureBuffer Implementation
// ============================================================================

SecureBuffer::SecureBuffer(size_t size) : data_(size, 0) {
    if (!data_.empty()) {
        locked_ = SecureMemory::lock(data_.data(), data_.size());
    }
}

SecureBuffer::SecureBuffer(const uint8_t* data, size_t size) : data_(data, data + size) {
    if (!data_.empty()) {
        locked_ = SecureMemory::lock(data_.data(), data_.size());
    }
}

SecureBuffer::SecureBuffer(std::span<const uint8_t> data)
    : data_(data.begin(), data.end()) {
    if (!data_.empty()) {
        locked_ = SecureMemory::lock(data_.data(), data_.size());
    }
}

SecureBuffer::~SecureBuffer() {
    clear();
}

SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept
    : data_(std::move(other.data_)), locked_(other.locked_) {
    other.locked_ = false;
}

SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
    if (this != &other) {
        clear();
        data_ = std::move(other.data_);
        locked_ = other.locked_;
        other.locked_ = false;
    }
    return *this;
}

void SecureBuffer::resize(size_t new_size) {
    if (new_size == data_.size()) return;

    if (locked_ && !data_.empty()) {
        SecureMemory::unlock(data_.data(), data_.size());
        locked_ = false;
    }

    data_.resize(new_size, 0);

    if (!data_.empty()) {
        locked_ = SecureMemory::lock(data_.data(), data_.size());
    }
}

void SecureBuffer::clear() noexcept {
    if (!data_.empty()) {
        SecureMemory::zero(data_.data(), data_.size());
        if (locked_) {
            SecureMemory::unlock(data_.data(), data_.size());
            locked_ = false;
        }
        data_.clear();
    }
}

// ============================================================================
// SecureString Implementation
// ============================================================================

SecureString::SecureString(std::string_view str) : data_(str) {}

SecureString::~SecureString() {
    clear();
}

SecureString::SecureString(SecureString&& other) noexcept
    : data_(std::move(other.data_)) {}

SecureString& SecureString::operator=(SecureString&& other) noexcept {
    if (this != &other) {
        clear();
        data_ = std::move(other.data_);
    }
    return *this;
}

void SecureString::clear() noexcept {
    if (!data_.empty()) {
        SecureMemory::zero(data_.data(), data_.size());
        data_.clear();
    }
}

} // namespace pwdmgr::crypto
