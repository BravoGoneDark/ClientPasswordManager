cmake_minimum_required(VERSION 3.20)
project(ClientPasswordManager VERSION 1.0.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Export compile commands for IDE tooling (clangd, VS Code, etc.)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ==============================================================================
# Security & Hardening Compiler Flags (CyberSecurity Baseline)
# ==============================================================================
if (MSVC)
    message(STATUS "Configuring MSVC Security & Hardening Flags")
    add_compile_options(
        /W4                   # Warning Level 4 (rigorous static warnings)
        /permissive-          # Strict C++ standard conformance
        /utf-8                # Force UTF-8 character encoding
        /GS                   # Buffer Security Check (Stack Canary defense)
        /sdl                  # Enable Additional Security Development Lifecycle checks
        /guard:cf             # Control Flow Guard (mitigates ROP/control flow hijacking)
    )
    # Linker security flags
    add_link_options(
        /DYNAMICBASE          # ASLR: Address Space Layout Randomization
        /NXCOMPAT             # DEP: Data Execution Prevention (no code execution on stack/heap)
        /HIGHENTROPYVA        # 64-bit ASLR high entropy address space
    )
else()
    # Clang / GCC flags for future cross-platform builds
    add_compile_options(
        -Wall -Wextra -Wpedantic
        -fstack-protector-strong
        -D_FORTIFY_SOURCE=2
        -fPIE
    )
    add_link_options(-pie -Wl,-z,relro,-z,now)
endif()

# ==============================================================================
# External Dependencies (FetchContent / Submodules)
# ==============================================================================
include(FetchContent)

# 1. nlohmann/json (Header-only modern JSON library)
FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG        v3.11.3
)
FetchContent_MakeAvailable(nlohmann_json)

# 2. Libsodium (Cryptographic Engine)
# Look for local precompiled libsodium in deps/libsodium or system path
find_path(SODIUM_INCLUDE_DIR sodium.h PATHS "${CMAKE_CURRENT_SOURCE_DIR}/deps/libsodium/include")
find_library(SODIUM_LIBRARY NAMES sodium libsodium PATHS "${CMAKE_CURRENT_SOURCE_DIR}/deps/libsodium/lib")

if (SODIUM_INCLUDE_DIR AND SODIUM_LIBRARY)
    message(STATUS "Found Libsodium: ${SODIUM_LIBRARY}")
    add_library(sodium_imported UNKNOWN IMPORTED)
    set_target_properties(sodium_imported PROPERTIES
        IMPORTED_LOCATION "${SODIUM_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${SODIUM_INCLUDE_DIR}"
    )
else()
    message(WARNING "Libsodium not found in deps/libsodium. Please configure deps/libsodium or install via vcpkg.")
endif()

# ==============================================================================
# Core Library
# ==============================================================================
set(CORE_SOURCES
    src/crypto/secure_memory.cpp
    src/crypto/random.cpp
    src/crypto/kdf.cpp
    src/crypto/cipher.cpp
    src/core/uuid.cpp
    src/core/credential.cpp
    src/core/vault.cpp
    src/storage/vault_file.cpp
)

add_library(pwdmgr_core STATIC ${CORE_SOURCES})

target_include_directories(pwdmgr_core PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/deps"
)

if (TARGET nlohmann_json::nlohmann_json)
    target_link_libraries(pwdmgr_core PUBLIC nlohmann_json::nlohmann_json)
endif()

if (TARGET sodium_imported)
    target_link_libraries(pwdmgr_core PUBLIC sodium_imported)
endif()

# ==============================================================================
# Main CLI Executable
# ==============================================================================
add_executable(ClientPasswordManager src/main.cpp)
target_link_libraries(ClientPasswordManager PRIVATE pwdmgr_core)

# ==============================================================================
# Test Executables
# ==============================================================================
add_executable(run_crypto_tests tests/test_crypto.cpp)
target_link_libraries(run_crypto_tests PRIVATE pwdmgr_core)

add_executable(run_vault_tests tests/test_vault.cpp)
target_link_libraries(run_vault_tests PRIVATE pwdmgr_core)

add_executable(run_storage_tests tests/test_storage.cpp)
target_link_libraries(run_storage_tests PRIVATE pwdmgr_core)
