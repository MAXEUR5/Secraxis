cmake_minimum_required(VERSION 3.16)
project(secraxis-vault-manager VERSION 0.9.2 LANGUAGES C CXX)

# The version the program reports (--version, the start page) lives in
# version.h; a release must not ship with the two disagreeing.
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/include/secraxis/version.h" _sx_version_line
     REGEX "SECRAXIS_VERSION = \"")
string(REGEX MATCH "[0-9]+\\.[0-9]+\\.[0-9]+" _sx_version "${_sx_version_line}")
if(NOT _sx_version STREQUAL PROJECT_VERSION)
  message(FATAL_ERROR "version.h says ${_sx_version}, CMakeLists.txt says ${PROJECT_VERSION}")
endif()

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
# The public source release carries no development tree (tests/ and the fuzz
# targets): there the tests default to off and cannot be turned on.
set(_sx_dev_tree OFF)
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/CMakeLists.txt" AND
   EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/fuzz_targets/CMakeLists.txt")
  set(_sx_dev_tree ON)
endif()
option(SECRAXIS_BUILD_TESTS "Build unit/integration/vector tests" ${_sx_dev_tree})
option(SECRAXIS_SANITIZE "Build with ASan+UBSan (GCC/Clang)" OFF)
option(SECRAXIS_MSAN "Build with MemorySanitizer (clang only)" OFF)
option(SECRAXIS_TSAN "Build with ThreadSanitizer" OFF)
option(SECRAXIS_FUZZ "Build libFuzzer targets (clang only)" OFF)
option(SECRAXIS_FUZZ_STANDALONE "Build standalone mutational fuzz drivers" OFF)
option(SECRAXIS_WERROR "Treat warnings as errors for Secraxis code" ON)
if((SECRAXIS_BUILD_TESTS OR SECRAXIS_FUZZ OR SECRAXIS_FUZZ_STANDALONE) AND NOT _sx_dev_tree)
  message(FATAL_ERROR "Tests and fuzz targets need the development tree "
                      "(tests/, src/fuzz_targets/), which the source release does not include.")
endif()

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# ---------------------------------------------------------------------------
# Warning / hardening interface for Secraxis code (NOT third_party)
# ---------------------------------------------------------------------------
add_library(secraxis_flags INTERFACE)
if(MSVC)
  target_compile_options(secraxis_flags INTERFACE /W4 /permissive-)
  if(SECRAXIS_WERROR)
    target_compile_options(secraxis_flags INTERFACE /WX)
  endif()
else()
  target_compile_options(secraxis_flags INTERFACE
    -Wall -Wextra -Wshadow -Wconversion -Wno-sign-conversion
    -Wpointer-arith -Wcast-qual -Wformat=2 -Wundef
    -fno-strict-aliasing
    -fstack-protector-strong)
  if(SECRAXIS_WERROR)
    target_compile_options(secraxis_flags INTERFACE -Werror)
  endif()
  if(NOT WIN32)
    target_compile_options(secraxis_flags INTERFACE -D_FORTIFY_SOURCE=2)
  endif()
endif()

if(WIN32 AND NOT MSVC)
  # DEP + ASLR (+high entropy) for MinGW builds.
  add_link_options(-Wl,--nxcompat -Wl,--dynamicbase -Wl,--high-entropy-va)
  # The GCC runtime (libstdc++, libgcc, winpthread) linked in: the program
  # then imports only Windows' own DLLs. Otherwise it would not start where
  # MinGW is not installed, and Windows looks for those DLLs in the current
  # folder before PATH, where a planted one would run inside the program
  # that reads the master password.
  add_link_options(-static)
endif()

# Sanitizers apply globally (including third_party) so instrumented and
# uninstrumented code never mix.
if(SECRAXIS_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
  add_link_options(-fsanitize=address,undefined)
endif()
if(SECRAXIS_MSAN)
  add_compile_options(-fsanitize=memory -fsanitize-memory-track-origins -fno-omit-frame-pointer -g)
  add_link_options(-fsanitize=memory)
endif()
if(SECRAXIS_TSAN)
  add_compile_options(-fsanitize=thread -g)
  add_link_options(-fsanitize=thread)
endif()
# libFuzzer is guided by coverage: all code under test carries the counters,
# not only the target file (fuzz targets link -fsanitize=fuzzer themselves).
if(SECRAXIS_FUZZ)
  add_compile_options(-fsanitize=fuzzer-no-link)
endif()

add_subdirectory(third_party)

# ---------------------------------------------------------------------------
# A2ONT — the built-in pre-encryption transform (docs/A2ONT_INTEGRATION.md).
# Compiled straight into secraxis_core under the same warning/hardening flags
# as the rest of Secraxis. Absolute paths so tests/ can build the
# A2ONT_TEST_ONLY flavor (vector tests only) from the same sources.
# ---------------------------------------------------------------------------
set(SECRAXIS_A2ONT_SOURCES
  src/a2ont/keccak.c
  src/a2ont/encoding.c
  src/a2ont/wipe.c
  src/a2ont/rng.c
  src/a2ont/prg.c
  src/a2ont/uniform.c
  src/a2ont/gf2.c
  src/a2ont/symbol_core.c
  src/a2ont/permutation.c
  src/a2ont/bit_premix.c
  src/a2ont/ar32.c
  src/a2ont/mds.c
  src/a2ont/chains.c
  src/a2ont/profile.c
  src/a2ont/header.c
  src/a2ont/a2ont_core.c
)
list(TRANSFORM SECRAXIS_A2ONT_SOURCES PREPEND ${CMAKE_CURRENT_SOURCE_DIR}/)

# ---------------------------------------------------------------------------
# secraxis_core — everything except main() and fuzz targets
# ---------------------------------------------------------------------------
# Grown phase by phase; every milestone must build green.
set(SECRAXIS_CORE_SOURCES
  src/platform/secure_buffer.cpp
  src/platform/hardening.cpp
  src/platform/fs_atomic.cpp
  src/platform/prompt.cpp
  src/crypto/crypto.cpp
  src/crypto/entropy.cpp
  src/crypto/aead.cpp
  src/crypto/kdf.cpp
  src/crypto/key_hierarchy.cpp
  src/seis_format/seis_header.cpp
  src/seis_format/padding.cpp
  src/seis_format/seis_container.cpp
  src/seis_format/canonical_codec.cpp
  src/runtime/runtime_store.cpp
  src/vault/vault_session.cpp
  src/export_import/export_import.cpp
  ${SECRAXIS_A2ONT_SOURCES}
)

add_library(secraxis_core STATIC ${SECRAXIS_CORE_SOURCES})
target_include_directories(secraxis_core PUBLIC include PRIVATE src)
target_link_libraries(secraxis_core PUBLIC secraxis_flags argon2 sodium)
if(WIN32)
  target_link_libraries(secraxis_core PUBLIC bcrypt)
endif()

# TEST BUILDS ONLY: registers KDF profile id 999 (16 MiB, t=1, p=1) so the
# container tamper-matrix tests run in milliseconds instead of minutes of
# Argon2. Release builds are made with SECRAXIS_BUILD_TESTS=OFF and therefore
# NEVER contain this profile; production parsers reject id 999.
# (Release checklist: `strings` the release binary for "SECRAXIS-WEAK-KDF".)
if(SECRAXIS_BUILD_TESTS OR SECRAXIS_FUZZ OR SECRAXIS_FUZZ_STANDALONE)
  target_compile_definitions(secraxis_core PRIVATE SECRAXIS_TEST_WEAK_KDF)
endif()

# AES-256-GCM-SIV (SEIS-AEAD-2, the default vault profile) needs a pinned
# libcrypto. Two validated backends behind the same aead_seal/aead_open
# abstraction (identical RFC 8452 wire format, same KAT gate):
#   * OpenSSL >= 3.2  (DEFAULT backend, owner preference):
#       -DSECRAXIS_OPENSSL_ROOT=<prefix with include/ and lib/libcrypto.a>
#       (built minimal: no-shared no-apps no-engine no-module
#        no-autoload-config — see scripts/build_openssl.sh)
#   * AWS-LC (validated alternative):
#       -DSECRAXIS_AWSLC_ROOT=<source tree or install prefix>
# Providing neither yields a portable build: only SEIS-AEAD-1 (XChaCha20-
# Poly1305); GCM-SIV vaults are then rejected as unsupported, never
# downgraded. Providing both is an error — one backend per build.
if(DEFINED SECRAXIS_OPENSSL_ROOT AND DEFINED SECRAXIS_AWSLC_ROOT)
  message(FATAL_ERROR "Select ONE GCM-SIV backend: SECRAXIS_OPENSSL_ROOT or SECRAXIS_AWSLC_ROOT")
endif()

if(DEFINED SECRAXIS_OPENSSL_ROOT)
  target_compile_definitions(secraxis_core PUBLIC SECRAXIS_HAVE_GCM_SIV SECRAXIS_GCM_SIV_OPENSSL)
  target_include_directories(secraxis_core SYSTEM PUBLIC ${SECRAXIS_OPENSSL_ROOT}/include)
  find_library(SECRAXIS_LIBCRYPTO NAMES libcrypto.a crypto
               PATHS ${SECRAXIS_OPENSSL_ROOT}/lib ${SECRAXIS_OPENSSL_ROOT}/lib64
               NO_DEFAULT_PATH REQUIRED)
  target_link_libraries(secraxis_core PUBLIC ${SECRAXIS_LIBCRYPTO})
  if(WIN32)
    # OpenSSL libcrypto on Windows: winsock + CryptoAPI cert store + BCrypt RNG
    target_link_libraries(secraxis_core PUBLIC ws2_32 crypt32 bcrypt)
  endif()
elseif(DEFINED SECRAXIS_AWSLC_ROOT)
  target_compile_definitions(secraxis_core PUBLIC SECRAXIS_HAVE_GCM_SIV SECRAXIS_GCM_SIV_AWSLC)
  target_include_directories(secraxis_core SYSTEM PUBLIC ${SECRAXIS_AWSLC_ROOT}/include)
  find_library(SECRAXIS_LIBCRYPTO NAMES libcrypto.a crypto
               PATHS ${SECRAXIS_AWSLC_ROOT}/build/crypto
                     ${SECRAXIS_AWSLC_ROOT}/lib ${SECRAXIS_AWSLC_ROOT}/lib64
               NO_DEFAULT_PATH REQUIRED)
  target_link_libraries(secraxis_core PUBLIC ${SECRAXIS_LIBCRYPTO})
  if(WIN32)
    target_link_libraries(secraxis_core PUBLIC ws2_32)
  endif()
endif()

# ---------------------------------------------------------------------------
# TUI library + application binary
# ---------------------------------------------------------------------------
add_library(secraxis_tui STATIC
  src/tui/tui_core.cpp
  src/tui/tui_text.cpp
  src/tui/tui_input.cpp
  src/tui/canvas.cpp
  src/tui/screen.cpp
  src/tui/terminal.cpp
  src/tui/ui_kit.cpp
  src/tui/renderer.cpp
  src/tui/launcher.cpp
  src/tui/launcher_view.cpp
  src/tui/history.cpp
  src/tui/settings.cpp
  src/tui/fs_dir.cpp
  src/tui/clipboard.cpp
  src/tui/app.cpp
)
target_include_directories(secraxis_tui PUBLIC include PRIVATE src)
target_link_libraries(secraxis_tui PUBLIC secraxis_core)
if(WIN32)
  target_link_libraries(secraxis_tui PUBLIC shell32)
endif()
if(NOT WIN32)
  find_package(Threads REQUIRED)
  target_link_libraries(secraxis_tui PUBLIC Threads::Threads)
endif()

add_executable(secraxis src/main.cpp src/cli.cpp)
target_link_libraries(secraxis PRIVATE secraxis_tui)
if(WIN32)
  target_link_libraries(secraxis PRIVATE user32 shell32)
  # The program icon (src/secraxis.rc), where a resource compiler is found.
  include(CheckLanguage)
  check_language(RC)
  if(CMAKE_RC_COMPILER)
    enable_language(RC)
    target_sources(secraxis PRIVATE src/secraxis.rc)
  endif()
endif()

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if(SECRAXIS_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

# Fuzz targets: libFuzzer or standalone builds, and with the tests (where
# they replay the committed corpora, tests/fuzz/corpus).
if(SECRAXIS_FUZZ OR SECRAXIS_FUZZ_STANDALONE OR SECRAXIS_BUILD_TESTS)
  add_subdirectory(src/fuzz_targets)
endif()
