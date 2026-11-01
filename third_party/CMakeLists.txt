# Third-party targets. Sources are vendored verbatim (see PIN.md); this file
# only provides build integration. Third-party code compiles with its own
# (relaxed) warning set — Secraxis code compiles with -Werror separately.
# (A2ONT is not third-party: it is built into secraxis_core from src/a2ont.)

# ---------------------------------------------------------------------------
# argon2 — PHC reference implementation, low-level context API.
# opt.c (SSE2+) on x86-64, ref.c elsewhere. Outputs are identical either way.
# ---------------------------------------------------------------------------
set(ARGON2_DIR ${CMAKE_CURRENT_SOURCE_DIR}/argon2)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "(x86_64|AMD64|amd64)")
  set(ARGON2_BACKEND ${ARGON2_DIR}/src/opt.c)
else()
  set(ARGON2_BACKEND ${ARGON2_DIR}/src/ref.c)
endif()

add_library(argon2 STATIC
  ${ARGON2_DIR}/src/argon2.c
  ${ARGON2_DIR}/src/core.c
  ${ARGON2_DIR}/src/encoding.c
  ${ARGON2_DIR}/src/thread.c
  ${ARGON2_DIR}/src/blake2/blake2b.c
  ${ARGON2_BACKEND}
)
target_include_directories(argon2 SYSTEM PUBLIC ${ARGON2_DIR}/include)
target_include_directories(argon2 PRIVATE ${ARGON2_DIR}/src)
set_target_properties(argon2 PROPERTIES POSITION_INDEPENDENT_CODE ON)
# libsodium also exports unprefixed blake2b_* symbols (for its own Argon2).
# Rename argon2's internal BLAKE2 symbols at compile time so both static
# libraries can be linked into one binary. Build-level only; sources verbatim.
target_compile_definitions(argon2 PRIVATE
  blake2b=sx_a2_blake2b
  blake2b_init=sx_a2_blake2b_init
  blake2b_init_key=sx_a2_blake2b_init_key
  blake2b_init_param=sx_a2_blake2b_init_param
  blake2b_update=sx_a2_blake2b_update
  blake2b_final=sx_a2_blake2b_final
  blake2b_long=sx_a2_blake2b_long
)
if(NOT WIN32)
  find_package(Threads REQUIRED)
  target_link_libraries(argon2 PUBLIC Threads::Threads)
endif()

# ---------------------------------------------------------------------------
# libsodium — imported. Windows: bundled official MinGW prebuilt (static).
# Linux: SECRAXIS_SODIUM_ROOT (libsodium 1.0.20 built from the pinned tarball,
# see MANUAL.md or remote/run_sanitizers.sh), else the system's (1.0.19+).
# ---------------------------------------------------------------------------
add_library(sodium STATIC IMPORTED GLOBAL)
if(WIN32)
  set(SODIUM_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/libsodium-win64)
  set_target_properties(sodium PROPERTIES
    IMPORTED_LOCATION ${SODIUM_ROOT}/lib/libsodium.a
    INTERFACE_INCLUDE_DIRECTORIES ${SODIUM_ROOT}/include
    INTERFACE_COMPILE_DEFINITIONS SODIUM_STATIC)
else()
  if(DEFINED SECRAXIS_SODIUM_ROOT)
    set(SODIUM_ROOT ${SECRAXIS_SODIUM_ROOT})
  else()
    set(SODIUM_ROOT /usr/local)
  endif()
  find_library(SODIUM_LIB NAMES libsodium.a sodium
               PATHS ${SODIUM_ROOT}/lib ${SODIUM_ROOT}/lib64 NO_DEFAULT_PATH)
  if(NOT SODIUM_LIB)
    find_library(SODIUM_LIB NAMES libsodium.a sodium REQUIRED)
  endif()
  find_path(SODIUM_INC sodium.h PATHS ${SODIUM_ROOT}/include NO_DEFAULT_PATH)
  if(NOT SODIUM_INC)
    find_path(SODIUM_INC sodium.h REQUIRED)
  endif()
  set_target_properties(sodium PROPERTIES
    IMPORTED_LOCATION ${SODIUM_LIB}
    INTERFACE_INCLUDE_DIRECTORIES ${SODIUM_INC})
endif()
