// hardening.h — process-level exposure reduction (agenda §13.3).
//
// Applied once at startup, before any secret is read. Every measure is
// best-effort: a step that fails is skipped (the report records it), never
// fatal, never logged. On Windows the minimum working set is also raised so
// that VirtualLock can lock secure memory (hardening.cpp).
#ifndef SECRAXIS_HARDENING_H
#define SECRAXIS_HARDENING_H

#include <cstdint>

namespace secraxis {

struct HardeningReport {
    // Each flag: 1 = applied, 0 = unavailable/failed (non-secret).
    uint8_t core_dumps_disabled = 0;   // RLIMIT_CORE=0 / WER opt-out
    uint8_t non_dumpable = 0;          // PR_SET_DUMPABLE=0 (Linux)
    uint8_t no_new_privs = 0;          // PR_SET_NO_NEW_PRIVS (Linux)
    uint8_t dep_aslr = 0;              // compile/link-time on Windows; probed
    uint8_t dll_system32_only = 0;     // Windows: libraries load from System32 only
    uint8_t image_load_policy = 0;     // Windows: no remote / low-integrity images,
                                       // no legacy extension-point DLLs
};

// Apply all platform hardening measures. Never throws, never logs secrets.
HardeningReport apply_process_hardening() noexcept;

}  // namespace secraxis

#endif  // SECRAXIS_HARDENING_H
