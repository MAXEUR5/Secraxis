#include "secraxis/hardening.h"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <sys/prctl.h>
#include <sys/resource.h>
#endif

namespace secraxis {

HardeningReport apply_process_hardening() noexcept {
    HardeningReport r;
#if defined(_WIN32)
    // Suppress Windows Error Reporting UI/dump generation for this process.
    // (Full dump policy is machine-wide; this is the per-process best effort.)
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    r.core_dumps_disabled = 1;
    // DEP/ASLR/high-entropy VA are set at link time (--nxcompat --dynamicbase
    // --high-entropy-va); record that the build carries them.
    r.dep_aslr = 1;
    // Libraries load from System32 only, never from the current folder or
    // PATH, where a planted DLL would run inside the program that reads the
    // master password. (The program itself imports only Windows DLLs: the
    // GCC runtime is linked in.) Looked up at run time: Windows 8+ / 7 with
    // KB2533623.
    SetDllDirectoryW(L"");
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    using SetDirsFn = BOOL(WINAPI*)(DWORD);
    if (auto set_dirs = reinterpret_cast<SetDirsFn>(
            reinterpret_cast<void*>(GetProcAddress(k32, "SetDefaultDllDirectories"))))
        r.dll_system32_only = set_dirs(0x00000800 /* LOAD_LIBRARY_SEARCH_SYSTEM32 */) ? 1 : 0;
    // No images from remote shares or low-integrity files, System32 copies
    // preferred; no legacy extension-point DLLs (AppInit_DLLs, Winsock LSPs,
    // global hooks of old IMEs) loaded into this process.
    using MitigationFn = BOOL(WINAPI*)(int, PVOID, SIZE_T);
    if (auto set_policy = reinterpret_cast<MitigationFn>(
            reinterpret_cast<void*>(GetProcAddress(k32, "SetProcessMitigationPolicy")))) {
        DWORD image = 0x1 | 0x2 | 0x4;  // NoRemoteImages, NoLowMandatoryLabelImages,
                                        // PreferSystem32Images
        DWORD ext = 0x1;                // DisableExtensionPoints
        const bool a = set_policy(10 /* ProcessImageLoadPolicy */, &image, sizeof(image)) != 0;
        const bool b =
            set_policy(6 /* ProcessExtensionPointDisablePolicy */, &ext, sizeof(ext)) != 0;
        r.image_load_policy = a && b ? 1 : 0;
    }
    // VirtualLock locks no more than the minimum working set allows: by
    // default 200 KB, about 44 pages, so most SecureBuffers stayed unlocked
    // and could be paged out. Raise the minimum to 64 MiB, room for the
    // secure memory of about 8,000 entries (two locked pages each); the
    // maximum stays a soft limit. If Windows refuses, locking stays as it was.
    // (secure_memory_is_locked_beyond_the_default_quota checks the effect.)
    HANDLE self = GetCurrentProcess();
    SIZE_T ws_min = 0, ws_max = 0;
    const SIZE_T want = SIZE_T{64} << 20;
    const SIZE_T want_max = want + (SIZE_T{64} << 20);
    if (GetProcessWorkingSetSize(self, &ws_min, &ws_max) && ws_min < want)
        SetProcessWorkingSetSize(self, want, ws_max > want_max ? ws_max : want_max);
#else
    struct rlimit rl;
    rl.rlim_cur = 0;
    rl.rlim_max = 0;
    if (setrlimit(RLIMIT_CORE, &rl) == 0) r.core_dumps_disabled = 1;
#if defined(PR_SET_DUMPABLE)
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0) r.non_dumpable = 1;
#endif
#if defined(PR_SET_NO_NEW_PRIVS)
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0) r.no_new_privs = 1;
#endif
#endif
    return r;
}

}  // namespace secraxis
