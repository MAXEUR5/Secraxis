/* OS CSPRNG backend (agenda 9.1): BCryptGenRandom / getrandom / arc4random_buf.
 * No deterministic RNG in production builds. */
#include <string.h>

#include "secraxis/a2ont.h"

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

int a2ont_rng_bytes(uint8_t *out, size_t len)
{
    NTSTATUS st = BCryptGenRandom(NULL, out, (ULONG)len,
                                  BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return st == STATUS_SUCCESS ? A2ONT_OK : A2ONT_ERR_RNG_FAILED;
}

const char *a2ont_rng_name(void)
{
    return "OS_CSPRNG(BCryptGenRandom)";
}

#elif defined(__APPLE__) || defined(__OpenBSD__) || defined(__FreeBSD__)
#include <stdlib.h>

int a2ont_rng_bytes(uint8_t *out, size_t len)
{
    arc4random_buf(out, len);
    return A2ONT_OK;
}

const char *a2ont_rng_name(void)
{
    return "OS_CSPRNG(arc4random_buf)";
}

#else /* Linux and other POSIX */
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/random.h>
#endif

static int dev_urandom(uint8_t *out, size_t len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
        return A2ONT_ERR_RNG_FAILED;
    while (len > 0) {
        ssize_t n = read(fd, out, len);
        if (n <= 0) {
            if (errno == EINTR)
                continue;
            close(fd);
            return A2ONT_ERR_RNG_FAILED;
        }
        out += (size_t)n;
        len -= (size_t)n;
    }
    close(fd);
    return A2ONT_OK;
}

int a2ont_rng_bytes(uint8_t *out, size_t len)
{
#if defined(__linux__)
    size_t done = 0;
    while (done < len) {
        ssize_t n = getrandom(out + done, len - done, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            if (errno == ENOSYS)
                return dev_urandom(out, len);
            return A2ONT_ERR_RNG_FAILED;
        }
        done += (size_t)n;
    }
    return A2ONT_OK;
#else
    return dev_urandom(out, len);
#endif
}

const char *a2ont_rng_name(void)
{
    return "OS_CSPRNG(getrandom//dev/urandom)";
}
#endif

int a2ont_rng_selftest(void)
{
    uint8_t a[32], b[32], zero[32];
    if (a2ont_rng_bytes(a, sizeof a) != A2ONT_OK)
        return 0;
    if (a2ont_rng_bytes(b, sizeof b) != A2ONT_OK)
        return 0;
    memset(zero, 0, sizeof zero);
    if (memcmp(a, b, sizeof a) == 0)
        return 0;
    if (memcmp(a, zero, sizeof a) == 0 || memcmp(b, zero, sizeof b) == 0)
        return 0;
    return 1;
}
