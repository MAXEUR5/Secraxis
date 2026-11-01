#include "wipe.h"

#if defined(_WIN32)
#include <windows.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
#include <string.h>
#include <strings.h>
#else
#define _DEFAULT_SOURCE 1
#include <string.h>
#endif

void a2ont_secure_wipe_impl(void *buf, size_t len)
{
    if (buf == NULL || len == 0)
        return;
#if defined(_WIN32)
    SecureZeroMemory(buf, len);
#elif defined(__OpenBSD__) || defined(__FreeBSD__) || \
    (defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25)))
    explicit_bzero(buf, len);
#else
    {
        volatile unsigned char *p = (volatile unsigned char *)buf;
        size_t i;
        for (i = 0; i < len; i++)
            p[i] = 0;
    }
#endif
}
