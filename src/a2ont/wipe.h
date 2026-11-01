#ifndef A2ONT_WIPE_H
#define A2ONT_WIPE_H

#include <stddef.h>

/* Guaranteed-not-elided memory wipe (SecureZeroMemory / explicit_bzero /
 * volatile fallback). */
void a2ont_secure_wipe_impl(void *buf, size_t len);

#endif
