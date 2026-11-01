#include <string.h>

#include "secraxis/a2ont.h"
#include "transforms.h"
#include "prg.h"
#include "wipe.h"

#define CHAIN_CHUNK 4096u

/* Forward chain: F[0]=S[0]+C[0]; F[i]=S[i]+F[i-1]+C[i]  (mod 256 or XOR).
 * Inverse: S[0]=F[0]-C[0]; S[i]=F[i]-F[i-1]-C[i]. Streamed in chunks. */
int a2ont_chain_forward(uint8_t *s, size_t L, const uint8_t *seed, uint64_t t,
                        const a2ont_iprofile *ip, int inverse)
{
    a2ont_prg prg;
    uint8_t cbuf[CHAIN_CHUNK];
    size_t done = 0;
    uint8_t prev = 0;
    if (L == 0)
        return A2ONT_OK;
    a2ont_prg_open(&prg, seed, ip->seed_len_bytes, "fwd-chain", t, L, ip, NULL, 0);
    while (done < L) {
        size_t n = L - done < CHAIN_CHUNK ? L - done : CHAIN_CHUNK;
        size_t i;
        a2ont_prg_read(&prg, cbuf, n);
        if (!inverse) {
            if (ip->chain_xor)
                for (i = 0; i < n; i++)
                    prev = s[done + i] = (uint8_t)(s[done + i] ^ prev ^ cbuf[i]);
            else
                for (i = 0; i < n; i++)
                    prev = s[done + i] = (uint8_t)(s[done + i] + prev + cbuf[i]);
        } else {
            if (ip->chain_xor)
                for (i = 0; i < n; i++) {
                    uint8_t f = s[done + i];
                    s[done + i] = (uint8_t)(f ^ prev ^ cbuf[i]);
                    prev = f;
                }
            else
                for (i = 0; i < n; i++) {
                    uint8_t f = s[done + i];
                    s[done + i] = (uint8_t)(f - prev - cbuf[i]);
                    prev = f;
                }
        }
        done += n;
    }
    a2ont_prg_close(&prg);
    a2ont_secure_wipe_impl(cbuf, sizeof cbuf);
    return A2ONT_OK;
}

/* Backward chain runs from the end; stream the constants into a full-size
 * buffer would cost L bytes, so instead we squeeze the whole "bwd-chain"
 * stream in chunks into a heap buffer only when L is large. To stay
 * low-copy we read the stream once into chunk windows from the END by
 * buffering: the XOF only squeezes forward, so we materialize the constant
 * stream (heap) and then walk backwards. */
#include <stdlib.h>

int a2ont_chain_backward(uint8_t *s, size_t L, const uint8_t *seed, uint64_t t,
                         const a2ont_iprofile *ip, int inverse)
{
    a2ont_prg prg;
    uint8_t *cb;
    size_t i;
    uint8_t nxt = 0;
    if (L == 0)
        return A2ONT_OK;
    cb = (uint8_t *)malloc(L);
    if (cb == NULL)
        return A2ONT_ERR_ALLOCATION_FAILED;
    a2ont_prg_open(&prg, seed, ip->seed_len_bytes, "bwd-chain", t, L, ip, NULL, 0);
    a2ont_prg_read(&prg, cb, L);
    a2ont_prg_close(&prg);
    if (!inverse) {
        if (ip->chain_xor)
            for (i = L; i-- > 0;)
                nxt = s[i] = (uint8_t)(s[i] ^ nxt ^ cb[i]);
        else
            for (i = L; i-- > 0;)
                nxt = s[i] = (uint8_t)(s[i] + nxt + cb[i]);
    } else {
        if (ip->chain_xor)
            for (i = L; i-- > 0;) {
                uint8_t v = s[i];
                s[i] = (uint8_t)(v ^ nxt ^ cb[i]);
                nxt = v;
            }
        else
            for (i = L; i-- > 0;) {
                uint8_t v = s[i];
                s[i] = (uint8_t)(v - nxt - cb[i]);
                nxt = v;
            }
    }
    a2ont_secure_wipe_impl(cb, L);
    free(cb);
    return A2ONT_OK;
}

int a2ont_xor_mask(uint8_t *s, size_t L, const uint8_t *seed, uint64_t t,
                   const a2ont_iprofile *ip)
{
    a2ont_prg prg;
    uint8_t mbuf[CHAIN_CHUNK];
    size_t done = 0;
    if (L == 0)
        return A2ONT_OK;
    a2ont_prg_open(&prg, seed, ip->seed_len_bytes, "mask", t, L, ip, NULL, 0);
    while (done < L) {
        size_t n = L - done < CHAIN_CHUNK ? L - done : CHAIN_CHUNK;
        size_t i;
        a2ont_prg_read(&prg, mbuf, n);
        for (i = 0; i < n; i++)
            s[done + i] ^= mbuf[i];
        done += n;
    }
    a2ont_prg_close(&prg);
    a2ont_secure_wipe_impl(mbuf, sizeof mbuf);
    return A2ONT_OK;
}
