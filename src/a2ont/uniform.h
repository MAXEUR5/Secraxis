/* Unbiased uniform sampling from a PRG stream (spec 2.4). */
#ifndef A2ONT_UNIFORM_H
#define A2ONT_UNIFORM_H

#include <stdint.h>

#include "prg.h"

/* Uniform integer in [0, n) — rejection sampling, LE interpretation. n>=1. */
uint64_t a2ont_uniform_int(a2ont_prg *prg, uint64_t n);

#endif
