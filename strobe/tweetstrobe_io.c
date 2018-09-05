/**
 * @cond internal
 * @file strobe.c
 * @copyright
 *   Copyright (c) 2015-2016 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief Strobe protocol code.
 */

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <limits.h> /* for INT_MAX */
#include <stdbool.h>

#include <stdio.h> // to delete

#include "tweetstrobe_io.h"

/* Sets the security level at 128 bits (but this holds even
 * when the attacker has lots of data).
 */
#define CAPACITY_BITS (2*STROBE_INTEROP_SECURITY_BITS)

/* Internal rate is 2 bytes less than sponge's "rate" */
#define PAD_BYTES 2
#define RATE_INNER ((25*sizeof(kword_t)-CAPACITY_BITS/8))
#define RATE (RATE_INNER-PAD_BYTES)

/* Pull in a Keccak-F implementation.  Use the target-specific
 * asm one if available.
 */
#include "keccak_f.c.inc"

/* These padding bytes are applied before F.  They are
 * required for parseability.  Their values are chosen
 * for compatibilty with cSHAKE.
 */
#define SHAKE_XOR_RATE 0x80
#define SHAKE_XOR_MARK 0x04

#ifndef MIN
#define MIN(x,y) (((x)<(y)) ? (x) : (y))
#endif


static void printState(strobe_t strobe) {
    for(size_t i = 0; i < sizeof(strobe->state.b); i++) {
        printf("%02x", strobe->state.b[i]);
    }
    printf("\n");
}

/* Mark current position and state, and run F.
 * Should be compatible with CSHAKE.
 */
static void _run_f (strobe_s *strobe, unsigned int p) {
    strobe->state.b[p] ^= strobe->pos_begin;
    strobe->pos_begin = 0;
    strobe->state.b[p+1] ^= SHAKE_XOR_MARK;
    strobe->state.b[RATE+1] ^= SHAKE_XOR_RATE;
    keccak_f(&strobe->state);
}

/* Place a "mark" in the hash, which is distinct from the effect of writing any byte
 * into the hash.  Then write the new mode into the hash.
 */
static inline void _begin_op(strobe_s *strobe, unsigned int * pptr, uint8_t flags) {
    unsigned int p = *pptr;

    /* This flag (in the param flags byte) indicates that the
     * object's role (as initiator or responder) has already
     * been determined.
     */
    const uint8_t FLAG_HAVE_ROLE = 1<<2;

    /* Mark the state */
    strobe->state.b[p++] ^= strobe->pos_begin;
    strobe->pos_begin = p;
    if (p >= RATE) { _run_f(strobe,p); p = 0; }

    /* Adjust the direction based on transport */
    if (flags & FLAG_T) {
        if (!(strobe->flags & FLAG_HAVE_ROLE)) {
            /* Set who is initiator and who is responder */
            strobe->flags |= FLAG_HAVE_ROLE | (flags & FLAG_I);
        }
        strobe->state.b[p] ^= strobe->flags & FLAG_I;
    }

    /* Absorb the rest of the mode marker */
    strobe->state.b[p++] ^= flags;
    uint8_t flags_that_cause_runf = FLAG_C;
    if (p >= RATE || (flags & flags_that_cause_runf)) { _run_f(strobe,p); p = 0; }
    *pptr = p;

    printf("==DEBUG ULTIME===");
    printState(strobe);
}

/* The core duplex mode */
static ssize_t _strobe_duplex (
    strobe_s *strobe,
    flags_t flags,
    uint8_t *inside,
    ssize_t len,
    bool more
) { 
    /* Sanity check */
    assert(strobe->position < RATE);

    if (len < 0) {
        assert(false);
        /* In production mode, no assert, but at least signal an error */
        return -1;
    }

    ssize_t len2 = len, ret = 0;
    uint8_t cumul = 0;
    uint8_t s2s = -1;
    uint8_t s2o = (flags & FLAG_C) ? -1 : 0;
    if ((flags & FLAG_I) || !(flags & FLAG_T)) s2s ^= s2o; // duplex <-> unduplex

    unsigned int p = strobe->position;
    if (!more)
    {
        /* Mark the beginning of the operation in the strobe state */
        _begin_op(strobe, &p, flags);
    }

    /* Figure out where to write input and output */
    const uint8_t *in = NULL;
    uint8_t *out = NULL;
    ssize_t avail = 0;

    if (!(flags & FLAG_A)) {
        inside = NULL;
    }

    if (flags & FLAG_I) {
        out = inside;
    } else {
        in = inside;
    }

    // 
    // do the thing
    // 
    while (len > 0) {
        /* First iteration will just skip to read section ... */
        len -= avail;

        for (; avail; avail--) {
            assert (p < RATE);    
            uint8_t s = strobe->state.b[p], i = in ? *in++ : 0, o;

            o = i ^ (s&s2o);
            strobe->state.b[p++] = i ^ (s & s2s);
            cumul |= o;
            if (out) *out++ = o;

            if (p >= RATE) {
                _run_f(strobe,p);
                p = 0;
            }
        }

        /* Get more data */
        if (strobe->io == NULL || !(flags & FLAG_T)) {
            /* Nothing to write; leave output as NULL */
            avail = len;
        } else if ((flags & FLAG_I) && len > 0) {
            /* Read from wire */
            avail = strobe->io->read(&strobe->io_ctx, &in, len);
        } else {
            /* Write to wire.  On the last iteration, len=0. */
            avail = strobe->io->write(&strobe->io_ctx, &out, len);
        }

        if (avail < 0) {
            /* IO fail! */
            strobe->position = p;
            return -1;
        } else if (avail > len) {
            avail = len;
        }
    }

    if ((flags & (0xF | FLAG_I)) == (TYPE_MAC | FLAG_I)) {
        /* Check MAC */
        ret = cumul ? -1 : len2;
    } else {
        ret = len2;
    }

    strobe->position = p;
    return ret;
}

/* Outer duplex mode: this one handles control words and reading/writing lengths. */
ssize_t strobe_operate (
    strobe_s *__restrict__ strobe,
    uint8_t flags,
    uint8_t *inside,
    size_t len,
    bool more
) {
    return _strobe_duplex(strobe, flags, inside, len, more);
}

static ssize_t cb_buffer_write(strobe_io_ctx_s *ctx, uint8_t **buffer, ssize_t size) {
    uint8_t *a = ctx->a, *b = ctx->b;
    ssize_t avail = b-a;
    if (size < 0 || size > avail) return -1;
    ctx->a = a+size;
    *buffer = a;
    return avail; // left in the buffer to write
}

static ssize_t cb_buffer_dont_write(strobe_io_ctx_s *ctx, uint8_t **buffer, ssize_t size) {
    (void)ctx;
    *buffer = NULL;
    if (size) return -1;
    return 0;
}

const strobe_io_callbacks_s strobe_io_cb_buffer = {
    (ssize_t (*)(strobe_io_ctx_s *, const uint8_t **, ssize_t))cb_buffer_write, cb_buffer_write
};
const strobe_io_callbacks_s strobe_io_cb_const_buffer = {
    (ssize_t (*)(strobe_io_ctx_s *, const uint8_t **, ssize_t))cb_buffer_write, cb_buffer_dont_write
};

void strobe_init (
    struct strobe_s *__restrict__ strobe,
    const uint8_t *description,
    size_t desclen
) {
    const uint8_t proto[18] = {
        1,RATE+PAD_BYTES,
        1,0, /* Empty NIST perso string */
        1,12*8, /* 12 = strlen("STROBEvX.Y.Z") */
        'S','T','R','O','B','E',
        'v',
        '0'+STROBE_INTEROP_V_MAJOR,'.',
        '0'+STROBE_INTEROP_V_MINOR,'.',
        '0'+STROBE_INTEROP_V_PATCH,
        /* Rest is 0s, which is already there because we memset it */
    };
    memset(strobe,0,sizeof(*strobe));
    memcpy(strobe,proto,sizeof(proto));
    keccak_f(&strobe->state);

    _strobe_duplex(strobe,FLAG_A|FLAG_M,(uint8_t*)description,desclen, false);
    printState(strobe);
}


