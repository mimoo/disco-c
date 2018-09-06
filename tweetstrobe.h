/**
 * @file strobe.h
 * @copyright
 *   Copyright (c) 2015-2016 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief Strobe lite protocol instances.
 */
#pragma once

/* TODO: Implement state compaction, particularly for PRNG state */
/* TODO: Test this against the Python reference. */

#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <stdbool.h>

#include "strobe_config.h"

// Size of the Keccak permutation
#if STROBE_INTEROP_F_BITS == 1600
#  define kword_t uint64_t
#elif STROBE_INTEROP_F_BITS == 800
#  define kword_t uint32_t
#elif STROBE_INTEROP_F_BITS == 400
#  define kword_t uint16_t
#else
#  error "Strobe supports only Keccak-F{400,800,1600}"
#endif

/** Keccak's domain: 25 words of size b/25, or b/8 bytes. */
typedef union {
    kword_t w[25];
    uint8_t b[25*sizeof(kword_t)/sizeof(uint8_t)];
} kdomain_s;

/** The main strobe state object. */
typedef struct strobe_s {
    kdomain_s state;
    uint8_t   position;
    uint8_t   pos_begin;
    uint8_t   flags;
    uint8_t   initiator;
} strobe_s, strobe_t[1];

/* Initialize a Strobe object with a protocol name */
void strobe_init (
    struct strobe_s *__restrict__ strobe,
    const uint8_t *protocol_name,
    size_t desclen
);

/* Operate on the Strobe object */
ssize_t strobe_operate (
    struct strobe_s *__restrict__ strobe,
    uint8_t control_flags,
    uint8_t *buffer,
    size_t buffer_len,
    bool more
);

/* Flags as defined in the paper */
#define FLAG_I (1<<0) /**< Inbound */
#define FLAG_A (1<<1) /**< Has application-side data (eg, not a MAC) */
#define FLAG_C (1<<2) /**< Uses encryption or rekeying. */
#define FLAG_T (1<<3) /**< Send or receive data via transport */
#define FLAG_M (1<<4) /**< Operation carries metadata. */

/* Operation types as defined in the paper */
#define TYPE_AD      FLAG_A /**< Context data, not sent to trensport */
#define TYPE_KEY    (FLAG_A | FLAG_C) /**< Symmetric key, not sent to transport */
#define TYPE_CLR    (FLAG_T | FLAG_A) /**< Data to be sent in the clear */
#define TYPE_ENC    (FLAG_T | FLAG_A | FLAG_C) /**< Data sent encrypted */
#define TYPE_MAC    (FLAG_T | FLAG_C) /**< Message authentication code */
#define TYPE_RATCHET FLAG_C    /**< Erase data to prevent rollback */
#define TYPE_PRF    (FLAG_I | FLAG_A | FLAG_C) /**< Return pseudorandom hash */

#if STROBE_CW_MAX_LENGTH_BYTES <= 1
typedef uint8_t strobe_length_t;
#elif STROBE_CW_MAX_LENGTH_BYTES <= 2
typedef uint16_t strobe_length_t;
#elif STROBE_CW_MAX_LENGTH_BYTES <= 4
typedef uint32_t strobe_length_t;
#elif STROBE_CW_MAX_LENGTH_BYTES <= 8
typedef uint64_t strobe_length_t;
#elif STROBE_CW_MAX_LENGTH_BYTES <= 16
typedef uint128_t strobe_length_t;
#else
#error "Can't deal with >128-bit length fields'"
#endif

/** Destroy a STROBE object by writing zeros over it. */
static inline void strobe_destroy(strobe_t strobe) {
    volatile uint8_t *p = strobe->state.b;
    int size_to_remove = 25*sizeof(kword_t)/sizeof(uint8_t);
    while (size_to_remove--){
        *p++ = 0;
    }
    strobe->position = 0;
    strobe->pos_begin = 0;
    strobe->flags = 0;
    strobe->initiator = 0;
}

/** clone a STROBE object */
static inline void strobe_clone(strobe_t src, strobe_t dst) {
    assert(src != NULL && dst != NULL);
    memcpy(dst->state.b, src->state.b, 25*sizeof(kword_t)/sizeof(uint8_t));
    dst->position = src->position;
    dst->pos_begin = src->pos_begin;
    dst->flags = src->flags;
    dst->initiator = src->initiator;
}

/* Endian swaps used by keccak implementation */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
static inline kword_t eswap_letoh(kword_t w) { return w; }
static inline kword_t eswap_htole(kword_t w) { return w; }
static inline uint16_t eswap_letoh_16(uint16_t w) { return w; }
static inline uint16_t eswap_htole_16(uint16_t w) { return w; }
static inline uint32_t eswap_letoh_32(uint32_t w) { return w; }
static inline uint32_t eswap_htole_32(uint32_t w) { return w; }
static inline uint64_t eswap_letoh_64(uint64_t w) { return w; }
static inline uint64_t eswap_htole_64(uint64_t w) { return w; }
static inline strobe_length_t eswap_letoh_sl(strobe_length_t w) { return w; }
static inline strobe_length_t eswap_htole_sl(strobe_length_t w) { return w; }
#else
#error "Fix eswap() on non-little-endian machine"
#endif
