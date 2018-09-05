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


/**
 * A control word holds flags and other information that control a STROBE operation.
 * Defined below.
 */
typedef uint8_t flags_t;

/* Strobe object, below */
struct strobe_s;

void strobe_init (
    struct strobe_s *__restrict__ strobe,
    const uint8_t *description,
    size_t desclen
);

ssize_t strobe_operate (
    struct strobe_s *__restrict__ strobe,
    flags_t control_flags,
    uint8_t *inside,
    size_t len,
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

/* Size of the operation */
#if STROBE_INTEROP_F_BITS == 1600
#define kword_t uint64_t
#elif STROBE_INTEROP_F_BITS == 800
#define kword_t uint32_t
#elif STROBE_INTEROP_F_BITS == 400
#define kword_t uint16_t
#else
#error "Strobe supports only Keccak-F{400,800,1600}"
#endif

/* IO callback context.  Opaque to STROBE. */
typedef struct {
    void *a, *b; /**< Two pointers for use by the callback context. */
#if STROBE_IO_CTX_HAS_FD
    int fd; /**< A file descriptor, or whatever. */
#endif
} strobe_io_ctx_s;

/** Callback context */
typedef struct {
    // FUTURE: make these return two values?
    /**
     * Read up to [size] bytes of data.  Set the buffer to where it
     * points, and return how many bytes were actually read.
     */
    ssize_t (*read)  (strobe_io_ctx_s *ctx, const uint8_t **buffer, ssize_t size);

    /**
     * The write callback is trickier.
     *
     * The first call returns a buffer to write the data to.
     *
     * The next call writes that data out, and returns a new (or more likely,
     * the same) buffer.
     */
    ssize_t (*write) (strobe_io_ctx_s *ctx, uint8_t **buffer,       ssize_t size);
} strobe_io_callbacks_s;
extern const strobe_io_callbacks_s strobe_io_cb_buffer, strobe_io_cb_const_buffer;

/** Keccak's domain: 25 words of size b/25, or b/8 bytes. */
typedef union {
    kword_t w[25];
    uint8_t b[25*sizeof(kword_t)/sizeof(uint8_t)];
} kdomain_s;

/** The main strobe state object. */
typedef struct strobe_s {
    kdomain_s state;
    uint8_t position, pos_begin, flags;

    const strobe_io_callbacks_s *io;
    strobe_io_ctx_s io_ctx;
} strobe_s, strobe_t[1];

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

typedef struct {
    uint8_t control;
    strobe_length_t len; 
} __attribute__((packed)) strobe_serialized_control_t;

/* Protocol building blocks */
#define TRY(foo) do { ssize_t _ret = (foo); if (_ret < 0) return _ret; } while(0)

/**
 * Destroy a STROBE object by writing zeros over it.
 * NB: if you don't have C11's memset_s, the compiler might optimize this call
 * away!
 */
static inline void strobe_destroy(strobe_t strobe) {
#ifdef __STDC_LIB_EXT1__
    memset_s(strobe,sizeof(*strobe),0,sizeof(*strobe));
#else
    memset(strobe,0,sizeof(*strobe));
#endif
}

/**
 * Detach the I/O from a STROBE object.
 */
static inline void strobe_detach(strobe_t strobe) {
    strobe->io = NULL;
    /* Not really relevant: */
    // strobe->io_ctx.a = strobe->io_ctx.b = NULL;
}

/** clone */
static inline void strobe_clone(strobe_t src, strobe_t dst) {
    memcpy(dst->state.b, src->state.b, 25*sizeof(kword_t)/sizeof(uint8_t));
    dst->position = src->position;
    dst->pos_begin = src->pos_begin;
    dst->flags = src->flags;
}

/** Reverse the role of a STROBE object (i.e. to emulate the other guy). */
static inline void strobe_reverse(strobe_t strobe) {
    strobe->flags ^= FLAG_I;
}

/** Attach a buffer to a strobe object. */
static inline void strobe_attach_buffer(strobe_t strobe, uint8_t *start, size_t length) {
    strobe->io = &strobe_io_cb_buffer;
    strobe->io_ctx.a = start;
    strobe->io_ctx.b = start+length;
}

/** Attach a buffer to a strobe object. */
static inline void strobe_attach_const_buffer(strobe_t strobe, uint8_t *start, size_t length) {
    strobe->io = &strobe_io_cb_const_buffer;
    strobe->io_ctx.a = start;
    strobe->io_ctx.b = start+length;
}

/** Same as operate, but only for sending data or putting it into the sponge. */
static inline ssize_t strobe_put (
    strobe_s *__restrict__ strobe,
    flags_t control_flags,
    const uint8_t *inside,
    size_t len
) {
    assert(!(control_flags & (FLAG_M|FLAG_I))); // can't be meta, or receive, or meta_receive
    return strobe_operate(strobe,control_flags,(uint8_t *)inside,len, false);
}

/** Receive data or extract it from the sponge. */
static inline ssize_t strobe_get (
    strobe_s *__restrict__ strobe,
    flags_t control_flags,
    uint8_t *inside,
    size_t len
) {
    assert(!(control_flags & FLAG_M)); // not meta
    assert((control_flags & (FLAG_T|FLAG_C)) != 0); // either transport(send/recv) or key stuf
    control_flags |= FLAG_I; // "receive mode"
    return strobe_operate(strobe,control_flags,(uint8_t *)inside,len, false);
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
