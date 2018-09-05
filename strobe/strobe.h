/**
 * @file strobe.h
 * @copyright
 *   Copyright (c) 2015-2016 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief Strobe lite protocol instances.
 */
#ifndef __STROBE_H__
#define __STROBE_H__

/* TODO: Implement state compaction, particularly for PRNG state */
/* TODO: Test this against the Python reference. */

#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>

#include "strobe_config.h"

/**
 * A control word holds flags and other information that control a STROBE operation.
 * Defined below.
 */
typedef uint32_t control_word_t;

/* Strobe object, below */
struct strobe_s;

/** Initialize a STROBE object, using the description as a domain separator. */
void strobe_init (
    struct strobe_s *__restrict__ strobe,
    const uint8_t *description,
    size_t desclen
);

/** Underlying duplex primitive. */
ssize_t strobe_duplex (
   struct strobe_s *__restrict__ strobe,
   control_word_t flags,
   uint8_t *inside,
   ssize_t len
);

/**
 * More complex duplex primitive.
 * First reads/writes metadata based on control_flags, then data.  Can pass
 * -len instead of len when reading.  This means any length up to len.
 * Returns the number of data bytes read, or <0 on error.
 */
ssize_t strobe_operate (
    struct strobe_s *__restrict__ strobe,
    control_word_t control_flags,
    uint8_t *inside,
    ssize_t len
);

#if STROBE_SUPPORT_PRNG
/** Seed the generator with len bytes of randomness. */
void strobe_seed_prng(const uint8_t *data, ssize_t len);

/**
 * Fill *data with len bytes of randomness.
 * Return <0 if the generator is not seeded.
 */
int __attribute__((warn_unused_result))
    strobe_randomize(uint8_t *data, ssize_t len);
#endif /* STROBE_SUPPORT_PRNG */

/* Flags as defined in the paper */
#define FLAG_I (1<<0) /**< Inbound */
#define FLAG_A (1<<1) /**< Has application-side data (eg, not a MAC) */
#define FLAG_C (1<<2) /**< Uses encryption or rekeying. */
#define FLAG_T (1<<3) /**< Send or receive data via transport */
#define FLAG_M (1<<4) /**< Operation carries metadata. */

#define FLAG_META_I (1<<20) /**< Metadata has I */
#define FLAG_META_A (1<<21) /**< Metadata has A (always set) */
#define FLAG_META_C (1<<22) /**< Metadata has C */
#define FLAG_META_T (1<<23) /**< Metadata has T */
#define FLAG_META_M (1<<24) /**< Metadata has M (always set) */
#define GET_META_FLAGS(cw) (((cw) >> 20) & 0x3F)

#define FLAG_MORE     (1<<28) /**< Continue a streaming operation. */
#define FLAG_NO_DATA  (1<<29) /**< Just send/recv the metadata, not the data. */

#if STROBE_SUPPORT_FLAG_POST
/**
 * Post-op ratchet and/or MAC.
 *
 * TODO: I might want to remove these, because some details of how this is
 * done might be application-specific.  In particular, some applications will
 * want to frame their MACs on the wire, and some will not.
 */
#define FLAG_POST_RATCHET (1<<30) /**< Ratchet state after */
#define FLAG_POST_MAC     (1<<31) /**< Send/receive MAC after */
#endif

/* Operation types as defined in the paper */
#define TYPE_AD FLAG_A /**< Context data, not sent to trensport */
#define TYPE_KEY (FLAG_A | FLAG_C) /**< Symmetric key, not sent to transport */
#define TYPE_CLR (FLAG_T | FLAG_A) /**< Data to be sent in the clear */
#define TYPE_ENC (FLAG_T | FLAG_A | FLAG_C) /**< Data sent encrypted */
#define TYPE_MAC (FLAG_T | FLAG_C) /**< Message authentication code */
#define TYPE_RATCHET FLAG_C    /**< Erase data to prevent rollback */
#define TYPE_PRF (FLAG_I | FLAG_A | FLAG_C) /**< Return pseudorandom hash */

/** For operate, have (n)-byte little-endian length field. */
#define CW_LENGTH_BYTES(n) ((uint32_t)(n)<<16)

#define STROBE_CW_GET_LENGTH_BYTES(cw) ((cw)>>16 & 0xF)

#define MAKE_IMPLICIT(cw) ((cw) &~ (FLAG_T | FLAG_META_T))
#define MAKE_LENGTHLESS(cw) ((cw) &~ CW_LENGTH_BYTES(0x0F))

#define GET_CONTROL_TAG(cw) (((cw)>>8)&0xFF)
#define CONTROL_WORD(w,value,flags) enum { w=value<<8|flags|FLAG_META_A|FLAG_META_M }

/* Recommended control words */
/* 0x00-0x0F: symmetric cryptography */
CONTROL_WORD(SYM_SCHEME     , 0x00, TYPE_CLR | CW_LENGTH_BYTES(2) | FLAG_META_T );
CONTROL_WORD(SYM_KEY        , 0x01, TYPE_KEY );
CONTROL_WORD(APP_PLAINTEXT  , 0x02, TYPE_CLR | CW_LENGTH_BYTES(2) | FLAG_META_T );
CONTROL_WORD(APP_CIPHERTEXT , 0x03, TYPE_ENC | CW_LENGTH_BYTES(2) | FLAG_META_T );
CONTROL_WORD(NONCE          , 0x04, TYPE_CLR | CW_LENGTH_BYTES(2) | FLAG_META_T );
CONTROL_WORD(AUTH_DATA      , 0x05, TYPE_CLR | CW_LENGTH_BYTES(2) | FLAG_META_T );
CONTROL_WORD(MAC            , 0x06, TYPE_MAC | CW_LENGTH_BYTES(2) );
CONTROL_WORD(HASH           , 0x07, TYPE_PRF | CW_LENGTH_BYTES(2) );
CONTROL_WORD(DERIVE_KEY     , 0x08, TYPE_PRF | CW_LENGTH_BYTES(2) );
CONTROL_WORD(BE_SLOW        , 0x0C, TYPE_RATCHET | CW_LENGTH_BYTES(4) );
CONTROL_WORD(SIV_PT_INNER   , 0x0D, TYPE_CLR ); /* FUTURE: implement SIV */
CONTROL_WORD(SIV_MAC_OUTER  , 0x0E, TYPE_CLR );
CONTROL_WORD(RATCHET        , 0x0F, TYPE_RATCHET );

/* 0x10-0x1F: Asymmetric key exchange and encryption */
CONTROL_WORD(KEM_SCHEME     , 0x10, TYPE_CLR | CW_LENGTH_BYTES(2) | FLAG_META_T );
CONTROL_WORD(PUBLIC_KEY     , 0x11, TYPE_CLR | CW_LENGTH_BYTES(2) | FLAG_META_T );
CONTROL_WORD(KEM_EPH        , 0x12, TYPE_CLR | CW_LENGTH_BYTES(2) | FLAG_META_T );
CONTROL_WORD(KEM_RESULT     , 0x13, TYPE_KEY );

/* 0x18-0x1F: Signatures */
CONTROL_WORD(SIG_SCHEME     , 0x18, TYPE_CLR | CW_LENGTH_BYTES(2) | FLAG_META_T );
CONTROL_WORD(SIG_EPH        , 0x19, TYPE_CLR | CW_LENGTH_BYTES(2) | FLAG_META_T );
CONTROL_WORD(SIG_CHALLENGE  , 0x1A, TYPE_PRF | CW_LENGTH_BYTES(2) );
CONTROL_WORD(SIG_RESPONSE   , 0x1B, TYPE_ENC | CW_LENGTH_BYTES(2) | FLAG_META_T );
CONTROL_WORD(SIG_DETERM     , 0x1C, TYPE_PRF | CW_LENGTH_BYTES(2) );

/* 0x20-0x2F: header and other metadata */
CONTROL_WORD(HANDSHAKE      , 0x20, TYPE_CLR | CW_LENGTH_BYTES(2) | FLAG_META_T );
CONTROL_WORD(VERSION        , 0x21, TYPE_CLR | CW_LENGTH_BYTES(2) | FLAG_META_T );
CONTROL_WORD(CIPHERSUITE    , 0x22, TYPE_CLR | CW_LENGTH_BYTES(2) | FLAG_META_T );
CONTROL_WORD(META_PLAINTEXT , 0x24, TYPE_CLR | CW_LENGTH_BYTES(2) | FLAG_META_T );
CONTROL_WORD(META_CIPHERTEXT, 0x25, TYPE_CLR | CW_LENGTH_BYTES(2) | FLAG_META_T );
CONTROL_WORD(CERTIFICATE    , 0x26, TYPE_CLR | CW_LENGTH_BYTES(2) | FLAG_META_T );
CONTROL_WORD(ENCRYPTED_CERT , 0x27, TYPE_ENC | CW_LENGTH_BYTES(2) | FLAG_META_T );
CONTROL_WORD(OVER           , 0x2E, TYPE_MAC | CW_LENGTH_BYTES(2) | FLAG_META_T );
CONTROL_WORD(CLOSE          , 0x2F, TYPE_MAC | CW_LENGTH_BYTES(2) | FLAG_META_T );

/* 0x30-0x3F: Certificates.
 *
 * These are still experimental and unimplemented, and will probably change.
 * The intention is that certs should look something like this:
 *
 * CERT_VERSION 1
 * CERT_SERIAL .{0,32} ? # for revocation, else omitted
 * CERT_VALIDITY? # omitted if your devices aren't tracking time or can't update
 * CERT_PURPOSE .*? # if your application makes such a distinction
 * ((CERT_REC_PRE .* CERT_REC_POST .*) | (CERT_NAME .*))
 *      ^ if the cert is an intermediate      ^ if it isn't an intermediate
 * (CERT_PK_SCHEME PUBLIC_KEY)+ # Limited to 1? Could have multiple?  Dunno.
 *
 * CERT_COMMENT *
 * (SIG_SCHEME SIG_CHAL SIG_EPH SIG_RESPONSE)+ # or similar depending on sig scheme
 *    ^ Possibly this should be limited to 1.
 *
 * If your application uses cert chains, they would be given in separate CERTIFICATE
 * (or ENCRYPTED_CERT) messages, in order from CA to leaf.  At any time, the client
 * could track "what's the most recent trusted intermediate which has authority over
 * the name I'm trying to contact."  Then if there are multiple certifying chains, the
 * untrusted ones would be ignored.
 */
CONTROL_WORD(CERT_VERSION   , 0x30, TYPE_CLR | CW_LENGTH_BYTES(2) | FLAG_META_T );
CONTROL_WORD(CERT_SERIAL    , 0x31, TYPE_CLR | CW_LENGTH_BYTES(2) | FLAG_META_T );
CONTROL_WORD(CERT_VALIDITY  , 0x32, TYPE_CLR | CW_LENGTH_BYTES(2) | FLAG_META_T );
CONTROL_WORD(CERT_PURPOSE   , 0x33, TYPE_CLR | CW_LENGTH_BYTES(2) | FLAG_META_T );
CONTROL_WORD(CERT_REC_PRE   , 0x34, TYPE_CLR | CW_LENGTH_BYTES(2) | FLAG_META_T );
CONTROL_WORD(CERT_REC_POST  , 0x35, TYPE_CLR | CW_LENGTH_BYTES(2) | FLAG_META_T );
CONTROL_WORD(CERT_NAME      , 0x36, TYPE_CLR | CW_LENGTH_BYTES(2) | FLAG_META_T );
CONTROL_WORD(CERT_PK_SCHEME , 0x37, TYPE_CLR | CW_LENGTH_BYTES(2) | FLAG_META_T );
CONTROL_WORD(CERT_COMMENT   , 0x3F, TYPE_CLR | CW_LENGTH_BYTES(2) | FLAG_META_T );

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
    control_word_t control_flags,
    const uint8_t *inside,
    ssize_t len
) {
    assert(!(control_flags & (FLAG_M|FLAG_I|FLAG_META_I))); // can't be meta, or receive, or meta_receive
    return strobe_operate(strobe,control_flags,(uint8_t *)inside,len);
}

/** Receive data or extract it from the sponge. */
static inline ssize_t strobe_get (
    strobe_s *__restrict__ strobe,
    control_word_t control_flags,
    uint8_t *inside,
    ssize_t len
) {
    assert(!(control_flags & FLAG_M)); // not meta
    assert((control_flags & (FLAG_T|FLAG_C)) != 0); // either transport(send/recv) or key stuf
    control_flags |= FLAG_I; // "receive mode"
    if (control_flags & FLAG_META_T) control_flags |= FLAG_META_I; // if it's meta_transport, add meta_recv
    return strobe_operate(strobe,control_flags,(uint8_t *)inside,len);
}

/* Endian swaps */
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

/**
 * Receive just control/metadata from the other party.
 * This is for complex protocols where you may not know what will come next.
 */
static inline ssize_t strobe_get_control (
    strobe_s *__restrict__ strobe,
    strobe_serialized_control_t *cw,
    uint32_t flags
) {
    unsigned int length_bytes = STROBE_CW_GET_LENGTH_BYTES(flags);
    control_word_t cwf = GET_META_FLAGS(flags) | FLAG_I | FLAG_T;

    cw->len = 0;
    ssize_t ret = strobe_duplex(strobe, cwf, (uint8_t *)cw, sizeof(cw->control) + length_bytes);

    /* Probably a nop, allowing tailcall, except we're inline anyway */
    cw->len = eswap_letoh_sl(cw->len);
    return ret;
}

static inline ssize_t strobe_put_mac( strobe_t strobe ) {
    return strobe_operate(strobe, MAC, NULL, STROBE_INTEROP_MAC_BYTES);
}

static inline ssize_t strobe_get_mac(strobe_t strobe ) {
    return strobe_operate(strobe, MAC|FLAG_I, NULL, STROBE_INTEROP_MAC_BYTES);
}

static inline ssize_t strobe_key (
    strobe_t strobe,
    control_word_t cw,
    const uint8_t *data,
    uint16_t len
) {
    assert(!(cw & FLAG_T));
    return strobe_put(strobe, cw, data, len);
}

#if STROBE_CONVENIENCE_ECDH
int strobe_eph_ecdh (
    strobe_t strobe,
    int i_go_first
);
#endif

#if X25519_SUPPORT_SIGN
int strobe_session_sign (
    strobe_t strobe,
    const uint8_t my_seckey[32],
    const uint8_t my_pubkey[32]
);
#endif

#if X25519_SUPPORT_VERIFY
int strobe_session_verify (
    strobe_t strobe,
    const uint8_t their_pubkey[32]
);
#if STROBE_SUPPORT_CERT_VERIFY
/* Parse a signature but don't verify it.
 * Useful for intermediate certs we don't trust.
 */
int strobe_session_dont_verify (
    strobe_t strobe,
    const uint8_t their_pubkey[32]
);
#endif
#endif

#endif /* __STROBE_H__ */
