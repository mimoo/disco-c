/**
 * @cond internal
 * @file strobe.c
 * @copyright
 *   Copyright (c) 2015-2016 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief Strobe protocol code.
 */

#define __STDC_WANT_LIB_EXT1__ 1 /* for memset_s */
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <limits.h> /* for INT_MAX */

#include "strobe.h"
#if X25519_SUPPORT_SIGN || X25519_SUPPORT_VERIFY || STROBE_CONVENIENCE_ECDH
#include "x25519.h"
#endif

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

/* Mark current position and state, and run F.
 * Should be compatible with CSHAKE.
 */
static void
_run_f (strobe_s *strobe, unsigned int p) {
    strobe->state.b[p] ^= strobe->pos_begin;
    strobe->pos_begin = 0;
    strobe->state.b[p+1] ^= SHAKE_XOR_MARK;
    strobe->state.b[RATE+1] ^= SHAKE_XOR_RATE;
    keccak_f(&strobe->state);
}

/* Place a "mark" in the hash, which is distinct from the effect of writing any byte
 * into the hash.  Then write the new mode into the hash.
 */
static inline void
_strobe_mark(strobe_s *strobe, unsigned int * pptr, uint8_t flags) {
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
}

/* The core duplex mode */
ssize_t strobe_duplex (
    strobe_s *strobe,
    control_word_t flags,
    uint8_t *inside,
    ssize_t len
) { 
    /* Sanity check */
    assert(strobe->position < RATE);

    if (len < 0) {
        assert(0);
        /* In production mode, no assert, but at least signal an error */
        return -1;
    }

#if STROBE_SANITY_CHECK_FLAGS
    /* Sanity check flags against what flags we know and are implementing. */
    control_word_t known_flags = FLAG_I|FLAG_A|FLAG_C|FLAG_T|FLAG_M;
    known_flags|= FLAG_META_I|FLAG_META_A|FLAG_META_C|FLAG_META_T|FLAG_META_M;
    known_flags|= CW_LENGTH_BYTES(0xF);
    known_flags|= 0xFF00;
    known_flags|= FLAG_MORE|FLAG_NO_DATA;
#if STROBE_SUPPORT_FLAG_POST
    known_flags|= FLAG_POST_RATCHET|FLAG_POST_MAC;
#endif
    if (flags &~ known_flags) {
        assert(0);
        /* In production mode, no assert, but at least signal an error */
        return -1;
    }
#endif

    ssize_t len2 = len, ret = 0;
    uint8_t cumul = 0;
    uint8_t s2s = -1;
    uint8_t s2o = (flags & FLAG_C) ? -1 : 0;
    if ((flags & FLAG_I) || !(flags & FLAG_T)) s2s ^= s2o; // duplex <-> unduplex

    unsigned int p = strobe->position;
    assert (p < RATE);
    if (!(flags & FLAG_MORE))
    {
        /* Mark the beginning of the operation in the strobe state */
        _strobe_mark(strobe, &p, flags);
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
static ssize_t strobe_operate_0 (
    strobe_s *__restrict__ strobe,
    uint32_t flags,
    uint8_t *inside,
    ssize_t len
) {
    unsigned int length_bytes = STROBE_CW_GET_LENGTH_BYTES(flags);
    control_word_t cwf = GET_META_FLAGS(flags);

    int more = flags & FLAG_MORE;

    int receiving_the_length = (cwf & FLAG_I) && length_bytes > 0 && !more;

    if (len < 0 && !receiving_the_length) {
        assert(((void)"strobe_operate length < 0, but not receiving the length",0));
        /* In case assertions are off... */
        return -1;
    }

    /* Read/write the control word */
    strobe_serialized_control_t str = {
        GET_CONTROL_TAG(flags),
        receiving_the_length ? 0 : eswap_htole_sl(len)
    };
    if (!more) {
        TRY(strobe_duplex(strobe, cwf, (uint8_t *)&str, sizeof(str.control) + length_bytes));
    }
    str.len = eswap_letoh_sl(str.len);

    // Check received control word and length
    if (  str.control != GET_CONTROL_TAG(flags)
       || str.len > INT_MAX
       || ((ssize_t)(len + str.len) > 0 && (ssize_t)str.len != len)
    ) {
        return -1;
    }
    len = str.len;

    if (flags & FLAG_NO_DATA) return 0;

    return strobe_duplex(strobe, flags, inside, len);
}

ssize_t __attribute__((noinline)) strobe_operate (
    strobe_s *__restrict__ strobe,
    uint32_t flags,
    uint8_t *inside,
    ssize_t len
) {
#if STROBE_SUPPORT_FLAG_POST
    int ret;
    TRY(( ret = strobe_operate_0(strobe, flags, inside, len) ));
    if (flags & FLAG_POST_RATCHET) {
        assert(!(flags & FLAG_MORE));
        strobe_operate_0(strobe, RATCHET, NULL, STROBE_INTEROP_RATCHET_BYTES);
    }
    if (flags & FLAG_POST_MAC) {
        assert(!(flags & FLAG_MORE));
        control_word_t cwmac = MAC | (flags & (FLAG_I | FLAG_META_I | FLAG_META_T));
        TRY( strobe_operate_0(strobe, cwmac, NULL, STROBE_INTEROP_MAC_BYTES) );
    }
    return ret;
#else
    /* Not supporting FLAG_POST_RATCHET or FLAG_POST_MAC */
    return strobe_operate_0(strobe, flags, inside, len);
#endif
}

static ssize_t cb_buffer_write(strobe_io_ctx_s *ctx, uint8_t **buffer, ssize_t size) {
    uint8_t *a = ctx->a, *b = ctx->b;
    ssize_t avail = b-a;
    if (size < 0 || size > avail) return -1;
    ctx->a = a+size;
    *buffer = a;
    return avail;
}

static ssize_t cb_buffer_dont_write(strobe_io_ctx_s *ctx, uint8_t **buffer, ssize_t size) {
    (void)ctx;
    *buffer = NULL;
    if (size) return -1;
    return 0;
}

const strobe_io_callbacks_s strobe_io_cb_buffer = {
    (ssize_t (*)(strobe_io_ctx_s *, const uint8_t **, ssize_t))cb_buffer_write, cb_buffer_write
}, strobe_io_cb_const_buffer = {
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

    strobe_duplex(strobe,FLAG_A|FLAG_M,(uint8_t*)description,desclen);
}

#if STROBE_SUPPORT_PRNG
#if STROBE_SINGLE_THREAD
static strobe_t tl_prng = {{{{0}},0,0,0,NULL,{NULL,NULL
#if STROBE_IO_CTX_HAS_FD
    ,0
#endif
}}};
#else
static _Thread_local strobe_t tl_prng = {{{{0}},0,0,0,NULL,{NULL,NULL
#if STROBE_IO_CTX_HAS_FD
    ,0
#endif
}}};
#endif

#define FLAG_PRNG_INITED (1<<4)
#define FLAG_PRNG_SEEDED (1<<5)
int strobe_randomize(uint8_t *data, ssize_t len) {
    if (!(tl_prng->flags & FLAG_PRNG_SEEDED)) {
        return -1;
    }
#if STROBE_SUPPORT_POST_FLAGS
    strobe_get(tl_prng,HASH|FLAG_POST_RATCHET,data,len);
#else
    strobe_get(tl_prng,HASH,data,len);
    strobe_operate(tl_prng, RATCHET, NULL, STROBE_INTEROP_RATCHET_BYTES);
#endif
    return 0;
}

void strobe_seed_prng(const uint8_t *data, ssize_t len) {
    if (!(tl_prng->flags & FLAG_PRNG_INITED)) {
        strobe_init(tl_prng,(const uint8_t *)"prng",4);
    }
#if STROBE_SUPPORT_POST_FLAGS
    strobe_put(tl_prng,SYM_KEY|FLAG_POST_RATCHET,data,len);
#else
    strobe_put(tl_prng,SYM_KEY,data,len);
    strobe_operate(tl_prng, RATCHET, NULL, STROBE_INTEROP_RATCHET_BYTES);
#endif
    tl_prng->flags |= (FLAG_PRNG_INITED | FLAG_PRNG_SEEDED);
}
#endif

#if X25519_SUPPORT_VERIFY
int strobe_session_verify (
    strobe_t strobe,
    const uint8_t their_pubkey[EC_PUBLIC_BYTES]
) {
    uint8_t nonce[EC_PUBLIC_BYTES], chal[EC_CHALLENGE_BYTES], resp[EC_PRIVATE_BYTES];

    /* TODO: use SIG_SCHEME to identify the signature scheme */
    strobe_put(strobe, MAKE_IMPLICIT(PUBLIC_KEY), their_pubkey, EC_PUBLIC_BYTES);
    TRY( strobe_get(strobe, SIG_EPH, nonce, EC_PUBLIC_BYTES) );
    strobe_get(strobe, SIG_CHALLENGE, chal, EC_CHALLENGE_BYTES);
    TRY( strobe_get(strobe, SIG_RESPONSE, resp, EC_PRIVATE_BYTES) );
    return x25519_verify_p2(resp, chal, nonce, their_pubkey);
}

#if STROBE_SUPPORT_CERT_VERIFY
int strobe_session_dont_verify (
    strobe_t strobe,
    const uint8_t their_pubkey[EC_PUBLIC_BYTES]
) {
    strobe_put(strobe, MAKE_IMPLICIT(PUBLIC_KEY), their_pubkey, EC_PUBLIC_BYTES);
    TRY( strobe_get(strobe, SIG_EPH, NULL, EC_PUBLIC_BYTES) );
    strobe_get(strobe, SIG_CHALLENGE, NULL, EC_CHALLENGE_BYTES);
    return strobe_get(strobe, SIG_RESPONSE, NULL, EC_PRIVATE_BYTES);
}
#endif
#endif

#if X25519_SUPPORT_SIGN
int strobe_session_sign (
    strobe_t strobe,
    const uint8_t my_seckey[EC_PRIVATE_BYTES],
    const uint8_t my_pubkey[EC_PUBLIC_BYTES]
) { 
    uint8_t nonce[EC_PUBLIC_BYTES], chal[EC_CHALLENGE_BYTES], resp[EC_UNIFORM_BYTES];

    uint8_t *const eph_secret = resp;
    /* The eph secret is put into resp; responding to it conveniently overwrites that. */

    /* FUTURE: an option not to put in public key, eg if it's already known to be
     * in the session log
     */
    strobe_put(strobe, MAKE_IMPLICIT(PUBLIC_KEY), my_pubkey, EC_PUBLIC_BYTES);

    /* OK, sample the randomness */
#if X25519_DETERMINISTIC_SIGS
    {
        strobe_t too;
        memcpy(too,strobe,sizeof(too));
        strobe_put(too,SYM_KEY,my_seckey,EC_PRIVATE_BYTES);
        strobe_get(too,HASH,eph_secret,EC_UNIFORM_BYTES);
        strobe_destroy(too);
    }
#else
    TRY( strobe_randomize(eph_secret,EC_PRIVATE_BYTES) );
#endif

    /* Nonce = g^eph */
    x25519_base_uniform(nonce,resp);
    TRY( strobe_put(strobe, SIG_EPH, nonce, EC_PUBLIC_BYTES) );

    /* Get the challenge */
    strobe_get(strobe, SIG_CHALLENGE, chal, EC_CHALLENGE_BYTES);

    /* Respond */
    x25519_sign_p2 (resp, chal, eph_secret, my_seckey);
    TRY( strobe_put(strobe, SIG_RESPONSE, resp, EC_PRIVATE_BYTES) );

#if EC_UNIFORM_BYTES > EC_PRIVATE_BYTES
    /* Doesn't happen for Curve25519, but clear the high bytes of the nonce
     * if they're not overwritten. */
    memset(resp,0,sizeof(resp));
#endif

    return 0;
}
#endif

#if STROBE_CONVENIENCE_ECDH
int strobe_eph_ecdh (
    strobe_t strobe,
    int i_go_first
) {
    uint8_t e_pub[EC_PUBLIC_BYTES], e_sec[EC_PRIVATE_BYTES], e_oth[EC_PUBLIC_BYTES];

    /* SEND EPH */
    TRY( strobe_randomize(e_sec,sizeof(e_sec)) );
    x25519_base(e_pub,e_sec,1);
    if (i_go_first)
        TRY( strobe_put(strobe, KEM_EPH, e_pub, sizeof(e_pub)) );

    /* RECV EPH */
    TRY( strobe_get(strobe, KEM_EPH, e_oth, sizeof(e_oth)) );

    /* SEND EPH */
    if (!i_go_first)
        TRY( strobe_put(strobe, KEM_EPH, e_pub, sizeof(e_pub)) );

    /* ECDH */
    TRY( x25519(e_pub, e_sec, e_oth, 1) );
    strobe_operate(strobe, KEM_RESULT, e_pub, sizeof(e_pub));

    return 0;
}

#endif // STROBE_CONVENIENCE_ECDH

