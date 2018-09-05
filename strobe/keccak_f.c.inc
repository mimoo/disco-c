/**
 * @cond internal
 * @file keccak_f.c.inc
 * @copyright
 *   Copyright (c) 2015-2016 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * 
 * Loosely based on CC0 implementations of Keccak-F:
 *      Keccak-Tiny:
 *          David Leon Gil
 *      TweetFIPS202:
 *          Dan J Bernstein
 *          Peter Schwabe
 *          Gilles van Assche
 *
 * @author Mike Hamburg
 *
 * @brief Keccak-f[n] implementation.  Designed to be included in another C
 *  file, so no headers.
 */

/* Could lose this to save size, maybe, depends on arch */
#ifndef STROBE_OPT_RC_TABLE
#define STROBE_OPT_RC_TABLE 1
#endif

/* Helper macros to unroll the permutation. */
#define REPEAT5(e) e e e e e
#if STROBE_OPT_FOR_SIZE // Size + 0 bytes, speed x 1/2
#    define FOR51(v, e) v = 0; REPEAT5(e; v += 1;)
#    define FOR55(v, e) for (v=0; v<25; v+= 5) { e; }
#    define REPEAT24(e) {int _j=0; for (_j=0; _j<24; _j++) { e }}
#elif STROBE_OPT_FOR_SPEED // Size + 600 bytes, speed x1
#    define FOR51(v, e) v = 0; REPEAT5(e; v += 1;)
#    define FOR55(v, e) v = 0; REPEAT5(e; v += 5;)
#    define REPEAT24(e) e e e e e e e e e e e e e e e e e e e e e e e e
#elif STROBE_OPT_FOR_SIZE_AGGRESSIVE // Terrible.  Actually makes things bigger
#    define FOR51(v, e) for (v=0; v<5; v++) { e; }
#    define FOR55(v, e) for (v=0; v<25; v+= 5) { e; }
#    define REPEAT24(e) {int _j=0; for (_j=0; _j<24; _j++) { e }}
#else // Size + 100 bytes, speed x 3/4
#    define FOR51(v, e) v = 0; REPEAT5(e; v += 1;)
#    define FOR55(v, e) for (v=0; v<25; v+= 5) { e; }
#    define REPEAT24(e) e e e e e e e e e e e e e e e e e e e e e e e e
#endif

#if STROBE_INTEROP_F_BITS == 1600
#define NROUNDS 24
#elif STROBE_INTEROP_F_BITS == 800
#define NROUNDS 22
#elif STROBE_INTEROP_F_BITS == 400
#define NROUNDS 20
#elif sSTROBE_INTEROP_F_BITS == 200
#define NROUNDS 18
#else
#error "Only implementing KeccakF[200,400,800,1600]'"
#endif

/** Rotate left */
static inline kword_t rol(kword_t x, int s) {
    static const int WBITS = 8*sizeof(kword_t);
    s %= WBITS;
    return (x << s) | (x >> (WBITS - s));
}

/*** The keccak-f[] permutation ***/
static void keccak_f(kdomain_s *state) {
    const uint8_t pi[24] = {
        10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
        15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
    };

    #define RC_B(x,n) ((((x##ull)>>n)&1)<<((1<<n)-1))
    #define RC_X(x) ((kword_t)(RC_B(x,0)|RC_B(x,1)|RC_B(x,2)|RC_B(x,3)|RC_B(x,4)|RC_B(x,5)|RC_B(x,6)))
    const kword_t RC[NROUNDS] = {
        #if NROUNDS >= 24
                RC_X(0x74), RC_X(0x21),
        #endif
        #if NROUNDS >= 22
                RC_X(0x58), RC_X(0x79),
        #endif
        #if NROUNDS >= 20
                RC_X(0x66), RC_X(0x16),
        #endif
        RC_X(0x48), RC_X(0x52), RC_X(0x53), RC_X(0x5d), RC_X(0x4f), RC_X(0x3f), 
        RC_X(0x26), RC_X(0x35), RC_X(0x0c), RC_X(0x0e), RC_X(0x55), RC_X(0x79), 
        RC_X(0x21), RC_X(0x1f), RC_X(0x70), RC_X(0x5e), RC_X(0x1a), RC_X(0x01)
    };

    kword_t* a = state->w;
    kword_t b[5] = {0}, t, u;
    unsigned int x, y;
    int i;

    for (i=0; i<25; i++) a[i] = eswap_letoh(a[i]);

    for (i = NROUNDS-1; i >=0; i--) {
        // Theta
        FOR51(x, b[x] = 0;)
        FOR55(y, FOR51(x, b[x] ^= a[x + y];))
        FOR55(y, FOR51(x,
            a[y + x] ^= b[(x + 4) % 5] ^ rol(b[(x + 1) % 5], 1);
        ))
        // Rho and pi
        t = a[1];
        x = y = 0;
        REPEAT24(u = a[pi[x]]; y += x+1; a[pi[x]] = rol(t, y); t = u; x++; )
        // Chi
        FOR55(y,
             FOR51(x, b[x] = a[y + x];)
             FOR51(x, a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]);)
        )
        // Iota
	    a[0] ^= RC[i];
    }

    for (i=0; i<25; i++) a[i] = eswap_htole(a[i]);
}
