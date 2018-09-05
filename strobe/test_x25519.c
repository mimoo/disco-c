/**
 * @cond internal
 * @file test_x25519.c
 * @copyright
 *   Copyright (c) 2016 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief Tests for x25519 key exchange and signatures.
 */
#include "x25519.h"
#include "strobe_config.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

static void __attribute__((unused))
randomize(uint8_t foo[X25519_BYTES]) {
    unsigned i;
    static unsigned int seed = 0x12345678;

    for (i=0; i<X25519_BYTES; i++) {
        seed += seed*seed | 5;
        foo[i] = seed>>24;
    }
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;

    int i;

    unsigned char
        secret1[X25519_BYTES],
        public1[X25519_BYTES],
        secret2[X25519_BYTES],
        public2[X25519_BYTES],
        shared1[X25519_BYTES],
        shared2[X25519_BYTES];

    for (i=0; i<1000; i++) {
        randomize(secret1);
        x25519_base(public1,secret1,i%2);

        randomize(secret2);
        x25519_base(public2,secret2,i%2);

        x25519(shared1,secret1,public2,i%2);
        x25519(shared2,secret2,public1,i%2);

        if (memcmp(shared1,shared2,sizeof(shared1))) {
            printf("FAIL shared %d\n",i);
        }
    }

#if X25519_SUPPORT_SIGN && X25519_SUPPORT_VERIFY
    unsigned char
        eph_secret[X25519_BYTES],
        eph_public[X25519_BYTES],
        challenge[X25519_BYTES],
        response[X25519_BYTES];
    for (i=0; i<1000; i++) {
        randomize(secret1);
        x25519_base(public1,secret1,0);
        randomize(eph_secret);
        x25519_base(eph_public,eph_secret,0);
        randomize(challenge);
        x25519_sign_p2(response,challenge,eph_secret,secret1);
        if (0 != x25519_verify_p2(response,challenge,eph_public,public1)) {
            printf("FAIL sign %d\n",i);
        }

        challenge[4] ^= 1;
        if (0 == x25519_verify_p2(response,challenge,eph_public,public1)) {
            printf("FAIL unsign %d\n",i);
        }
    }
#endif

    unsigned char base[X25519_BYTES] = {9};
    unsigned char key[X25519_BYTES] = {9};
    unsigned char *b = base, *k = key, *tmp;

    for (i=0; i<1000; i++) {
        x25519(b,k,b,1);
        tmp = b; b = k; k = tmp;
    }
    for (i=0; i<X25519_BYTES; i++) printf("%02x", k[i]);
    printf("\n");
    return 0;
}
