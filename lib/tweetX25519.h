#ifndef __CURVE25519_H__
#define __CURVE25519_H__

#include <stdint.h>

int crypto_scalarmult(uint8_t *q, const uint8_t *n, const uint8_t *p);
int crypto_box_keypair(uint8_t *y, uint8_t *x);

#endif /* __CURVE25519_H__ */