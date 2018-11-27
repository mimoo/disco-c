#ifndef __CURVE25519_H__
#define __CURVE25519_H__

typedef unsigned char u8;
typedef unsigned long long u64;

int crypto_scalarmult(u8 *q, const u8 *n, const u8 *p);
int crypto_box_keypair(u8 *y, u8 *x);

#endif /* __CURVE25519_H__ */