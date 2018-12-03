#ifndef __CURVE25519_H__
#define __CURVE25519_H__

int crypto_scalarmult(unsigned char *q, const unsigned char *n, const unsigned char *p);
int crypto_box_keypair(unsigned char *y, unsigned char *x);

#endif /* __CURVE25519_H__ */
