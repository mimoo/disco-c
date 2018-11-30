#ifndef DISCO_SYMMETRIC_H_
#define DISCO_SYMMETRIC_H_
#include "tweetstrobe.h"

// hashing

typedef struct discoHashCtx_ {
  strobe_s strobe;
  uint8_t initialized;
} discoHashCtx;

#define INITIALIZED 111

// Hashing
void disco_Hash(uint8_t* input, size_t input_len, uint8_t* out, size_t out_len);
void disco_HashNew(discoHashCtx* ctx);
void disco_HashWrite(discoHashCtx* ctx, uint8_t* input, size_t input_len);
void disco_HashWriteTuple(discoHashCtx* ctx, uint8_t* input, size_t input_len);
void disco_HashSum(discoHashCtx* ctx, uint8_t* out, size_t out_len);
void disco_HashResetCtx(discoHashCtx* ctx);

// Key Derivation
void disco_DeriveKeys(uint8_t* inputKey, size_t key_len, uint8_t* out,
                      size_t out_len);

// Integrity Protection
void disco_ProtectIntegrity(uint8_t* key, size_t key_len, uint8_t* data,
                            size_t data_len, uint8_t* out, size_t out_len);
bool disco_VerifyIntegrity(uint8_t* key, size_t key_len, uint8_t* data,
                           size_t data_len, uint8_t* tag, size_t tag_len);

/*
// Authenticated Encryption
ssize_t disco_Encrypt(uint8_t* key, size_t key_len, uint8_t* plaintext,
                      size_t plaintext_len, size_t plaintext_capacity);
ssize_t disco_Decrypt(uint8_t* key, size_t key_len, uint8_t* ciphertext,
                      size_t ciphertext_len);

// Authenticated Encryption with Additional Data
ssize_t disco_EncryptAndAuthenticate(uint8_t* key, size_t key_len,
                                     uint8_t* plaintext, size_t plaintext_len,
                                     size_t plaintext_capacity);
ssize_t disco_DecryptAndAuthenticate(uint8_t* key, size_t key_len,
                                     uint8_t* ciphertext,
                                     size_t ciphertext_len);
*/

typedef struct discoRandomCtx_ {
  strobe_s strobe;
  uint8_t initialized;
} discoRandomCtx;

// Pseudo-Random Number Generator
void disco_RandomSeed(discoRandomCtx* ctx, uint8_t* seed, size_t seed_len);
void disco_InjectEntropy(discoRandomCtx* ctx, uint8_t* entropy,
                         size_t entropy_len);
void disco_RandomGet(discoRandomCtx* ctx, uint8_t* out, size_t out_len);

#endif // DISCO_SYMMETRIC_H_
