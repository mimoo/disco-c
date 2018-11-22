#include "tweetstrobe.h"

// hashing

typedef struct discoHashCtx_ {
  strobe_s strobe;
  uint8_t initialized;
} discoHashCtx;

#define INITIALIZED 111

void disco_Hash(uint8_t* input, size_t input_len, uint8_t* out, size_t out_len);
void disco_HashNew(discoHashCtx* ctx);
void disco_HashWrite(discoHashCtx* ctx, uint8_t* input, size_t input_len);
void disco_HashWriteTuple(discoHashCtx* ctx, uint8_t* input, size_t input_len);
void disco_HashSum(discoHashCtx* ctx, uint8_t* out, size_t out_len);
void disco_HashResetCtx(discoHashCtx* ctx);

void disco_DeriveKeys(uint8_t* inputKey, size_t key_len, uint8_t* out,
                      size_t out_len);
void disco_ProtectIntegrity(uint8_t* key, size_t key_len, uint8_t* data,
                            size_t data_len, uint8_t* out, size_t out_len);
bool disco_VerifyIntegrity(uint8_t* key, size_t key_len, uint8_t* data,
                           size_t data_len, uint8_t* tag, size_t tag_len);