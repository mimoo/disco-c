#include <assert.h>
#include <stdio.h>

#include "tweetstrobe.h"
#include "symmetric.h"

// disco_Hash is a simple hash function that can produce a digest of any length
// from an `input`. The minimum output length `out_len` accepted is 32 bytes.
// The `out` buffer must have at least `out_len` bytes of capacity to receive
// the digest.
void disco_Hash(uint8_t* input, size_t input_len, uint8_t* out,
                size_t out_len) {
  assert(out_len >= 32);
  strobe_s strobe;
  strobe_init(&strobe, (uint8_t*)"DiscoHash", 9);
  strobe_operate(&strobe, TYPE_AD, input, input_len, false);
  strobe_operate(&strobe, TYPE_PRF, out, out_len, false);
}

// disco_HashNew is a way to hold on to a hash context in order to continuously
// write to it. This is usefull when we don't know in advance what we're going
// to hash, or if we going to have to produce a digest at several point in time.
// It is to be used once to initialize a discoHashCtx context.
// Then the context can be used with disco_HashWrite or disco_HashWriteTuple to
// absorb a message to hash.
// Then the context can be used with disco_HashSum to produce a digest of any
// length.
void disco_HashNew(discoHashCtx* ctx) {
  assert(ctx != NULL);
  strobe_init(&(ctx->strobe), (uint8_t*)"DiscoHash", 9);
  strobe_operate(&(ctx->strobe), TYPE_AD, NULL, 0,
                 false);  // to start streaming
  ctx->initialized = INITIALIZED;
}

// disco_HashWrite absorbs data to hash. Several call to this function on
// fragmented data are equivalent to a single call to this function on the full
// data (or a single call to disco_Hash on the full data).
void disco_HashWrite(discoHashCtx* ctx, uint8_t* input, size_t input_len) {
  assert(ctx->initialized == INITIALIZED);
  assert((input != NULL && input_len > 0) || input_len == 0);
  strobe_operate(&(ctx->strobe), TYPE_AD, input, input_len, true);
}

// disco_HashWriteTuple absorbs data to hash, and place delimiters around it.
// Several calls to this function on fragmented data are not equivalent to a
// single call to that function on the full data. To reproduce the same digest
// you must call disco_HashWriteTuple in-order with the same fragments of data.
void disco_HashWriteTuple(discoHashCtx* ctx, uint8_t* input, size_t input_len) {
  assert(ctx->initialized == INITIALIZED);
  assert((input != NULL && input_len > 0) || input_len == 0);
  strobe_operate(&(ctx->strobe), TYPE_AD, input, input_len, false);
}

// disco_HashSum produces a digest. It does not mutate the context, and thus can
// be re-used many times to produce the same digest. The context can also be
// used to absorb more data to hash after.
void disco_HashSum(discoHashCtx* ctx, uint8_t* out, size_t out_len) {
  assert(ctx->initialized == INITIALIZED);
  assert(out != NULL && out_len > 0);
  strobe_s copy = ctx->strobe;
  strobe_operate(&copy, TYPE_PRF, out, out_len, false);
}

// reset the context for re-use. Must be re-initialized after that.
void disco_HashResetCtx(discoHashCtx* ctx) {
  ctx->initialized = 0;
  strobe_destroy(&(ctx->strobe));
}
