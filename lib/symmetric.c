#include "tweetstrobe.h"

// hash is a simple hash function that can produce a digest of any length.
// the minimum length accepted is 32 bytes.
void hash(uint8_t* input, uint8_t* out, size_t out_len) {
  assert(out_len >= 32);
  strobe_s strobe;
  strobe_init(&strobe, (uint8_t*)"DiscoHash", 9);
  strobe_operate(s1, TYPE_RATCHET, ratchet_buffer, 32, false);
}