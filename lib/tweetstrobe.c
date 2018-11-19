/**
 * @cond internal
 * @file strobe.c
 * @copyright
 *   Copyright (c) 2015-2016 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief Strobe protocol code.
 */

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <limits.h> /* for INT_MAX */
#include <stdbool.h>

#include <stdio.h>  // to delete

#include "tweetstrobe.h"

/* Sets the security level at 128 bits (but this holds even
 * when the attacker has lots of data).
 */
#define CAPACITY_BITS (2 * STROBE_INTEROP_SECURITY_BITS)

/* Internal rate is 2 bytes less than sponge's "rate" */
#define PAD_BYTES 2
#define RATE_INNER ((25 * sizeof(kword_t) - CAPACITY_BITS / 8))
#define RATE (RATE_INNER - PAD_BYTES)

/* Pull in a Keccak-F implementation.  Use the target-specific
 * asm one if available.
 */
#include "keccak_f.c.inc"

static void _run_f(strobe_s *strobe, unsigned int pos) {
  strobe->state.b[pos] ^= strobe->pos_begin;
  strobe->pos_begin = 0;
  strobe->state.b[pos + 1] ^= 0x04;
  strobe->state.b[RATE + 1] ^= 0x80;
  keccak_f(&strobe->state);
}

static inline void _begin_op(strobe_s *strobe, uint8_t flags) {
  unsigned int pos = strobe->position;

  // Adjust the direction based on transport
  if (flags & FLAG_T) {
    if (strobe->initiator == 2) {  // None
      // Set who is initiator and who is responder
      strobe->initiator = flags & FLAG_I;
    }
    flags ^= strobe->initiator;
  }

  // Mark the state
  strobe->state.b[pos] ^= strobe->pos_begin;
  pos++;
  strobe->pos_begin = pos;
  if (pos >= RATE) {
    _run_f(strobe, pos);
    pos = 0;
  }

  // Absorb the rest of the mode marker
  strobe->state.b[pos] ^= flags;
  pos++;

  if (pos >= RATE || (flags & FLAG_C) != 0) {
    _run_f(strobe, pos);
    pos = 0;
  }

  // Save the state position
  strobe->position = pos;
}

/* The core duplex mode */
static ssize_t _strobe_duplex(strobe_s *strobe, uint8_t *buffer,
                              size_t buffer_len, bool cbefore, bool cafter,
                              bool recv_MAC) {
  // get our position in state
  unsigned int pos = strobe->position;

  // for recv_MAC
  uint8_t MAC_verif = 0;

  // consume the buffer
  size_t left = buffer_len;
  while (left > 0) {
    // duplex magic
    if (cbefore) {
      *buffer ^= strobe->state.b[pos];
    }
    strobe->state.b[pos] ^= *buffer;
    if (cafter) {
      *buffer = strobe->state.b[pos];
    }
    // recv_MAC
    if (recv_MAC) {
      MAC_verif |= *buffer;
    }
    // advance
    pos++;
    buffer++;
    left--;
    // runF
    if (pos >= RATE) {
      _run_f(strobe, pos);
      pos = 0;
    }
  }

  // save state position
  strobe->position = pos;

  // recv_MAC
  if (recv_MAC) {
    if (MAC_verif == 0) {
      return 0;
    } else {
      return -1;
    }
  }

  // return length of what was written/read/modified
  return buffer_len;
}

// strobe_operate
// Note: if you're using PRF, RATCHET or send_MAC. Your buffer needs to be
// initialized with 0s.
ssize_t strobe_operate(strobe_s *strobe, uint8_t flags, uint8_t *buffer,
                       size_t buffer_len, bool more) {
  assert(strobe->position < RATE);

  // set buffer to 0 if RATCHET, send_MAC or PRF
  // RATCHET = C, send_MAC = C | T, PRF = I | A | C
  if ((flags & FLAG_C) == FLAG_C) {
    if (flags == (FLAG_I | FLAG_A | FLAG_C) || flags == (FLAG_C) ||
        flags == (FLAG_C | FLAG_T)) {
      for (size_t i = 0; i < buffer_len; i++) {
        buffer[i] = 0;
      }
    }
  }

  if (more) {
    assert(flags == strobe->flags);
  } else {
    _begin_op(strobe, flags);
    strobe->flags = flags;
  }

  bool cafter = (flags & (FLAG_C | FLAG_I | FLAG_T)) == (FLAG_C | FLAG_T);
  bool cbefore = (flags & FLAG_C) && (!cafter);
  bool recv_MAC = (flags & (0xF | FLAG_I)) == (TYPE_MAC | FLAG_I);

  return _strobe_duplex(strobe, buffer, buffer_len, cbefore, cafter, recv_MAC);
}

void strobe_init(strobe_s *strobe, const uint8_t *protocol_name,
                 size_t protocol_name_len) {
  const uint8_t proto[18] = {
      1, RATE + PAD_BYTES, 1, 0, /* Empty NIST perso string */
      1, 12 * 8,                 /* 12 = strlen("STROBEvX.Y.Z") */
      'S', 'T', 'R', 'O', 'B', 'E', 'v', '0' + STROBE_INTEROP_V_MAJOR, '.',
      '0' + STROBE_INTEROP_V_MINOR, '.', '0' + STROBE_INTEROP_V_PATCH,
      /* Rest is 0s, which is already there because we memset it */
  };
  memset(strobe, 0, sizeof(*strobe));
  memcpy(strobe, proto, sizeof(proto));
  keccak_f(&strobe->state);

  strobe->initiator = 2;  // None

  strobe_operate(strobe, FLAG_A | FLAG_M, (uint8_t *)protocol_name,
                 protocol_name_len, false);

  strobe->initialized = 111;
}

bool strobe_isInitialized(strobe_s *strobe) {
  if (strobe->initialized == 111) {
    return true;
  } else {
    return false;
  }
}

/** Destroy a STROBE object by writing zeros over it. */
inline void strobe_destroy(strobe_s *strobe) {
  volatile uint8_t *p = strobe->state.b;
  int size_to_remove = 25 * sizeof(kword_t) / sizeof(uint8_t);
  while (size_to_remove--) {
    *p++ = 0;
  }
  strobe->position = 0;
  strobe->pos_begin = 0;
  strobe->flags = 0;
  strobe->initiator = 0;
  strobe->initialized = 0;
}

/** clone a STROBE object */
inline void strobe_clone(const strobe_s *src, strobe_s *dst) {
  assert(src != NULL && dst != NULL);
  memcpy(dst->state.b, src->state.b, 25 * sizeof(kword_t) / sizeof(uint8_t));
  dst->position = src->position;
  dst->pos_begin = src->pos_begin;
  dst->flags = src->flags;
  dst->initiator = src->initiator;
  dst->initialized = src->initialized;
}

void strobe_print(const strobe_s *strobe) {
  for (int i = 0; i < sizeof(strobe->state); i++) {
    printf("%02x", strobe->state.b[i]);
  }
  printf("\n");
}
