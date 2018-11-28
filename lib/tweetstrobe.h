/*
 * This is a re-write of strobe from David Wong
 * no idea how the MIT license or licenses work so...
 * here is teh original copyright
 */

/**
 * @file strobe.h
 * @copyright
 *   Copyright (c) 2015-2016 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief Strobe lite protocol instances.
 */
#ifndef __STROBE_H__
#define __STROBE_H__

// remember:

#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <stdbool.h>

/****************************************************************/
/*                            STROBE                            */
/****************************************************************/

#ifndef STROBE_INTEROP_V_MAJOR
/** INTEROP: STROBE  major version number. */
#define STROBE_INTEROP_V_MAJOR 1
#endif

#ifndef STROBE_INTEROP_V_MINOR
/** INTEROP: STROBE  minor version number. */
#define STROBE_INTEROP_V_MINOR 0
#endif

#ifndef STROBE_INTEROP_V_PATCH
/** INTEROP: STROBE  patch version number. */
#define STROBE_INTEROP_V_PATCH 2
#endif

/****************************************************************/
/*                            KECCAK                            */
/****************************************************************/

#ifndef STROBE_INTEROP_SECURITY_BITS
/**
 * INTEROP: STROBE nominal security strength, in bits.
 *
 * The capacity of the sponge will be 2*STROBE_INTEROP_SECURITY_BITS
 * long.  Therefore certain security properties will scale better
 * than the 128-bit security level implies.  In particular, if you
 * use 256-bit keys at a 128-bit security level, the 128-bit security
 * holds even if the attacker acquires enormous amounts of data.
 */
#define STROBE_INTEROP_SECURITY_BITS 128
#endif

#ifndef KECCAK_INTEROP_F_BITS
/** INTEROP: STROBE  bit size.  Default is Keccak-F800. */
//#define KECCAK_INTEROP_F_BITS 800
#define KECCAK_INTEROP_F_BITS 1600
#endif

#ifndef KECCAK_OPT_FOR_SIZE
/** Global: optimize STROBE code for size at the expense of speed. */
#define KECCAK_OPT_FOR_SIZE 0
#endif

#ifndef KECCAK_OPT_FOR_SPEED
/** Global: optimize STROBE code for speed at the expense of size. */
#define KECCAK_OPT_FOR_SPEED 0
#endif

// Size of the Keccak permutation
#if KECCAK_INTEROP_F_BITS == 1600
#define kword_t uint64_t
#elif KECCAK_INTEROP_F_BITS == 800
#define kword_t uint32_t
#elif KECCAK_INTEROP_F_BITS == 400
#define kword_t uint16_t
#else
#error "Strobe supports only Keccak-F{400,800,1600}"
#endif

/** Keccak's domain: 25 words of size b/25, or b/8 bytes. */
typedef union {
  kword_t w[25];
  uint8_t b[25 * sizeof(kword_t) / sizeof(uint8_t)];
} kdomain_s;

/** The main strobe state object. */
typedef struct strobe_s_ {
  kdomain_s state;
  uint8_t position;
  uint8_t pos_begin;
  uint8_t flags;
  uint8_t initiator;
  uint8_t initialized;  // strobe is initialized if this value is set to 111.
                        // This is because we cannot assume that a boolean would
                        // be set to false initially (C stuff). A uint8_t is a
                        // short value but here we do not care about security
                        // much, rather catching bugs early in a development
                        // environement.
} strobe_s;

/* Initialize a Strobe object with a protocol name */
void strobe_init(strobe_s *strobe, const char *protocol_name, size_t desclen);

/* Operate on the Strobe object */
bool strobe_operate(strobe_s *strobe, uint8_t control_flags, uint8_t *buffer,
                    size_t buffer_len, bool more);

/* Flags as defined in the paper */
#define FLAG_I (1 << 0) /**< Inbound */
#define FLAG_A (1 << 1) /**< Has application-side data (eg, not a MAC) */
#define FLAG_C (1 << 2) /**< Uses encryption or rekeying. */
#define FLAG_T (1 << 3) /**< Send or receive data via transport */
#define FLAG_M (1 << 4) /**< Operation carries metadata. */

/* Operation types as defined in the paper */
#define TYPE_AD FLAG_A /**< Context data, not sent to trensport */
#define TYPE_KEY                                                             \
  (FLAG_A | FLAG_C)                /**< Symmetric key, not sent to transport \
                                      */
#define TYPE_CLR (FLAG_T | FLAG_A) /**< Data to be sent in the clear */
#define TYPE_ENC (FLAG_T | FLAG_A | FLAG_C) /**< Data sent encrypted */
#define TYPE_MAC (FLAG_T | FLAG_C)          /**< Message authentication code */
#define TYPE_RATCHET FLAG_C /**< Erase data to prevent rollback */
#define TYPE_PRF (FLAG_I | FLAG_A | FLAG_C) /**< Return pseudorandom hash */

bool strobe_isInitialized(strobe_s *strobe);
void strobe_destroy(strobe_s *strobe);
void strobe_print(const strobe_s *strobe);

#endif /* __STROBE_H__ */