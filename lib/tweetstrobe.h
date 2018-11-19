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
#pragma once

// remember:

#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <stdbool.h>

#include "strobe_config.h"

// Size of the Keccak permutation
#if STROBE_INTEROP_F_BITS == 1600
#define kword_t uint64_t
#elif STROBE_INTEROP_F_BITS == 800
#define kword_t uint32_t
#elif STROBE_INTEROP_F_BITS == 400
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
typedef struct strobe_s {
  kdomain_s state;
  uint8_t position;
  uint8_t pos_begin;
  uint8_t flags;
  uint8_t initiator;
  bool initialized;
} strobe_s;

/* Initialize a Strobe object with a protocol name */
void strobe_init(struct strobe_s *__restrict__ strobe,
                 const uint8_t *protocol_name, size_t desclen);

/* Operate on the Strobe object */
ssize_t strobe_operate(struct strobe_s *__restrict__ strobe,
                       uint8_t control_flags, uint8_t *buffer,
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

#if STROBE_CW_MAX_LENGTH_BYTES <= 1
typedef uint8_t strobe_length_t;
#elif STROBE_CW_MAX_LENGTH_BYTES <= 2
typedef uint16_t strobe_length_t;
#elif STROBE_CW_MAX_LENGTH_BYTES <= 4
typedef uint32_t strobe_length_t;
#elif STROBE_CW_MAX_LENGTH_BYTES <= 8
typedef uint64_t strobe_length_t;
#elif STROBE_CW_MAX_LENGTH_BYTES <= 16
typedef uint128_t strobe_length_t;
#else
#error "Can't deal with >128-bit length fields'"
#endif

void strobe_destroy(strobe_s *strobe);
void strobe_clone(const strobe_s *src, strobe_s *dst);
void strobe_print(const strobe_s *strobe);
