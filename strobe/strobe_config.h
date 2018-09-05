/**
 * @file strobe_config.h
 * @copyright
 *   Copyright (c) 2016 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief Configuration for STROBE code.
 */

#ifndef __STROBE_CONFIG_H__
#define __STROBE_CONFIG_H__

/****************************************************************/
/*                            STROBE                            */
/****************************************************************/

#ifndef STROBE_INTEROP_F_BITS
/** INTEROP: STROBE  bit size.  Default is Keccak-F800. */
//#define STROBE_INTEROP_F_BITS 800
#define STROBE_INTEROP_F_BITS 1600
#endif

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

#ifndef STROBE_INTEROP_RATCHET_BYTES
/** INTEROP: number of bytes used by default ratchet operations */
#define STROBE_INTEROP_RATCHET_BYTES (STROBE_INTEROP_SECURITY_BITS/8)
#endif

#ifndef STROBE_SINGLE_THREAD
/**
 * If set, assert that STROBE functions (in particular, strobe_randomize)
 * will only ever be called by a single thread, so that thread-safety is not
 * required.
 */
#define STROBE_SINGLE_THREAD 0
#endif

#ifndef STROBE_IO_CTX_HAS_FD
/** IO contexts has a "file descriptor" pointer (for sockets on a non-embedded system) */
#define STROBE_IO_CTX_HAS_FD 1
#endif

#ifndef STROBE_OPT_FOR_SIZE
/** Global: optimize STROBE code for size at the expense of speed. */
#define STROBE_OPT_FOR_SIZE 0
#endif

#ifndef STROBE_OPT_FOR_SPEED
/** Global: optimize STROBE code for speed at the expense of size. */
#define STROBE_OPT_FOR_SPEED 0
#endif

#ifndef STROBE_SANITY_CHECK_FLAGS
/** On each operation, sanity-check that the flags requested are actually
 * implemented, eg that the caller isn't using the MORE flag when the callee
 * ifdef'd it out.
 */
#define STROBE_SANITY_CHECK_FLAGS 1
#endif

#ifndef STROBE_SUPPORT_PRNG
/** Support pseudorandom generator.
 * Required by A New Hope, convenience ECDH, nondeterministic signing.
 */
#define STROBE_SUPPORT_PRNG 1
#endif

#ifndef STROBE_SUPPORT_FLAG_POST
/** Support experimental post-op flags FLAG_POST_RATCHET, FLAG_POST_MAC */
#define STROBE_SUPPORT_FLAG_POST 1
#endif

#ifndef STROBE_INTEROP_MAC_BYTES
/** The MAC length, used by MAC convenience functions */
#define STROBE_INTEROP_MAC_BYTES 16
#endif

#ifndef STROBE_CW_MAX_LENGTH_BYTES
/** Maximum number of bytes in a length field */
#define STROBE_CW_MAX_LENGTH_BYTES 4
#endif

#ifndef STROBE_CONVENIENCE_ECDH
/** Support convenient strobe_eph_ecdh function.
 *
 * You might not want this even if you're using ECDH, because
 * it implies a particular message flow.
 */
#define STROBE_CONVENIENCE_ECDH 1
#endif

/****************************************************************/
/*                            X25519                            */
/****************************************************************/

#ifndef X25519_SUPPORT_SIGN
/** Support creation of X25519 signatures.  NB: these are different from Ed25519 signatures! */
#define X25519_SUPPORT_SIGN 1
#endif

#ifndef X25519_DETERMINISTIC_SIGS
/** Make X25519 signatures deterministic */
#define X25519_DETERMINISTIC_SIGS 1
#endif

#ifndef X25519_SUPPORT_VERIFY
/** Support verification of X25519 signatures. */
#define X25519_SUPPORT_VERIFY X25519_SUPPORT_SIGN
#endif

#ifndef STROBE_EC_SIGN_P1
/** Default sign and verify algorithms. */
#if X25519_SUPPORT_SIGN
#define STROBE_EC_SIGN_P1 x25519_base_uniform
#define STROBE_EC_SIGN_P2 x25519_sign_p2
#endif
#if X25519_SUPPORT_VERIFY
#define STROBE_EC_VERIFY x25519_verify_p2
#endif
#endif

#ifndef STROBE_SUPPORT_CERT_VERIFY
/** Support certificate verify */
#define STROBE_SUPPORT_CERT_VERIFY X25519_SUPPORT_VERIFY
#endif

#ifndef X25519_USE_POWER_CHAIN
/** Use less time and more code for inversion in X25519 */
#define X25519_USE_POWER_CHAIN (!STROBE_OPT_FOR_SIZE)
#endif

#ifndef X25519_WBITS
/** Curve25519: Internal word width for implementation.  Should be
 * set to the target machine's word size.  Supported 16, 32, 64.
 */
#ifdef __SIZEOF_INT128__
#define X25519_WBITS 64
#else
#define X25519_WBITS 32
#endif
#endif

#ifndef X25519_MEMCPY_PARAMS
/** Copy parameters in and out instead of referencing them.
 * Required on big-endian systems and those with strong alignment constraints.
 */
#if __ARMEL__ && defined(__ARM_FEATURE_UNALIGNED) && __ARM_FEATURE_UNALIGNED == 0
#define X25519_MEMCPY_PARAMS 1
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define X25519_MEMCPY_PARAMS 0
#else
#define X25519_MEMCPY_PARAMS 1
#endif
#endif

#endif // __STROBE_CONFIG_H__

