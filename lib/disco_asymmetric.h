/**
 * The EmbeddedDisco Library
 * =========================
 *
 * This protocol was designed and implemented by David Wong.
 * - contact: david.wong@nccgroup.trust
 * - more info: www.embeddeddisco.com
 *
 */

#ifndef __DISCO_H__
#define __DISCO_H__

#include "tweetstrobe.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

// the maximum size of a Disco (encrypted or not) message
#define MAX_SIZE_MESSAGE 65000

// asymmetric
typedef struct keyPair_ {
  uint8_t priv[32];
  uint8_t pub[32];
  bool isSet;
} keyPair;

//
// Handshake Patterns
// =================
// The following defines were generated using python
// You can manually audit the handshake_patterns.py file

#define HANDSHAKE_N "Noise_N_25519_STROBEv1.0.2\0|s\0eR\0"
#define HANDSHAKE_K "Noise_K_25519_STROBEv1.0.2\0s|s\0eRS\0"
#define HANDSHAKE_X "Noise_X_25519_STROBEv1.0.2\0|s\0eRsS\0"
#define HANDSHAKE_NN "Noise_NN_25519_STROBEv1.0.2\0\0e|eE\0"
#define HANDSHAKE_KN "Noise_KN_25519_STROBEv1.0.2\0s\0e|eED\0"
#define HANDSHAKE_NK "Noise_NK_25519_STROBEv1.0.2\0|s\0eR|eE\0"
#define HANDSHAKE_KK "Noise_KK_25519_STROBEv1.0.2\0s|s\0eRS|eED\0"
#define HANDSHAKE_NX "Noise_NX_25519_STROBEv1.0.2\0\0e|eEsR\0"
#define HANDSHAKE_KX "Noise_KX_25519_STROBEv1.0.2\0s\0e|eEDsR\0"
#define HANDSHAKE_XN "Noise_XN_25519_STROBEv1.0.2\0\0e|eE|sD\0"
#define HANDSHAKE_IN "Noise_IN_25519_STROBEv1.0.2\0\0es|eED\0"
#define HANDSHAKE_XK "Noise_XK_25519_STROBEv1.0.2\0|s\0eR|eE|sD\0"
#define HANDSHAKE_IK "Noise_IK_25519_STROBEv1.0.2\0|s\0eRsS|eED\0"
#define HANDSHAKE_XX "Noise_XX_25519_STROBEv1.0.2\0\0e|eEsR|sD\0"
#define HANDSHAKE_IX "Noise_IX_25519_STROBEv1.0.2\0\0es|eEDsR\0"

//
// States
// ======
// See the Disco specification to understand the meaning of these states.

typedef struct symmetricState_ {
  strobe_s strobe;
  bool isKeyed;
} symmetricState;

typedef struct handshakeState_ {
  symmetricState symmetric_state;

  keyPair s;
  keyPair e;
  keyPair rs;
  keyPair re;

  bool initiator;
  const char *message_patterns;
  bool sending;
  bool handshake_done;

  bool half_duplex;
} handshakeState;

//
// Public API
// ==========

// used to generate long-term key pairs
void disco_generateKeyPair(keyPair *kp);

// used to initialized your handshakeState with a handshake pattern
void disco_Initialize(handshakeState *hs, const char *handshake_pattern,
                      bool initiator, uint8_t *prologue, size_t prologue_len,
                      keyPair *s, keyPair *e, keyPair *rs, keyPair *re);

// used to generate the next handshake message to send
bool disco_WriteMessage(handshakeState *hs, uint8_t *payload,
                        size_t payload_len, uint8_t *message_buffer,
                        size_t *message_len, strobe_s *client_s,
                        strobe_s *server_s);

// used to parse a the last handshake message received
bool disco_ReadMessage(handshakeState *hs, uint8_t *message, size_t message_len,
                       uint8_t *payload_buffer, size_t *payload_len,
                       strobe_s *client_s, strobe_s *server_s);

// post-handshake encryption
void disco_EncryptInPlace(strobe_s *strobe, uint8_t *plaintext,
                          size_t plaintext_len, size_t plaintext_capacity);

// post-handshake decryption
bool disco_DecryptInPlace(strobe_s *strobe, uint8_t *ciphertext,
                          size_t ciphertext_len);

//
//
//

#endif /* __DISCO_H__ */