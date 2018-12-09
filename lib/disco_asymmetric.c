#include "disco_asymmetric.h"
#include "tweetX25519.h"
#include "tweetstrobe.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

//
// Handshake Patterns
// ==================
// Handshake patterns are written as string literals, where every character
// represent a token. This is implementation-specific and you can safely ignore
// this if you are not auditing the code.

// clang-format off
#define token_e        'e'
#define token_s        's'
#define token_ee       'E'
#define token_es       'R'
#define token_se       'D'
#define token_ss       'S'
#define token_psk      'p'

#define token_end_turn      '|'
#define token_end_handshake '\0'
// clang-format on

//
// Asymmetric Cryptography
// ======
// Used for key exchanges.

static inline void DH(keyPair mine, keyPair theirs, uint8_t *output) {
  crypto_scalarmult(output, mine.priv, theirs.pub);
}

//
// SymmetricState
// ==============
// Refer to the Disco specification to understand the meaning of these
// functions.

static inline void initializeSymmetric(symmetricState *ss,
                                       const char *protocol_name,
                                       size_t protocol_name_len) {
  strobe_init(&(ss->strobe), protocol_name, protocol_name_len);
}

static inline void mixKey(symmetricState *ss, uint8_t *input_key_material) {
  strobe_operate(&(ss->strobe), TYPE_AD, input_key_material, 32, false);
  ss->isKeyed = true;
}

static inline void mixHash(symmetricState *ss, uint8_t *data, size_t data_len) {
  strobe_operate(&(ss->strobe), TYPE_AD, data, data_len, false);
}

/*
static inline void mixKeyAndHash(symmetricState *ss,
                                 uint8_t *input_key_material) {
  strobe_operate(&(ss->strobe), TYPE_AD, input_key_material, 32, false);
}

static inline void getHandshakeHash(symmetricState *ss, uint8_t *result) {
  strobe_operate(&(ss->strobe), TYPE_PRF, result, 32, false);
}
*/

// note that this function modifies the plaintext in place, and requires the
// plaintext buffer to have 16 more bytes of capacity for the authentication tag
// if the symmetric state is keyed
static inline void encryptAndHash(symmetricState *ss, uint8_t *plaintext,
                                  size_t plaintext_len) {
  if (!ss->isKeyed) {
    strobe_operate(&(ss->strobe), TYPE_CLR, plaintext, plaintext_len, false);
  } else {
    strobe_operate(&(ss->strobe), TYPE_ENC, plaintext, plaintext_len, false);
    strobe_operate(&(ss->strobe), TYPE_MAC, plaintext + plaintext_len, 16,
                   false);
  }
}

// note that the decryption occurs in place, and the the result is
// `ciphertext_len-16` in case the symmetric state is keyed.
static inline bool decryptAndHash(symmetricState *ss, uint8_t *ciphertext,
                                  size_t ciphertext_len) {
  if (!ss->isKeyed) {
    return strobe_operate(&(ss->strobe), TYPE_CLR | FLAG_I, ciphertext,
                          ciphertext_len, false);
  }

  if (ciphertext_len < 16) {
    return false;
  }

  strobe_operate(&(ss->strobe), TYPE_ENC | FLAG_I, ciphertext,
                 ciphertext_len - 16, false);

  return strobe_operate(&(ss->strobe), TYPE_MAC | FLAG_I,
                        ciphertext + ciphertext_len - 16, 16, false);
}

// split takes a symmetric state ss, a strobe state s1 and an empty
// but allocated strobe state s2
// TODO: perhaps return only s1 if this is a one-way handshake pattern?
// TODO: how do I ensure that a server don't send msg on a one-way hp?
void split(symmetricState *ss, strobe_s *s1, strobe_s *s2, bool half_duplex) {
  assert(s1 != NULL);
  if (!half_duplex) {
    assert(s2 != NULL);
  }

  // s1 = our current strobe state
  *s1 = ss->strobe;
  if (!half_duplex) {
    // s2 = s1
    *s2 = ss->strobe;
  }

  // differentiate by aborbing different domain strings
  strobe_operate(s1, TYPE_AD | FLAG_M, (uint8_t *)"initiator", 9, false);
  if (!half_duplex) {
    strobe_operate(s2, TYPE_AD | FLAG_M, (uint8_t *)"responder", 9, false);
  }
  // forward-secrecy
  unsigned char ratchet_buffer[32];
  strobe_operate(s1, TYPE_RATCHET, ratchet_buffer, 32, false);
  if (!half_duplex) {
    strobe_operate(s2, TYPE_RATCHET, ratchet_buffer, 32, false);
  }
}

//
// HandshakeState
// ==============
// Refer to the Disco specification to understand the meaning of these
// functions.

// destroy removes any secret information contained in the handshakeState passed
// as argument
void destroy(handshakeState *hs) {
  uint8_t size_to_remove;
  // remove keys
  volatile uint8_t *p;
  if (hs->s.isSet) {
    p = hs->s.priv;
    size_to_remove = 32;
    while (size_to_remove--) {
      *p++ = 0;
    }
  }
  if (hs->e.isSet) {
    p = hs->e.priv;
    size_to_remove = 32;
    while (size_to_remove--) {
      *p++ = 0;
    }
  }
  // remove symmetric state / strobe
  strobe_destroy(&(hs->symmetric_state.strobe));
}

/**
 * @brief to initialize a handshakeState
 * disco_Initialize is used to initialize a non-NULL handshakeState with a
 * protocol name, a Noise handshake pattern, a boolean indicating if the
 * handshakeState represents a client or a server, an optional prologue, a set
 * of optional key pairs (depending on the handshake pattern chosen).
 * @hs           a non-NULL handshakeState to be initialized.
 * @hp           the chosen handshake pattern. see tweetdisco.h for the
 * handshake patterns define (HANDSHAKE_NX, HANDSHAKE_NK, etc.)
 * @initiator    true if the peer is the client (sending the first message).
 * False if the peer is the server.
 * @prologue     any data that was exchanged between the two peers prior to the
 * handshake. See Noise's specification for more information on this field.
 * @prologue_len The length of the `prologue` buffer.
 * @s            NULL or a keypair containing the peer's long-term static key.
 * @e            NULL or a keypair containing the peer's ephemeral key (see
 * fallback patterns in the Noise specification).
 * @rs           NULL or a keypair containing the remote peer's long-term static
 * key.
 * @re           NULL or a keypair containing the remote peer's ephemeral key
 * (see fallback patterns in the Noise specification).
 */
void disco_Initialize(handshakeState *hs, const char *handshake_pattern,
                      bool initiator, uint8_t *prologue, size_t prologue_len,
                      keyPair *s, keyPair *e, keyPair *rs, keyPair *re) {
  assert(handshake_pattern != NULL);
  assert((prologue_len > 0 && prologue != NULL) ||
         (prologue_len == 0 && prologue == NULL));

  // handshake_pattern is of the following form:
  // "protocol_name \x00 pre-message patterns \x00 message patterns"
  initializeSymmetric(&(hs->symmetric_state), handshake_pattern,
                      strlen(handshake_pattern));
  handshake_pattern = handshake_pattern + strlen(handshake_pattern) + 1;

  hs->symmetric_state.isKeyed = false;

  // prologue
  mixHash(&(hs->symmetric_state), prologue, prologue_len);

  // set variables
  if (s != NULL) {
    // TODO: should we do assert(hs->s.isSet) ?
    hs->s = *s;
    hs->s.isSet = true;
  } else {
    hs->s.isSet = false;
  }
  if (e != NULL) {
    hs->e = *e;
    hs->e.isSet = true;
  } else {
    hs->e.isSet = false;
  }
  if (rs != NULL) {
    hs->rs = *rs;
    hs->rs.isSet = true;
  } else {
    hs->rs.isSet = false;
  }
  if (re != NULL) {
    hs->re = *re;
    hs->re.isSet = true;
  } else {
    hs->re.isSet = false;
  }
  hs->initiator = initiator;
  hs->sending = initiator;
  hs->handshake_done = false;

  // pre-messages
  bool direction = true;
  // handshake_pattern is of the following form:
  // pre_message_patterns | token_end_handshake | message_patterns"
  while (*handshake_pattern != token_end_handshake) {
    switch (*handshake_pattern) {
      case token_s:
        if ((initiator && direction) || (!initiator && !direction)) {
          mixHash(&(hs->symmetric_state), hs->s.pub, 32);
        } else {
          mixHash(&(hs->symmetric_state), hs->rs.pub, 32);
        }
        break;
      case token_e:
        if ((initiator && direction) || (!initiator && !direction)) {
          mixHash(&(hs->symmetric_state), hs->e.pub, 32);
        } else {
          mixHash(&(hs->symmetric_state), hs->re.pub, 32);
        }
        break;
      case token_end_turn:
        direction = !direction;
        break;
      case token_end_handshake:
        break;
      default:
        assert(false);
    }
    // next token
    handshake_pattern++;
  }

  // point to message patterns
  hs->message_patterns = handshake_pattern + 1;

  // half duplex is disabled by default
  hs->half_duplex = false;
}

/**
 * disco_WriteMessage takes
 * @hs an initialized `handshakeState`.
 * @payload an optional (can be NULL) payload to send at the end of the
 * handshake message. Depending on the handshake the security properties
 * associated to that payload can be different (even non-existent).
 * @payload_len the length of the optional payload (can be 0).
 * @message_buffer the buffer that will contain the final handshake
 * message to send to the other peer. It must be allocated with enough room for
 * the
 * relevant handshake message's content, the additional payload (of size
 * `payload_len`) and each authentication tag (16 bytes).
 * @message_len will be overwritten with the length of the message written in
 * message_buffer
 * @client_s the Strobe state that will be used by the client to encrypt
 * data
 * post-handshake. It can be set to `NULL` if this is not processing the end of
 * the handshake.
 * @server_s the Strobe state that will be used by the server to encrypt
 * data
 * post-handshake. It can be set to `NULL` if this is not processing the end of
 * the handshake.
 * @return the length of the content written in `message_buffer`.
 */
bool disco_WriteMessage(handshakeState *hs, uint8_t *payload,
                        size_t payload_len, uint8_t *message_buffer,
                        size_t *message_len, strobe_s *client_s,
                        strobe_s *server_s) {
  assert(hs != NULL && message_buffer != NULL);
  assert(
      (payload == NULL && payload_len == 0) ||
      (payload != NULL && payload_len > 0 && payload_len < MAX_SIZE_MESSAGE));
  // TODO: should the payload_len be a return -1 ?
  assert(hs->handshake_done == false && hs->sending == true);

  // Fetches and deletes the next message pattern from message_patterns
  assert(hs->message_patterns != NULL);
  uint8_t *p = message_buffer;
  uint8_t DH_result[32];

  // state machine
  const char *current_token = hs->message_patterns;
  while (true) {
    switch (*current_token) {
      case token_e:
        assert(!hs->e.isSet);
        disco_generateKeyPair(&(hs->e));
        memcpy(p, hs->e.pub, 32);
        p += 32;
        mixHash(&(hs->symmetric_state), hs->e.pub, 32);
        break;
      case token_s:
        assert(hs->s.isSet);
        memcpy(p, hs->s.pub, 32);
        encryptAndHash(&(hs->symmetric_state), p, 32);
        p += 32;
        if (hs->symmetric_state.isKeyed) {
          p += 16;
        }
        break;
      case token_ee:
        // TODO: does this really replaces everything in DH_Result?
        DH(hs->e, hs->re, DH_result);
        mixKey(&(hs->symmetric_state), DH_result);
        // TODO: reset DH_result?
        //
        break;
      case token_es:
        if (hs->initiator) {
          DH(hs->e, hs->rs, DH_result);
        } else {
          DH(hs->s, hs->re, DH_result);
        }
        mixKey(&(hs->symmetric_state), DH_result);
        break;
      case token_se:
        if (hs->initiator) {
          DH(hs->s, hs->re, DH_result);
        } else {
          DH(hs->e, hs->rs, DH_result);
        }
        mixKey(&(hs->symmetric_state), DH_result);
        break;
      case token_ss:
        DH(hs->s, hs->rs, DH_result);
        mixKey(&(hs->symmetric_state), DH_result);
        break;
      case token_end_turn:
        hs->sending = !hs->sending;
        hs->message_patterns = current_token + 1;
        goto payload;
      case token_end_handshake:
        hs->handshake_done = true;
        goto payload;
      default:
        assert(false);
    }
    current_token++;
  }
payload:
  // Payload
  if (payload != NULL) {
    memcpy(p, payload, payload_len);
  }

  encryptAndHash(&(hs->symmetric_state), p, payload_len);

  p += payload_len;
  if (hs->symmetric_state.isKeyed) {
    p += 16;
  }

  // Split?
  if (hs->handshake_done == true) {
    split(&(hs->symmetric_state), client_s, server_s, hs->half_duplex);
    hs->message_patterns = NULL;
    destroy(hs);
  }

  // set length of what was written into buffer
  *message_len = p - message_buffer;

  //
  return true;
}

/**
 * @brief used to read and process the next handshake message.
 * disco_ReadMessage reads and process the next handshake message.
 * @hs             the initialized `handshakeState`.
 * @message        the received message buffer.
 * @message_len    the length of the received message.
 * @payload_buffer this buffer will be over-written with the received
 * payload. Its capacity should contain enough room for it. You can calculate
 * this required size by substracting other content from the message's length.
 * @payload_len    will be the length of the produced payload
 * @client_s       the Strobe state that will be used by the client to
 * encrypt data post-handshake. It can be set to `NULL` if this is not
 * processing the end of the handshake.
 * @server_s       the Strobe state that will be used by the server to
 * encrypt data post-handshake. It can be set to `NULL` if this is not
 * processing the end of the handshake.
 * @return                the length of the content written in `payload_buffer`.
 */
bool disco_ReadMessage(handshakeState *hs, uint8_t *message, size_t message_len,
                       uint8_t *payload_buffer, size_t *payload_len,
                       strobe_s *client_s, strobe_s *server_s) {
  assert(hs != NULL && message != NULL && payload_buffer != NULL);
  assert(hs->handshake_done == false && hs->sending == false);
  assert(hs->message_patterns != NULL);

  if (message_len >= 65535) {
    return false;
  }
  uint8_t DH_result[32];

  // state machine
  const char *current_token = hs->message_patterns;
  while (true) {
    switch (*current_token) {
      case token_e:
        if (message_len < 32) {
          return false;
        }
        assert(!hs->re.isSet);
        memcpy(hs->re.pub, message, 32);
        message_len -= 32;
        message += 32;
        hs->re.isSet = true;
        mixHash(&(hs->symmetric_state), hs->re.pub, 32);
        break;
      case token_s:
        assert(!hs->rs.isSet);
        size_t ciphertext_len = 32;
        if (hs->symmetric_state.isKeyed) {
          ciphertext_len += 16;
        }
        if (message_len < ciphertext_len) {
          return false;
        }

        bool res =
            decryptAndHash(&(hs->symmetric_state), message, ciphertext_len);
        if (!res) {
          return false;
        }
        memcpy(hs->rs.pub, message, 32);
        message_len -= ciphertext_len;
        message += ciphertext_len;
        hs->rs.isSet = true;
        break;
      case token_ee:
        // TODO: does this really replaces everything in DH_Result?
        DH(hs->e, hs->re, DH_result);
        mixKey(&(hs->symmetric_state), DH_result);
        // TODO: reset DH_result?
        break;
      case token_es:
        if (hs->initiator) {
          DH(hs->e, hs->rs, DH_result);
        } else {
          DH(hs->s, hs->re, DH_result);
        }
        mixKey(&(hs->symmetric_state), DH_result);
        break;
      case token_se:
        if (hs->initiator) {
          DH(hs->s, hs->re, DH_result);
        } else {
          DH(hs->e, hs->rs, DH_result);
        }
        mixKey(&(hs->symmetric_state), DH_result);
        break;
      case token_ss:
        DH(hs->s, hs->rs, DH_result);
        mixKey(&(hs->symmetric_state), DH_result);
        break;
      case token_end_turn:
        hs->sending = !hs->sending;
        hs->message_patterns = current_token + 1;
        goto payload;
      case token_end_handshake:
        hs->handshake_done = true;
        goto payload;
      default:
        assert(false);
    }
    current_token++;
  }
payload:
  // Decrypt payload
  if (hs->symmetric_state.isKeyed && message_len < 16) {  // a tag must be here
    return false;
  }
  bool res = decryptAndHash(&(hs->symmetric_state), message, message_len);
  if (!res) {
    return false;  // TODO: should we return different errors?
  }
  if (hs->symmetric_state.isKeyed) {
    message_len -= 16;  // remove the authentication tag if there is one
  }
  memcpy(payload_buffer, message, message_len);

  // Split?
  if (hs->handshake_done == true) {
    split(&(hs->symmetric_state), client_s, server_s, hs->half_duplex);
    hs->message_patterns = NULL;
    destroy(hs);
  }

  // set the decrypted payload length
  *payload_len = message_len;

  // return length of what was read into buffer
  return true;
}

// disco_EncryptInPlace takes a plaintext and replaces it with the encrypted
// plaintext and 16 bytes of authentication tag.
// For this reason, the buffer must have 16 additional bytes than plaintext_len
// Note that the strobe state is also mutated to reflect the send_ENC and
// send_MAC operations
void disco_EncryptInPlace(strobe_s *strobe, uint8_t *plaintext,
                          size_t plaintext_len, size_t plaintext_capacity) {
  assert(plaintext_capacity >= plaintext_len + 16);
  assert(plaintext != NULL);
  strobe_operate(strobe, TYPE_ENC, plaintext, plaintext_len, false);
  strobe_operate(strobe, TYPE_MAC, plaintext + plaintext_len, 16, false);
}

// disco_DecryptInPlace decrypts the ciphertext and replaces the buffer's
// content with the obtained plaintext. the new length will be 16 bytes less
// Note that the strobe state is also mutated to reflect the recv_ENC and
// recv_MAC operations
bool disco_DecryptInPlace(strobe_s *strobe, uint8_t *ciphertext,
                          size_t ciphertext_len) {
  assert(ciphertext != NULL);
  // can't contain authentication tag
  if (ciphertext_len < 16) {
    return false;
  }
  // decrypt in place
  strobe_operate(strobe, TYPE_ENC | FLAG_I, ciphertext, ciphertext_len - 16,
                 false);
  // verify authentication tag
  int res = strobe_operate(strobe, TYPE_MAC | FLAG_I,
                           ciphertext + ciphertext_len - 16, 16, false);
  // bad authentication tag
  if (res < 0) {
    return false;
    // TODO: should we destroy the strobe object at this point?
  }
  // all good
  return true;
}
