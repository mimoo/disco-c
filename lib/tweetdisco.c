//
// THIS IS BETA SOFTWARE
//
// TODO:
// * do we need to check return value of strobe_operate() ?
// 	- sounds like it either returns -1 or len (or important info for
// recv_MAC)
//
#include "tweetdisco.h"
#include "tweet25519.h"
#include "tweetstrobe.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

//
// Crypto
//

void disco_generateKeyPair(keyPair *kp) {
  crypto_box_keypair(kp->pub, kp->priv);
  kp->isSet = true;
}

void DH(keyPair mine, keyPair theirs, uint8_t *output) {
  crypto_scalarmult(output, mine.priv, theirs.pub);
}

//
// SymmetricState
//

void initializeSymmetric(symmetricState *ss, uint8_t *protocol_name,
                         size_t protocol_name_len) {
  strobe_init(&(ss->strobe), protocol_name, protocol_name_len);
}

void mixKey(symmetricState *ss, uint8_t *input_key_material) {
  strobe_operate(&(ss->strobe), TYPE_AD, input_key_material, 32, false);
  ss->isKeyed = true;
}

void mixHash(symmetricState *ss, uint8_t *data, size_t data_len) {
  strobe_operate(&(ss->strobe), TYPE_AD, data, data_len, false);
}

void mixKeyAndHash(symmetricState *ss, uint8_t *input_key_material) {
  strobe_operate(&(ss->strobe), TYPE_AD, input_key_material, 32, false);
}

void getHandshakeHash(symmetricState *ss, uint8_t *result) {
  strobe_operate(&(ss->strobe), TYPE_PRF, result, 32, false);
}

// two things that are bad here:
// * out must be of length plaintext_len + 16
// * this modifies the plaintext
void encryptAndHash(symmetricState *ss, uint8_t *plaintext,
                    size_t plaintext_len) {
  if (!ss->isKeyed) {
    strobe_operate(&(ss->strobe), TYPE_CLR, plaintext, plaintext_len, false);
  } else {
    strobe_operate(&(ss->strobe), TYPE_ENC, plaintext, plaintext_len, false);
    strobe_operate(&(ss->strobe), TYPE_MAC, plaintext + plaintext_len, 16,
                   false);
  }
}

// bad thing:
// * the caller needs to check if the ciphertext_len is greater than 16!!!!!!
// 		- re-read Disco, but the check is actually only for isKeyed =
// true
// 		- but it should be for both, when it's not true, we are
// expecting
// a
// key right?
bool decryptAndHash(symmetricState *ss, uint8_t *ciphertext,
                    size_t ciphertext_len) {
  if (!ss->isKeyed) {
    strobe_operate(&(ss->strobe), TYPE_CLR | FLAG_I, ciphertext, ciphertext_len,
                   false);
  } else {
    if (ciphertext_len < 16) {
      return false;
    }

    /*

    strobe_operate(strobe, TYPE_ENC | FLAG_I, ciphertext, ciphertext_len - 16,
                   false);
    // verify authentication tag
    ssize_t res = strobe_operate(strobe, TYPE_MAC | FLAG_I,
                                 ciphertext + ciphertext_len - 16, 16, false);
     */

    strobe_operate(&(ss->strobe), TYPE_ENC | FLAG_I, ciphertext,
                   ciphertext_len - 16, false);

    ssize_t res = strobe_operate(&(ss->strobe), TYPE_MAC | FLAG_I,
                                 ciphertext + ciphertext_len - 16, 16, false);
    if (res < 0) {
      return false;
    }
  }
  return true;
}

unsigned char ratchet_buffer[16];

// split takes a symmetric state ss, a strobe state s1 and an empty
// but allocated strobe state s2
// TODO: perhaps return only s1 if this is a one-way handshake pattern?
// TODO: how do I ensure that a server don't send msg on a one-way hp?
void split(symmetricState *ss, strobe_s *s1, strobe_s *s2) {
  assert(s1 != NULL && s2 != NULL);
  // s1 = our current strobe state
  strobe_clone(&(ss->strobe), s1);

  // s2 = s1
  strobe_clone(s1, s2);

  //
  strobe_operate(s1, TYPE_AD | FLAG_M, (uint8_t *)"initiator", 9, false);
  strobe_operate(s2, TYPE_AD | FLAG_M, (uint8_t *)"responder", 9, false);

  for (int i = 0; i < 16; i++) {
    ratchet_buffer[i] = 0;
  }
  strobe_operate(s1, TYPE_RATCHET, ratchet_buffer, 16, false);
  for (int i = 0; i < 16; i++) {
    ratchet_buffer[i] = 0;
  }
  strobe_operate(s2, TYPE_RATCHET, ratchet_buffer, 16, false);
}

//
// handshakeState
//

// destroy hs except symmetric state
void destroy(handshakeState *hs) {
  int size_to_remove;
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

// disco_Initialize needs the symmetric_state
void disco_Initialize(handshakeState *hs, const handshakePattern hp,
                      bool initiator, uint8_t *prologue, size_t prologue_len,
                      keyPair *s, keyPair *e, keyPair *rs, keyPair *re) {
  assert(hs != NULL);
  assert((prologue_len > 0 && prologue != NULL) ||
         (prologue_len == 0 && prologue == NULL));

  // checking if keys are set correctly
  if (strcmp((const char *)hp.name, "N") == 0) {
    assert((initiator && rs) || (!initiator && s));
  }
  // TODO: more checks that we're initializing with the correct keys depending
  // on the handshake pattern

  // derive protocol name
  char protocol_name[40];  // 27 + \0 (removed later) + "psk0" + "psk1" +
                           // "psk2" <
                           // 40 // TODO: DEFFERED PATTERNS?
  sprintf(protocol_name, "Noise_%s_25519_STROBEv1.0.2", hp.name);

  initializeSymmetric(&(hs->symmetric_state), (uint8_t *)protocol_name,
                      strlen((char *)protocol_name));

  hs->symmetric_state.isKeyed = false;

  // prologue
  if (prologue != NULL && prologue_len != 0) {
    mixHash(&(hs->symmetric_state), prologue, prologue_len);
  }

  // set variables
  if (s != NULL) {
    hs->s = *s;
    hs->s.isSet = true;
  } else {
    hs->s.isSet = false;  // needed, I don't know why...
  }
  if (e != NULL) {
    hs->e = *e;
    hs->e.isSet = true;
  } else {
    hs->e.isSet = false;  // needed
  }
  if (rs != NULL) {
    hs->rs = *rs;
    hs->rs.isSet = true;
  } else {
    hs->rs.isSet = false;  // needed
  }
  if (re != NULL) {
    hs->re = *re;
    hs->re.isSet = true;
  } else {
    hs->re.isSet = false;  // needed
  }
  hs->initiator = initiator;
  hs->sending = initiator;
  hs->handshake_done = false;

  // pre-message
  bool direction = true;
  token current_token = token_end_turn;
  for (uint8_t token_counter = 0; current_token != token_end_handshake;
       token_counter++) {
    current_token = hp.pre_message_patterns[token_counter];
    switch (current_token) {
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
  }

  // point to message patterns
  hs->message_patterns = hp.message_patterns;
}

// idea:
// * have a fixed sized buffer for sending messages during the handshake
// * have a fixed sized buffer for receiving messages during the handshake
// * same buffer?
// * reset buffer to 0 everytime right before writing to it?
ssize_t disco_WriteMessage(handshakeState *hs, uint8_t *payload,
                           size_t payload_len, uint8_t *message_buffer,
                           strobe_s *client_s, strobe_s *server_s) {
  assert(hs != NULL && payload != NULL && message_buffer != NULL);
  assert(hs->handshake_done == false && hs->sending == true);

  // Fetches and deletes the next message pattern from message_patterns
  assert(hs->message_patterns != NULL);
  uint8_t *p = message_buffer;
  uint8_t DH_result[32];

  // state machine
  token *current_token = hs->message_patterns;
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
  assert(!(payload == NULL && payload_len != 0));
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
    split(&(hs->symmetric_state), client_s, server_s);
    hs->message_patterns = NULL;
    destroy(hs);
  }

  // return length of what was written into buffer
  return p - message_buffer;
}

// disco_ReadMessage reads and process the next message.
// TODO: this is not the nicest API at the moment because the caller does not
// know how much size it should allocate to the payload_buffer argument
ssize_t disco_ReadMessage(handshakeState *hs, uint8_t *message,
                          size_t message_len, uint8_t *payload_buffer,
                          strobe_s *client_s, strobe_s *server_s) {
  assert(hs != NULL && message != NULL && payload_buffer != NULL);
  assert(hs->handshake_done == false && hs->sending == false);

  // Fetches and deletes the next message pattern from message_patterns
  assert(hs->message_patterns != NULL);
  uint8_t DH_result[32];

  // state machine
  token *current_token = hs->message_patterns;
  while (true) {
    switch (*current_token) {
      case token_e:
        if (message_len < 32) {
          return -1;
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
        int ciphertext_len = 32;
        if (hs->symmetric_state.isKeyed) {
          ciphertext_len += 16;
        }
        if (message_len < ciphertext_len) {
          return -1;
        }

        bool res =
            decryptAndHash(&(hs->symmetric_state), message, ciphertext_len);
        if (!res) {
          return -1;
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
  // Payload
  if (hs->symmetric_state.isKeyed && message_len < 16) {  // a tag must be here
    return -1;
  }
  bool res = decryptAndHash(&(hs->symmetric_state), message, message_len);
  if (!res) {
    return -1;
  }

  // the real length of the message (minus tag)
  if (hs->symmetric_state.isKeyed) {
    message_len -= 16;
  }
  // TODO: payload_buffer might not have enough room
  // only copy what's left in payload buffer!!!
  memcpy(payload_buffer, message, message_len);

  // Split?
  if (hs->handshake_done == true) {
    split(&(hs->symmetric_state), client_s, server_s);
    hs->message_patterns = NULL;
    destroy(hs);
  }

  // return length of what was read into buffer
  return message_len;
}

// disco_EncryptInPlace takes a plaintext and replaces it with the encrypted
// plaintext
// and 16 bytes of authentication tag.
// For this reason, the buffer must have 16 additional bytes than plaintext_len
// Note that the strobe state is also mutated to reflect the send_ENC and
// send_MAC operations
void disco_EncryptInPlace(strobe_s *strobe, uint8_t *plaintext,
                          size_t plaintext_len, size_t plaintext_capacity) {
  assert(plaintext_capacity == plaintext_len + 16);
  strobe_operate(strobe, TYPE_ENC, plaintext, plaintext_len, false);
  strobe_operate(strobe, TYPE_MAC, plaintext + plaintext_len, 16, false);
}

// disco_DecryptInPlace decrypts the ciphertext and replaces the buffer's
// content
// with the obtained plaintext. the new length will be 16 bytes less
// Note that the strobe state is also mutated to reflect the recv_ENC and
// recv_MAC operations
bool disco_DecryptInPlace(strobe_s *strobe, uint8_t *ciphertext,
                          size_t ciphertext_len) {
  // can't contain authentication tag
  if (ciphertext_len < 16) {
    return false;
  }
  // decrypt in place
  strobe_operate(strobe, TYPE_ENC | FLAG_I, ciphertext, ciphertext_len - 16,
                 false);
  // verify authentication tag
  ssize_t res = strobe_operate(strobe, TYPE_MAC | FLAG_I,
                               ciphertext + ciphertext_len - 16, 16, false);
  // bad authentication tag
  if (res < 0) {
    return false;
    // TODO: should we destroy the strobe object at this point?
  }
  // all good
  return true;
}
