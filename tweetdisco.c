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

//
// Crypto
//

void disco_generateKeyPair(keyPair *kp) {
  crypto_box_keypair(kp->pub, kp->priv);
  kp->isSet = true;
}

void _disco_DH(keyPair mine, keyPair theirs, u8 *output) {
  crypto_scalarmult(output, mine.priv, theirs.pub);
}

//
// SymmetricState
//

void _disco_InitializeSymmetric(symmetricState *ss, u8 *protocol_name,
                                size_t protocol_name_len) {
  strobe_init(&(ss->strobe), protocol_name, protocol_name_len);
}

void _disco_MixKey(symmetricState *ss, u8 *input_key_material) {
  strobe_operate(&(ss->strobe), TYPE_AD, input_key_material, 32, false);
  ss->isKeyed = true;
}

void _disco_MixHash(symmetricState *ss, u8 *data, size_t data_len) {
  strobe_operate(&(ss->strobe), TYPE_AD, data, data_len, false);
}

void _disco_MixKeyAndHash(symmetricState *ss, u8 *input_key_material) {
  strobe_operate(&(ss->strobe), TYPE_AD, input_key_material, 32, false);
}

void _disco_GetHandshakeHash(symmetricState *ss, u8 *result) {
  strobe_operate(&(ss->strobe), TYPE_PRF, result, 32, false);
}

// two things that are bad here:
// * out must be of length plaintext_len + 16
// * this modifies the plaintext
void _disco_EncryptAndHash(symmetricState *ss, u8 *plaintext,
                           size_t plaintext_len) {
  if (!ss->isKeyed) {
    strobe_operate(&(ss->strobe), TYPE_CLR, plaintext, plaintext_len, false);
  } else {
    printf("debug2:");
    for (int i = 0; i < plaintext_len + 16; i++) {
      printf("%02x", plaintext[i]);
    }
    printf("\n");
    strobe_operate(&(ss->strobe), TYPE_ENC, plaintext, plaintext_len, false);
    printf("strobe state before send_MAC:\n");
    for (int i = 0; i < sizeof(ss->strobe->state); i++) {
      printf("%02x", ss->strobe->state.b[i]);
    }
    printf("\n");

    // prepare for tag
    for (int i = 0; i < 16; i++) {
      plaintext[i + plaintext_len] = 0;
    }
    strobe_operate(&(ss->strobe), TYPE_MAC, plaintext + plaintext_len, 16,
                   false);
    printf("strobe state after send_MAC:\n");
    for (int i = 0; i < sizeof(ss->strobe->state); i++) {
      printf("%02x", ss->strobe->state.b[i]);
    }
    printf("\n");
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
bool _disco_DecryptAndHash(symmetricState *ss, u8 *ciphertext,
                           size_t ciphertext_len) {
  if (!ss->isKeyed) {
    strobe_operate(&(ss->strobe), TYPE_CLR | FLAG_I, ciphertext, ciphertext_len,
                   false);
  } else {
    if (ciphertext_len < 16) {
      return false;
    }
    strobe_operate(&(ss->strobe), TYPE_ENC | FLAG_I, ciphertext,
                   ciphertext_len - 16, false);
    printf("strobe state before recv_MAC:\n");
    for (int i = 0; i < sizeof(ss->strobe->state); i++) {
      printf("%02x", ss->strobe->state.b[i]);
    }
    printf("\n");
    printf("mac on:\n");
    for (int i = 0; i < 16; i++) {
      printf("%02x", ciphertext[ciphertext_len - 16 + i]);
    }
    printf("\n");
    ssize_t res = strobe_operate(&(ss->strobe), TYPE_MAC | FLAG_I,
                                 ciphertext + ciphertext_len - 16, 16, false);
    printf("strobe state after recv_MAC:\n");
    for (int i = 0; i < sizeof(ss->strobe.state); i++) {
      printf("%02x", ss->strobe.state.b[i]);
    }
    printf("\n");
    if (res < 0) {
      printf("hey\n");
      return false;
    }
  }
  return true;
}

unsigned char ratchet_buffer[16];

// _disco_Split takes a symmetric state ss, a strobe state s1 and an empty
// but allocated strobe state s2
// TODO: perhaps return only s1 if this is a one-way handshake pattern?
// TODO: how do I ensure that a server don't send msg on a one-way hp?
void _disco_Split(symmetricState *ss, strobe_s **s1, strobe_s **s2) {
  assert(ss != NULL);
  assert(s1 != NULL && s2 != NULL);
  assert(*s1 == NULL && *s2 == NULL);

  // s1 = our current strobe state
  *s1 = &(ss->strobe);
  printf("DEBUG: %p %p\n\n", s1, s2);

  // s2 = s1
  *s2 = (strobe_s *)calloc(1, sizeof(strobe_s));
  strobe_clone(*s1, *s2);

  //
  strobe_operate(*s1, TYPE_AD | FLAG_M, (u8 *)"initiator", 9, false);
  strobe_operate(*s2, TYPE_AD | FLAG_M, (u8 *)"responder", 9, false);

  for (int i = 0; i < 16; i++) {
    ratchet_buffer[i] = 0;
  }
  strobe_operate(*s1, TYPE_RATCHET, ratchet_buffer, 16, false);
  for (int i = 0; i < 16; i++) {
    ratchet_buffer[i] = 0;
  }
  strobe_operate(*s2, TYPE_RATCHET, ratchet_buffer, 16, false);

  printf("DEBUG: %p %p\n\n", s1, s2);
}

//
// handshakeState
//

// destroy hs except symmetric state
void _disco_Destroy(handshakeState *hs) {
  int size_to_remove;
  volatile u8 *p;
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
}

// disco_Initialize needs the symmetric_state
void disco_Initialize(handshakeState *hs, handshakePattern hp, bool initiator,
                      u8 *prologue, size_t prologue_len, keyPair *s, keyPair *e,
                      keyPair *rs, keyPair *re) {
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

  _disco_InitializeSymmetric(&(hs->symmetric_state), (u8 *)protocol_name,
                             strlen((char *)protocol_name));

  // prologue
  if (prologue != NULL && prologue_len != 0) {
    _disco_MixHash(&(hs->symmetric_state), prologue, prologue_len);
  }

  // set variables
  if (s != NULL) {
    hs->s = *s;
    hs->s.isSet = true;
  }
  if (e != NULL) {
    hs->e = *e;
    hs->e.isSet = true;
  }
  if (rs != NULL) {
    hs->rs = *rs;
    hs->rs.isSet = true;
  }
  if (re != NULL) {
    hs->re = *re;
    hs->re.isSet = true;
  }
  hs->initiator = initiator;
  hs->sending = initiator;
  hs->handshake_done = false;

  // pre-message
  bool direction = true;
  token current_token = token_end_turn;
  for (u8 token_counter = 0; current_token != token_end_handshake;
       token_counter++) {
    current_token = hp.pre_message_patterns[token_counter];
    switch (current_token) {
      case token_s:
        if ((initiator && direction) || (!initiator && !direction)) {
          _disco_MixHash(&(hs->symmetric_state), hs->s.pub, 32);
        } else {
          _disco_MixHash(&(hs->symmetric_state), hs->rs.pub, 32);
        }
        break;
      case token_e:
        if ((initiator && direction) || (!initiator && !direction)) {
          _disco_MixHash(&(hs->symmetric_state), hs->e.pub, 32);
        } else {
          _disco_MixHash(&(hs->symmetric_state), hs->re.pub, 32);
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
int disco_WriteMessage(handshakeState *hs, u8 *payload, size_t payload_len,
                       u8 *message_buffer, strobe_s **client_s,
                       strobe_s **server_s) {
  assert(client_s != NULL && server_s != NULL);
  assert(*client_s == NULL && *server_s == NULL);
  assert(hs != NULL && payload != NULL && message_buffer != NULL);
  assert(hs->handshake_done == false && hs->sending == true);

  // Fetches and deletes the next message pattern from message_patterns
  assert(hs->message_patterns != NULL);
  u8 *p = message_buffer;
  u8 DH_result[32];

  token current_token = token_e;
  u8 token_counter;
  for (token_counter = 0; (current_token != token_end_handshake) &&
                              (current_token != token_end_turn);
       token_counter++) {
    current_token = hs->message_patterns[token_counter];

    switch (current_token) {
      case token_e:
        printf("e token\n");
        assert(!hs->e.isSet);
        disco_generateKeyPair(&(hs->e));
        memcpy(p, hs->e.pub, 32);
        p += 32;
        _disco_MixHash(&(hs->symmetric_state), hs->e.pub, 32);
        break;
      case token_s:
        printf("s token\n");
        assert(hs->s.isSet);
        memcpy(p, hs->s.pub, 32);
        _disco_EncryptAndHash(&(hs->symmetric_state), p, 32);
        p += 32;
        if (hs->symmetric_state->isKeyed) {
          p += 16;
        }
        break;
      case token_ee:
        printf("ee token\n");
        // TODO: does this really replaces everything in DH_Result?
        _disco_DH(hs->e, hs->re, DH_result);
        _disco_MixKey(&(hs->symmetric_state), DH_result);
        // TODO: reset DH_result?
        break;
      case token_es:
        printf("es token\n");
        if (hs->initiator) {
          _disco_DH(hs->e, hs->rs, DH_result);
        } else {
          _disco_DH(hs->s, hs->re, DH_result);
        }
        _disco_MixKey(&(hs->symmetric_state), DH_result);
        break;
      case token_se:
        printf("se token\n");
        if (hs->initiator) {
          _disco_DH(hs->s, hs->re, DH_result);
        } else {
          _disco_DH(hs->e, hs->rs, DH_result);
        }
        _disco_MixKey(&(hs->symmetric_state), DH_result);
        break;
      case token_ss:
        printf("ss token\n");
        _disco_DH(hs->s, hs->rs, DH_result);
        _disco_MixKey(&(hs->symmetric_state), DH_result);
        break;
      case token_end_turn:
        printf("end of turn\n");
        hs->sending = !hs->sending;
        break;
      case token_end_handshake:
        printf("end of handshake\n");
        hs->handshake_done = true;
        break;
      default:
        assert(false);
    }
  }

  // Payload
  assert(!(payload == NULL && payload_len != 0));
  if (payload != NULL) {
    memcpy(p, payload, payload_len);
  }
  _disco_EncryptAndHash(&(hs->symmetric_state), p, payload_len);

  printf("debug:");
  for (int i = 0; i < payload_len + 16; i++) {
    printf("%02x", p[i]);
  }
  printf("\n");

  p += payload_len;
  if (hs->symmetric_state->isKeyed) {
    p += 16;
  }

  // Split?
  if (current_token == token_end_handshake) {
    printf("spliting\n");
    printf("DEBUG: %p %p\n\n", client_s, server_s);
    _disco_Split(&(hs->symmetric_state), client_s, server_s);
    printf("DEBUG: %p %p\n\n", client_s, server_s);
    hs->message_patterns = NULL;
    _disco_Destroy(hs);
  } else {
    hs->message_patterns += token_counter + 1;
  }

  // return length of what was written into buffer
  return p - message_buffer;
}

int disco_ReadMessage(handshakeState *hs, u8 *message, size_t message_len,
                      u8 *payload_buffer, strobe_s **client_s,
                      strobe_s **server_s) {
  assert(client_s != NULL && server_s != NULL);
  assert(*client_s == NULL && *server_s == NULL);
  assert(hs != NULL && message != NULL && payload_buffer != NULL);
  assert(hs->handshake_done == false && hs->sending == false);

  // Fetches and deletes the next message pattern from message_patterns
  assert(hs->message_patterns != NULL);
  u8 DH_result[32];

  token current_token = token_e;
  u8 token_counter;
  for (token_counter = 0; (current_token != token_end_handshake) &&
                              (current_token != token_end_turn);
       token_counter++) {
    current_token = hs->message_patterns[token_counter];

    switch (current_token) {
      case token_e:
        printf("e token\n");
        if (message_len < 32) {
          return -1;
        }
        assert(!hs->re.isSet);
        memcpy(hs->re.pub, message, 32);
        message_len -= 32;
        message += 32;
        hs->re.isSet = true;
        _disco_MixHash(&(hs->symmetric_state), hs->re.pub, 32);
        break;
      case token_s:
        printf("s token\n");
        assert(!hs->s.isSet);
        int ciphertext_len = 32;
        if (hs->symmetric_state->isKeyed) {
          ciphertext_len += 16;
        }
        if (message_len < ciphertext_len) {
          return -1;
        }
        bool res = _disco_DecryptAndHash(&(hs->symmetric_state), message,
                                         ciphertext_len);
        if (!res) {
          return false;
        }
        memcpy(hs->rs.pub, message, 32);
        message_len -= ciphertext_len;
        message += ciphertext_len;
        hs->rs.isSet = true;
        break;
      case token_ee:
        printf("ee token\n");
        // TODO: does this really replaces everything in DH_Result?
        _disco_DH(hs->e, hs->re, DH_result);
        _disco_MixKey(&(hs->symmetric_state), DH_result);
        // TODO: reset DH_result?
        break;
      case token_es:
        printf("es token\n");
        if (hs->initiator) {
          _disco_DH(hs->e, hs->rs, DH_result);
        } else {
          _disco_DH(hs->s, hs->re, DH_result);
        }
        _disco_MixKey(&(hs->symmetric_state), DH_result);
        break;
      case token_se:
        printf("se token\n");
        if (hs->initiator) {
          _disco_DH(hs->s, hs->re, DH_result);
        } else {
          _disco_DH(hs->e, hs->rs, DH_result);
        }
        _disco_MixKey(&(hs->symmetric_state), DH_result);
        break;
      case token_ss:
        printf("ss token\n");
        _disco_DH(hs->s, hs->rs, DH_result);
        _disco_MixKey(&(hs->symmetric_state), DH_result);
        break;
      case token_end_turn:
        printf("end turn token\n");
        hs->sending = !hs->sending;
        break;
      case token_end_handshake:
        printf("end handshake token\n");
        hs->handshake_done = true;
        break;
      default:
        assert(false);
    }
  }

  printf("so far so good, finished reading all tokens\n");

  printf("received handshake encrypted payload:\n");
  for (int i = 0; i < message_len; i++) {
    printf("%02x", message[i]);
  }
  printf("\n");

  printf("strobe state:\n");
  for (int i = 0; i < sizeof(hs->symmetric_state->strobe->state); i++) {
    printf("%02x", hs->symmetric_state->strobe->state.b[i]);
  }
  printf("\n");

  // Payload
  printf("iskeyed: %d - payload_len: %zu\n", hs->symmetric_state->isKeyed,
         message_len);
  if (hs->symmetric_state->isKeyed && message_len < 16) {  // a tag must be here
    return -1;
  }
  printf("trying decryption\n");
  bool res =
      _disco_DecryptAndHash(&(hs->symmetric_state), message, message_len);
  if (!res) {
    return -1;
  }
  // the real length of the message (minus tag)
  if (hs->symmetric_state->isKeyed) {
    message_len -= 16;
  }
  // TODO: payload_buffer might not have enough room
  // only copy what's left in payload buffer!!!
  memcpy(payload_buffer, message, message_len);

  // Split?
  if (current_token == token_end_handshake) {
    printf("splitting!\n");
    _disco_Split(&(hs->symmetric_state), client_s, server_s);
    hs->message_patterns = NULL;
    _disco_Destroy(hs);
  } else {
    hs->message_patterns += token_counter + 1;
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
void disco_EncryptInPlace(strobe_s *strobe, u8 *plaintext, size_t plaintext_len,
                          size_t plaintext_capacity) {
  assert(plaintext_capacity == plaintext_len + 16);
  strobe_operate(strobe, TYPE_ENC, plaintext, plaintext_len, false);
  // prepare for tag
  for (int i = 0; i < 16; i++) {
    plaintext[i + plaintext_len] = 0;
  }
  strobe_operate(strobe, TYPE_MAC, plaintext + plaintext_len, 16, false);
}

// disco_DecryptInPlace decrypts the ciphertext and replaces the buffer's
// content
// with the obtained plaintext. the new length will be 16 bytes less
// Note that the strobe state is also mutated to reflect the recv_ENC and
// recv_MAC operations
bool disco_DecryptInPlace(strobe_s *strobe, u8 *ciphertext,
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
  if (res == -1) {
    return false;
    // TODO: should we destroy the strobe object at this point?
  }
  // all good
  return true;
}
