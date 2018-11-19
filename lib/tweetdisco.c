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
bool _disco_DecryptAndHash(symmetricState *ss, u8 *ciphertext,
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
      printf("heyhey\n");
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
void _disco_Split(symmetricState *ss, strobe_s *s1, strobe_s *s2) {
  assert(s1 != NULL && s2 != NULL);
  // s1 = our current strobe state
  strobe_clone(&(ss->strobe), s1);

  // s2 = s1
  strobe_clone(s1, s2);

  //
  strobe_operate(s1, TYPE_AD | FLAG_M, (u8 *)"initiator", 9, false);
  strobe_operate(s2, TYPE_AD | FLAG_M, (u8 *)"responder", 9, false);

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
void _disco_Destroy(handshakeState *hs) {
  int size_to_remove;
  // remove keys
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
  // remove symmetric state / strobe
  strobe_destroy(&(hs->symmetric_state.strobe));
}

// disco_Initialize needs the symmetric_state
void disco_Initialize(handshakeState *hs, const handshakePattern hp,
                      bool initiator, u8 *prologue, size_t prologue_len,
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

  _disco_InitializeSymmetric(&(hs->symmetric_state), (u8 *)protocol_name,
                             strlen((char *)protocol_name));

  hs->symmetric_state.isKeyed = false;

  // prologue
  if (prologue != NULL && prologue_len != 0) {
    _disco_MixHash(&(hs->symmetric_state), prologue, prologue_len);
  }

  // set variables
  if (s != NULL) {
    printf("init setting s\n");
    hs->s = *s;
    hs->s.isSet = true;
  } else {
    hs->s.isSet = false;  // needed, I don't know why...
  }
  if (e != NULL) {
    printf("init setting e\n");
    hs->e = *e;
    hs->e.isSet = true;
  } else {
    hs->e.isSet = false;  // needed
  }
  if (rs != NULL) {
    printf("init setting rs\n");
    hs->rs = *rs;
    hs->rs.isSet = true;
  } else {
    hs->rs.isSet = false;  // needed
  }
  if (re != NULL) {
    printf("init setting re\n");
    hs->re = *re;
    hs->re.isSet = true;
  } else {
    hs->re.isSet = false;  // needed
  }
  printf("init debug s:%d rs:%d, e:%d, re:%d\n", hs->s.isSet, hs->rs.isSet,
         hs->e.isSet, hs->re.isSet);
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
ssize_t disco_WriteMessage(handshakeState *hs, u8 *payload, size_t payload_len,
                           u8 *message_buffer, strobe_s *client_s,
                           strobe_s *server_s) {
  assert(hs != NULL && payload != NULL && message_buffer != NULL);
  assert(hs->handshake_done == false && hs->sending == true);

  // Fetches and deletes the next message pattern from message_patterns
  assert(hs->message_patterns != NULL);
  u8 *p = message_buffer;
  u8 DH_result[32];

  // state machine
  token *current_token = hs->message_patterns;
  while (true) {
    switch (*current_token) {
      case token_e:
        printf("e token\n");
        assert(!hs->e.isSet);
        disco_generateKeyPair(&(hs->e));
        memcpy(p, hs->e.pub, 32);
        printf("e generated:");
        for (int i = 0; i < 32; i++) {
          printf("%02x", hs->e.pub[i]);
        }
        printf("\n");
        p += 32;
        _disco_MixHash(&(hs->symmetric_state), hs->e.pub, 32);
        break;
      case token_s:
        printf("s token\n");
        printf("strobe state before encrypting s\n");
        strobe_print(&(hs->symmetric_state.strobe));
        assert(hs->s.isSet);
        memcpy(p, hs->s.pub, 32);
        _disco_EncryptAndHash(&(hs->symmetric_state), p, 32);
        printf("encrypted s\n");
        for (int i = 0; i < 32 + 16; i++) {
          printf("%02x", p[i]);
        }
        printf("\n");
        p += 32;
        if (hs->symmetric_state.isKeyed) {
          p += 16;
        }
        break;
      case token_ee:
        printf("ee token\n");
        printf("strobe state before ee\n");
        strobe_print(&(hs->symmetric_state.strobe));
        printf("my e:");
        for (int i = 0; i < 32; i++) {
          printf("%02x", hs->e.pub[i]);
        }
        printf("\ntheir e:");
        for (int i = 0; i < 32; i++) {
          printf("%02x", hs->re.pub[i]);
        }
        printf("\n");
        // TODO: does this really replaces everything in DH_Result?
        _disco_DH(hs->e, hs->re, DH_result);
        _disco_MixKey(&(hs->symmetric_state), DH_result);
        // TODO: reset DH_result?
        //
        printf("strobe state after ee\n");
        for (int i = 0; i < sizeof(hs->symmetric_state.strobe.state); i++) {
          printf("%02x", hs->symmetric_state.strobe.state.b[i]);
        }
        printf("\n");
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
        hs->message_patterns = current_token + 1;
        goto payload;
      case token_end_handshake:
        printf("end of handshake\n");
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

  _disco_EncryptAndHash(&(hs->symmetric_state), p, payload_len);

  printf("strobe state after encrypting payload\n");
  strobe_print(&(hs->symmetric_state.strobe));

  p += payload_len;
  if (hs->symmetric_state.isKeyed) {
    p += 16;
  }

  // Split?
  if (hs->handshake_done == true) {
    printf("spliting\n");
    _disco_Split(&(hs->symmetric_state), client_s, server_s);
    hs->message_patterns = NULL;
    _disco_Destroy(hs);
  }

  // return length of what was written into buffer
  return p - message_buffer;
}

// disco_ReadMessage reads and process the next message.
// TODO: this is not the nicest API at the moment because the caller does not
// know how much size it should allocate to the payload_buffer argument
ssize_t disco_ReadMessage(handshakeState *hs, u8 *message, size_t message_len,
                          u8 *payload_buffer, strobe_s *client_s,
                          strobe_s *server_s) {
  assert(hs != NULL && message != NULL && payload_buffer != NULL);
  assert(hs->handshake_done == false && hs->sending == false);

  // Fetches and deletes the next message pattern from message_patterns
  assert(hs->message_patterns != NULL);
  u8 DH_result[32];

  // state machine
  token *current_token = hs->message_patterns;
  while (true) {
    switch (*current_token) {
      case token_e:
        printf("e token\n");
        if (message_len < 32) {
          return -1;
        }
        assert(!hs->re.isSet);
        memcpy(hs->re.pub, message, 32);
        printf("e received:\n");
        for (int i = 0; i < 32; i++) {
          printf("%02x", hs->re.pub[i]);
        }
        printf("\n");
        message_len -= 32;
        message += 32;
        hs->re.isSet = true;
        _disco_MixHash(&(hs->symmetric_state), hs->re.pub, 32);
        break;
      case token_s:
        printf("s token\n");

        printf("strobe state before decrypting s\n");
        for (int i = 0; i < sizeof(hs->symmetric_state.strobe.state); i++) {
          printf("%02x", hs->symmetric_state.strobe.state.b[i]);
        }
        printf("\n");

        assert(!hs->rs.isSet);
        int ciphertext_len = 32;
        if (hs->symmetric_state.isKeyed) {
          ciphertext_len += 16;
        }
        if (message_len < ciphertext_len) {
          return -1;
        }

        printf("ciphertext to decrypt\n");
        for (int i = 0; i < ciphertext_len; i++) {
          printf("%02x", message[i]);
        }
        printf("\n");
        bool res = _disco_DecryptAndHash(&(hs->symmetric_state), message,
                                         ciphertext_len);
        if (!res) {
          return -1;
        }
        memcpy(hs->rs.pub, message, 32);
        message_len -= ciphertext_len;
        message += ciphertext_len;
        hs->rs.isSet = true;
        break;
      case token_ee:
        printf("ee token\n");
        printf("strobe state before ee\n");
        strobe_print(&(hs->symmetric_state.strobe));
        printf("my e:");
        for (int i = 0; i < 32; i++) {
          printf("%02x", hs->e.pub[i]);
        }
        printf("\ntheir e:");
        for (int i = 0; i < 32; i++) {
          printf("%02x", hs->re.pub[i]);
        }
        printf("\n");

        // TODO: does this really replaces everything in DH_Result?
        _disco_DH(hs->e, hs->re, DH_result);
        _disco_MixKey(&(hs->symmetric_state), DH_result);
        // TODO: reset DH_result?

        printf("strobe state after ee\n");
        for (int i = 0; i < sizeof(hs->symmetric_state.strobe.state); i++) {
          printf("%02x", hs->symmetric_state.strobe.state.b[i]);
        }
        printf("\n");
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
        hs->message_patterns = current_token + 1;
        goto payload;
      case token_end_handshake:
        printf("end handshake token\n");
        hs->handshake_done = true;
        goto payload;
      default:
        assert(false);
    }
    current_token++;
  }
payload:

  printf("so far so good, finished reading all tokens\n");

  // Payload
  if (hs->symmetric_state.isKeyed && message_len < 16) {  // a tag must be here
    return -1;
  }

  printf("trying decryption\n");
  bool res =
      _disco_DecryptAndHash(&(hs->symmetric_state), message, message_len);
  if (!res) {
    return -1;
  }

  printf("strobe state after decrypting payload\n");
  strobe_print(&(hs->symmetric_state.strobe));

  // the real length of the message (minus tag)
  if (hs->symmetric_state.isKeyed) {
    message_len -= 16;
  }
  // TODO: payload_buffer might not have enough room
  // only copy what's left in payload buffer!!!
  memcpy(payload_buffer, message, message_len);

  // Split?
  if (hs->handshake_done == true) {
    printf("splitting!\n");
    _disco_Split(&(hs->symmetric_state), client_s, server_s);
    hs->message_patterns = NULL;
    _disco_Destroy(hs);
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
  if (res < 0) {
    return false;
    // TODO: should we destroy the strobe object at this point?
  }
  // all good
  return true;
}
