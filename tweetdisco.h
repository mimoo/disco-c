#pragma once

#include "strobe.h"

#include <stdlib.h>
#include <stdbool.h>

// clarity shortcuts 
typedef unsigned char u8;
#define TRY(foo) do { ssize_t _ret = (foo); if (_ret < 0) return _ret; } while(0)

// enums
typedef enum token {
  token_e  = 1,
  token_s  = 2,
  token_ee = 3,
  token_es = 4,
  token_se = 5,
  token_ss = 6,
  token_end_turn      = 7,
  token_end_handshake = 8
} token;

// asymmetric
typedef struct keyPair {
  unsigned char private[32];
  unsigned char public[32];
  bool isSet;
} keyPair;

// states
typedef struct symmetricState {
	strobe_t strobe;
	bool isKeyed;
} symmetricState;

typedef struct handshakeState {
	symmetricState symmetric_state;

  keyPair s;
  keyPair e;
  keyPair rs;
  keyPair re;

  bool initiator;
  token *message_patterns; 
  bool sending;
  bool handshake_done;
} handshakeState;

typedef struct handshakePattern {
	u8    name[10];
	token *pre_message_patterns; 
	token *message_patterns; 
} handshakePattern;

// prototypes
void disco_Initialize(handshakeState *hs, handshakePattern hp, bool initiator, u8 *prologue, size_t prologue_len, keyPair *s, keyPair *e, keyPair *rs, keyPair *re);
int disco_WriteMessage(handshakeState *hs, u8 *payload, size_t payload_len, u8 *message_buffer, strobe_t s1, strobe_t s2);
int disco_ReadMessage(handshakeState *hs, u8 *message, size_t message_len, u8 *payload_buffer, strobe_t s1, strobe_t s2);
void disco_generateKeyPair(keyPair *kp);


