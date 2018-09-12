//
// THIS IS BETA SOFTWARE
// 
// TODO:
// * do we need to check return value of strobe_operate() ?
// 	- sounds like it either returns -1 or len (or important info for recv_MAC)
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
	crypto_box_keypair(kp->public, kp->private);
	kp->isSet = true;
}

void _disco_DH(keyPair mine, keyPair theirs, u8 *output) {
	crypto_scalarmult(output, mine.private, theirs.public);
}

//
// SymmetricState
// 

void _disco_InitializeSymmetric(symmetricState *ss, u8 *protocol_name, size_t protocol_name_len) {
	strobe_init(ss->strobe, protocol_name, protocol_name_len);
}

void _disco_MixKey(symmetricState *ss, u8 *input_key_material) {
	strobe_operate(ss->strobe, TYPE_AD, input_key_material, 32, false);
	ss->isKeyed = true;
}

void _disco_MixHash(symmetricState *ss, u8 *data, size_t data_len) {
	strobe_operate(ss->strobe, TYPE_AD, data, data_len, false);
}

void _disco_MixKeyAndHash(symmetricState *ss, u8 *input_key_material) {
	strobe_operate(ss->strobe, TYPE_AD, input_key_material, 32, false);
}

void _disco_GetHandshakeHash(symmetricState *ss, u8 *result) {
	strobe_operate(ss->strobe, TYPE_PRF, result, 32, false);
}

// two things that are bad here:
// * out must be of length plaintext_len + 16
// * this modifies the plaintext
void _disco_EncryptAndHash(symmetricState *ss, u8 *plaintext, size_t plaintext_len) {
	if(!ss->isKeyed) {
		strobe_operate (ss->strobe, TYPE_CLR, plaintext, plaintext_len, false);
	} else {

		printf("debug2:");
		for(int i=0; i<plaintext_len+16;i++) {
			printf("%02x",plaintext[i]);
		}
		printf("\n");
		strobe_operate (ss->strobe, TYPE_ENC, plaintext, plaintext_len, false);
		printf("debug2:");
		for(int i=0; i<plaintext_len+16;i++) {
			printf("%02x",plaintext[i]);
		}
		printf("\n");
		strobe_operate (ss->strobe, TYPE_MAC, plaintext + plaintext_len, 16, false);
	}
}

// bad thing:
// * the caller needs to check if the ciphertext_len is greater than 16!!!!!!
// 		- re-read Disco, but the check is actually only for isKeyed = true
// 		- but it should be for both, when it's not true, we are expecting a key right?
bool _disco_DecryptAndHash(symmetricState *ss, u8 *ciphertext, size_t ciphertext_len) {
	if(!ss->isKeyed) {
		if(ciphertext_len < 32) { // TKTK
			return false;
		}
		strobe_operate (ss->strobe, TYPE_CLR | FLAG_I, ciphertext, ciphertext_len, false);
	} else {
		if(ciphertext_len < 16) {
			return false;
		}
		strobe_operate (ss->strobe, TYPE_ENC | FLAG_I, ciphertext, ciphertext_len - 16, false);
		ssize_t res = strobe_operate (ss->strobe, TYPE_MAC | FLAG_I, ciphertext + ciphertext_len - 16, 16, false);
		if(res == -1) {
			return false;
		}		
	}
	return true;
}

unsigned char ratchet_buffer[16];

void _disco_Split(symmetricState *ss, strobe_s *s1, strobe_t s2) {
	//
	s1 = (strobe_s*)ss->strobe;
	strobe_clone(s1, s2); 

	//
	strobe_operate (s1, TYPE_AD | FLAG_M, (u8*)"initiator", 9, false);
	strobe_operate (s2, TYPE_AD | FLAG_M, (u8*)"responder", 9, false);

	for(int i = 0; i < 16; i++) {
		ratchet_buffer[i] = 0;
	}
	strobe_operate (s1, TYPE_RATCHET, ratchet_buffer, 16, false);
	for(int i = 0; i < 16; i++) {
		ratchet_buffer[i] = 0;
	}
	strobe_operate (s2, TYPE_RATCHET, ratchet_buffer, 16, false);
}

//
// handshakeState
//

// destroy hs except symmetric state
void _disco_Destroy(handshakeState *hs) {
	int size_to_remove;
	volatile u8 *p;
	if(hs->s.isSet) {
		p = hs->s.private;
		size_to_remove = 32;
	  while (size_to_remove--){
	    *p++ = 0;
	 	}
	}
	if(hs->e.isSet) {
		p = hs->e.private;
		size_to_remove = 32;
	  while (size_to_remove--){
	    *p++ = 0;
	 	}
	}
}

void disco_Initialize(handshakeState *hs, handshakePattern hp, bool initiator, u8 *prologue, size_t prologue_len, keyPair *s, keyPair *e, keyPair *rs, keyPair *re) {

	// checking if keys are set correctly
	if(strcmp((const char*)hp.name, "N") == 0) {
		assert((initiator && rs) || (!initiator && s));
	}
	// TODO: more checks that we're initializing with the correct keys depending on the handshake pattern

	// derive protocol name
	u8 protocol_name[40]; // 27 + \0 (removed later) + "psk0" + "psk1" + "psk2" < 40 // TODO: DEFFERED PATTERNS?
	sprintf((char*)protocol_name, "Noise_%s_25519_STROBEv1.0.2", hp.name); 
	_disco_InitializeSymmetric(&(hs->symmetric_state), protocol_name, strlen((char*)protocol_name) - 1);

	// prologue
	if(prologue != NULL && prologue_len != 0) {
		_disco_MixHash(&(hs->symmetric_state), prologue, prologue_len);
	}

	// set variables
	if(s != NULL) {
		hs->s = *s;
		hs->s.isSet = true;
	}
	if(e != NULL) {
		hs->e = *e;
		hs->e.isSet = true;
	}
	if(rs != NULL) {
		hs->rs = *rs;
		hs->rs.isSet = true;
	}
	if(re != NULL) {
		hs->re = *re;
		hs->re.isSet = true;
	}
	hs->initiator = initiator;
	hs->sending = initiator;
	hs->handshake_done = false;

	// pre-message
	bool direction = true;
	token current_token = token_end_turn;
	for(u8 token_counter = 0; current_token != token_end_handshake; token_counter++) {
		current_token = hp.pre_message_patterns[token_counter];
		switch(current_token) {
			case token_s:
				if((initiator && direction) || (!initiator && !direction)) {
					_disco_MixHash(&(hs->symmetric_state), hs->s.public, 32);
				} else {
					_disco_MixHash(&(hs->symmetric_state), hs->rs.public, 32);
				}
				break;
			case token_e:
				if((initiator && direction) || (!initiator && !direction)) {
					_disco_MixHash(&(hs->symmetric_state), hs->e.public, 32);
				} else {
					_disco_MixHash(&(hs->symmetric_state), hs->re.public, 32);
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

	// message patterns
	hs->message_patterns = hp.message_patterns;
}

// idea:
// * have a fixed sized buffer for sending messages during the handshake
// * have a fixed sized buffer for receiving messages during the handshake
// * same buffer?
// * reset buffer to 0 everytime right before writing to it?
int disco_WriteMessage(handshakeState *hs, u8 *payload, size_t payload_len, u8 *message_buffer, strobe_t s1, strobe_t s2) {
	assert(!hs->handshake_done);
	assert(hs->sending);
	// Fetches and deletes the next message pattern from message_patterns
	assert(hs->message_patterns != NULL);
	u8 *p = message_buffer;
	u8 DH_result[32];

	token current_token = token_e;
	u8 token_counter;
	for(token_counter = 0; (current_token != token_end_handshake) && (current_token != token_end_turn); token_counter++) {
		current_token = hs->message_patterns[token_counter];
		switch(current_token) {
			case token_e:
				printf("e token\n");
				assert(!hs->e.isSet);
				disco_generateKeyPair(&(hs->e));
				memcpy(p, hs->e.public, 32);
				p += 32;
				_disco_MixHash(&(hs->symmetric_state), hs->e.public, 32);
				break;
			case token_s:
				printf("s token\n");
				assert(hs->s.isSet);
				memcpy(p, hs->s.public, 32);
				_disco_EncryptAndHash(&(hs->symmetric_state), p, 32);
				p += 32;
				if(hs->symmetric_state.isKeyed) {
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
				if(hs->initiator) {
					_disco_DH(hs->e, hs->rs, DH_result);
				} else {
					_disco_DH(hs->s, hs->re, DH_result);
				}
				_disco_MixKey(&(hs->symmetric_state), DH_result);
				break;
			case token_se:
				printf("se token\n");
				if(hs->initiator) {
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
				hs->sending = !hs->sending;
				break;
			case token_end_handshake:
				hs->handshake_done = true;
				break;
			default:
				assert(false);
		}
	}

	// Payload
	assert(!(payload == NULL && payload_len != 0));
	if(payload != NULL) {
		memcpy(p, payload, payload_len);
	}
	_disco_EncryptAndHash(&(hs->symmetric_state), p, payload_len);


	printf("debug:");
	for(int i=0; i<payload_len+16;i++) {
		printf("%02x",p[i]);
	}
	printf("\n");

	p += payload_len;
	if(hs->symmetric_state.isKeyed) {
		p += 16;
	}


	// Split?
	if(current_token == token_end_handshake) {
		assert(s1 == NULL && s2 != NULL);
		_disco_Split(&(hs->symmetric_state), s1, s2);
		hs->message_patterns = NULL;
		_disco_Destroy(hs);
	} else {
		hs->message_patterns += token_counter + 1;
	}

	// return length of what was written into buffer
	return p - message_buffer;
}


int disco_ReadMessage(handshakeState *hs, u8 *message, size_t message_len, u8 *payload_buffer, strobe_t s1, strobe_t s2) {
	assert(!hs->handshake_done);
	assert(!hs->sending);
	// Fetches and deletes the next message pattern from message_patterns
	assert(hs->message_patterns != NULL);
	u8 DH_result[32];

	token current_token = token_e;
	u8 token_counter;
	for(token_counter = 0; (current_token != token_end_handshake) && (current_token != token_end_turn); token_counter++) {
		current_token = hs->message_patterns[token_counter];
		switch(current_token) {
			case token_e:
				printf("e token\n");
				if(message_len < 32) {
					return -1;
				}
				assert(!hs->re.isSet);
				memcpy(hs->re.public, message, 32);
				message_len -= 32;
				message += 32;
				hs->re.isSet = true;
				_disco_MixHash(&(hs->symmetric_state), hs->re.public, 32);
				break;
			case token_s:
				printf("s token\n");
				assert(!hs->s.isSet);
				int ciphertext_len = 32;
				if(hs->symmetric_state.isKeyed) {
					ciphertext_len += 16;
				}
				if(message_len < ciphertext_len) {
						return -1;
				}
				bool res = _disco_DecryptAndHash(&(hs->symmetric_state), message, ciphertext_len);
				if(!res) {
					return false;
				}
				memcpy(hs->rs.public, message, 32);
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
				if(hs->initiator) {
					_disco_DH(hs->e, hs->rs, DH_result);
				} else {
					_disco_DH(hs->s, hs->re, DH_result);
				}
				_disco_MixKey(&(hs->symmetric_state), DH_result);
				break;
			case token_se:
				printf("se token\n");
				if(hs->initiator) {
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
				hs->sending = !hs->sending;
				break;
			case token_end_handshake:
				hs->handshake_done = true;
				break;
			default:
				assert(false);
		}
	}

	printf("so far so good, finished reading all tokens\n");

	printf("debug:");
	for(int i=0; i<message_len;i++) {
		printf("%02x",message[i]);
	}
	printf("\n");

	// Payload
	printf("debug %d - %zu\n", hs->symmetric_state.isKeyed, message_len);
	if(hs->symmetric_state.isKeyed && message_len < 16) { // a tag must be here
		return -1;
	}
	bool res = _disco_DecryptAndHash(&(hs->symmetric_state), message, message_len);
	if(!res) {
		return -1;
	}
	if(hs->symmetric_state.isKeyed) { // the real length of the message (minus tag)
		message_len -= 16;
	} 
	// TODO: payload_buffer might not have enough room
	// only copy what's left in payload buffer!!!
	memcpy(payload_buffer, message, message_len);
	
	// Split?
	if(current_token == token_end_handshake) {
		assert(s1 == NULL && s2 != NULL);
		_disco_Split(&(hs->symmetric_state), s1, s2);
		hs->message_patterns = NULL;
		_disco_Destroy(hs);
	} else {
		hs->message_patterns += token_counter + 1;
	}

	// return length of what was read into buffer
	return message_len;
}

