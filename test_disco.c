#include "tweetdisco.h"
#include <stdio.h>

int main() {
	// this is how you use a handshake pattern
	// just copy/paste from the list of patterns
	token pre_message_patterns[] = {token_end_turn,	// →
									 token_s, token_end_handshake}; // ← s
	token message_patterns[] = {token_e, token_es, token_end_handshake}; // → e, es
	handshakePattern hp = {
		.name = "N",
		.pre_message_patterns = (token*)pre_message_patterns, 
		.message_patterns = (token*)message_patterns
	};

	// N
	keyPair server_keypair;
	disco_generateKeyPair(&server_keypair);

	// initialize handshakeState
	handshakeState hs;
	disco_Initialize(&hs, hp, true, NULL, 0, NULL, NULL, &server_keypair, NULL);
	u8 out[500];
	strobe_s *s1;
	strobe_t s2;
	u8 text[] = "hey!";
	int out_len = disco_WriteMessage(&hs, text, 5, out, s1, s2);
	if(out_len == -1) {
		printf("oups\n");
		return 1;
	}
	printf("sent %d bytes\n", out_len);

	// same
	handshakeState hs2;
	disco_Initialize(&hs2, hp, false, NULL, 0, &server_keypair, NULL, NULL, NULL);

	u8 in[500];
	strobe_s *s3;
	strobe_t s4;
	int in_len = disco_ReadMessage(&hs2, out, out_len, in, s3, s4);
	if(out_len == -1) {
		printf("oups\n");
		return 1;
	}
	printf("received %d bytes:%s\n", in_len, in);
}
