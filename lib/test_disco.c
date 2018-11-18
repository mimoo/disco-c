#include "tweetdisco.h"
#include <stdio.h>

void test_disco() {
  // in Disco-c, this is how you use a handshake pattern:
  // just copy/paste an already existing pattern from the list of patterns
  // here we copy/pasted the N pattern
  token pre_message_patterns[] = {token_end_turn,                 // →
                                  token_s, token_end_handshake};  // ← s
  token message_patterns[] = {token_e, token_es,
                              token_end_handshake};  // → e, es
  handshakePattern hp = {.name = "N",
                         .pre_message_patterns = (token *)pre_message_patterns,
                         .message_patterns = (token *)message_patterns};

  // generate server keypair
  keyPair server_keypair;
  disco_generateKeyPair(&server_keypair);

  // initialize client
  handshakeState hs_client;
  printf("wtf hs_client: %d\n", hs_client.re.isSet);
  disco_Initialize(&hs_client, hp, true, NULL, 0, NULL, NULL, &server_keypair,
                   NULL);

  // initialize server
  handshakeState hs_server;
  printf("wtf hs_server: %d\n", hs_server.re.isSet);
  disco_Initialize(&hs_server, hp, false, NULL, 0, &server_keypair, NULL, NULL,
                   NULL);

  // write the first handshake message → e, es
  u8 out[500];
  strobe_s c_write;
  strobe_s c_read;
  u8 text[] = "hey!";
  int out_len = disco_WriteMessage(&hs_client, text, 5, out, &c_write, &c_read);
  if (out_len < 0) {
    printf("can't write handshake message\n");
    abort();
  }

  // handshake should be done for the client
  assert(c_write.initialized && c_read.initialized);

  // debug
  printf("sent %d bytes\n", out_len);

  // process the first handshake message → e, es
  u8 in[500];
  strobe_s s_read;
  strobe_s s_write;
  int in_len =
      disco_ReadMessage(&hs_server, out, out_len, in, &s_read, &s_write);
  if (in_len < 0) {
    printf("can't read handshake message\n");
    abort();
  }

  assert(s_write.initialized && s_read.initialized);

  // debug
  printf("received %d bytes:%s\n", in_len, in);

  // trying to send a post-handshake message
  u8 pt_in_place[] =
      "Us little brogammers we like to brogamme on our motorbikes yeah ";
  u8 *ct_and_mac = (u8 *)malloc(sizeof(pt_in_place) + 16);
  memcpy(ct_and_mac, pt_in_place, sizeof(pt_in_place));

  disco_EncryptInPlace(&c_write, ct_and_mac, sizeof(pt_in_place),
                       sizeof(pt_in_place) + 16);

  // decrypt
  if (disco_DecryptInPlace(&s_read, ct_and_mac, sizeof(pt_in_place) + 16) ==
      false) {
    printf("cannot decrypt in place");
    abort();
  }
  printf("final decrypt in place: %s\n", ct_and_mac);
}

int main() {
  // doing a loop coz I have a bug SOMETIMES
  for (int j = 0;; j++) {
    printf("iteration #%d\n", j);
    test_disco();
  }

}
