#include "disco_asymmetric.h"
#include "disco_symmetric.h"
#include <stdio.h>

void test_N() {
  // generate server keypair
  keyPair server_keypair;
  disco_generateKeyPair(&server_keypair);

  // initialize client
  handshakeState hs_client;
  disco_Initialize(&hs_client, HANDSHAKE_N, true, NULL, 0, NULL, NULL,
                   &server_keypair, NULL);

  // initialize server
  handshakeState hs_server;
  disco_Initialize(&hs_server, HANDSHAKE_N, false, NULL, 0, &server_keypair,
                   NULL, NULL, NULL);

  // write the first handshake message → e, es
  uint8_t out[500];
  strobe_s c_write;
  strobe_s c_read;
  size_t out_len;
  int ret =
      disco_WriteMessage(&hs_client, NULL, 0, out, &out_len, &c_write, &c_read);
  if (ret < 0) {
    printf("can't write handshake message\n");
    abort();
  }

  // handshake should be done for the client
  assert(strobe_isInitialized(&c_write) && strobe_isInitialized(&c_read));

  // debug
  printf("sent %zu bytes\n", out_len);

  // process the first handshake message → e, es
  uint8_t in[500];
  strobe_s s_read;
  strobe_s s_write;
  size_t in_len;
  ret = disco_ReadMessage(&hs_server, out, out_len, in, &in_len, &s_read,
                          &s_write);
  if (ret < 0) {
    printf("can't read handshake message\n");
    abort();
  }

  assert(strobe_isInitialized(&s_write) && strobe_isInitialized(&s_read));

  // debug
  printf("received %zu bytes:%s\n", in_len, in);

  // trying to send a post-handshake message
  uint8_t pt_in_place[] =
      "Us little brogammers we like to brogamme on our motorbikes yeah ";
  uint8_t *ct_and_mac = (uint8_t *)malloc(sizeof(pt_in_place) + 16);
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
  free(ct_and_mac);
}

void test_NX() {
  // generate server keypair
  keyPair server_keypair;
  disco_generateKeyPair(&server_keypair);

  // initialize client
  handshakeState hs_client;
  disco_Initialize(&hs_client, HANDSHAKE_NX, true, NULL, 0, NULL, NULL, NULL,
                   NULL);

  // initialize server
  handshakeState hs_server;
  disco_Initialize(&hs_server, HANDSHAKE_NX, false, NULL, 0, &server_keypair,
                   NULL, NULL, NULL);

  // write the first handshake message → e, es
  uint8_t out[500];
  uint8_t text[] = "hey!";
  size_t out_len;
  int ret = disco_WriteMessage(&hs_client, text, 5, out, &out_len, NULL, NULL);
  if (ret < 0) {
    printf("can't write handshake message\n");
    abort();
  }

  // debug
  printf("sent %zu bytes\n", out_len);
  for (size_t i = 0; i < out_len; i++) {
    printf("%02x", out[i]);
  }
  printf("\n");

  // process the first handshake message → e, es
  uint8_t in[500];
  size_t in_len;
  ret = disco_ReadMessage(&hs_server, out, out_len, in, &in_len, NULL, NULL);
  if (ret < 0) {
    printf("can't read handshake message\n");
    abort();
  }

  // debug
  printf("received %zu bytes:%s\n", in_len, in);
  printf("hs_client and hs_server state after first trip\n");
  strobe_print(&(hs_client.symmetric_state.strobe));
  strobe_print(&(hs_server.symmetric_state.strobe));

  // create second handshake message
  printf("\n\npreparing second handshake message ->\n\n");
  strobe_s s_write;
  strobe_s s_read;
  ret = disco_WriteMessage(&hs_server, (uint8_t *)"hello hello", 12, out,
                           &out_len, &s_read, &s_write);
  if (ret < 0) {
    printf("can't write handshake message\n");
    abort();
  }

  // should be initialized
  assert(s_write.initialized && s_read.initialized);

  // debug
  printf("sent %zu bytes:\n", out_len);
  for (size_t i = 0; i < out_len; i++) {
    printf("%02x", out[i]);
  }
  printf("\n");

  // process second handshake message
  printf("\n\nparsing second handshake message <-\n\n");
  strobe_s c_write;
  strobe_s c_read;
  ret = disco_ReadMessage(&hs_client, out, out_len, in, &in_len, &c_write,
                          &c_read);
  if (ret < 0) {
    printf("can't read handshake message\n");
    abort();
  }

  // debug
  printf("received %zu bytes:%s\n", in_len, in);

  // should be initialized
  assert(c_write.initialized && c_read.initialized);

  // trying to send a post-handshake message
  uint8_t pt_in_place[] =
      "Us little brogammers we like to brogamme on our motorbikes yeah ";
  uint8_t *ct_and_mac = (uint8_t *)malloc(sizeof(pt_in_place) + 16);
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

  // another one
  memcpy(ct_and_mac, pt_in_place, sizeof(pt_in_place));
  disco_EncryptInPlace(&c_write, ct_and_mac, sizeof(pt_in_place),
                       sizeof(pt_in_place) + 16);
  if (disco_DecryptInPlace(&s_read, ct_and_mac, sizeof(pt_in_place) + 16) ==
      false) {
    printf("cannot decrypt in place");
    abort();
  }
  printf("final decrypt in place: %s\n", ct_and_mac);
  free(ct_and_mac);
}

void test_IK() {
  // generate server keypair
  keyPair client_keypair;
  keyPair server_keypair;
  disco_generateKeyPair(&client_keypair);
  disco_generateKeyPair(&server_keypair);

  // initialize client
  handshakeState hs_client;
  disco_Initialize(&hs_client, HANDSHAKE_IK, true, NULL, 0, &client_keypair,
                   NULL, &server_keypair, NULL);

  // initialize server
  handshakeState hs_server;
  disco_Initialize(&hs_server, HANDSHAKE_IK, false, NULL, 0, &server_keypair,
                   NULL, NULL, NULL);

  // write the first handshake message → e, es, s, ss
  uint8_t out[500];
  uint8_t text[] = "hey!";
  size_t out_len;
  int ret = disco_WriteMessage(&hs_client, text, 5, out, &out_len, NULL, NULL);
  if (ret < 0) {
    printf("can't write handshake message\n");
    abort();
  }

  // debug
  printf("sent %zu bytes\n", out_len);
  for (size_t i = 0; i < out_len; i++) {
    printf("%02x", out[i]);
  }
  printf("\n");

  // process the first handshake message
  uint8_t in[500];
  size_t in_len;
  ret = disco_ReadMessage(&hs_server, out, out_len, in, &in_len, NULL, NULL);
  if (ret < 0) {
    printf("can't read handshake message\n");
    abort();
  }

  // debug
  printf("received %zu bytes:%s\n", in_len, in);
  printf("hs_client and hs_server state after first trip\n");
  strobe_print(&(hs_client.symmetric_state.strobe));
  strobe_print(&(hs_server.symmetric_state.strobe));

  // create second handshake message <- e, ee, se
  printf("\n\npreparing second handshake message ->\n\n");
  strobe_s s_write;
  strobe_s s_read;
  ret = disco_WriteMessage(&hs_server, (uint8_t *)"hello hello", 12, out,
                           &out_len, &s_read, &s_write);
  if (ret < 0) {
    printf("can't write handshake message\n");
    abort();
  }

  // should be initialized
  assert(s_write.initialized && s_read.initialized);

  // debug
  printf("sent %zu bytes:\n", out_len);
  for (size_t i = 0; i < out_len; i++) {
    printf("%02x", out[i]);
  }
  printf("\n");

  // process second handshake message
  printf("\n\nparsing second handshake message <-\n\n");
  strobe_s c_write;
  strobe_s c_read;
  ret = disco_ReadMessage(&hs_client, out, out_len, in, &in_len, &c_write,
                          &c_read);
  if (ret < 0) {
    printf("can't read handshake message\n");
    abort();
  }

  // debug
  printf("received %zu bytes:%s\n", in_len, in);

  // should be initialized
  assert(c_write.initialized && c_read.initialized);

  // trying to send a post-handshake message
  uint8_t pt_in_place[] =
      "Us little brogammers we like to brogamme on our motorbikes yeah ";
  uint8_t *ct_and_mac = (uint8_t *)malloc(sizeof(pt_in_place) + 16);
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

  // other direction
  uint8_t pt_in_place2[] = "this is hopefully the last test for today";
  uint8_t *ct_and_mac2 = (uint8_t *)malloc(sizeof(pt_in_place2) + 16);
  memcpy(ct_and_mac2, pt_in_place2, sizeof(pt_in_place2));

  disco_EncryptInPlace(&s_write, ct_and_mac2, sizeof(pt_in_place2),
                       sizeof(pt_in_place2) + 16);

  // decrypt
  if (disco_DecryptInPlace(&c_read, ct_and_mac2, sizeof(pt_in_place2) + 16) ==
      false) {
    printf("cannot decrypt in place");
    abort();
  }
  printf("final decrypt in place: %s\n", ct_and_mac2);
  free(ct_and_mac);
  free(ct_and_mac2);
}

void test_HashInteropGolang() {
  uint8_t input[] = "hi, how are you?";
  uint8_t out[32];
  disco_Hash(input, 16, out, 32);
  uint8_t res[] =
      "\xed\xa8\x50\x6c\x1f\xb0\xbb\xcc\x3f\x62\x62\x6f\xef\x07\x4b\xbf\x2d\x09"
      "\xa8\xc7\xc6\x08\xf3\xfa\x14\x82\xc9\xa6\x25\xd0\x0f\x75";
  for (int i = 0; i < 32; i++) {
    assert(out[i] == res[i]);
  }
  printf("\n");
}

void test_Hash() {
  // hashing with simple disco_Hash function
  uint8_t input[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
  uint8_t out[32];
  disco_Hash(input, 10, out, 32);
  /*
  printf("result:\n");
  for (int i = 0; i < 32; i++) {
    printf("%02x", out[i]);
  }
  printf("\n");
  */

  // hashing with New-Write-Sum
  discoHashCtx ctx;
  disco_HashNew(&ctx);
  disco_HashWrite(&ctx, input, 10);
  uint8_t out2[32];
  // compare
  disco_HashSum(&ctx, out2, 32);
  for (int i = 0; i < 32; i++) {
    assert(out[i] == out2[i]);
  }

  // hash again and compare
  disco_HashSum(&ctx, out2, 32);
  for (int i = 0; i < 32; i++) {
    assert(out[i] == out2[i]);
  }

  // this time hash in two times
  disco_HashResetCtx(&ctx);
  disco_HashNew(&ctx);
  disco_HashWrite(&ctx, input, 5);
  disco_HashWrite(&ctx, input + 5, 5);
  disco_HashSum(&ctx, out2, 32);
  for (int i = 0; i < 32; i++) {
    assert(out[i] == out2[i]);
  }

  // hash with Tuple
  disco_HashResetCtx(&ctx);
  disco_HashNew(&ctx);
  disco_HashWriteTuple(&ctx, input, 5);
  disco_HashWriteTuple(&ctx, input + 5, 5);
  disco_HashSum(&ctx, out2, 32);
  bool different = false;
  for (int i = 0; i < 32; i++) {
    if (out[i] != out2[i]) {
      different = true;
      break;
    }
  }
  assert(different);
}

int main() {
  // doing a loop coz I have a bug SOMETIMES
  for (int j = 0; j < 10; j++) {
    printf("iteration #%d\n", j);
    printf("\n\ntesting N\n\n");
    test_N();
    printf("\n\ntesting NX\n\n");
    test_NX();
    printf("\n\ntesting IK\n\n");
    test_IK();
  }

  test_Hash();
  test_HashInteropGolang();
}
