#include "tweetdisco.h"
#include <stdio.h>

#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

uint8_t hexchar2bin(const char *hex) {
  uint8_t res = 0;
  for (int i = 0; i < 2; i++) {
    if (hex[i] >= '0' && hex[i] <= '9') {
      res ^= hex[i] - '0';
    } else if (hex[i] >= 'A' && hex[i] <= 'F') {
      res ^= hex[i] - 'A' + 10;
    } else if (hex[i] >= 'a' && hex[i] <= 'f') {
      res ^= hex[i] - 'a' + 10;
    } else {
      printf("not a valid hex string");
      abort();
    }
  }
  return res;
}

int hex2bin(const char *hex, uint8_t *out) {
  if (out == NULL) return 0;
  const char *p = hex;
  unsigned char *q = out;
  while (*p != 0) {
    //    printf("p: %02x - %c\n", *p, *p);
    *q = hexchar2bin(p);
    q += 1;
    p += 2;  // advance 2 chars
  }

  return 1;
}

int main(int argc, char const *argv[]) {
  // get server address, port and key from arguments
  if (argc != 4) {
    printf("usage: ./client server_address server_port server_public_key\n");
    return 1;
  }

  // server port
  struct sockaddr_in serv_addr;
  memset(&serv_addr, '0', sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(atoi(argv[2]));

  // server address
  if (inet_pton(AF_INET, argv[1], &serv_addr.sin_addr) <= 0) {
    printf("\nInvalid address/ Address not supported \n");
    return -1;
  }

  // server keypair
  assert(strlen(argv[3]) == 64);
  keyPair server_keypair;
  hex2bin(argv[3], server_keypair.pub);

  // initialize client
  handshakeState hs_client;
  disco_Initialize(&hs_client, HANDSHAKE_NK, true, NULL, 0, NULL, NULL,
                   &server_keypair, NULL);

  // generate the first handshake message → e, es
  uint8_t out[500];
  int out_len = disco_WriteMessage(&hs_client, NULL, 0, out + 2, NULL, NULL);
  if (out_len < 0) {
    printf("can't generate first handshake message\n");
    return -1;
  }

  // add framing (2 bytes of length)
  out[0] = (out_len >> 8) & 0xFF;
  out[1] = out_len & 0xFF;
  out_len += 2;

  // connect
  int sock = 0;
  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    printf("\n Socket creation error \n");
    return -1;
  }
  if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    printf("\nConnection Failed \n");
    return -1;
  }

  // send first handshake message
  ssize_t sent = send(sock, out, out_len, 0);
  if (sent < 0) {
    printf("\nSending first handshake message failed\n");
    return -1;
  }
  printf("Hello message of %zd bytes sent\n", sent);

  // receive second handshake message
  uint8_t in[500];
  ssize_t in_len = read(sock, in, 1024);
  if (in_len < 0) {
    printf("\nReceive second handshake message failed\n");
    return -1;
  }

  // remove framing
  size_t length = (in[0] << 8) | in[1];
  if (length != in_len - 2) {
    printf("\nmessage was possibly fragmented, we don't handle that\n");
    return -1;
  }
  in_len = length;

  // parse second handshake message
  strobe_s c_write;
  strobe_s c_read;
  uint8_t payload[500];
  if (in_len > 500) {
    printf("\nwe don't suppor this yet\n");
    return -1;
  }
  ssize_t payload_len =
      disco_ReadMessage(&hs_client, in, in_len, payload, &c_write, &c_read);
  if (payload_len < 0) {
    printf("can't read handshake message\n");
    abort();
  }

  // print out payload/payload_len

  assert(strobe_isInitialized(&c_read) && strobe_isInitialized(&c_write));

  //
  return 0;
}
