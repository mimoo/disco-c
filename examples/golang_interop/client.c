#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "disco_asymmetric.h"

// helper function to decode hexadecimal string into a buffer. Not the nicest
// thing but it works.
int hex2bin(const char *hex, uint8_t *out) {
  if (out == NULL) return 0;
  const char *p = hex;
  uint8_t *q = out;
  while (*p != 0) {
    *q = 0;
    for (int i = 0; i < 2; i++) {
      if (p[i] >= '0' && p[i] <= '9') {
        *q ^= p[i] - '0';
      } else if (p[i] >= 'A' && p[i] <= 'F') {
        *q ^= p[i] - 'A' + 10;
      } else if (p[i] >= 'a' && p[i] <= 'f') {
        *q ^= p[i] - 'a' + 10;
      } else {
        return -1;
      }
      if (i == 0) {
        *q = *q << 4;
      }
    }
    q += 1;
    p += 2;
  }
  return 1;
}

/*
 * We will use the NK handshake pattern to test interoperability with the Go
 * implementation of Disco
 */
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
    return 1;
  }

  // server keypair
  assert(strlen(argv[3]) == 64);
  keyPair server_keypair;
  if (hex2bin(argv[3], server_keypair.pub) < 0) {
    printf("invalid server pubkey\n");
    return 1;
  }

  // initialize client
  handshakeState hs_client;
  disco_Initialize(&hs_client, HANDSHAKE_NK, true, NULL, 0, NULL, NULL,
                   &server_keypair, NULL);

  // generate the first handshake message → e, es
  uint8_t out[500];
  size_t out_len;
  bool ret =
      disco_WriteMessage(&hs_client, NULL, 0, out + 2, &out_len, NULL, NULL);
  if (!ret) {
    printf("can't generate first handshake message\n");
    return 1;
  }

  // add framing (2 bytes of length)
  out[0] = (out_len >> 8) & 0xFF;
  out[1] = out_len & 0xFF;
  out_len += 2;

  // connect
  int sock = 0;
  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    printf("\n Socket creation error \n");
    return 1;
  }
  if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    printf("\nConnection Failed \n");
    return 1;
  }

  // send first handshake message
  ssize_t sent = send(sock, out, out_len, 0);
  if (sent < 0) {
    printf("\nSending first handshake message failed\n");
    return 1;
  }
  printf("Hello message of %zd bytes sent\n", sent);

  // receive second handshake message
  uint8_t in[500];
  ssize_t in_len = read(sock, in, 1024);
  if (in_len <= 0) {
    printf("\nReceive second handshake message failed\n");
    return 1;
  }

  printf("received %zd bytes\n", in_len);

  // remove framing
  size_t length = (in[0] << 8) | in[1];
  printf("without framing: %zu bytes\n", length);
  if (length != in_len - 2) {
    printf("\nmessage was possibly fragmented, we don't handle that\n");
    return 1;
  }
  in_len = length;

  // parse second handshake message
  strobe_s c_write;
  strobe_s c_read;
  uint8_t payload[500];
  if (in_len > 500) {
    printf("\nwe don't suppor this yet\n");
    return 1;
  }
  size_t payload_len;
  ret = disco_ReadMessage(&hs_client, in + 2, in_len, payload, &payload_len,
                          &c_write, &c_read);
  if (!ret) {
    printf("can't read handshake message\n");
    abort();
  }
  // print out payload/payload_len
  assert(strobe_isInitialized(&c_read) && strobe_isInitialized(&c_write));

  // handshake done!
  printf("handshake done!\n");

  // loop: receive a line from the terminal and send it to the server
  while (true) {
    // get line
    char *buffer = NULL;
    size_t size;
    getline(&buffer, &size, stdin);
    // encrypt
    out_len = sizeof(buffer) + 16;                         // plaintext + tag
    uint8_t *ct_and_mac = (uint8_t *)malloc(out_len + 2);  // +2 (length)
    memcpy(ct_and_mac + 2, (uint8_t *)buffer, sizeof(buffer));
    disco_EncryptInPlace(&c_write, ct_and_mac + 2, sizeof(buffer), out_len);

    // length framing
    ct_and_mac[0] = (out_len >> 8) & 0xFF;
    ct_and_mac[1] = out_len & 0xFF;
    printf("debug: %d, %d\n", ct_and_mac[0], ct_and_mac[1]);

    // send
    sent = send(sock, ct_and_mac, out_len + 2, 0);
    if (sent < 0) {
      printf("\nSending first handshake message failed\n");
      return 1;
    }
    printf("message of %zd bytes sent\n", sent);

    // free
    free(buffer);
    free(ct_and_mac);
  }

  //
  return 0;
}
