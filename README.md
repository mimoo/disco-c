# EmbeddedDisco

**EmbeddedDisco** is a modern protocol and a cryptographic library in C. It offers different ways of encrypting communications, as well as different cryptographic primitives for all of an application's needs. It targets simplicity, security and portability, with around **1000 lines-of-code**, not a single malloc and a design based solely on the well-accepted SHA-3 and Curve25519 cryptographic primitives. It's for embedded devices, automotive chips, etc.

![size](https://www.cryptologie.net/upload/LOC.png)

This repository is light on detail as it is actively under developement. To have a more gentle introduction, [check this blogpost](https://www.cryptologie.net/article/432/introducing-disco/). **The state of this library is quite experimental. Please do not use it in production.** [A more mature implementation of Disco exists in Go](http://discocrypto.com/#/). More implementations are [listed here](https://github.com/mimoo/disco/issues/4).

In order to make this library more stable I need your help. Play with the library, [contact me here](https://www.cryptologie.net/contact), provide feedback, post issues :) I'm happy to help.

## Quick Example

Here's how you setup a **server** with the `IK` handshake (the server's identity is known to the client; the client advertises it's identity during the handshake):

```c
#include "disco_asymmetric.h"
#include <stdio.h>

int main() {
  // generate long-term static keypair
  keyPair server_keypair;
  disco_generateKeyPair(&server_keypair);

  // initialize disco for the Noise IK handshake pattern
  handshakeState hs_server;
  disco_Initialize(&hs_server, HANDSHAKE_IK, false, NULL, 0, &server_keypair,
                   NULL, NULL, NULL);

  // process the first handshake message → e, es, s, ss
  u8 in[500];
  size_t in_len
  bool ret = disco_ReadMessage(&hs_server, out, out_len, in, &in_len, NULL, NULL);
  if (!ret) {
    abort();
  }

  // validate the client's identity via a whitelist or a public key infrastructure 
  // or trust-on-first-use, etc.

  // create second handshake message ← e, ee, se
  strobe_s s_write;
  strobe_s s_read;
  size_t out_len;
  ret = disco_WriteMessage(&hs_server, (u8 *)"second payload", 15,
                                       out, &out_len, &s_read, &s_write);
  if (!ret) {
    abort();
  }

  // send `out` of size `out_len` to the client...

  // should be initialized
  assert(s_write.initialized && s_read.initialized);

  // decrypt
  if (disco_DecryptInPlace(&s_read, ciphertext, ciphertext_len) ==
      false) {
    abort();
  }

  // send `ciphertext` of size `ciphertext_len - 16` to the client...
}
```

Here's how you setup a **client**:

```c
#include "disco_asymmetric.h"
#include <stdio.h>

int main() {
  // generate long-term client keypair
  keyPair client_keypair;
  disco_generateKeyPair(&client_keypair);

  // obtain server's key somehow...
  keyPair server_keypair;
  server_keypair.pub = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};

  // initialize disco                        
  handshakeState hs_client;
  disco_Initialize(&hs_client, HANDSHAKE_IK, true, NULL, 0, &client_keypair,
                   NULL, &server_keypair, NULL);

  // write the first handshake message → e, es, s, ss
  u8 out[500];
  size_t out_len;
  bool ret =
      disco_WriteMessage(&hs_client, (u8*)"hey!", 5, out, &out_len, NULL, NULL);
  if (!ret) {
    abort();
  }

  // process second handshake message ← e, ee, se
  strobe_s c_write;
  strobe_s c_read;
  size_t in_len;
  ret =
      disco_ReadMessage(&hs_client, out, out_len, in, &in_len, &c_write, &c_read);
  if (!ret) {
    abort();
  }

  // payload `in` of size `in_len` has been received

  // should be initialized
  assert(c_write.initialized && c_read.initialized);

  // send a post-handshake message
  u8 plaintext[] = "just a simple message";
  u8* ciphertext = (u8*)malloc(sizeof(plaintext) + 16);
  memcpy(ciphertext, plaintext, sizeof(plaintext));

  disco_EncryptInPlace(&c_write, ciphertext, sizeof(plaintext),
                       sizeof(plaintext) + 16);

  // send the `ciphertext` of size `size(plaintext)+16`
}
```

To use the symmetric parts of the library, simply include `disco_symmetric.h`:

```c
#include "disco_symmetric.h"

int main() {
  uint8_t input[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
  uint8_t out[32];
  // here is how we hash something
  disco_Hash(input, 10, out, 32);
}
```

## How to use?

[Check the documentation](https://www.embeddeddisco.com) here.

## Need help?

This library is still heavily experimental. Its goal is to support as many platforms as possible. If you need help making it work for a specific platform please post an issue. If you have feedback, or suggestions, please post an issue as well.