# EmbeddedDisco

**EmbeddedDisco** is a modern protocol and a cryptographic library in C. It offers different ways of encrypting communications, as well as different cryptographic primitives for all of an application's needs. It targets simplicity and minimalism, with around 1,000 lines-of-code and a design based solely on the SHA-3 and Curve25519 cryptographic primitives.

This repository is light on detail as it is actively under developement. To have a more gentle introduction, [check this blogpost](https://www.cryptologie.net/article/432/introducing-disco/) in C. **The state of this library is quite experimental. Please do not use it in production.** [A more mature implementation of Disco exists in Go](http://discocrypto.com/#/). More implementations are [listed here](https://github.com/mimoo/disco/issues/4).

If you need help to play with the library, [contact me](https://www.cryptologie.net/contact) or post an issue :) I'm happy to help.

## Example

Here's how you setup a **server** with the `IK` handshake (the server's identity is known to the client; the client advertises it's identity during the handshake):

```c
#include "tweetdisco.h"
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
  ssize_t in_len = disco_ReadMessage(&hs_server, out, out_len, in, NULL, NULL);
  if (in_len < 0) {
    abort();
  }

  // validate the client's identity via a whitelist or a public key infrastructure 
  // or trust-on-first-use, etc.

  // create second handshake message ← e, ee, se
  strobe_s s_write;
  strobe_s s_read;
  ssize_t out_len = disco_WriteMessage(&hs_server, (u8 *)"second payload", 15,
                                       out, &s_read, &s_write);
  if (out_len < 0) {
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
#include "tweetdisco.h"
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
  ssize_t out_len =
      disco_WriteMessage(&hs_client, (u8*)"hey!", 5, out, NULL, NULL);
  if (out_len < 0) {
    abort();
  }

  // process second handshake message ← e, ee, se
  strobe_s c_write;
  strobe_s c_read;
  ssize_t in_len =
      disco_ReadMessage(&hs_client, out, out_len, in, &c_write, &c_read);
  if (in_len < 0) {
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

## More

The library is currently optimized for code-size. It was done by:

1. re-writing [Strobe-C](https://strobe.sourceforge.io) to make it smaller in size, simpler and closer to the official specification.
2. I'm using [tweetNaCl's X25519](https://tweetnacl.cr.yp.to/) implementation. Strobe has one from Mike Hamburg as well. I need to compare. This can be replaced by more robust implementations for hardware devices that want to implement masking and other side-channel mitigation techniques.
3. I'm using `randombytes()` from [NaCl](https://nacl.cr.yp.to/). The idea here is that any platform can provide a `randombytes` function.
4. I'm using Mike Hamburg's implementation of Keccak-f which is based on [TweetFIPS202](https://keccak.team/2015/tweetfips202.html). This can be replaced by an application's own optimzed implementation of Keccak-f if developers are willing to increase the code size and decrease the readability.

Here are a list of TODOs:

- [ ] should Disco use [Strobe's Schnorr signature](https://strobe.sourceforge.io/papers/) instead of ed25519? It would be smaller in code size. The problem is that ed25519 is supported in more languages and is well accepted as a standard. On the other hand ed25519 uses SHA-512 which we don't want to support.
- [ ] write good documentation. Doxygen is really ugly. Is there a better alternative?
- [ ] figure out if *randombytes* from *nacl* is enough, check what [libhydrogen]() does
- [ ] go through each TODO in the code
- [ ] enforce a maximum message length for the readmessage/writemessage functions? (Noise's specification has a limit of 65535 bytes I believe?)
- [ ] check that I don't crash the application unecessarily (and return errors whenever possible)
- [ ] cleanup make file, remove -g and ASAN
