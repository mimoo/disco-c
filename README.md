# TweetDisco

This is an implementation of [Disco](https://www.cryptologie.net/article/432/introducing-disco/) in C. **This code is quite experimental. Please do not use in production.** [A more mature implementation of Disco exists in Go](http://discocrypto.com/#/).

It is called tweetdisco because the implementation's goal is code size, but it is unfortunately not tweetable :)

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

## TODO

It is optimized for code-size at the moment, mostly because I suck at optimizing things:

* I re-wrote [Strobe-C]() to make it smaller in size and simpler.
* I'm using [tweetNaCl's X25519]() implementation. But why not Mike Hamburg's one?
* I'm using `randombytes()` from [NaCl]()
* I'm using Mike Hamburg's implementation of Keccak-f which is based on [TweetFIPS202]()
* I should probably use Strobe's suggestion for signature instead of ed25519
    - (because ed25519 requires a different hash function)

- [x] re-write `tweetdisco` with `tweetstrobe` new `strobe_operate()`
- [ ] write good doc
- [ ] rename *tweetdisco* to *embeddedDisco* or something? (tweet might have a bad connotation)
- [ ] extract *curve25519* from *tweetnacl*, because that's all I really need 
- [ ] figure out if *randombytes* from *nacl* is enough, check what *libhydrogen* does
- [ ] should I re-write "everything" with `const`?
- [ ] why does sprintf and strlen use "signed" chars?
- [ ] figure out a maximum message length for the readmessage/writemessage functions (use size_t instead of int?)
- [x] `assert` is probably removed by optimizations, so I should prob avoid using it in important places?
- [ ] check that I don't crash the application unecessarily (and return -1 or something instead)
- [ ] accept an external API for generating randomness instead of generating randomness ourselves? or have it XOR'ed with ours?
- [ ] cleanup make file, remove -g and ASAN
