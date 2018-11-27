# EmbeddedDisco

**EmbeddedDisco** is a modern protocol and a cryptographic library in C. It offers different ways of encrypting communications, as well as different cryptographic primitives for all of an application's needs. It targets simplicity and minimalism, with around **1,000 lines-of-code**, not a single malloc and a design based solely on the well-accepted SHA-3 and Curve25519 cryptographic primitives.

![short](https://www.cryptologie.net/upload/LOC.png)

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

## How to use?

Note that Disco is configured with `Keccak-f[1600]` and `128-bit` of security. This settings can be changed for `keccak-f[800]`/`keccak-f[400]` or `256-bit` of security. This is all done in `tweetstrobe.h` by defining `STROBE_INTEROP_SECURITY_BITS` and `KECCAK_INTEROP_F_BITS`.

## Establishing a secure session between two peers

To use the **asymmetric handshakes** of Disco, include disco in your project:

```c
#include "disco_asymmetric.h"
```

The available functions are available in the same header. They consists of:

```c
// used to generate long-term key pairs
void disco_generateKeyPair(keyPair *kp);

// used to initialized your handshakeState with a handshake pattern
void disco_Initialize(handshakeState *hs, handshakePattern hp, bool initiator,
                      uint8_t *prologue, size_t prologue_len, keyPair *s,
                      keyPair *e, keyPair *rs, keyPair *re);

// used to generate a handshake message
ssize_t disco_WriteMessage(handshakeState *hs, uint8_t *payload,
                           size_t payload_len, uint8_t *message_buffer,
                           strobe_s *client_s, strobe_s *server_s);

// used to parse a handshake message
ssize_t disco_ReadMessage(handshakeState *hs, uint8_t *message,
                          size_t message_len, uint8_t *payload_buffer,
                          strobe_s *client_s, strobe_s *server_s);

// post-handshake encryption
void disco_EncryptInPlace(strobe_s *strobe, uint8_t *plaintext,
                          size_t plaintext_len, size_t plaintext_capacity);

// post-handshake decryption
bool disco_DecryptInPlace(strobe_s *strobe, uint8_t *ciphertext,
                          size_t ciphertext_len);
```

the different handshake patterns are defined in `tweetdisco.h` as:

* `HANDSHAKE_N`: the server only receives messages (one-way), the client is not authenticated, the client knows the server public key.
* `HANDSHAKE_K`: the server only receives messages (one-way), the server knows the client public key, the client knows the server public key.
* `HANDSHAKE_X`: the server only receives messages (one-way), the client transmits its public key during the handshake, the client knows the server public key.
* `HANDSHAKE_NK`: the client is not authenticated, the client knows the server public key.
* `HANDSHAKE_KK`: the server knows the client public key, the client knows the server public key.
* `HANDSHAKE_NX`: the client is not authenticated, the server transmits its public key during the handshake.
* `HANDSHAKE_KX`: the server knows the client public key, the server transmits its public key during the handshake.
* `HANDSHAKE_XK`: the client transmits its public key during the handshake, the client knows the server public key.
* `HANDSHAKE_IK`: the client transmits its public key during the handshake, the client knows the server public key.
* `HANDSHAKE_XX`: the client transmits its public key during the handshake, the server transmits its public key during the handshake.
* `HANDSHAKE_IX`: the client transmits its public key during the handshake, the server transmits its public key during the handshake.

Refer to the [Noise specification](http://noiseprotocol.org/noise.html) to know:

* how many messages to write or read for a specific handshake pattern
* what the security properties of the handshake pattern are

At the end of the handshake, two strobe state are returned by `disco_WriteMessage` and `disco_ReadMessage`. One is for the client to encrypt to the server and the other is for the server to encrypt to the client.

## Hashing, Encrypting, Authenticating, Deriving Keys, etc.

To use the **symmetric parts** of Disco, include the following file in your projects:

```c
#include "disco_symmetric.h"
```

The following functions are available:

```c
// Hashing
void disco_Hash(uint8_t* input, size_t input_len, uint8_t* out, size_t out_len);
void disco_HashNew(discoHashCtx* ctx);
void disco_HashWrite(discoHashCtx* ctx, uint8_t* input, size_t input_len);
void disco_HashWriteTuple(discoHashCtx* ctx, uint8_t* input, size_t input_len);
void disco_HashSum(discoHashCtx* ctx, uint8_t* out, size_t out_len);
void disco_HashResetCtx(discoHashCtx* ctx);

// Key Derivation
void disco_DeriveKeys(uint8_t* inputKey, size_t key_len, uint8_t* out,
                      size_t out_len);

// Integrity Protection
void disco_ProtectIntegrity(uint8_t* key, size_t key_len, uint8_t* data,
                            size_t data_len, uint8_t* out, size_t out_len);
bool disco_VerifyIntegrity(uint8_t* key, size_t key_len, uint8_t* data,
                           size_t data_len, uint8_t* tag, size_t tag_len);

// Pseudo-Random Number Generator
void disco_RandomSeed(discoRandomCtx* ctx, uint8_t* seed, size_t seed_len);
void disco_InjectEntropy(discoRandomCtx* ctx, uint8_t* entropy,
                         size_t entropy_len);
void disco_RandomGet(discoRandomCtx* ctx, uint8_t* out, size_t out_len);
```

## Need help?

This library is still heavily experimental. Its goal is to support as many platforms as possible. If you need help making it work for a specific platform please post an issue. If you have feedback, or suggestions, please post an issue as well.

## More

The library is currently optimized for code-size. It was done by:

1. re-writing [Strobe-C](https://strobe.sourceforge.io) to make it smaller in size, simpler and closer to the official specification.
2. I'm using [tweetNaCl's X25519](https://tweetnacl.cr.yp.to/) implementation. Strobe has one from Mike Hamburg as well. I need to compare. This can be replaced by more robust implementations for hardware devices that want to implement masking and other side-channel mitigation techniques.
3. I'm using `randombytes()` from [NaCl](https://nacl.cr.yp.to/). The idea here is that any platform can provide a `randombytes` function.
4. I'm using Mike Hamburg's implementation of Keccak-f which is based on [TweetFIPS202](https://keccak.team/2015/tweetfips202.html). This can be replaced by an application's own optimzed implementation of Keccak-f if developers are willing to increase the code size and decrease the readability.

Here are a list of TODOs:

- [ ] should Disco use [Strobe's Schnorr signature](https://strobe.sourceforge.io/papers/) instead of ed25519? It would be smaller in code size. The problem is that ed25519 is supported in more languages and is well accepted as a standard. On the other hand ed25519 uses SHA-512 which we don't want to support.
- [ ] write good documentation. Doxygen is really ugly. Is there a better alternative?
- [ ] figure out if *randombytes* from *nacl* is enough, check what [libhydrogen](https://github.com/jedisct1/libhydrogen) does
- [ ] go through each TODO in the code
- [ ] enforce a maximum message length for the readmessage/writemessage functions? (Noise's specification has a limit of 65535 bytes I believe?)
- [ ] check that I don't crash the application unecessarily (and return errors whenever possible)
- [ ] cleanup make file, remove -g and ASAN
