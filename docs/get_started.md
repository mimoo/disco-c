# Get Started

## Project layout

    mkdocs.yml             # documentation configuration file.
    handshake_patterns.py  # script to generate part of disco_asymmetric.h
    docs/                  # documentation files.
    examples/              # examples of using EmbeddedDisco.
    lib/                  
        devurandom.c       # 
        disco_asymmetric.h #
        disco_symmetric.h  
        keccak_f.c.inc     
        tweetX25519.h      
        tweetstrobe.h      
        ...                

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
bool disco_WriteMessage(handshakeState *hs, uint8_t *payload, size_t payload_len,
                       uint8_t *message_buffer, size_t *message_len,
                       strobe_s *client_s, strobe_s *server_s);

// used to parse a handshake message
bool disco_ReadMessage(handshakeState *hs, uint8_t *message, size_t message_len,
                      uint8_t *payload_buffer, size_t *payload_len,
                      strobe_s *client_s, strobe_s *server_s);

// post-handshake encryption
void disco_EncryptInPlace(strobe_s *strobe, uint8_t *plaintext,
                          size_t plaintext_len, size_t plaintext_capacity);

// post-handshake decryption
bool disco_DecryptInPlace(strobe_s *strobe, uint8_t *ciphertext,
                          size_t ciphertext_len);
```

the different handshake patterns are defined in `disco_asymmetric.h` as:

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
#include "symmetric.h"
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