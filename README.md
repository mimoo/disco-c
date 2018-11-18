# TweetDisco

**THIS IS VERY BAD CODE AND IT DOES NOT WORK AND YOU SHOULDN'T EVEN LOOK AT IT**

**DID YOU READ THE LINE ABOVE?**

**IF YOU READ THE LINE ABOVE WHY ARE YOU STILL READING THIS**

**I SAID THAT YOU SHOULD NOT LOOK AT THIS**

This is mostly me doing a proof of concept of [Disco](http://discocrypto.com/#/) in C.

It is optimized for code-size at the moment, mostly because I suck at optimizing things:

* I re-wrote [Strobe-C]() to make it smaller in size and simpler.
* I'm using [tweetNaCl's X25519]() implementation. But why not Mike Hamburg's one?
* I'm using `randombytes()` from [NaCl]()
* I'm using Mike Hamburg's implementation of Keccak-f which is based on [TweetFIPS202]()
* I should probably use Strobe's suggestion for signature instead of ed25519
    - (because ed25519 requires a different hash function)

## How to test

```
make test
```

## TODO

- [x] re-write `tweetdisco` with `tweetstrobe` new `strobe_operate()`
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
