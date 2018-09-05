# TweetDisco

**THIS IS VERY BAD CODE AND IT DOES NOT WORK AND YOU SHOULDN'T EVEN LOOK AT IT**

This is mostly me doing a proof of concept of [Disco](http://discocrypto.com/#/) in C.

It is optimized for code-size at the moment, mostly because I suck at optimizing things:

* I re-wrote [Strobe-C]() to make it smaller in size and simpler.
* I'm using [tweetNaCl's X25519]() implementation.
* I'm using `randombytes()` from [NaCl]()
* I'm using Mike Hamburg's implementation of Keccak-f, but I'm thinking of switching to [TweetFIPS202]()

## How to try

```
make test
```

## TODO

- [ ] re-write `tweetdisco` with `tweetstrobe` new `strobe_operate()`
- [ ] rename *tweetdisco* to *embeddedDisco* or something? (tweet might have a bad connotation)
- [ ] extract *curve25519* from *tweetnacl*, because that's all I really need 
- [ ] figure out if *tweetfips202* can be used as the keccak permutation for *tweetstrobe*? That would reduce the LOC stat further
- [ ] figure out if *randombytes* from *nacl* is enough, check what *libhydrogen* does
- [ ] should I re-write "everything" with `const`?
- [ ] why does sprintf and strlen use "signed" chars?
- [ ] figure out a maximum message length for the readmessage/writemessage functions (use size_t instead of int?)
- [ ] `assert` is probably removed by optimizations, so I should prob avoid using it in important places?
- [ ] check that I don't crash the application unecessarily (and return -1 or something instead)
- [ ] accept an external API for generating randomness instead of generating randomness ourselves? or have it XOR'ed with ours?
