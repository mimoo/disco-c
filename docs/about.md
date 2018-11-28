# Disco

Embedded Disco is an implementation of disco, a protocol designed by merging the [Noise protocol framework](https://noiseprotocol.org/) and the [Strobe protocol framework](https://strobe.sourceforge.io/). This means that it supports a subset of Noise's handshakes while offering the cryptographic primitive Strobe has to offer. In other words, you can use EmbeddedDisco to securely connect peers together, or to do basic cryptographic operations like hashing or encrypting. All of that in only **1000 lines of code**.

![trust graph](https://www.cryptologie.net/upload/Screen_Shot_2018-10-19_at_2.37_.40_PM_.png)

* The secure protocol parts are based on the [Disco specification](http://discocrypto.com/disco.html) which extends the [Noise protocol framework](https://noiseprotocol.org/). The Noise protocol framework is used by many applications including [WhatsApp](https://www.whatsapp.com/security/WhatsApp-Security-Whitepaper.pdf), [Wireguard](https://www.wireguard.com/papers/wireguard.pdf), the [Bitcoin lightning network](https://github.com/lightningnetwork/lightning-rfc/blob/master/08-transport.md), etc.
* The symmetric cryptographic primitives are all based on the [Strobe protocol framework](https://strobe.sourceforge.io/specs/). solely relies on the [SHA-3 permutation](https://en.wikipedia.org/wiki/SHA-3) (called keccak-f) which is a [FIST standard](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.202.pdf) and has undergone [years of cryptanalysis](https://keccak.team/third_party.html) during the [SHA-3 competition](https://en.wikipedia.org/wiki/NIST_hash_function_competition).
* The asymmetric cryptographic primitive (X25519) was designed by Daniel J. Bernstein et al. It is a [strong standard](https://tools.ietf.org/html/rfc8410) used in most protocols nowadays (including SSL/[TLS 1.3](https://tools.ietf.org/html/rfc8446#section-7.4.2)). EmbeddedDisco uses the [tweetNaCl](https://tweetnacl.cr.yp.to/) implementation, written by Daniel J. Bernstein et al. as well.

Want to know more about the technical details? Watch our [presentation at Black Hat Europe 2017](https://www.youtube.com/watch?v=bTGLO4obxco).

## Learn More

To learn more about it, you can read [this blog post](https://www.cryptologie.net/article/432/disco/) or watch our [presentation at Black Hat Europe 2017](https://www.youtube.com/watch?v=bTGLO4obxco).

If you want help, head to the [issues on github](https://github.com/mimoo/disco-c).

If you want to stay tuned on what we're doing, we don't have a mailing list but we have better: [a subreddit over at r/discocrypto](https://www.reddit.com/r/discocrypto/).


