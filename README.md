# TweetDisco

**THIS IS VERY BAD CODE AND IT DOES NOT WORK AND YOU SHOULDN'T EVEN LOOK AT IT**


## TODO

* **name**: change *tweetdisco* to *embeddedDisco* ?
    - "tweet" has a bad connotation, nobody wants to use that
* extract *curve25519* from *tweetnacl*, I don't need the rest
* make a *tweetstrobe* from *strobe*
* figure out if *tweetfips202* can be used as the keccak permutation for *tweetstrobe*
* figure out if *randombytes* from *nacl* is enough, check what *libhydrogen* does
* implement *disco*
* should I re-write everything with `const`?
* why does sprintf and strlen use signed chars?
* figure out a maximum message length for the readmessage/writemessage functions
    - use size_t instead of int?
* there is probably a way to optimize and remove `assert`s, so probably I should crash in a different kind of way?
    - or not crash, and return -1 or something
* accept an external API for generating randomness instead of generating randomness ourselves?
