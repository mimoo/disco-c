# This is a draft of a Makefile
# it contains stuff like -g and -std=c11 and -fsanitize=address that are not
# useful for production binaries
CFLAGS= -g -O1 -Wall -Werror -std=c99 -fsanitize=address

.PHONY: all clean test test_strobe

all: disco_asymmetric.a

# make a library, is this useful?
disco.a: disco_symmetric.o disco_asymmetric.o tweetstrobe.o tweetX25519.o randombytes.o
	ar -cvq disco_asymmetric.a disco_asymmetric.o tweetstrobe.o tweetX25519.o randombytes.o

# Disco protocol
disco_asymmetric.o: lib/disco_asymmetric.c lib/disco_asymmetric.h
	$(CC) $(CFLAGS) lib/disco_asymmetric.c -c -o disco_asymmetric.o

# the disco_symmetric functions wrappers for strobe
disco_symmetric.o: lib/disco_symmetric.c lib/disco_symmetric.h lib/tweetstrobe.h
	$(CC) $(CFLAGS) lib/disco_symmetric.c -c -o disco_symmetric.o

# we use this for X25519 (no ed25519)
tweetX25519.o: lib/tweetX25519.c lib/tweetX25519.h
	$(CC) $(CFLAGS) lib/tweetX25519.c -c -o tweetX25519.o

# we need this for tweetnacl
randombytes.o: 
	$(CC) $(CFLAGS) lib/devurandom.c -c -o randombytes.o

# our modification of strobe
tweetstrobe.o: lib/tweetstrobe.c lib/tweetstrobe.h lib/keccak_f.c.inc 
	$(CC) $(CFLAGS) lib/tweetstrobe.c -c -o tweetstrobe.o

# test is probably how you should compile your own program
test: tests/test_disco.c disco_asymmetric.o tweetstrobe.o tweetX25519.o randombytes.o disco_symmetric.o
	$(CC) $(CFLAGS) -g tests/test_disco.c -c -o test_disco.o -I lib
	$(CC) $(CFLAGS) -g test_disco.o disco_asymmetric.o disco_symmetric.o tweetstrobe.o tweetX25519.o randombytes.o -o test
	./test

# test our implementation of tweetstrobe
test_strobe: tests/test_strobe.c tweetstrobe.o
	$(CC) $(CFLAGS) tests/test_strobe.c -c -o test.o -I lib
	$(CC) $(CFLAGS) test.o tweetstrobe.o -o test
	./test

clean:
	rm *.o
	rm -f disco_asymmetric
	rm -f test
	rm -f *.a