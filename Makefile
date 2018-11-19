CFLAGS= -g -O1 -Wall -Werror -std=c11 -fsanitize=address

.PHONY: all clean test test_strobe

# This is a draft of a Makefile
# it contains stuff like -g and -std=c11 and -fsanitize=address that are not
# useful for production binaries
all: tweetdisco.a

# make a library, is this useful?
tweetdisco.a: tweetdisco.o tweetstrobe.o tweet25519.o randombytes.o
	ar -cvq tweetdisco.a tweetdisco.o tweetstrobe.o tweet25519.o randombytes.o

# :)
tweetdisco.o: lib/tweetdisco.c lib/tweetdisco.h
	$(CC) $(CFLAGS) lib/tweetdisco.c -I strobe -c -o tweetdisco.o

# we use this for X25519 (no ed25519)
tweet25519.o: 
	$(CC) $(CFLAGS) lib/tweet25519.c -c -o tweet25519.o

# we need this for tweetnacl
randombytes.o: 
	$(CC) $(CFLAGS) lib/devurandom.c -c -o randombytes.o

# our modification of strobe
tweetstrobe.o: lib/tweetstrobe.c lib/tweetstrobe.h lib/keccak_f.c.inc 
	$(CC) $(CFLAGS) lib/tweetstrobe.c -c -o tweetstrobe.o

# test is probably how you should compile your own program
test: lib/test_disco.c tweetdisco.o tweetstrobe.o tweet25519.o randombytes.o
	$(CC) $(CFLAGS) -g lib/test_disco.c -c -o test_disco.o
	$(CC) $(CFLAGS) -g test_disco.o tweetdisco.o tweetstrobe.o tweet25519.o randombytes.o -o test
	./test

# test our implementation of tweetstrobe
test_strobe: lib/test_strobe.c tweetstrobe.o
	$(CC) $(CFLAGS) lib/test_strobe.c -c -o test.o
	$(CC) $(CFLAGS) test.o tweetstrobe.o -o test
	./test

clean:
	rm *.o
	rm -f tweetdisco
	rm -f test
	rm -f *.a