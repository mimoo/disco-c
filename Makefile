CFLAGS= -g -O1 -Wall -Werror -std=c11 -fsanitize=address

.PHONY: all clean test

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
tweetstrobe.o: lib/tweetstrobe.c lib/tweetstrobe.h lib/keccak_f.c.inc lib/strobe_config.h
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

# delete this when done v
# our modification but still has the io/attach feature of strobe
test_strobe_io: lib/test_strobe_io.c
	cd strobe && make tweetstrobe_io.o && mv tweetstrobe_io.o ../
	$(CC) $(CFLAGS) lib/test_strobe_io.c -I strobe -c -o test.o
	$(CC) $(CFLAGS) test.o tweetstrobe_io.o -o test
	./test

# the real strobe
test_real_strobe: lib/test_real_strobe.c
	cd strobe && make strobe.o && make x25519.o && mv strobe.o ../ && mv x25519.o ../
	$(CC) $(CFLAGS) lib/test_real_strobe.c -I strobe -c -o test.o
	$(CC) $(CFLAGS) test.o strobe.o x25519.o -o test
	./test

clean:
	rm *.o
	rm -f tweetdisco
	rm -f test
	rm -f *.a