.PHONY: all clean test

all: tweetdisco.a

# make a library, is this useful?
tweetdisco.a: tweetdisco.o tweetstrobe.o tweetnacl.o randombytes.o
	ar -cvq tweetdisco.a tweetdisco.o tweetstrobe.o tweetnacl.o randombytes.o

# :)
tweetdisco.o: tweetdisco.c tweetdisco.h
	$(CC) tweetdisco.c -I tweetnacl -I strobe -c -o tweetdisco.o

# we use this for x25519
tweetnacl.o: 
	cd tweetnacl && $(CC) tweetnacl.c -c -o ../tweetnacl.o

# we need this for tweetnacl
randombytes.o: 
	cd nacl-20110221/randombytes && $(CC) devurandom.c -c -o randombytes.o && mv randombytes.o ../../

# our modification of strobe
tweetstrobe.o: strobe/tweetstrobe.c strobe/tweetstrobe.h
	cd strobe && make tweetstrobe.o && mv tweetstrobe.o ../

# test is probably how you should compile your own program
test: test_disco.c tweetdisco.o tweetstrobe.o tweetnacl.o randombytes.o
	$(CC) test_disco.c -I tweetnacl -I strobe -c -o test_disco.o
	$(CC) test_disco.o tweetdisco.o tweetstrobe.o tweetnacl.o randombytes.o -o test
	./test

# test our implementation of tweetstrobe
test_strobe: test_strobe.c tweetstrobe.o
	$(CC) test_strobe.c -I strobe -c -o test.o
	$(CC) test.o tweetstrobe.o -o test
	./test

# our modification but still has the io/attach feature of strobe
test_strobe_io: test_strobe_io.c tweetstrobe_io.o
	cd strobe && make tweetstrobe_io.o && mv tweetstrobe_io.o ../
	$(CC) test_strobe_io.c -I strobe -c -o test.o
	$(CC) test.o tweetstrobe_io.o -o test
	./test

# the real deal
test_real_strobe: test_real_strobe.c
	cd strobe && make strobe.o && make x25519.o && mv strobe.o ../ && mv x25519.o ../
	$(CC) test_real_strobe.c -I strobe -c -o test.o
	$(CC) test.o strobe.o x25519.o -o test
	./test

clean:
	rm -f *.o
	rm -f tweetdisco
	rm -f test
	rm -f *.a