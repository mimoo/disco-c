# Copyright (c) 2015-2016 Cryptography Research, Inc.
# Author: Mike Hamburg
# Description: STROBE Makefile. for 
 
CC= gcc
ARMCC= arm-none-eabi-gcc -fstack-usage -DNDEBUG
CFLAGS= -std=c11 -Os -Wall -Wextra -Werror $(XCFLAGS)
ARMLDFLAGS= -lc -specs=rdimon.specs
ARMTARGET= -mcpu=cortex-m4 -mthumb -DSTROBE_SINGLE_THREAD=1 

.PHONY: all todo clean size-arm test-arm test-native test-strobe test-connection

all: build/test_x25519 build/test_x25519.arm build/test_strobe

build/timestamp:
	mkdir build
	touch $@

build/%.arm.o: %.c build/timestamp *.h Makefile
	$(ARMCC) $(CFLAGS) $(ARMTARGET) -o $@ -c $<

build/%.o: %.c build/timestamp *.h Makefile
	$(CC) $(CFLAGS) -o $@ -c $<

build/test_x25519.arm: build/x25519.arm.o build/test_x25519.arm.o
	$(ARMCC) $(ARMTARGET) -o $@ $^ $(ARMLDFLAGS)

build/test_x25519: build/x25519.o build/test_x25519.o
	$(CC) $(TARGET) -o $@ $^ $(LDFLAGS)
	
test-strobe: build/test_strobe
build/test_strobe: build/strobe.o build/x25519.o build/test_strobe.o
	$(CC) $(TARGET) -o $@ $^ $(LDFLAGS)

size-arm: build/test_x25519.arm
	size build/x25519.arm.o
	cat build/x25519.arm.su || true
	nm --size build/x25519.arm.o | perl -pe 's/[0-9a-f]+/hex $&/e'

test-arm: size-arm
	time ./build/test_x25519.arm

test-native: build/test_x25519
	build/test_x25519

test-connection: build/test_strobe
	./$< --keygen > build/keys
	sh -c "`head -n 1 build/keys`" > /dev/null &
	sleep 1
	sh -c "`tail -n 1 build/keys`"

todo::
	@egrep --color 'TODO|FIXME|HACK|XXX|(\bBUG\b)|WTF|PERF' *.c *.h arm/*.inc
	
clean::
	rm -fr build release keys