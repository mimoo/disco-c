curdir = "examples/golang_interop"

all:
	@echo "usage:"
	@echo "- make client"
	@echo "   then ./client server_address server_port server_public_key"
	@echo "- make server"

client: client.c
	cd ../.. && make && cp *.o $(curdir) && cd $(curdir)
	$(CC) client.c -fsanitize=address,undefined -g -I ../../lib -c -o client.o
	$(CC) -fsanitize=address,undefined -g client.o disco_asymmetric.o tweetstrobe.o tweetX25519.o randombytes.o -o client

server:
	go run server.go

clean: 
	rm *.o 
	rm client
