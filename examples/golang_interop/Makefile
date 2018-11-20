curdir = "examples/golang_interop"

all:
	@echo "usage:"
	@echo "- make client"
	@echo "   then ./client server_address server_port server_public_key"
	@echo "- make server"

client:
	cd ../.. && make && cp *.o $(curdir) && cd $(curdir)
	$(CC) client.c -fsanitize=address -I ../../lib -c -o client.o
	$(CC) -fsanitize=address client.o tweetdisco.o tweetstrobe.o tweet25519.o randombytes.o -o client

server:
	go run server.go

clean: 
	rm *.o 
	rm client