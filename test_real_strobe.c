#include "strobe.h"
#include <stdio.h>

void print(const char *desc, unsigned char *buffer, size_t len) {
	printf("%s:", desc);
	for(int i=0; i<len; i++) {
		printf("%02x", buffer[i]);
	}
	printf("\n");
}

int main() {
	// init
	strobe_t s1;
	strobe_t s2;
	unsigned char name[] = "hey";
	strobe_init(s1, name, 3);
	strobe_init(s2, name, 3);
	// buffer
	unsigned char out[600];
	for(int i=0; i<600; i++) {
		out[i] = 0;
	}




	// send hello
	uint8_t text[] = "hello\n";
	print("0. hello: ", text, 7);
	// send_ENC
	strobe_attach_buffer(s1, out, 600);
	ssize_t ret = strobe_put(s1, TYPE_ENC, text, 7);
	if (ret < 0) {
		printf("error\n");
		return 1;
	}
	print("1. E(hello): ", out, ret);
	// send_MAC
	ret = strobe_put(s1, TYPE_MAC, NULL, 16);
	if (ret < 0) {
		printf("error2\n");
		return 1;
	}
	print("2. send_MAC", out, 16+7);

	// recv_ENC
	unsigned char in[600];
	strobe_attach_buffer(s2, out, 600);
	ret = strobe_get(s2, TYPE_ENC | FLAG_I, in, 7);
	if (ret < 0) {
		printf("error2\n");
		return 1;
	}
	print("3. recv_ENC", in, ret);

	// receive mac
	ret = strobe_get(s2, TYPE_MAC | FLAG_I, NULL, 16);
	if (ret < 0) {
		printf("error2\n");
		return 1;
	}
	printf("4. recv_MAC: %ld", ret);

	return 0;
}