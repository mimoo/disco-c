#include "tweetnacl.h"
#include "randombytes.h"

int main() {
	unsigned char a[5];
	randombytes(a, 5);
	return 0;
}