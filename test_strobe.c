#include "tweetstrobe.h"
#include <stdio.h>

void print(const char *desc, unsigned char *buffer, size_t len) {
  printf("%s:", desc);
  for (int i = 0; i < len; i++) {
    printf("%02x", buffer[i]);
  }
  printf("\n");
}

void assert_eq(
    const char *seq1, const char *seq2,
    size_t len) {  // buffer, {0x3b, 0x89, 0xe8, 0x2e, 0xb0, 0x7c, 0xfd}, ret)
  for (size_t i = 0; i < len; i++) {
    if (seq1[i] != seq2[i]) {
      printf("wrong value %02x and %02x\n", seq1[i], seq2[i]);
      exit(1);
    }
  }
}

int main() {
  // init
  strobe_s s1;
  strobe_s s2;
  unsigned char name[] = "hey";
  strobe_init(&s1, name, 3);
  strobe_init(&s2, name, 3);

  // buffer
  unsigned char buffer[600];
  for (int i = 0; i < 600; i++) {
    buffer[i] = 0;
  }

  // 0. hello
  memcpy(buffer, (unsigned char *)"hello\n", 7);
  print("0. hello", buffer, 7);

  // 1. send_ENC
  ssize_t ret = strobe_operate(&s1, TYPE_ENC, buffer, 7, false);
  if (ret < 0) {
    printf("error\n");
    return 1;
  }
  printf("debug%ld\n", ret);
  print("1. E(hello)", buffer, ret);
  assert_eq((const char *)buffer, "\x3b\x89\xe8\x2e\xb0\x7c\xfd", ret);

  // send_MAC
  ssize_t ret2 = strobe_operate(&s1, TYPE_MAC, buffer + 7, 16, false);
  if (ret2 < 0) {
    printf("error2\n");
    return 1;
  }
  print("2. send_MAC", buffer, ret + ret2);
  assert_eq((const char *)buffer + ret,
            "\x0e\x8b\x81\xb2\x7b\xdb\x4d\x35\xf1\x54\x9a\xf7\x54\xdf\x06\xab",
            ret2);

  // recv_ENC
  ret = strobe_operate(&s2, TYPE_ENC | FLAG_I, buffer, 7, false);
  if (ret < 0) {
    printf("error2\n");
    return 1;
  }
  print("3. recv_ENC", buffer, ret);
  assert_eq((const char *)buffer, "\x68\x65\x6c\x6c\x6f\x0a\x00", ret);

  // receive mac
  ret = strobe_operate(&s2, TYPE_MAC | FLAG_I, buffer + 7, 16, false);
  if (ret < 0) {
    printf("error2\n");
    return 1;
  }
  printf("4. recv_MAC: %ld", ret);

  return 0;
}