/**
 * @cond internal
 * @file test_strobe.c
 * @copyright
 *   Copyright (c) 2016 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief Test/example code for STROBE.
 */
#define _GNU_SOURCE 1
#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "x25519.h"
#include "strobe.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>

/* FUTURE: should these go into header? */
static inline __attribute__((unused))
ssize_t strobe_put_and_steg_mac (
    strobe_t strobe,
    control_word_t cw,
    const uint8_t *data,
    ssize_t len,
    uint16_t pad
) {
    TRY( strobe_put(strobe, cw|FLAG_META_C|FLAG_C, data, len) );
    TRY( strobe_put(strobe, MAC|FLAG_META_T|FLAG_META_C, NULL, pad + STROBE_INTEROP_MAC_BYTES) );
    return len;
}

static inline  __attribute__((unused))
ssize_t strobe_get_and_steg_mac (
    strobe_t strobe,
    control_word_t cw,
    uint8_t *data,
    ssize_t len
) {
    ssize_t len2;
    TRY( len = strobe_get(strobe, cw|FLAG_META_C|FLAG_C, data, len) );
    TRY( len2 = strobe_get(strobe, MAC|FLAG_META_T|FLAG_META_C, NULL, -(1<<14)) );
    if (len2 < STROBE_INTEROP_MAC_BYTES) return -1;
    return len;
}

int strobe_x_mksocket_client (
    uint16_t port
) {
    struct sockaddr_in addr;

    int sock = socket(AF_INET , SOCK_STREAM , 0);
    if (sock == -1) { return -1; } 
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_family = AF_INET;
    addr.sin_port = htons( port );
    if (connect(sock , (struct sockaddr *)&addr , sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }
    return sock;
}

int strobe_x_mksocket_server (
    uint16_t port
) {
    struct sockaddr_in addr;
    int option = 1;

    int sock = socket(AF_INET , SOCK_STREAM , 0);
    if (sock == -1) { return -1; } 

    if(setsockopt(sock, SOL_SOCKET,SO_REUSEADDR,(const char*)&option,sizeof(option)) < 0)
        return -1;

    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_family = AF_INET;
    addr.sin_port = htons( port );
    if (bind(sock , (struct sockaddr *)&addr , sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }
    if (listen(sock,1)) return -1;
    int sock2 = accept(sock,NULL,NULL);
    close(sock);
    return sock2;
}

// FUTURE: combine sending.
static ssize_t cb_recv(strobe_io_ctx_s *ctx, const uint8_t **buffer, ssize_t size) {
    uint8_t *a = ctx->a, *b = ctx->b; // a=start b=end

    if (size < 0) {
        return -1;
    } else if (size == 0) {
        return 0;
    } else if (size > b-a) {
        size = b-a;
    }

    *buffer = a;
    ssize_t avail = recv(ctx->fd, a, size, MSG_WAITALL); // read 'avail' (at most 'size') in buffer 'a'
    if (avail == 0) avail = -1; // Cause an error on end of file

    return avail;
}

static ssize_t cb_send(strobe_io_ctx_s *ctx, uint8_t **buffer, ssize_t size) {
    (void)size; /* don't care how many bytes you're gonna write */

    uint8_t *a = ctx->a, *b = ctx->b;

    ssize_t ret;
    if (*buffer > a && *buffer <= b) {
        TRY(( ret = send(ctx->fd, a, *buffer-a, 0) ));
        if (ret != *buffer-a) return -1;
    }

    *buffer = a;
    return b-a;
}

const strobe_io_callbacks_s strobe_x_cb_socket = { cb_recv, cb_send };

static double now(void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec + tv.tv_usec/1000000.0;
}

int hexchar(char x) {
    if (x>= '0' && x <= '9') return x-'0';
    if (x>= 'a' && x <= 'f') return 10 + x-'a';
    if (x>= 'A' && x <= 'F') return 10 + x-'A';
    return -1;
}

int hex2bin(unsigned char *bin, size_t len, const char *hex) {
    if (strlen(hex) != len*2) return -1;
    unsigned int i;
    int res = 0;
    for (i=0; i<2*len; i++) {
        int c = hexchar(hex[i]);
        if (c<0) return -1;
        res = 16*res+c;
        if (i%2 == 1) {
            *(bin++) = res;
            res = 0;
        }
    }
    return 0;
}

static const char *descr = "toy protocol";

uint8_t g_buffer[1024];

static void strobe_x_attach_socket(strobe_t strobe, int sock, uint8_t *buffer, size_t size) {
    strobe->io = &strobe_x_cb_socket;
    strobe->io_ctx.a = buffer;
    strobe->io_ctx.b = buffer + size;
    strobe->io_ctx.fd = sock;
}

int strobe_toy_client (
    strobe_t strobe,
    const uint8_t their_pubkey[32],
    int sock
) {
    strobe_init(strobe, (const uint8_t *)descr, strlen(descr));
    strobe_x_attach_socket(strobe,sock,g_buffer,sizeof(g_buffer));
    TRY( strobe_eph_ecdh(strobe, 1) );
    TRY( strobe_session_verify(strobe, their_pubkey) );

    return 0;
}

int strobe_sym_client_server (
    strobe_t strobe,
    int sock
) {
    const char *descr0="hello", *key="my key";
    strobe_init(strobe, (const uint8_t *)descr0, strlen(descr0));
    strobe_put(strobe, SYM_KEY, (const uint8_t *)key, strlen(key));
    strobe_x_attach_socket(strobe,sock,g_buffer,sizeof(g_buffer));
    return 0;
}

int strobe_toy_server (
    strobe_t strobe,
    const uint8_t my_seckey[32],
    int sock
) {
    strobe_init(strobe, (const uint8_t *)descr, strlen(descr));
    strobe_x_attach_socket(strobe,sock,g_buffer,sizeof(g_buffer));
    TRY( strobe_eph_ecdh(strobe, 0) );
    uint8_t my_pubkey[32];
    x25519_base(my_pubkey, my_seckey,0);
    TRY( strobe_session_sign(strobe, my_seckey, my_pubkey) );

    return 0;
}

#ifdef TEST_KECCAK
void dokeccak(strobe_t sponge, uint8_t xor);
#endif

int echo_server(strobe_t strobe) {
    int ret=0;
    ssize_t get = 0;
    const char *s_ = "I got your message! It was: ";
    size_t off = strlen(s_);
    unsigned char buffer[1024+1+off];
    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer,s_,off);

    while (ret >= 0) {
        get = strobe_get(strobe,APP_CIPHERTEXT|FLAG_POST_MAC,&buffer[off],-(int)sizeof(buffer)-off);
        if (get < 0) { ret = get; break; }
        buffer[get+off] = 0;
        printf("Received %zd %s\n", get, &buffer[off]);
        printf("Sending %zd %s\n", get+off, buffer);

        ret = strobe_put(strobe,APP_CIPHERTEXT|FLAG_POST_MAC,buffer,get+off);
    }
    return ret;
}

int echo_client(strobe_t strobe) {

    char *linep = NULL;
    size_t linep_size = 0; 

    int ret=0;
    ssize_t get;
    unsigned char buffer[1024];

    memset(buffer, 0, sizeof(buffer));
    while (ret >= 0) {
        get = getline(&linep, &linep_size, stdin);
		//printf("GET %d\n", get);
        if (get <= 0) { ret = get; break; }
        if (get > 1024) { ret = -1; break; }
		if ((uint16_t)get != (size_t)get) { return -1; }
        ret = strobe_put(strobe,APP_CIPHERTEXT|FLAG_POST_MAC,(uint8_t*)linep,get-1);
        if (ret < 0) break;
        get = strobe_get(strobe,APP_CIPHERTEXT|FLAG_POST_MAC,buffer,1-(int)sizeof(buffer));

        if (get < 0) { ret = get; break; }
        buffer[get] = 0;
        printf("Received %zd %s\n", get, buffer);
    }

    free(linep);
    return ret;
}

int main(int argc, char **argv) {
    int ret = 0, sock = 0;

    uint8_t pub[32], sec[32], seed[32]={0};

    strobe_t strobe;

    int randfd = open("/dev/urandom",O_RDONLY);
    if (randfd < 0) {
        printf("Can't open /dev/urandom: %s\n", strerror(errno));
        return -1;
    } else if ((ret = read(randfd,seed,sizeof(seed))) != sizeof(seed)) {
        printf("Can't read /dev/urandom: %s\n", strerror(errno));
        return -1;
    }

    strobe_seed_prng(seed,sizeof(seed));

    if (argc == 3 && !strcmp(argv[1],"--client")) {

            if (hex2bin(pub,sizeof(pub),argv[2])) {
                printf("bad hex\n");
                return -1;
            }
            sock = strobe_x_mksocket_client(4444);
            if (sock < 0) ret = sock;
            else ret = strobe_toy_client(strobe,pub,sock);
            if (ret >= 0) ret = echo_client(strobe);

    } else if (argc == 2 && !strcmp(argv[1],"--sym-client")) {
            sock = strobe_x_mksocket_client(4444);
            if (sock < 0) ret = sock;
            else ret = strobe_sym_client_server(strobe,sock);
            if (ret >= 0) ret = echo_client(strobe);

    } else if (argc == 2 && !strcmp(argv[1],"--sym-server")) {
            sock = strobe_x_mksocket_server(4444);
            if (sock < 0) ret = sock;
            else ret = strobe_sym_client_server(strobe,sock);
            if (ret >= 0) ret = echo_server(strobe);

    } else if (argc == 3 && !strcmp(argv[1],"--server")) {
        if (hex2bin(sec,sizeof(sec),argv[2])) {
            printf("bad hex\n");
            return -1;
        }

        sock = strobe_x_mksocket_server(4444);
        if (sock < 0) ret = sock;
        else ret = strobe_toy_server(strobe,sec,sock);
        if (ret >= 0) ret = echo_server(strobe);

    } else if (argc == 2 && !strcmp(argv[1],"--keygen")) {
        uint8_t pub[32],sec[32];
        if (( ret = strobe_randomize(sec,sizeof(sec)) ) >= 0 ) {
            int i;
            printf("%s --server ", argv[0]);
            for (i=0; i<32; i++) printf("%02x",sec[i]);
            printf("\n");  
            x25519_base(pub,sec,0);
            printf("%s --client ", argv[0]);
            for (i=0; i<32; i++) printf("%02x",pub[i]);
            printf("\n");
            return 0;
        }
    } else if (argc == 2 && !strcmp(argv[1],"--bench")) {
        const int BYTES = 10000, ROUNDS = 100;
        uint8_t buffer[BYTES];
        uint8_t buffer2[BYTES+4];
        memset(buffer,0,sizeof(buffer));
        strobe_init(strobe,(const unsigned char *)"benching",5);
        double t = now();

        for (int i=0; i<ROUNDS; i++) {
            strobe_attach_buffer(strobe,buffer2,sizeof(buffer2));
            int ret = strobe_operate(strobe,APP_CIPHERTEXT,buffer,sizeof(buffer));
            if (ret<0) return -1;
        }
        t = now()-t;
        printf("%dB/%0.3fs = %0.3fkB/s\n", BYTES*ROUNDS, t, BYTES*ROUNDS/t/1000);
        return 0;
#ifdef TEST_KECCAK
    } else if (argc == 2 && !strcmp(argv[1],"--tv")) {
        memset(strobe,0,sizeof(strobe));
        dokeccak(strobe,0);
        for (int i=0; i<25*4; i++)
            printf("%02x ", strobe->state->b[i]);
        printf("\n");

#endif
    } else {
        printf(
            "Usage: %s --keygen\n"
            "       %s --client key\n"
            "       %s --server key\n"
            "       %s --client-too key\n"
            "       %s --server-too key\n"
            "       %s --bench\n",
        argv[0],argv[0],argv[0],
        argv[0],argv[0],argv[0]
        );
        return -1;
    }
    if (sock) close(sock);
    printf("ret = %d\n", ret);
    return 0;
}