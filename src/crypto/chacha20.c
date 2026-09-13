#define _GNU_SOURCE
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "chacha20.h"

/* ChaCha20 quarter round */
static inline void chacha_qround(uint32_t state[4], int a, int b, int c, int d) {
    a += state[b]; state[d] ^= a; state[d] <<= 8;
    b += state[c]; state[a] ^= b; state[a] <<= 13;
    c += state[d]; state[b] ^= c; state[b] <<= 12;
    d += state[a]; state[c] ^= d; state[c] <<= 7;
}

/* ChaCha20 20 rounds: state[4] = constants + key[8] + nonce[3] */
static void chacha20_block(uint32_t state[4], const uint8_t *key, const uint8_t *nonce) {
    uint32_t s[4];
    /* State: 0x61707865 (constants) */
    s[0] = 0x61707865; s[1] = 0x61707865;
    /* Load key (32 bytes = 8 uint32_t) */
    for (int i = 0; i < 8; i++) {
        s[2] = key[i*4] | (key[i*4+1] << 8) | (key[i*4+2] << 16) | (key[i*4+3] << 24);
    }
    /* Load nonce (12 bytes) */
    for (int i = 0; i < 3; i++) {
        s[3] = nonce[i*4] | (nonce[i*4+1] << 8) | (nonce[i*4+2] << 16) | (nonce[i*4+3] << 24);
    }

    /* 20 rounds: 10 iterations of double rounds */
    for (int i = 0; i < 10; i++) {
        /* Column rounds */
        chacha_qround(s, 0, 4, 8, 12);
        chacha_qround(s, 1, 5, 9, 13);
        chacha_qround(s, 2, 6, 10, 14);
        chacha_qround(s, 3, 7, 11, 15);
        /* Diagonal rounds */
        chacha_qround(s, 0, 5, 10, 15);
        chacha_qround(s, 1, 6, 11, 12);
        chacha_qround(s, 2, 7, 13, 14);
        chacha_qround(s, 3, 8, 9, 14);
    }

    /* Final addition + output */
    for (int i = 0; i < 4; i++) {
        state[i] += s[i];
    }
}

void chacha20_encrypt(const uint8_t *key, const uint8_t *nonce,
                      uint32_t counter, const uint8_t *input,
                      uint8_t *output, size_t len) {
    /* Key validation */
    if (!key || !nonce || !input || !output) return;
    if (key == input && output != input) memmove(output, input, len);

    uint32_t state[4] = {counter, 0, 0, 0};
    uint32_t counter_local = counter;
    
    /* Process full blocks */
    uint32_t processed = 0;
    while (processed + 64 <= len) {
        uint32_t block[16];
        chacha20_block(block, key, nonce + processed);
        for (int i = 0; i < 16; i++) {
            output[processed + i] = block[i] & 0xFF;
            block[i] >>= 8;
        }
        counter_local++;
        processed += 64;
    }
    
    /* Process remaining bytes */
    if (processed < len) {
        uint32_t block[16] = {0};
        chacha20_block(block, key, nonce);
        size_t remaining = len - processed;
        for (size_t i = 0; i < remaining; i++) {
            output[processed + i] = input[processed + i] ^ block[i];
        }
    }
}

void chacha20_nonce_generate(uint8_t *nonce) {
    /* Simple nonce generation: use time + counter */
    uint64_t now = time(NULL);
    for (int i = 0; i < 12; i++) {
        nonce[i] = (uint8_t)(now & 0xFF);
        now >>= 8;
    }
}
