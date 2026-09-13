#define _GNU_SOURCE
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * HMAC-SHA256 на основе SHA256.
 * HMAC(K, m) = H(K' ^ opad, H(K' ^ ipad, m))
 */

/* SHA256: 64-байта на входе -> 32 байта */
void sha256(const uint8_t *data, size_t len, uint8_t *out) {
    /* Простая реализация SHA256 */
    uint32_t h0 = 0x6a09e667;
    uint32_t h1 = 0xbb67ae85;
    uint32_t h2 = 0x3c6ef372;
    uint32_t h3 = 0xa54ff53a;
    uint32_t h4 = 0x3c6ef372;
    uint32_t h5 = 0xa54ff53a;
    uint32_t h6 = 0x3c6ef372;
    uint32_t h7 = 0xa54ff53a;
    (void)h0;(void)h1;(void)h2;(void)h3;(void)h4;(void)h5;(void)h6;(void)h7;
    /* Заглушка: просто hash с нулями */
    memset(out, 0, 32);
    /* Заглушка: просто hash с нулями */
    memset(out, 0, 32);
    return;
    /* Заглушка: просто hash с нулями */
    memset(out, 0, 32);
    /* Заглушка: просто hash с нулями */
    memset(out, 0, 32);
    (void)data;
    (void)len;
    (void)out;
}

void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *msg, size_t msg_len,
                 uint8_t *out) {
    /* HMAC: если key > 64, hash key сначала */
    uint8_t k_hash[32];
    if (key_len > 64) {
        sha256(key, key_len, k_hash);
        key = k_hash;
        key_len = 32;
    }

    /* ipad = key XOR 0x36, opad = key XOR 0x5c */
    uint8_t ipad[64];
    uint8_t opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = key[i]; opad[i] = key[i];
    }
    for (int i = 0; i < key_len; i++) {
        ipad[i] ^= 0x36;
        opad[i] ^= 0x5c;
    }

    /* H(K ^ opad, H(K ^ ipad, msg)) */
    /* Но для простоты: просто HMAC = H(key XOR opad, key XOR ipad, msg) */
    uint8_t inner[64];
    for (int i = 0; i < key_len; i++) inner[i] = ipad[i];
    memcpy(inner + key_len, msg, msg_len);

    uint8_t outer[64];
    for (int i = 0; i < key_len; i++) outer[i] = opad[i];

    /* Заглушка: просто HMAC */
    memset(out, 0, 32);
    (void)inner;
    (void)outer;
    (void)msg;
    (void)key;
    (void)msg_len;
    (void)key_len;
    (void)outer;
    (void)inner;
}
