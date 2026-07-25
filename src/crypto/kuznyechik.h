#ifndef KUZNYECHIK_H
#define KUZNYECHIK_H

#include <stdint.h>
#include <stddef.h>

#define KUZNYECHIK_BLOCK_SIZE 16
#define KUZNYECHIK_KEY_SIZE   32
#define KUZNYECHIK_EXPANDED_KEY_SIZE 160
#define KUZNYECHIK_ROUNDS     10

typedef struct {
    uint8_t data[KUZNYECHIK_EXPANDED_KEY_SIZE];
} kuznyechik_key_t;

/* Расширение ключа (256 бит → 10 раундовых ключей) */
void kuznyechik_set_key(const uint8_t *key, uint8_t *expanded_key);

/* Шифрование одного блока (16 байт) */
void kuznyechik_encrypt_block(uint8_t *block, const uint8_t *expanded_key);

/* Расшифрование одного блока (16 байт) */
void kuznyechik_decrypt_block(uint8_t *block, const uint8_t *expanded_key);

/* CTR-режим: шифрование/расшифрование потоковых данных */
void kuznyechik_encrypt_ctr(
    const uint8_t *in,
    uint8_t *out,
    size_t len,
    const uint8_t *expanded_key,
    const uint8_t *nonce
);

/* Утилиты */
void kuznyechik_encrypt_ecb(
    const uint8_t *in,
    uint8_t *out,
    size_t len,
    const uint8_t *expanded_key
);

#endif /* KUZNYECHIK_H */
