#ifndef KEY_DERIVATION_H
#define KEY_DERIVATION_H

#include <stdint.h>
#include <stddef.h>

#define PBKDF2_ITERATIONS 64
#define SHA256_RESULT_SIZE 32

/* PBKDF2-HMAC-SHA256 для деривации ключа */
void pbkdf2(const uint8_t *password, const uint8_t *salt,
            uint32_t iterations, const uint8_t *key, /* expanded_key */
            uint8_t *out); /* 32 байта */

/*
 * Формирование расширенного ключа (160 байт):
 * expanded_key[160]: первые 160 байт = PBKDF2 result (32 байт) + salt (32 байт) + 0x00...
 */
void key_derive_full(uint64_t session_id, const uint8_t *nonce,
                     uint8_t *expanded_key_out);

#endif /* KEY_DERIVATION_H */
