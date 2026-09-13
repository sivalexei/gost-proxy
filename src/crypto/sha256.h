#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

#define SHA256_HASH_SIZE 32

/* SHA-256 hash function */
void sha256_hash(const uint8_t *input, size_t len, uint8_t *output);

/* SHA-256 HMAC function */
void sha256_hmac(const uint8_t *key, const uint8_t *message,
                 uint8_t *output, size_t key_len);

/* SHA-256 with padding */
void sha256_hash_padded(const uint8_t *input, size_t len, uint8_t *output);

#endif /* SHA256_H */
