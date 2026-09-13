#ifndef CHACHA20_H
#define CHACHA20_H

#include <stdint.h>
#include <stddef.h>

#define CHACHA20_KEY_SIZE 32
#define CHACHA20_NONCE_SIZE 12
#define CHACHA20_BLOCK_SIZE 64

/* ChaCha20 encrypt/decrypt: same operation for key + nonce + counter */
void chacha20_encrypt(const uint8_t *key, const uint8_t *nonce,
                      uint32_t counter, const uint8_t *input,
                      uint8_t *output, size_t len);

/* Generate nonce: 12 bytes random */
void chacha20_nonce_generate(uint8_t *nonce);

#endif /* CHACHA20_H */
