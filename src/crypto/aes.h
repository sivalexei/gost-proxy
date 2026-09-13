#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stddef.h>

#define AES_KEY_SIZE 16
#define AES_BLOCK_SIZE 16
#define AES_MAX_KEY_SIZE 32

/* AES-128/192/256 encryption and decryption */
void aes_encrypt(const uint8_t *key, const uint8_t *iv,
                 const uint8_t *input, uint8_t *output, size_t len);
void aes_decrypt(const uint8_t *key, const uint8_t *iv,
                 const uint8_t *input, uint8_t *output, size_t len);

/* AES-CBC mode wrapper */
void aes_cbc_encrypt(const uint8_t *key, const uint8_t *iv,
                     const uint8_t *input, uint8_t *output, size_t len);
void aes_cbc_decrypt(const uint8_t *key, const uint8_t *iv,
                     const uint8_t *input, uint8_t *output, size_t len);

#endif /* AES_H */
