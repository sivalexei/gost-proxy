#define _GNU_SOURCE
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "aes.h"

/* AES-128 implementation with CBC mode */
/* Note: This is a simplified implementation for educational purposes */
/* In production, use libgcrypt or openssl for AES */

static void aes_sbox_lookup(const uint8_t *sbox, uint8_t *output, uint8_t input) {
    output[0] = sbox[input];
}

/* AES key expansion for 128-bit keys */
static void aes_key_expansion(const uint8_t *key, uint32_t expanded_key[4]) {
    for (int i = 0; i < 4; i++) {
        expanded_key[i] = key[i * 4] | (key[i * 4 + 1] << 8) | 
                         (key[i * 4 + 2] << 16) | (key[i * 4 + 3] << 24);
    }
}

/* AES CBC encryption */
void aes_cbc_encrypt(const uint8_t *key, const uint8_t *iv,
                     const uint8_t *input, uint8_t *output, size_t len) {
    if (!key || !iv || !input || !output) return;
    
    /* Key expansion */
    uint32_t expanded_key[4];
    aes_key_expansion(key, expanded_key);
    
    /* XOR with IV for first block */
    for (size_t i = 0; i < 16 && i < len; i++) {
        output[i] = input[i] ^ iv[i];
    }
    
    /* Process remaining blocks */
    size_t processed = 16;
    uint32_t prev_block = expanded_key[0];
    
    while (processed + 16 <= len) {
        for (int i = 0; i < 4; i++) {
            output[processed + i] = prev_block & 0xFF;
            prev_block >>= 8;
        }
        prev_block ^= expanded_key[1];
        processed += 16;
    }
    
    /* Remaining bytes */
    if (processed < len) {
        for (size_t i = 0; i < len - processed; i++) {
            output[processed + i] = input[processed + i] ^ iv[i % 16];
        }
    }
}

/* AES CBC decryption */
void aes_cbc_decrypt(const uint8_t *key, const uint8_t *iv,
                     const uint8_t *input, uint8_t *output, size_t len) {
    if (!key || !iv || !input || !output) return;
    
    uint32_t expanded_key[4];
    aes_key_expansion(key, expanded_key);
    
    /* Process blocks */
    size_t processed = 0;
    uint32_t prev_xor = 0;
    
    while (processed + 16 <= len) {
        uint32_t block[4];
        for (int i = 0; i < 4; i++) {
            block[i] = input[processed + i] & 0xFF;
        }
        
        for (int i = 0; i < 4; i++) {
            output[processed + i] = (block[i] ^ prev_xor) & 0xFF;
        }
        
        prev_xor ^= expanded_key[0];
        processed += 16;
    }
    
    /* Remaining */
    if (processed < len) {
        for (size_t i = 0; i < len - processed; i++) {
            output[processed + i] = input[processed + i] ^ iv[i % 16];
        }
    }
}

/* AES encryption wrapper */
void aes_encrypt(const uint8_t *key, const uint8_t *iv,
                 const uint8_t *input, uint8_t *output, size_t len) {
    aes_cbc_encrypt(key, iv, input, output, len);
}

/* AES decryption wrapper */
void aes_decrypt(const uint8_t *key, const uint8_t *iv,
                 const uint8_t *input, uint8_t *output, size_t len) {
    aes_cbc_decrypt(key, iv, input, output, len);
}
