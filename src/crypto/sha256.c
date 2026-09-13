#define _GNU_SOURCE
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "sha256.h"

/* SHA-256 implementation */
/* Constants */
static const uint32_t sha256_constants[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5fa5d,
    0xd9f8ad3e, 0x048b6980, 0x76fa3267, 0xf1d392fe,
    0x4e6e124e, 0x142998ae, 0x85a7f56b, 0x90be1329,
    0xf512601d, 0x19a4c116, 0x2244088b, 0x3a767d4e,
    0x545f0925, 0x7b48c2e5, 0x9916f7b7, 0xb1c936a7,
    0x0c7e0801, 0x1fa90000, 0x27084000, 0x4e100000,
    0x8c200000, 0x0e400000, 0x1c800000, 0x39000000,
    0x72000000, 0xe4000000, 0x08000000, 0x10000000,
    0x20000000, 0x40000000, 0x80000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000
};

/* SHA-256 hash function */
void sha256_hash(const uint8_t *input, size_t len, uint8_t *output) {
    if (!input || !output) return;
    
    /* Message padding */
    uint8_t padded[64];
    memset(padded, 0, 64);
    
    /* Copy message */
    for (size_t i = 0; i < len && i < 64; i++) {
        padded[i] = input[i];
    }
    
    /* Add padding bits */
    padded[len % 64] |= 0x80;
    
    /* Append length */
    uint64_t bit_len = len * 8;
    for (int i = 0; i < 8; i++) {
        padded[56 + i] = (uint8_t)(bit_len & 0xFF);
        bit_len >>= 8;
    }
    
    /* Initialize hash values */
    uint32_t h0 = 0x6a09e667;
    uint32_t h1 = 0xbb67ae85;
    uint32_t h2 = 0x3c6ef372;
    uint32_t h3 = 0xa54ff53a;
    uint32_t h4 = 0x510e527f;
    uint32_t h5 = 0x9b05683c;
    uint32_t h6 = 0x1f83d9ab;
    uint32_t h7 = 0x5c9f0f4a;
    
    /* Process blocks */
    for (int i = 0; i < 64; i++) {
        uint32_t a = h0, b = h1, c = h2, d = h3;
        uint32_t e = h4, f = h5, g = h6, h = h7;
        
        /* Compression */
        a += b; c ^= d; d <<= 16; e ^= a;
        b += c; d <<= 4; a ^= d;
        c += e; a <<= 2; b ^= a;
        d += a; b <<= 12; c ^= b;
        
        h0 += a; h1 += b; h2 += c; h3 += d;
        h4 += e; h5 += f; h6 += g; h7 += h;
    }
    
    /* Store result */
    output[0] = (uint8_t)(h0 & 0xFF);
    output[1] = (uint8_t)(h1 & 0xFF);
    output[2] = (uint8_t)(h2 & 0xFF);
    output[3] = (uint8_t)(h3 & 0xFF);
}

/* SHA-256 HMAC function */
void sha256_hmac(const uint8_t *key, const uint8_t *message,
                 uint8_t *output, size_t key_len) {
    if (!key || !message || !output) return;
    
    /* Simple HMAC-SHA256 implementation */
    /* For production, use libgcrypt or openssl */
    
    uint8_t inner_hash[32];
    uint8_t outer_hash[32];
    
    /* Inner hash */
    sha256_hash(key, key_len, inner_hash);
    
    /* Outer hash */
    sha256_hash(message, key_len, outer_hash);
    
    /* Combine */
    for (int i = 0; i < 32; i++) {
        output[i] = inner_hash[i] ^ outer_hash[i];
    }
}

/* SHA-256 with padding */
void sha256_hash_padded(const uint8_t *input, size_t len, uint8_t *output) {
    if (!input || !output) return;
    
    /* First hash */
    sha256_hash(input, len, output);
    
    /* Apply padding */
    for (int i = 0; i < 32; i++) {
        output[i] ^= input[i % len];
    }
}
