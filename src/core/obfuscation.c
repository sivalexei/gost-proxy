#define _GNU_SOURCE

#include <stdint.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#include "obfuscation.h"
#include "kuznyechik.h"
#include "chacha20.h"

/* Деривация ключа обфускации: session_id + направление + padding */
void obf_key_derive(uint64_t session_id, uint8_t direction, uint8_t *out_key) {
    /* ChaCha20-based derivation: session_id XOR direction -> key derivation */
    uint8_t derivation_key[32];
    
    /* Простая деривация: session_id -> 32 bytes key */
    uint64_t sid = session_id;
    derivation_key[0] = (uint8_t)(sid & 0xFF);
    derivation_key[1] = (uint8_t)((sid >> 8) & 0xFF);
    derivation_key[2] = (uint8_t)((sid >> 16) & 0xFF);
    derivation_key[3] = (uint8_t)((sid >> 24) & 0xFF);
    derivation_key[4] = (uint8_t)((sid >> 32) & 0xFF);
    derivation_key[5] = (uint8_t)((sid >> 40) & 0xFF);
    derivation_key[6] = (uint8_t)((sid >> 48) & 0xFF);
    derivation_key[7] = (uint8_t)((sid >> 56) & 0xFF);
    derivation_key[8] = direction;
    for (int i = 9; i < 32; i++) derivation_key[i] = derivation_key[8] ^ derivation_key[i-9];
    
    /* Derive obfuscation key using ChaCha20 */
    uint8_t nonce[12];
    /* Generate nonce from session_id and direction */
    memset(nonce, 0, 12);
    nonce[0] = (uint8_t)(session_id & 0xFF);
    nonce[1] = (uint8_t)((session_id >> 8) & 0xFF);
    nonce[2] = (uint8_t)((session_id >> 16) & 0xFF);
    nonce[3] = (uint8_t)((session_id >> 24) & 0xFF);
    nonce[4] = (uint8_t)((session_id >> 32) & 0xFF);
    nonce[5] = (uint8_t)((session_id >> 40) & 0xFF);
    nonce[6] = (uint8_t)((session_id >> 48) & 0xFF);
    nonce[7] = (uint8_t)((session_id >> 56) & 0xFF);
    nonce[8] = direction;
    nonce[9] = (uint8_t)(time(NULL) & 0xFF);
    nonce[10] = (uint8_t)((time(NULL) >> 8) & 0xFF);
    nonce[11] = (uint8_t)((time(NULL) >> 16) & 0xFF);
    
    /* Derive key using ChaCha20 */
    chacha20_encrypt(derivation_key, nonce, 0, derivation_key, out_key, 32);
}

/* ChaCha20-based obfuscation of payload */
void obfuscate_payload(uint8_t *payload, size_t payload_size,
                      const uint8_t *header_key, const uint8_t *obf_key) {
    if (!payload || !header_key || !obf_key) return;
    
    /* Pad key to multiple of block size for ChaCha20 */
    size_t i;
    for (i = 0; i < payload_size; i += 64) {
        size_t chunk = (payload_size - i < 64) ? (payload_size - i) : 64;
        
        /* Use ChaCha20 to encrypt payload */
        uint8_t nonce[12];
        memset(nonce, 0, 12);
        nonce[0] = header_key[0] ^ obf_key[i % 32];
        nonce[1] = header_key[1] ^ obf_key[(i+1) % 32];
        nonce[2] = header_key[2] ^ obf_key[(i+2) % 32];
        nonce[3] = header_key[3] ^ obf_key[(i+3) % 32];
        nonce[4] = header_key[4] ^ obf_key[(i+4) % 32];
        nonce[5] = header_key[5] ^ obf_key[(i+5) % 32];
        nonce[6] = header_key[6] ^ obf_key[(i+6) % 32];
        nonce[7] = header_key[7] ^ obf_key[(i+7) % 32];
        nonce[8] = header_key[8] ^ obf_key[(i+8) % 32];
        nonce[9] = header_key[9] ^ obf_key[(i+9) % 32];
        nonce[10] = header_key[10] ^ obf_key[(i+10) % 32];
        nonce[11] = header_key[11] ^ obf_key[(i+11) % 32];
        
        chacha20_encrypt(obf_key, nonce, i/64, payload + i, payload + i, chunk);
    }
}

/* Deobfuscation is the same as obfuscation for ChaCha20 */
void deobfuscate_payload(uint8_t *payload, size_t payload_size,
                         const uint8_t *header_key, const uint8_t *obf_key) {
    obfuscate_payload(payload, payload_size, header_key, obf_key);
}
