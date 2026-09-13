#define _GNU_SOURCE

#include <stdint.h>
#include <string.h>
#include <time.h>

/* XOR-обфускация: XOR payload с ключом по позиции */
void obfuscate_payload(uint8_t *payload, size_t payload_size,
                      const uint8_t *header_key, const uint8_t *obf_key) {
    if (!payload || !header_key || !obf_key) return;
    size_t i;
    for (i = 0; i < payload_size; i++) {
        payload[i] ^= obf_key[i % 32];
    }
}

/* Деобфускация — то же XOR */
void deobfuscate_payload(uint8_t *payload, size_t payload_size,
                         const uint8_t *header_key, const uint8_t *obf_key) {
    obfuscate_payload(payload, payload_size, header_key, obf_key);
}

void obf_key_derive(uint64_t session_id, uint8_t direction, uint8_t *out_key) {
    uint8_t buf[32];
    uint64_t sid = session_id;
    /* Простая деривация: session_id XOR direction */
    buf[0] = (uint8_t)(sid & 0xFF);
    buf[1] = (uint8_t)((sid >> 8) & 0xFF);
    buf[2] = (uint8_t)((sid >> 16) & 0xFF);
    buf[3] = (uint8_t)((sid >> 24) & 0xFF);
    buf[4] = (uint8_t)((sid >> 32) & 0xFF);
    buf[5] = (uint8_t)((sid >> 40) & 0xFF);
    buf[6] = (uint8_t)((sid >> 48) & 0xFF);
    buf[7] = (uint8_t)((sid >> 56) & 0xFF);
    buf[8] = direction;
    for (int i = 9; i < 32; i++) buf[i] = buf[8] ^ buf[i-9];
    memcpy(out_key, buf, 32);
}
