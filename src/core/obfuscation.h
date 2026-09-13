#ifndef OBFUSCATION_H
#define OBFUSCATION_H

#include <stdint.h>
#include <stddef.h>

#define OBF_KEY_SIZE 32

/* Деривация ключа обфускации: session_id + направление */
void obf_key_derive(uint64_t session_id, uint8_t direction, uint8_t *out_key);

/* XOR-обфускация payload: XOR каждого байта с ключом по позиции */
void obfuscate_payload(uint8_t *payload, size_t payload_size,
                      const uint8_t *header_key, const uint8_t *obf_key);

/* XOR-деобфускация (та же функция) */
void deobfuscate_payload(uint8_t *payload, size_t payload_size,
                         const uint8_t *header_key, const uint8_t *obf_key);

#endif /* OBFUSCATION_H */
