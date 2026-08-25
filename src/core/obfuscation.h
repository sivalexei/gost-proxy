#ifndef OBFUSCATION_H
#define OBFUSCATION_H

#include <stdint.h>

#define OBF_KEY_SIZE 16
#define OBF_HEADER_SIZE 16

void obf_key_derive(uint64_t session_id, uint8_t direction, uint8_t *out_key);
void obfuscate_payload(uint8_t *payload, size_t payload_len, const uint8_t *header, const uint8_t *obf_key);
void deobfuscate_payload(uint8_t *payload, size_t payload_len, const uint8_t *header, const uint8_t *obf_key);

#endif /* OBFUSCATION_H */
