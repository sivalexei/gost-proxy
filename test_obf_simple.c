/* Тест: обфусцируем payload с данными+padding, деобфусцируем, сравниваем */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "src/core/obfuscation.h"

int main(void) {
    uint8_t payload[1408];
    uint8_t orig[1408];
    uint8_t header[16] = {
        0x47,0x4F,0x53,0x54, 0x02,
        0x00,0x00,0x00,0x01,
        0x00,0x00,0x00,0x00,0x00,0x00,0x01,0xAA
    };
    uint8_t obf_key[16] = {
        0xAA,0x01,0xBB,0x02,0xCC,0x03,0xDD,0x04,
        0xEE,0x05,0xFF,0x06,0x00,0x07,0x11,0x08
    };

    /* Заполняем payload случайными данными */
    for (int i = 0; i < 1408; i++) payload[i] = (uint8_t)(i * 7 + 3);

    printf("=== TEST 1: mismatched obf/deobf lengths ===\n");
    printf("Client obfuscate(8+108), Server deobfuscate(8+1396)\n");
    /* Клиент обфусцировал только 8+108 байт */
    obfuscate_payload(payload, 8+108, header, obf_key);
    /* Сервер деобфусцирует 8+1396 — stream индексы сдвигаются */
    deobfuscate_payload(payload, 8+1396, header, obf_key);

    int errors = 0;
    for (int i = 0; i < 1408; i++) {
        if (payload[i] != (uint8_t)(i * 7 + 3)) {
            errors++;
        }
    }
    printf("  errors: %d\n", errors);

    printf("\n=== TEST 2: matching obf/deobf lengths (FIXED) ===\n");
    for (int i = 0; i < 1408; i++) payload[i] = (uint8_t)(i * 7 + 3);
    printf("Both obfuscate(8+1396)\n");
    obfuscate_payload(payload, 8+1396, header, obf_key);
    deobfuscate_payload(payload, 8+1396, header, obf_key);

    errors = 0;
    for (int i = 0; i < 1408; i++) {
        if (payload[i] != (uint8_t)(i * 7 + 3)) {
            if (errors < 5)
                printf("  byte[%d]: expected 0x%02x, got 0x%02x\n", i, (uint8_t)(i*7+3), payload[i]);
            errors++;
        }
    }
    printf("  errors: %d\n", errors);
    return errors > 0 ? 1 : 0;
}
