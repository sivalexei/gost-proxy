/* Тест: реальная проблема — клиент obfuscate 8+tl, сервер deobfuscate 8+MAX_PAYLOAD-4 */
#include <stdio.h>
#include <string.h>
#include "src/core/obfuscation.h"

int main(void) {
    uint8_t payload[1408];
    uint8_t header[16] = {
        0x47,0x4F,0x53,0x54, 0x02,
        0x00,0x00,0x00,0x01,
        0x00,0x00,0x00,0x00,0x00,0x00,0x01,0xAA
    };
    uint8_t obf_key[16] = {
        0xAA,0x01,0xBB,0x02,0xCC,0x03,0xDD,0x04,
        0xEE,0x05,0xFF,0x06,0x00,0x07,0x11,0x08
    };

    /* Payload: 8 байт заголовок + 100 данных + padding + хвост с мусором */
    memset(payload, 0, sizeof(payload));
    payload[3] = 2; payload[7] = 108;  /* tl=108 */
    for (int i = 8; i < 108; i++) payload[i] = (uint8_t)(i % 256);
    /* Хвост с мусором (как бывает при reuse буфера) */
    for (int i = 108; i < 1408; i++) payload[i] = (uint8_t)((i * 7 + 3) % 256);

    printf("=== OLD BUG: client obfuscate(8+108), server deobfuscate(8+1396) ===\n");
    /* Клиент обфусцировал только 8+108 */
    obfuscate_payload(payload, 8+108, header, obf_key);
    /* Сервер деобфусцирует всё 8+1396 — stream индексы не совпадут */
    deobfuscate_payload(payload, 8+1396, header, obf_key);

    int errors = 0;
    for (int i = 0; i < 108; i++) {
        uint8_t expected = (i < 4) ? 0 : (i == 3 ? 2 : i == 7 ? 108 : (i % 256));
        if (payload[i] != expected) {
            if (errors < 10)
                printf("  byte[%d]: exp=0x%02x got=0x%02x\n", i, expected, payload[i]);
            errors++;
        }
    }
    printf("  errors in payload[0..107]: %d\n", errors);

    /* Теперь проверим FULL roundtrip (как теперь на клиенте) */
    memset(payload, 0, sizeof(payload));
    payload[3] = 2; payload[7] = 108;
    for (int i = 8; i < 108; i++) payload[i] = (uint8_t)(i % 256);
    for (int i = 108; i < 1408; i++) payload[i] = (uint8_t)((i * 7 + 3) % 256);

    printf("\n=== FIXED: client obfuscate(8+1396), server deobfuscate(8+1396) ===\n");
    obfuscate_payload(payload, 8+1396, header, obf_key);
    deobfuscate_payload(payload, 8+1396, header, obf_key);

    errors = 0;
    for (int i = 0; i < 1408; i++) {
        uint8_t expected = (i < 4) ? 0 : (i == 3 ? 2 : i == 7 ? 108 : (i % 256));
        if (i >= 108) expected = (uint8_t)((i * 7 + 3) % 256);
        if (payload[i] != expected) {
            if (errors < 10)
                printf("  byte[%d]: exp=0x%02x got=0x%02x\n", i, expected, payload[i]);
            errors++;
        }
    }
    printf("  errors in payload[0..1407]: %d\n", errors);
    return errors > 0 ? 1 : 0;
}
