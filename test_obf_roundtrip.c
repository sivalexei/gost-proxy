/* Standalone тест: obfuscate → deobfuscate roundtrip */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "src/core/obfuscation.h"

int main(void) {
    uint8_t payload[1408];  /* 8 + MAX_PAYLOAD-4 = 8+1396 */
    uint8_t header[16] = {
        0x47,0x4F,0x53,0x54,  /* magic */
        0x02,                  /* type */
        0x00,0x00,0x00,0x01,  /* conn_id */
        0x00,0x00,0x00,0x00, 0x00,0x00,0x01,0xAA  /* session_id */
    };
    uint8_t obf_key[16] = {
        0xAA,0x01,0xBB,0x02,0xCC,0x03,0xDD,0x04,
        0xEE,0x05,0xFF,0x06,0x00,0x07,0x11,0x08
    };

    /* Заполним payload: первые 8 байт — counter+length, остальные — данные */
    memset(payload, 0, sizeof(payload));
    /* counter = 2 */
    payload[0] = 0; payload[1] = 0; payload[2] = 0; payload[3] = 2;
    /* length = 100 */
    payload[4] = 0; payload[5] = 0; payload[6] = 0; payload[7] = 100;
    /* Данные — уникальные байты */
    for (int i = 8; i < 108; i++) {
        payload[i] = (uint8_t)(i % 256);
    }
    /* Остальное — нули (как memset на клиенте) */

    printf("=== CLIENT: obfuscate(8+MAX_PAYLOAD-4=%d bytes) ===\n", 8 + 1396);
    obfuscate_payload(payload, 8 + 1396, header, obf_key);

    printf("=== SERVER: deobfuscate(8+MAX_PAYLOAD-4=%d bytes) ===\n", 8 + 1396);
    deobfuscate_payload(payload, 8 + 1396, header, obf_key);

    /* Проверим все байты */
    int errors = 0;
    for (int i = 0; i < 108; i++) {
        uint8_t expected = (i < 8) ? 
            ((i < 4) ? (uint8_t)(i * 0) : (i == 4 ? 0 : i == 5 ? 0 : i == 6 ? 0 : 100)) :
            (uint8_t)(i % 256);
        /* counter */
        if (i < 4) { expected = 0; }
        if (i == 3) { expected = 2; }
        /* length */
        if (i >= 4 && i < 8) {
            if (i == 4) expected = 0;
            if (i == 5) expected = 0;
            if (i == 6) expected = 0;
            if (i == 7) expected = 100;
        }
        if (i >= 8) expected = (uint8_t)(i % 256);

        if (payload[i] != expected) {
            printf("ERROR at byte %d: expected 0x%02x, got 0x%02x\n", i, expected, payload[i]);
            if (errors < 5) errors++;
        }
    }
    /* Проверим, что хвост (108..1407) = нули */
    for (int i = 108; i < 1408; i++) {
        if (payload[i] != 0) {
            printf("ERROR at byte %d (zero region): expected 0x00, got 0x%02x\n", i, payload[i]);
            if (errors < 10) errors++;
        }
    }

    if (errors == 0) {
        printf("SUCCESS: roundtrip OK (all bytes match)\n");
        return 0;
    } else {
        printf("FAIL: %d errors\n", errors);
        return 1;
    }
}
