/* Тест: старый баг — obfuscate только 8+tl, deobfuscate 8+MAX_PAYLOAD-4 */
#include <stdio.h>
#include <string.h>
#include "src/core/obfuscation.h"

int main(void) {
    uint8_t payload[1408];
    uint8_t header[16] = {0};
    uint8_t obf_key[16] = {0};
    int tl = 100;

    memset(payload, 0, sizeof(payload));
    payload[3] = 2; payload[7] = 100;
    for (int i = 8; i < 108; i++) payload[i] = (uint8_t)(i % 256);

    /* СТАРЫЙ баг: клиент обфусцировал только 8+tl */
    obfuscate_payload(payload, 8+tl, header, obf_key);
    /* Сервер деобфусцирует весь MAX_PAYLOAD-4+8 */
    deobfuscate_payload(payload, 8+1396, header, obf_key);

    int errors = 0;
    for (int i = 8; i < 108; i++) {
        if (payload[i] != (uint8_t)(i % 256)) errors++;
    }
    /* Проверим хвост: клиент их НЕ обфусцировал, они остались нулями */
    for (int i = 108; i < 1408; i++) {
        if (payload[i] != 0) errors++;
    }
    printf("OLD BUG: errors=%d\n", errors);
    return errors > 0 ? 1 : 0;
}
