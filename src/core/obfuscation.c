#include <string.h>
#include <stdint.h>
#include "obfuscation.h"

/* Простой хеш заголовка для обфускации (XOR-链 + session_id) */
void obf_key_derive(uint64_t session_id, uint8_t direction, uint8_t *out_key) {
    /* Direction: 0 = client→server, 1 = server→client */
    uint8_t key_bytes[8];
    memcpy(key_bytes, &session_id, 8);
    key_bytes[0] ^= direction;  /* разделим потоки */

    for (int i = 0; i < 8; i++) {
        out_key[i] = key_bytes[i];
        out_key[i + 8] = key_bytes[(i + 3) % 8] ^ 0x55;
    }
}

/* Обфускация payload: XOR с псевдослучайной последовательностью из header+key */
void obfuscate_payload(uint8_t *payload, size_t payload_len,
                       const uint8_t *header, const uint8_t *obf_key) {
    /* Генерируем псевдослучайный ключ потока из header и session-ключа */
    uint8_t stream[256];
    memset(stream, 0, sizeof(stream));
    uint32_t idx = 0;

    /* Инициализация: header (16 байт) */
    for (int i = 0; i < OBF_HEADER_SIZE && i < (int)payload_len; i++) {
        stream[i] = header[i];
    }
    idx = OBF_HEADER_SIZE;

    /* Расширение: добавляем obf_key */
    for (int i = 0; i < OBF_KEY_SIZE; i++) {
        stream[idx] = obf_key[i];
        idx++;
    }

    /* XOR с псевдослучайными байтами */
    /* Для простоты: используем XOR с накоплением */
    uint8_t state = 0;
    for (size_t i = 0; i < payload_len; i++) {
        if (idx >= 256) {
            /* Перезаполняем из предыдущих байт */
            for (int j = 0; j < OBF_HEADER_SIZE && (idx + j) < 256; j++) {
                stream[idx + j] = stream[i % 256] ^ header[j];
            }
            idx = 0;
        }
        state ^= stream[idx];
        idx++;
        payload[i] ^= state;
    }
}

/* Деобфускация: тот же XOR — симметричная операция */
void deobfuscate_payload(uint8_t *payload, size_t payload_len,
                         const uint8_t *header, const uint8_t *obf_key) {
    obfuscate_payload(payload, payload_len, header, obf_key);
}
