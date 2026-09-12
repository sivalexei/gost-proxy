#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "kuznyechik.h"

/* Тестовые векторы из RFC 7801 (ГОСТ Р 34.12-2015) */

/* Счётчик провалов: main возвращает 1, если хоть один тест не прошёл,
 * чтобы `make test` и %check в RPM реально падали при неверном шифре. */
static int failures = 0;

static void test_key_expansion(void) {
    printf("Тест 1: Расширение ключа (RFC 7801 §5.4)... ");

    uint8_t key[32] = {
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
    };

    /* Expected round keys from RFC 7801 §5.4 */
    uint8_t expected_K3[16] = {
        0xDB, 0x31, 0x48, 0x53, 0x15, 0x69, 0x43, 0x43,
        0x22, 0x8D, 0x6A, 0xEF, 0x8C, 0xC7, 0x8C, 0x44
    };
    uint8_t expected_K4[16] = {
        0x3D, 0x45, 0x53, 0xD8, 0xE9, 0xCF, 0xEC, 0x68,
        0x15, 0xEB, 0xAD, 0xC4, 0x0A, 0x9F, 0xFD, 0x04
    };
    uint8_t expected_K10[16] = {
        0x72, 0xE9, 0xDD, 0x74, 0x16, 0xBC, 0xF4, 0x5B,
        0x75, 0x5D, 0xBA, 0xA8, 0x8E, 0x4A, 0x40, 0x43
    };

    uint8_t expanded[160];
    kuznyechik_set_key(key, expanded);

    int ok = 1;
    if (memcmp(expanded + 32, expected_K3, 16) != 0) {
        printf("ПРОВАЛЕН (K3)\n");
        printf("  Ожидалось: ");
        for (int i = 0; i < 16; i++) printf("%02X", expected_K3[i]);
        printf("\n  Получено:  ");
        for (int i = 0; i < 16; i++) printf("%02X", expanded[32 + i]);
        printf("\n");
        ok = 0;
    }
    if (memcmp(expanded + 48, expected_K4, 16) != 0) {
        printf("ПРОВАЛЕН (K4)\n");
        printf("  Ожидалось: ");
        for (int i = 0; i < 16; i++) printf("%02X", expected_K4[i]);
        printf("\n  Получено:  ");
        for (int i = 0; i < 16; i++) printf("%02X", expanded[48 + i]);
        printf("\n");
        ok = 0;
    }
    if (memcmp(expanded + 144, expected_K10, 16) != 0) {
        printf("ПРОВАЛЕН (K10)\n");
        printf("  Ожидалось: ");
        for (int i = 0; i < 16; i++) printf("%02X", expected_K10[i]);
        printf("\n  Получено:  ");
        for (int i = 0; i < 16; i++) printf("%02X", expanded[144 + i]);
        printf("\n");
        ok = 0;
    }

    if (ok) printf("ПРОЙДЕН\n");
    else failures++;
}

static void test_encrypt_block(void) {
    printf("Тест 2: Шифрование (RFC 7801 §5.5)... ");

    uint8_t key[32] = {
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
    };

    uint8_t block[16] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00,
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88
    };

    uint8_t expected[16] = {
        0x7F, 0x67, 0x9D, 0x90, 0xBE, 0xBC, 0x24, 0x30,
        0x5A, 0x46, 0x8D, 0x42, 0xB9, 0xD4, 0xED, 0xCD
    };

    uint8_t expanded[160];
    kuznyechik_set_key(key, expanded);
    kuznyechik_encrypt_block(block, expanded);

    if (memcmp(block, expected, 16) == 0) {
        printf("ПРОЙДЕН\n");
    } else {
        failures++;
        printf("ПРОВАЛЕН\n");
        printf("  Ожидалось: ");
        for (int i = 0; i < 16; i++) printf("%02X ", expected[i]);
        printf("\n  Получено:  ");
        for (int i = 0; i < 16; i++) printf("%02X ", block[i]);
        printf("\n");
    }
}

static void test_decrypt_block(void) {
    printf("Тест 3: Расшифрование (RFC 7801 §5.6)... ");

    uint8_t key[32] = {
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
    };

    uint8_t ciphertext[16] = {
        0x7F, 0x67, 0x9D, 0x90, 0xBE, 0xBC, 0x24, 0x30,
        0x5A, 0x46, 0x8D, 0x42, 0xB9, 0xD4, 0xED, 0xCD
    };

    uint8_t expected[16] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00,
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88
    };

    uint8_t expanded[160];
    kuznyechik_set_key(key, expanded);
    kuznyechik_decrypt_block(ciphertext, expanded);

    if (memcmp(ciphertext, expected, 16) == 0) {
        printf("ПРОЙДЕН\n");
    } else {
        failures++;
        printf("ПРОВАЛЕН\n");
        printf("  Ожидалось: ");
        for (int i = 0; i < 16; i++) printf("%02X ", expected[i]);
        printf("\n  Получено:  ");
        for (int i = 0; i < 16; i++) printf("%02X ", ciphertext[i]);
        printf("\n");
    }
}

static void test_ctr_mode(void) {
    printf("Тест 4: CTR-режим (roundtrip)... ");

    uint8_t key[32] = {
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
    };

    uint8_t plaintext[32] = "Hello, GOST Proxy Server!!!";
    uint8_t ciphertext[32] = {0};
    uint8_t decrypted[32] = {0};
    uint8_t nonce[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                         0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
                         0x00, 0x00, 0x00, 0x00};

    uint8_t expanded[160];
    kuznyechik_set_key(key, expanded);

    kuznyechik_encrypt_ctr(plaintext, ciphertext, 27, expanded, nonce);
    kuznyechik_encrypt_ctr(ciphertext, decrypted, 27, expanded, nonce);

    if (memcmp(plaintext, decrypted, 27) == 0) {
        printf("ПРОЙДЕН\n");
    } else {
        failures++;
        printf("ПРОВАЛЕН\n");
        printf("  Ожидалось: %.27s\n", plaintext);
        printf("  Получено:  %.27s\n", decrypted);
    }
}

static void test_roundtrip(void) {
    printf("Тест 5: Полный roundtrip encrypt→decrypt... ");

    uint8_t key[32] = {
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
    };

    uint8_t block[16], original[16] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00,
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88
    };
    memcpy(block, original, 16);

    uint8_t expanded[160];
    kuznyechik_set_key(key, expanded);

    kuznyechik_encrypt_block(block, expanded);
    kuznyechik_decrypt_block(block, expanded);

    if (memcmp(block, original, 16) == 0) {
        printf("ПРОЙДЕН\n");
    } else {
        failures++;
        printf("ПРОВАЛЕН\n");
        printf("  Ожидалось: ");
        for (int i = 0; i < 16; i++) printf("%02X ", original[i]);
        printf("\n  Получено:  ");
        for (int i = 0; i < 16; i++) printf("%02X ", block[i]);
        printf("\n");
    }
}

int main(void) {
    printf("=== Тесты ГОСТ Р 34.12-2015 (RFC 7801) ===\n\n");

    test_key_expansion();
    test_encrypt_block();
    test_decrypt_block();
    test_ctr_mode();
    test_roundtrip();

    if (failures == 0) {
        printf("\n=== Все тесты пройдены ===\n");
        return 0;
    }
    printf("\n=== ПРОВАЛЕНО ТЕСТОВ: %d ===\n", failures);
    return 1;
}
