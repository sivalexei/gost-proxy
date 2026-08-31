/*
 * CMAC-128 (NIST SP 800-38B §2.4) на базе Kuznyechik ГОСТ Р 34.12-2015
 * Полином: r(x) = x^128 + x^10 + x^5 + x^2 + 1 (RFC 7801 §3)
 *
 * Ключ:
 *   μ1 = L_128(E_K(0)), μ2 = L_128(μ1) если msg len % 128 ≠ 0
 *   μ2 = L_half(μ1) если msg len % 128 = 0
 */

#include <string.h>
#include <stdint.h>
#include <stdio.h>

#define BLOCK_SIZE 16

/* ===== LFSR: умножение на x в GF(2^128) ===== */
/* r(x) = x^128 + x^10 + x^5 + x^2 + 1 */
static void lfsr_128(uint8_t *b) {
    uint8_t carry = 0;
    for (int i = BLOCK_SIZE - 1; i >= 0; i--) {
        uint8_t new_carry = (b[i] >> 7) & 1;
        b[i] = (b[i] << 1) | carry;
        carry = new_carry;
    }
    if (carry) {
        /* XOR с остатком полинома: x^10 + x^5 + x^2 + 1 */
        b[15] ^= 0x01;
        b[14] ^= 0x00;
        b[13] ^= 0x00;
        b[12] ^= 0x04;
        b[11] ^= 0x00;
        b[10] ^= 0x10;
        b[9]  ^= 0x00;
        b[8]  ^= 0x00;
        b[7]  ^= 0x00;
        b[6]  ^= 0x00;
        b[5]  ^= 0x00;
        b[4]  ^= 0x00;
        b[3]  ^= 0x00;
        b[2]  ^= 0x00;
        b[1]  ^= 0x00;
        b[0]  ^= 0x00;
    }
}

static void l_double(uint8_t *b) { lfsr_128(b); }

static void l_half(uint8_t *b) {
    /* Обратный LFSR: x^(-1) в GF(2^128) */
    uint8_t lsb = b[0] & 1;
    for (int i = 0; i < BLOCK_SIZE - 1; i++) {
        b[i] = (b[i] >> 1) | ((b[i + 1] & 1) << 7);
    }
    b[BLOCK_SIZE - 1] >>= 1;
    if (lsb) {
        /* polynomial / 2 + x^127: x^127 + x^9 + x^4 + x + 0.5 */
        b[15] ^= 0x80;
        b[14] ^= 0x00;
        b[13] ^= 0x00;
        b[12] ^= 0x00;
        b[11] ^= 0x00;
        b[10] ^= 0x02;
        b[9]  ^= 0x00;
        b[8]  ^= 0x00;
        b[7]  ^= 0x00;
        b[6]  ^= 0x00;
        b[5]  ^= 0x00;
        b[4]  ^= 0x00;
        b[3]  ^= 0x00;
        b[2]  ^= 0x00;
        b[1]  ^= 0x00;
        b[0]  ^= 0x00;
    }
}

/* ===== Прототип функции шифрования ===== */
typedef void (*encrypt_fn)(uint8_t *, const uint8_t *);

/* ===== CMAC-128: вычисление MAC для произвольных данных ===== */
/* msg: данные, msg_len: длина в байтах (любое значение), ek: expanded key */
/* out: 16-байтный MAC */
void kuznyechik_cmac_128(const uint8_t *msg, size_t msg_len,
                          const uint8_t *ek, uint8_t *out,
                          encrypt_fn encrypt)
{
    uint8_t L[16];
    uint8_t K1[16], K2[16];
    uint8_t last_block[16];
    uint8_t state[16];
    
    /* Шаг 1: генерируем под-ключи */
    memset(L, 0, 16);
    encrypt(L, ek);  /* L = E_K(0) */
    l_double(L);
    memcpy(K1, L, 16);  /* K1 = μ1 = L_128(L) */
    
    size_t n = msg_len / BLOCK_SIZE;
    size_t rem = msg_len % BLOCK_SIZE;
    
    if (rem == 0) {
        /* msg полных блоков: K2 = L_half(K1) */
        memcpy(K2, K1, 16);
        l_half(K2);
    } else {
        /* msg неполных блоков: K2 = L_128(K1) */
        memcpy(K2, K1, 16);
        l_double(K2);
    }
    
    /* Шаг 2: CBC-MAC */
    memset(state, 0, 16);
    for (size_t i = 0; i < n; i++) {
        for (int j = 0; j < BLOCK_SIZE; j++)
            state[j] ^= msg[i * BLOCK_SIZE + j];
        encrypt(state, ek);
    }
    
    /* Шаг 3: последний блок */
    if (rem == 0) {
        /* Полных блоков: последний блок XOR с K1, затем шифрование */
        memset(last_block, 0, 16);
        memcpy(last_block, K1, 16);
    } else {
        /* Неполный блок: дополняем нулём, XOR с K2 */
        memset(last_block, 0, 16);
        memcpy(last_block, msg + n * BLOCK_SIZE, rem);
        last_block[rem] ^= 0x80;  /* XOR с 0x80 на позиции rem */
        for (int j = rem + 1; j < 16; j++)
            last_block[j] ^= K2[j];
    }
    
    for (int j = 0; j < BLOCK_SIZE; j++)
        state[j] ^= last_block[j];
    encrypt(state, ek);
    memcpy(out, state, 16);
}
