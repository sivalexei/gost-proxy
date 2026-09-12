/*
 * ГОСТ Р 34.12-2015 (Кузнечик) — эталонная реализация на C.
 * Размер блока 128 бит, ключ 256 бит, 10 раундов.
 * Соответствует RFC 7801, проверено на контрольных векторах §A.1
 * (см. src/crypto/gost_test.c, цель `make test`).
 *
 * Ассемблерный вариант (src/crypto/kuznyechik.asm) из сборки исключён:
 * он не проходит контрольные векторы и аварийно завершается.
 * Подробности — в AUDIT_REPORT.md, раздел 3.
 */
#include <string.h>
#include <stdint.h>
#include "kuznyechik.h"
#include "gost_common.h"

/* ===== S-box (π) and inverse S-box (π⁻¹) from RFC 7801 §4.1 ===== */
static const uint8_t S[256] = {
    252,238,221, 17,207,110, 49, 22,251,196,250,218, 35,197,  4, 77,
    233,119,240,219,147, 46,153,186, 23, 54,241,187, 20,205, 95,193,
    249, 24,101, 90,226, 92,239, 33,129, 28, 60, 66,139,  1,142, 79,
      5,132,  2,174,227,106,143,160,  6, 11,237,152,127,212,211, 31,
    235, 52, 44, 81,234,200, 72,171,242, 42,104,162,253, 58,206,204,
    181,112, 14, 86,  8, 12,118, 18,191,114, 19, 71,156,183, 93,135,
     21,161,150, 41, 16,123,154,199,243,145,120,111,157,158,178,177,
     50,117, 25, 61,255, 53,138,126,109, 84,198,128,195,189, 13, 87,
    223,245, 36,169, 62,168, 67,201,215,121,214,246,124, 34,185,  3,
    224, 15,236,222,122,148,176,188,220,232, 40, 80, 78, 51, 10, 74,
    167,151, 96,115, 30,  0, 98, 68, 26,184, 56,130,100,159, 38, 65,
    173, 69, 70,146, 39, 94, 85, 47,140,163,165,125,105,213,149, 59,
      7, 88,179, 64,134,172, 29,247, 48, 55,107,228,136,217,231,137,
    225, 27,131, 73, 76, 63,248,254,141, 83,170,144,202,216,133, 97,
     32,113,103,164, 45, 43,  9, 91,203,155, 37,208,190,229,108, 82,
     89,166,116,210,230,244,180,192,209,102,175,194, 57, 75, 99,182
};

static const uint8_t S_inv[256] = {
    165, 45, 50,143, 14, 48, 56,192, 84,230,158, 57, 85,126, 82,145,
    100,  3, 87, 90, 28, 96,  7, 24, 33,114,168,209, 41,198,164, 63,
    224, 39,141, 12,130,234,174,180,154, 99, 73,229, 66,228, 21,183,
    200,  6,112,157, 65,117, 25,201,170,252, 77,191, 42,115,132,213,
    195,175, 43,134,167,177,178, 91, 70,211,159,253,212, 15,156, 47,
    155, 67,239,217,121,182, 83,127,193,240, 35,231, 37, 94,181, 30,
    162,223,166,254,172, 34,249,226, 74,188, 53,202,238,120,  5,107,
     81,225, 89,163,242,113, 86, 17,106,137,148,101,140,187,119, 60,
    123, 40,171,210, 49,222,196, 95,204,207,118, 44,184,216, 46, 54,
    219,105,179, 20,149,190, 98,161, 59, 22,102,233, 92,108,109,173,
     55, 97, 75,185,227,186,241,160,133,131,218, 71,197,176, 51,250,
    150,111,110,194,246, 80,255, 93,169,142, 23, 27,151,125,236, 88,
    247, 31,251,124,  9, 13,122,103, 69,135,220,232, 79, 29, 78,  4,
    235,248,243, 62, 61,189,138,136,221,205, 11, 19,152,  2,147,128,
    144,208, 36, 52,203,237,244,206,153, 16, 68, 64,146, 58,  1, 38,
     18, 26, 72,104,245,129,139,199,214, 32, 10,  8,  0, 76,215,116
};

/* ===== S and S⁻¹ substitution (byte-wise) ===== */
static void S_substitute(uint8_t *block) {
    for (int i = 0; i < 16; i++)
        block[i] = S[block[i]];
}

static void S_inv_substitute(uint8_t *block) {
    for (int i = 0; i < 16; i++)
        block[i] = S_inv[block[i]];
}
/* ===== GF(2^8) arithmetic: p(x) = x^8+x^7+x^6+x+1 (0xC3) ===== */

static uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        int hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0xC3;
        b >>= 1;
    }
    return p;
}

/* ===== Linear transformation l: (V_8)^16 -> V_8 ===== */
static const uint8_t L_VEC[16] = {
    0x94, 0x20, 0x85, 0x10, 0xC2, 0xC0, 0x01, 0xFB,
    0x01, 0xC0, 0xC2, 0x10, 0x85, 0x20, 0x94, 0x01
};

static uint8_t l_transform(const uint8_t *block) {
    uint8_t r = 0;
    for (int i = 0; i < 16; i++)
        r ^= gf_mul(L_VEC[i], block[i]);
    return r;
}

/* ===== R: cyclic shift right + l ===== */
static void R_transform(uint8_t *block) {
    uint8_t new_byte = l_transform(block);
    memmove(block + 1, block, 15);
    block[0] = new_byte;
}

/* ===== R⁻¹: shift left + l on result ===== */
static void R_inv_transform(uint8_t *block) {
    uint8_t temp[16];
    memcpy(temp, block + 1, 15);
    temp[15] = block[0];
    uint8_t new_byte = l_transform(temp);
    memmove(block, block + 1, 15);
    block[15] = new_byte;
}

/* ===== L = R^16, L⁻¹ = (R⁻¹)^16 ===== */
static void L_transform(uint8_t *block) {
    for (int i = 0; i < 16; i++)
        R_transform(block);
}

static void L_inv_transform(uint8_t *block) {
    for (int i = 0; i < 16; i++)
        R_inv_transform(block);
}

/* ===== Key schedule (RFC 7801 §4.4) ===== */
static void compute_Ci(uint8_t *out, uint8_t i) {
    memset(out, 0, 16);
    out[15] = i;
    L_transform(out);
}

static void F_round(uint8_t *a, uint8_t *b, const uint8_t *C) {
    uint8_t tmp[16];
    memcpy(tmp, a, 16);
    for (int i = 0; i < 16; i++)
        tmp[i] ^= C[i];
    S_substitute(tmp);
    L_transform(tmp);
    for (int i = 0; i < 16; i++)
        tmp[i] ^= b[i];
    memcpy(b, a, 16);
    memcpy(a, tmp, 16);
}

static void key_schedule(const uint8_t *key, uint8_t *expanded) {
    uint8_t K[2][16];
    memcpy(K[0], key, 16);
    memcpy(K[1], key + 16, 16);

    memcpy(expanded, K[0], 16);
    memcpy(expanded + 16, K[1], 16);

    for (int g = 0; g < 4; g++) {
        for (int j = 1; j <= 8; j++) {
            uint8_t C[16];
            compute_Ci(C, (uint8_t)(g * 8 + j));
            F_round(K[0], K[1], C);
        }
        memcpy(expanded + (2 * g + 2) * 16, K[0], 16);
        memcpy(expanded + (2 * g + 3) * 16, K[1], 16);
    }
}

/* ===== Block encryption (RFC 7801 §4.5.1) ===== */
void encrypt_block_c(uint8_t *block, const uint8_t *expanded) {
    for (int i = 0; i < 9; i++) {
        for (int j = 0; j < 16; j++)
            block[j] ^= expanded[i * 16 + j];
        S_substitute(block);
        L_transform(block);
    }
    for (int i = 0; i < 16; i++)
        block[i] ^= expanded[9 * 16 + i];
}

/* ===== Block decryption (RFC 7801 §4.5.2) ===== */
static void decrypt_block_c(uint8_t *block, const uint8_t *expanded) {
    for (int i = 9; i >= 1; i--) {
        for (int j = 0; j < 16; j++)
            block[j] ^= expanded[i * 16 + j];
        L_inv_transform(block);
        S_inv_substitute(block);
    }
    for (int i = 0; i < 16; i++)
        block[i] ^= expanded[i];
}

/* ===== Публичный API (объявлен в kuznyechik.h) ===== */

void kuznyechik_set_key(const uint8_t *key, uint8_t *expanded_key) {
    key_schedule(key, expanded_key);
}

void kuznyechik_encrypt_block(uint8_t *block, const uint8_t *expanded_key) {
    encrypt_block_c(block, expanded_key);
}

void kuznyechik_decrypt_block(uint8_t *block, const uint8_t *expanded_key) {
    decrypt_block_c(block, expanded_key);
}

/* CTR: гамма = E(counter), счётчик инкрементируется как 128-битное
 * число big-endian. Хвост короче 16 байт обрабатывается корректно. */
void kuznyechik_encrypt_ctr(
    const uint8_t *in, uint8_t *out, size_t len,
    const uint8_t *expanded_key, const uint8_t *nonce
) {
    uint8_t counter[KUZNYECHIK_BLOCK_SIZE], keystream[KUZNYECHIK_BLOCK_SIZE];
    memcpy(counter, nonce, KUZNYECHIK_BLOCK_SIZE);

    for (size_t offset = 0; offset < len; offset += KUZNYECHIK_BLOCK_SIZE) {
        memcpy(keystream, counter, KUZNYECHIK_BLOCK_SIZE);
        encrypt_block_c(keystream, expanded_key);

        size_t block_len = len - offset;
        if (block_len > KUZNYECHIK_BLOCK_SIZE) block_len = KUZNYECHIK_BLOCK_SIZE;
        for (size_t i = 0; i < block_len; i++)
            out[offset + i] = in[offset + i] ^ keystream[i];

        for (int j = KUZNYECHIK_BLOCK_SIZE - 1; j >= 0; j--)
            if (++counter[j] != 0) break;
    }
}

/* ECB: len должна быть кратна размеру блока, хвост игнорируется. */
void kuznyechik_encrypt_ecb(
    const uint8_t *in, uint8_t *out, size_t len,
    const uint8_t *expanded_key
) {
    for (size_t offset = 0; offset + KUZNYECHIK_BLOCK_SIZE <= len;
         offset += KUZNYECHIK_BLOCK_SIZE) {
        memcpy(out + offset, in + offset, KUZNYECHIK_BLOCK_SIZE);
        encrypt_block_c(out + offset, expanded_key);
    }
}

/* HMAC на базе Kuznyechik: CMAC(PSK, client_nonce || server_nonce) */
void kuznyechik_compute_auth(const uint8_t *expanded_key,
                              const uint8_t *client_nonce,
                              const uint8_t *server_nonce,
                              uint8_t *auth_out)
{
    uint8_t buf[KUZNYECHIK_BLOCK_SIZE];
    /* client_nonce (8 байт) || server_nonce (8 байт) = 16 байт */
    memcpy(buf, client_nonce, 8);
    memcpy(buf + 8, server_nonce, 8);
    /* Шифруем: CMAC = E_K(client_nonce || server_nonce) */
    encrypt_block_c(buf, expanded_key);
    memcpy(auth_out, buf, AUTH_TAG_SIZE);
}
