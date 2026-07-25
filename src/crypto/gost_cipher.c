/*
 * ГОСТ Р 34.12-2015 (Кузнечик) — implementations based on RFC 7801.
 * Block size: 128 bits, Key size: 256 bits, 10 rounds.
 */
#include <string.h>
#include <stdint.h>
#include "kuznyechik.h"

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
/* l(b[15],...,b[0]) = 0x94*b[15] ⊕ 0x20*b[14] ⊕ 0x85*b[13] ⊕ 0x10*b[12]
                      ⊕ 0xC2*b[11] ⊕ 0xC0*b[10] ⊕ 0x01*b[9] ⊕ 0xFB*b[8]
                      ⊕ 0x01*b[7] ⊕ 0xC0*b[6] ⊕ 0xC2*b[5] ⊕ 0x10*b[4]
                      ⊕ 0x85*b[3] ⊕ 0x20*b[2] ⊕ 0x94*b[1] ⊕ 0x01*b[0] */
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
/* R(a_15||...||a_0) = l(a_15,...,a_0) || a_15 || ... || a_1 */
static void R_transform(uint8_t *block) {
    uint8_t new_byte = l_transform(block);
    memmove(block + 1, block, 15);
    block[0] = new_byte;
}

/* R⁻¹: shift left + l on result */
/* R⁻¹(a_15||...||a_0) = a_14 || ... || a_0 || l(a_14,...,a_0,a_15) */
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

/* ===== S and S⁻¹ substitution (byte-wise) ===== */

static void S_substitute(uint8_t *block) {
    for (int i = 0; i < 16; i++)
        block[i] = S[block[i]];
}

static void S_inv_substitute(uint8_t *block) {
    for (int i = 0; i < 16; i++)
        block[i] = S_inv[block[i]];
}

/* ===== LSX = L ∘ S ∘ X[k] ===== */

static void LSX(uint8_t *block, const uint8_t *round_key) {
    for (int i = 0; i < 16; i++)
        block[i] ^= round_key[i];
    S_substitute(block);
    L_transform(block);
}

/* ===== L⁻¹S⁻¹X[k] — inverse of LSX ===== */

static void LSX_inv(uint8_t *block, const uint8_t *round_key) {
    for (int i = 0; i < 16; i++)
        block[i] ^= round_key[i];
    L_inv_transform(block);
    S_inv_substitute(block);
}

/* ===== Key schedule (RFC 7801 §4.4) ===== */
/* C_i = L(Vec_128(i)), i=1..8  (used in groups of 8) */
/* F[k](a,b) = (LSX[k](a) ⊕ b, a) */
/* (K_3,K_4) = F[C_8]...F[C_1](K_1,K_2) */
/* (K_5,K_6) = F[C_16]...F[C_9](K_3,K_4) */
/* etc. */

static void compute_Ci(uint8_t *out, uint8_t i) {
    memset(out, 0, 16);
    out[15] = i;
    L_transform(out);
}

static void F_round(uint8_t *a, uint8_t *b, const uint8_t *C) {
    uint8_t tmp[16];
    memcpy(tmp, a, 16);
    LSX(tmp, C);
    for (int i = 0; i < 16; i++)
        tmp[i] ^= b[i];
    memcpy(b, a, 16);
    memcpy(a, tmp, 16);
}

static void key_schedule(const uint8_t *key, uint8_t *expanded) {
    uint8_t K[2][16];
    memcpy(K[0], key, 16);       /* K_1 */
    memcpy(K[1], key + 16, 16);  /* K_2 */

    /* Store K_1, K_2 */
    memcpy(expanded, K[0], 16);
    memcpy(expanded + 16, K[1], 16);

    /* Generate K_3..K_10 in groups of 8 F rounds */
    for (int g = 0; g < 4; g++) {
        for (int j = 1; j <= 8; j++) {
            uint8_t C[16];
            compute_Ci(C, (uint8_t)(g * 8 + j));
            F_round(K[0], K[1], C);
        }
        /* After 8 F rounds: K[0]=K_{2g+3}, K[1]=K_{2g+4} */
        memcpy(expanded + (2 * g + 2) * 16, K[0], 16);
        memcpy(expanded + (2 * g + 3) * 16, K[1], 16);
    }
}

/* ===== Block encryption (RFC 7801 §4.5.1) ===== */
/* E(a) = X[K_10] ∘ LSX[K_9] ∘ ... ∘ LSX[K_1](a) */

static void encrypt_block_c(uint8_t *block, const uint8_t *expanded) {
    for (int i = 0; i < 9; i++)
        LSX(block, expanded + i * 16);
    /* Final X[K_10] only (no S, no L) */
    for (int i = 0; i < 16; i++)
        block[i] ^= expanded[9 * 16 + i];
}

/* ===== Block decryption (RFC 7801 §4.5.2) ===== */
/* D(b) = X[K_1] ∘ L⁻¹S⁻¹X[K_2] ∘ ... ∘ L⁻¹S⁻¹X[K_10](b) */

static void decrypt_block_c(uint8_t *block, const uint8_t *expanded) {
    /* D(b) = X[K_1] ∘ L⁻¹S⁻¹X[K_2] ∘ ... ∘ L⁻¹S⁻¹X[K_10](b) */
    /* Apply L⁻¹S⁻¹X[K_10] down to L⁻¹S⁻¹X[K_2] */
    for (int i = 9; i >= 1; i--)
        LSX_inv(block, expanded + i * 16);
    /* Final X[K_1] */
    for (int i = 0; i < 16; i++)
        block[i] ^= expanded[i];
}

/* ===== Public API ===== */

void kuznyechik_set_key(const uint8_t *key, uint8_t *expanded_key) {
    key_schedule(key, expanded_key);
}

void kuznyechik_encrypt_block(uint8_t *block, const uint8_t *expanded_key) {
    encrypt_block_c(block, expanded_key);
}

void kuznyechik_decrypt_block(uint8_t *block, const uint8_t *expanded_key) {
    decrypt_block_c(block, expanded_key);
}

void kuznyechik_encrypt_ctr(
    const uint8_t *in, uint8_t *out, size_t len,
    const uint8_t *expanded_key, const uint8_t *nonce
) {
    uint8_t counter[16], keystream[16];
    memcpy(counter, nonce, 16);

    for (size_t offset = 0; offset < len; offset += 16) {
        memcpy(keystream, counter, 16);
        encrypt_block_c(keystream, expanded_key);

        size_t block_len = (len - offset > 16) ? 16 : (len - offset);
        for (size_t i = 0; i < block_len; i++)
            out[offset + i] = in[offset + i] ^ keystream[i];

        /* Increment counter (big-endian) */
        for (int j = 15; j >= 0; j--) {
            if (++counter[j] != 0) break;
        }
    }
}

void kuznyechik_encrypt_ecb(
    const uint8_t *in, uint8_t *out, size_t len,
    const uint8_t *expanded_key
) {
    for (size_t offset = 0; offset < len; offset += 16) {
        memcpy(out + offset, in + offset, 16);
        encrypt_block_c(out + offset, expanded_key);
    }
}
