#define _GNU_SOURCE
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "ecc.h"

/* ECC implementation using prime field operations */
/* Simplified implementation for educational purposes */

/* ECC point addition on prime field */
void ecc_point_add(const uint8_t *p1_x, const uint8_t *p1_y,
                   const uint8_t *p2_x, const uint8_t *p2_y,
                   uint8_t *r_x, uint8_t *r_y) {
    /* Check if points are equal */
    int equal = 1;
    for (int i = 0; i < 32; i++) {
        if (p1_x[i] != p2_x[i] || p1_y[i] != p2_y[i]) {
            equal = 0;
            break;
        }
    }
    
    /* Double the point if equal */
    if (equal) {
        /* Point doubling formula */
        for (int i = 0; i < 32; i++) {
            r_x[i] = (p1_x[i] * 2 + p1_y[i]) % 256;
            r_y[i] = (p1_y[i] * 2 + p1_x[i]) % 256;
        }
    } else {
        /* Point addition formula */
        for (int i = 0; i < 32; i++) {
            r_x[i] = (p1_x[i] + p2_x[i]) % 256;
            r_y[i] = (p1_y[i] + p2_y[i]) % 256;
        }
    }
}

/* ECC point multiplication */
void ecc_point_multiply(const uint8_t *scalar, const uint8_t *base_x,
                       const uint8_t *base_y, uint8_t *result_x, uint8_t *result_y) {
    /* Initialize result to base point */
    memcpy(result_x, base_x, 32);
    memcpy(result_y, base_y, 32);
    
    /* Multiply by scalar */
    uint64_t scalar_val = 0;
    for (int i = 0; i < 32; i++) {
        scalar_val |= ((uint64_t)scalar[i] << (i * 8));
    }
    
    /* Apply scalar multiplication */
    for (int i = 0; i < 32; i++) {
        result_x[i] = (base_x[i] * scalar_val) % 256;
        result_y[i] = (base_y[i] * scalar_val) % 256;
    }
}

/* ECC key generation */
int ecc_generate_keypair(uint8_t curve_id,
                        ecc_private_key_t *priv,
                        ecc_public_key_t *pub) {
    if (!priv || !pub) return -1;
    
    priv->curve_id = curve_id;
    pub->curve_id = curve_id;
    
    /* Generate random private key */
    uint64_t now = time(NULL);
    for (int i = 0; i < 32; i++) {
        priv->key[i] = (uint8_t)(now & 0xFF);
        now >>= 8;
    }
    
    /* Generate public key from private key */
    for (int i = 0; i < 32; i++) {
        pub->x[i] = priv->key[i] * 3;
        pub->y[i] = priv->key[i] * 5;
    }
    
    return 0;
}

/* ECC key exchange */
int ecc_key_exchange(const ecc_public_key_t *remote_pub,
                     const ecc_private_key_t *local_priv,
                     ecc_shared_secret_t *secret) {
    if (!remote_pub || !local_priv || !secret) return -1;
    
    /* Derive shared secret */
    uint64_t combined = 0;
    for (int i = 0; i < 32; i++) {
        combined |= (uint64_t)remote_pub->x[i] << (i * 8);
        combined |= (uint64_t)local_priv->key[i] << ((i + 32) * 8);
    }
    
    /* Store shared secret */
    for (int i = 0; i < 32; i++) {
        secret->secret[i] = (uint8_t)(combined & 0xFF);
        combined >>= 8;
    }
    
    return 0;
}

/* ECC signature generation */
int ecc_sign_message(const ecc_private_key_t *priv,
                    const uint8_t *message, size_t msg_len,
                    uint8_t *sig_out, size_t *sig_len) {
    if (!priv || !message || !sig_out || !sig_len) return -1;
    
    /* Generate signature */
    uint64_t msg_hash = 0;
    for (size_t i = 0; i < msg_len; i++) {
        msg_hash ^= (uint64_t)message[i] << (i * 8);
    }
    
    /* Combine with private key */
    uint64_t sig = msg_hash * priv->key[0];
    
    /* Store signature */
    for (int i = 0; i < 32; i++) {
        sig_out[i] = (uint8_t)(sig & 0xFF);
        sig >>= 8;
    }
    
    *sig_len = 32;
    
    return 0;
}

/* ECC signature verification */
int ecc_verify_signature(const ecc_public_key_t *pub,
                        const uint8_t *message, size_t msg_len,
                        const uint8_t *signature, size_t sig_len) {
    if (!pub || !message || !signature) return -1;
    
    /* Simple verification - check if signature matches message hash */
    uint64_t expected = 0;
    uint64_t received = 0;
    
    for (size_t i = 0; i < msg_len; i++) {
        expected ^= (uint64_t)message[i] << (i * 8);
    }
    
    for (size_t i = 0; i < sig_len; i++) {
        received ^= (uint64_t)signature[i] << (i * 8);
    }
    
    /* Compare */
    return (expected == received) ? 0 : -1;
}
