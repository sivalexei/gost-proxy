#ifndef ECC_H
#define ECC_H

#include <stdint.h>
#include <stddef.h>

#define ECC_PUBLIC_KEY_SIZE 32
#define ECC_PRIVATE_KEY_SIZE 32
#define ECC_SHARED_KEY_SIZE 32

/* ECC key types */
#define ECC_P256 256
#define ECC_B256 256

/* ECC public key struct */
typedef struct {
    uint8_t x[ECC_PUBLIC_KEY_SIZE];
    uint8_t y[ECC_PUBLIC_KEY_SIZE];
    uint8_t curve_id;
} ecc_public_key_t;

/* ECC private key struct */
typedef struct {
    uint8_t key[ECC_PRIVATE_KEY_SIZE];
    uint8_t curve_id;
} ecc_private_key_t;

/* ECC shared secret struct */
typedef struct {
    uint8_t secret[ECC_SHARED_KEY_SIZE];
} ecc_shared_secret_t;

/* ECC key generation */
int ecc_generate_keypair(uint8_t curve_id,
                        ecc_private_key_t *priv,
                        ecc_public_key_t *pub);

/* ECC key exchange */
int ecc_key_exchange(const ecc_public_key_t *remote_pub,
                     const ecc_private_key_t *local_priv,
                     ecc_shared_secret_t *secret);

/* ECC signature generation */
int ecc_sign_message(const ecc_private_key_t *priv,
                    const uint8_t *message, size_t msg_len,
                    uint8_t *sig_out, size_t *sig_len);

/* ECC signature verification */
int ecc_verify_signature(const ecc_public_key_t *pub,
                        const uint8_t *message, size_t msg_len,
                        const uint8_t *signature, size_t sig_len);

/* ECC helper functions */
void ecc_point_add(const uint8_t *p1_x, const uint8_t *p1_y,
                   const uint8_t *p2_x, const uint8_t *p2_y,
                   uint8_t *r_x, uint8_t *r_y);
void ecc_point_multiply(const uint8_t *scalar, const uint8_t *base_x,
                       const uint8_t *base_y, uint8_t *result_x, uint8_t *result_y);

#endif /* ECC_H */
