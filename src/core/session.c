#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "kuznyechik.h"
#include "gost_common.h"
#include "protocol.h"

/* MAC = encrypt(xor_all_blocks_of_payload, key) */
static void compute_mac(
    const uint8_t *payload, size_t payload_len,
    const uint8_t *expanded_key,
    uint8_t *mac_out
) {
    uint8_t block[16];
    memset(block, 0, 16);

    for (size_t offset = 0; offset < payload_len; offset += 16) {
        size_t block_len = (payload_len - offset > 16) ? 16 : (payload_len - offset);
        for (size_t i = 0; i < block_len; i++)
            block[i] ^= payload[offset + i];
    }

    memcpy(mac_out, block, 16);
    kuznyechik_encrypt_block(mac_out, expanded_key);
}

static void make_ctr_nonce(const uint8_t *session_nonce, uint32_t counter, uint8_t *out16) {
    memcpy(out16, session_nonce, NONCE_SIZE);
    out16[12] = (counter >> 24) & 0xFF;
    out16[13] = (counter >> 16) & 0xFF;
    out16[14] = (counter >> 8)  & 0xFF;
    out16[15] = (counter >> 0)  & 0xFF;
}

/*
 * protocol_pack_data — шифрование и упаковка пакета данных.
 *
 * Формат payload (до шифрования):
 *   [0..3]   packet_counter (4 байта, big-endian, открытый — нужен接收ателю для CTR)
 *   [4..7]   data_len (4 байта, big-endian)
 *   [8..7+N] данные
 *   [8+N..MAX_PAYLOAD-1] нули (padding до 1400 байт)
 *
 * Шифруем всё КРОМЕ первых 4 байт (counter). Counter открытый.
 * MAC вычисляется от ВСЕГО payload (включая открытый counter).
 */
int protocol_pack_data(
    gost_packet_t *pkt,
    uint64_t session_id,
    uint32_t conn_id,
    const uint8_t *data,
    size_t data_len,
    const uint8_t *expanded_key,
    const uint8_t *nonce,
    uint32_t *counter
) {
    if (!pkt || !data || !expanded_key || !nonce || !counter) return -1;
    if (data_len > MAX_PAYLOAD - 4) return -1;

    memset(pkt, 0, sizeof(gost_packet_t));
    pkt->magic = htonl(GOST_PROXY_MAGIC);
    pkt->type = PKT_DATA;
    pkt->conn_id = htonl(conn_id);
    pkt->session_id = htonll(session_id);

    uint32_t pkt_counter = *counter;
    printf("[PACK] counter=%u, data_len=%zu, nonce[0..7]=%02x%02x%02x%02x%02x%02x%02x%02x\n",
           pkt_counter, data_len,
           nonce[0], nonce[1], nonce[2], nonce[3], nonce[4], nonce[5], nonce[6], nonce[7]);
    fflush(stdout);

    /* Counter — открытый (не шифруется) */
    pkt->payload[0] = (pkt_counter >> 24) & 0xFF;
    pkt->payload[1] = (pkt_counter >> 16) & 0xFF;
    pkt->payload[2] = (pkt_counter >> 8)  & 0xFF;
    pkt->payload[3] = (pkt_counter >> 0)  & 0xFF;

    /* data_len после counter */
    pkt->payload[4] = (data_len >> 24) & 0xFF;
    pkt->payload[5] = (data_len >> 16) & 0xFF;
    pkt->payload[6] = (data_len >> 8)  & 0xFF;
    pkt->payload[7] = (data_len >> 0)  & 0xFF;

    /* Данные */
    memcpy(pkt->payload + 8, data, data_len);

    /* Шифруем всё КРОМЕ первых 4 байт (counter) */
    uint8_t ctr_nonce[16];
    make_ctr_nonce(nonce, pkt_counter, ctr_nonce);
    kuznyechik_encrypt_ctr(pkt->payload + 4, pkt->payload + 4, MAX_PAYLOAD - 4,
                           expanded_key, ctr_nonce);

    /* Encrypt-then-MAC: MAC от ВСЕГО payload (включая открытый counter) */
    compute_mac(pkt->payload, MAX_PAYLOAD, expanded_key, pkt->auth_tag);

    (*counter) += 2; /* шаг 2: клиент чётные, сервер нечётные */
    return 0;
}

/*
 * protocol_unpack_data — расшифрование и извлечение данных.
 *
 * 1. Читаем counter из первых 4 байт payload (открытый)
 * 2. Проверяем MAC от ВСЕГО payload
 * 3. Расшифровываем payload (кроме counter) с использованием counter
 * 4. Извлекаем data_len и данные
 */
int protocol_unpack_data(
    const gost_packet_t *pkt,
    uint8_t *data,
    size_t *data_len,
    uint32_t *out_conn_id,
    const uint8_t *expanded_key,
    const uint8_t *nonce,
    uint32_t *counter
) {
    if (!pkt || !data || !data_len || !expanded_key || !nonce || !counter) return -1;

    /* Извлекаем conn_id */
    if (out_conn_id) *out_conn_id = ntohl(pkt->conn_id);

    /* Читаем counter из первых 4 байт (открытый) */
    uint32_t pkt_counter = ((uint32_t)pkt->payload[0] << 24) |
                           ((uint32_t)pkt->payload[1] << 16) |
                           ((uint32_t)pkt->payload[2] << 8)  |
                           ((uint32_t)pkt->payload[3]);
    printf("[UNPACK] pkt_counter=%u, nonce[0..7]=%02x%02x%02x%02x%02x%02x%02x%02x\n", pkt_counter,
           nonce[0], nonce[1], nonce[2], nonce[3], nonce[4], nonce[5], nonce[6], nonce[7]);
    fflush(stdout);

    /* Проверяем MAC от ВСЕГО payload */
    uint8_t expected_mac[AUTH_TAG_SIZE];
    compute_mac(pkt->payload, MAX_PAYLOAD, expanded_key, expected_mac);
    if (memcmp(pkt->auth_tag, expected_mac, AUTH_TAG_SIZE) != 0) {
        return -1;
    }

    /* Расшифровываем всё КРОМЕ первых 4 байт (counter) */
    uint8_t decrypted[MAX_PAYLOAD - 4];
    uint8_t ctr_nonce[16];
    make_ctr_nonce(nonce, pkt_counter, ctr_nonce);
    kuznyechik_encrypt_ctr(pkt->payload + 4, decrypted, MAX_PAYLOAD - 4,
                           expanded_key, ctr_nonce);

    /* Извлекаем data_len */
    uint32_t dl = ((uint32_t)decrypted[0] << 24) |
                  ((uint32_t)decrypted[1] << 16) |
                  ((uint32_t)decrypted[2] << 8)  |
                  ((uint32_t)decrypted[3]);
    if (dl > MAX_PAYLOAD - 4) return -1;

    printf("[UNPACK] dl=%u, dec_first8=", dl);
    for (int i = 0; i < 8; i++) printf("%02x", decrypted[i]);
    printf(", enc_first8=");
    for (int i = 0; i < 8; i++) printf("%02x", pkt->payload[4+i]);
    printf("\n");
    fflush(stdout);

    *data_len = dl;
    memcpy(data, decrypted + 4, dl);

    /* НЕ обновляем counter — он обновляется только при pack */
    return 0;
}

int protocol_create_handshake(
    gost_packet_t *pkt,
    uint64_t session_id,
    const uint8_t *expanded_key
) {
    if (!pkt || !expanded_key) return -1;

    memset(pkt, 0, sizeof(gost_packet_t));
    pkt->magic = htonl(GOST_PROXY_MAGIC);
    pkt->type = PKT_HANDSHAKE;
    pkt->session_id = htonll(session_id);

    /* Auth tag = шифрование session_id как подпись */
    uint8_t signature[16];
    memset(signature, 0, 16);
    memcpy(signature, &session_id, 8);
    kuznyechik_encrypt_block(signature, expanded_key);
    memcpy(pkt->auth_tag, signature, AUTH_TAG_SIZE);

    return 0;
}

int protocol_verify_handshake(
    const gost_packet_t *pkt,
    const uint8_t *expanded_key
) {
    if (!pkt || !expanded_key) return -1;
    if (pkt->type != PKT_HANDSHAKE) return -1;
    if (ntohl(pkt->magic) != GOST_PROXY_MAGIC) return -1;
    return 0;
}
