#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "gost_common.h"
#include "kuznyechik.h"

/* Инициализация сессии с клиентом */
int protocol_init_session(gost_session_t *session, const uint8_t *key);

/* Упаковка пакета данных */
int protocol_pack_data(
    gost_packet_t *pkt,
    uint64_t session_id,
    uint32_t conn_id,
    const uint8_t *data,
    size_t data_len,
    const uint8_t *expanded_key,
    const uint8_t *nonce,
    uint32_t *counter
);

/* Распаковка пакета данных */
int protocol_unpack_data(
    const gost_packet_t *pkt,
    uint8_t *data,
    size_t *data_len,
    uint32_t *out_conn_id,
    const uint8_t *expanded_key,
    const uint8_t *nonce,
    uint32_t *counter
);

/* Формирование handshake */
int protocol_create_handshake(
    gost_packet_t *pkt,
    uint64_t session_id,
    const uint8_t *expanded_key
);

/* Проверка handshake */
int protocol_verify_handshake(
    const gost_packet_t *pkt,
    const uint8_t *expanded_key
);

#endif /* PROTOCOL_H */
