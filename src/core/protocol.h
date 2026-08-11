#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "gost_common.h"
#include "kuznyechik.h"

/* Генерация seed для динамических заголовков из session_id */
void protocol_generate_header_seed(uint64_t session_id, uint8_t *seed, size_t seed_len);

/* Генерация перестановки полей заголовка из seed (Fisher-Yates) */
void protocol_generate_header_permutation(const uint8_t *seed, uint8_t *perm, size_t perm_len);


/* Вычисление длины padding для пакета */
uint32_t protocol_compute_padding(const uint8_t *seed, uint32_t seed_len);

/* Вставка случайного padding в payload */
void protocol_insert_padding(uint8_t *payload, uint32_t *data_len,
                              uint32_t padding_len, const uint8_t *seed);



/* Инициализация сессии с клиентом */
int protocol_init_session(gost_session_t *session, const uint8_t *key);

/* Формирование CPS challenge/answer — возвращает 0 если challenge принят */
int protocol_make_cps_challenge(gost_packet_t *pkt, const uint8_t *seed, size_t seed_len,
                                 uint8_t *challenge_out, uint8_t *answer_out);

/* Формирование fake QUIC-пакета для имитации */
int protocol_make_fake_quic(gost_packet_t *pkt, const uint8_t *seed, size_t seed_len);

/* Формирование fake DNS-запроса для имитации */
int protocol_make_fake_dns(gost_packet_t *pkt, const uint8_t *seed, size_t seed_len);

/* Формирование fake TLS ClientHello для имитации */
int protocol_make_fake_tls(gost_packet_t *pkt, const uint8_t *seed, size_t seed_len);

/* Проверка CPS challenge — возвращает 0 если challenge верный */
int protocol_verify_cps_challenge(const gost_packet_t *pkt, uint8_t *answer, size_t answer_len);

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


#endif /* PROTOCOL_H */
