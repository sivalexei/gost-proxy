#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "gost_common.h"
#include "kuznyechik.h"
#include "obfuscation.h"

/* Вычисление длины padding для сессии */
uint32_t protocol_compute_padding_len(uint64_t session_id);

/* Инициализация PRNG (вызвать один раз при старте) */
void protocol_prng_init(void);

/* Вставка случайного padding в payload (ПОСЛЕ данных)
 * Возвращает: длину вставленного padding в байтах */
uint32_t protocol_insert_padding(uint8_t *payload, uint32_t *data_len,
                                 uint32_t padding_len, uint64_t session_id);


/* Инициализация сессии с клиентом (убрано — больше не нужно) */
/* int protocol_init_session(gost_session_t *session, const uint8_t *key); */

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
int protocol_compute_cps_answer(uint64_t session_id, const uint8_t *expanded_key, uint8_t *answer);

/* Упаковка пакета данных с обфускацией
 * session_id — в host byte order (НЕ htonll)
 * obf_key_dir — направление: 0 = client->server, 1 = server->client
 */
int protocol_pack_data(
    gost_packet_t *pkt,
    uint64_t session_id,          /* host byte order */
    uint32_t conn_id,
    const uint8_t *data,
    size_t data_len,
    const uint8_t *expanded_key,
    const uint8_t *nonce,
    uint32_t *counter,
    uint8_t obf_key_dir
);

/* Распаковка пакета данных с обфускацией
 * session_id — в host byte order (НЕ htonll)
 * obf_key_dir — направление: 0 = client->server, 1 = server->client
 */
int protocol_unpack_data(
    const gost_packet_t *pkt,
    uint8_t *data,
    size_t *data_len,
    uint32_t *out_conn_id,
    const uint8_t *expanded_key,
    const uint8_t *nonce,
    uint32_t *counter,
    uint8_t obf_key_dir
);

/* Формирование handshake с аутентификацией
 * client_nonce и server_nonce — по 8 байт каждый
 * session_nonce — 12-байтный nonce сессии (вкладывается в payload) */
int protocol_create_handshake(
    gost_packet_t *pkt,
    uint64_t session_id,          /* host byte order */
    const uint8_t *expanded_key,
    const uint8_t *client_nonce,
    const uint8_t *server_nonce,
    const uint8_t *session_nonce
);

/* Auth-tag для DISCONNECT: HMAC(session_id, conn_id) с EK
 * prevent: anyone can disconnect another user's session */
void compute_disconnect_auth(uint64_t session_id, uint32_t conn_id,
                              const uint8_t *expanded_key, uint8_t *auth);

#endif /* PROTOCOL_H */
