#ifndef GOST_COMMON_H
#define GOST_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <arpa/inet.h>

/* Магия протокола */
#define GOST_PROXY_MAGIC 0x474F5354  /* "GOST" */

/* Byte-swap для 64-бит (нет в glibc) */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    #define htonll(x) (((uint64_t)htonl((uint32_t)((x) >> 32))) | \
                        (((uint64_t)htonl((uint32_t)(x))) << 32))
    #define ntohll(x) htonll(x)
#else
    #define htonll(x) (x)
    #define ntohll(x) (x)
#endif

/* Типы пакетов */
#define PKT_HANDSHAKE           0x01
#define PKT_HANDSHAKE_ACK       0x01
#define PKT_AUTH_REQ            0x05   /* Аутентификация клиента */
#define PKT_AUTH_RESP           0x06   /* Ответ аутентификации */
#define PKT_DATA                0x02
#define PKT_KEEPALIVE   0x03
#define PKT_DISCONNECT  0x04

/* Типы имитации (CPS) */
#define PKT_SIM_QUIC        0x10
#define PKT_SIM_DNS         0x11
#define PKT_SIM_TLS         0x12
#define PKT_SIM_CHALLENGE   0x13

/* Динамические заголовки */
#define HEADER_PERM_ENABLED 1
#define HEADER_SEED_SIZE    8
#define HEADER_FIELD_COUNT  4

/* Случайный padding */
#define PADDING_ENABLED     1
#define PADDING_MIN_BYTES   8
#define PADDING_MAX_BYTES   128

/* Размеры полей */
#define SESSION_ID_SIZE 8
#define AUTH_TAG_SIZE   16
#define NONCE_SIZE      12
#define MAX_PAYLOAD     1400

/* Структура пакета протокола (фиксированный порядок полей) */
typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint8_t  type;
    uint32_t conn_id;       /* ID соединения для мультиплексирования */
    uint64_t session_id;
    uint8_t  payload[MAX_PAYLOAD];
    uint8_t  auth_tag[AUTH_TAG_SIZE];
} gost_packet_t;

/* Порядок полей при динамической перестановке */
typedef struct {
    uint8_t  field_order[HEADER_FIELD_COUNT]; /* индексы полей в перестановке */
    uint8_t  seed[HEADER_SEED_SIZE];          /* seed для генерации perестановки */
    uint32_t padding_len;                     /* длина padding в байтах */
} header_permutation_t;

/* Перестановки полей заголовка: [magic, type, conn_id, session_id] */
#define FLD_MAGIC   0
#define FLD_TYPE    1
#define FLD_CONN_ID 2
#define FLD_SESS_ID 3

/* Окно допустимых counter для защиты от replay-атак */
#define COUNTER_WINDOW_SIZE 1024

/* Клиентская сессия */
typedef struct {
    uint64_t session_id;
    uint8_t  key[32];
    uint8_t  expanded_key[160];
    uint8_t  nonce[NONCE_SIZE];
    uint32_t counter;
    uint32_t last_counter;    /* последний принятый counter (для replay protection) */
    int      active;
    /* Динамические заголовки */
    uint8_t  header_seed[HEADER_SEED_SIZE];
    uint8_t  header_perm[HEADER_FIELD_COUNT]; /* perестановка полей */
    /* CPS имитация */
    uint8_t  cps_enabled;
    uint8_t  cps_challenge[32];
    uint8_t  cps_response[32];
} gost_session_t;

#endif /* GOST_COMMON_H */
