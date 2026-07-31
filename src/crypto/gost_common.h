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
                        ((uint64_t)htonl((uint32_t)(x)) << 32))
    #define ntohll(x) htonll(x)
#else
    #define htonll(x) (x)
    #define ntohll(x) (x)
#endif

/* Типы пакетов */
#define PKT_HANDSHAKE           0x01
#define PKT_HANDSHAKE_ACK       0x01
#define PKT_DATA                0x02
#define PKT_KEEPALIVE   0x03
#define PKT_DISCONNECT  0x04

/* Размеры полей */
#define SESSION_ID_SIZE 8
#define AUTH_TAG_SIZE   16
#define NONCE_SIZE      12
#define MAX_PAYLOAD     1400

/* Структура пакета протокола */
typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint8_t  type;
    uint32_t conn_id;       /* ID соединения для мультиплексирования */
    uint64_t session_id;
    uint8_t  payload[MAX_PAYLOAD];
    uint8_t  auth_tag[AUTH_TAG_SIZE];
} gost_packet_t;

/* Клиентская сессия */
typedef struct {
    uint64_t session_id;
    uint8_t  key[32];
    uint8_t  expanded_key[160];
    uint8_t  nonce[NONCE_SIZE];
    uint32_t counter;
    int      active;
} gost_session_t;

#endif /* GOST_COMMON_H */
