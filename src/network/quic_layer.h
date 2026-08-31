#ifndef QUIC_LAYER_H
#define QUIC_LAYER_H

#include <stdint.h>
#include <stddef.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "gost_common.h"

#define QUIC_MAX_PAYLOAD 1350
#define QUIC_SERVER_ADDR_MAX 64
#define QUIC_SERVER_PORT_MAX 6

/* Результат операции QUIC */
typedef enum {
    QUIC_OK = 0,
    QUIC_ERROR = -1,
    QUIC_TIMEOUT = -2,
    QUIC_CLOSED = -3
} quic_result_t;

/* Контекст QUIC-клиента */
typedef struct quic_client {
    void *reg;            /* Registration */
    void *con;            /* Connection handle */
    int   server_fd;      /* Underlying UDP socket fd */
    char  server_addr[QUIC_SERVER_ADDR_MAX];
    uint16_t server_port;
    uint8_t session_id[8];
    uint8_t nonce[NONCE_SIZE]; /* 12-байтный nonce для CTR-шифрования */
    int   active;
} quic_client_t;

/* Контекст QUIC-сервера */
typedef struct quic_server {
    void *reg;            /* Registration */
    void *con;            /* Listen connection handle */
    int   server_fd;      /* Underlying UDP socket fd */
    char  bind_addr[64];
    uint16_t bind_port;
    int   active;
} quic_server_t;

/*
 * Инициализация QUIC-клиента и подключение к серверу
 * Возвращает 0 при успехе, -1 при ошибке
 */
int quic_client_connect(quic_client_t *qc, const char *server_addr, uint16_t server_port,
                        const uint8_t *key);

/*
 * Отправить данные через QUIC-туннель
 * Возвращает количество отправленных байт или ошибку
 */
ssize_t quic_client_send(quic_client_t *qc, const uint8_t *data, size_t len);

/*
 * Принять данные из QUIC-туннеля с таймаутом (мс)
 * Возвращает количество принятых байт, 0 при таймауте, -1 при ошибке
 */
ssize_t quic_client_recv(quic_client_t *qc, uint8_t *buf, size_t max_len, int timeout_ms);

/*
 * Отправить keepalive (пинг серверу)
 */
int quic_client_keepalive(quic_client_t *qc);

/*
 * Закрыть QUIC-клиента
 */
void quic_client_close(quic_client_t *qc);

/*
 * Инициализация QUIC-сервера
 * Возвращает 0 при успехе, -1 при ошибке
 */
int quic_server_start(quic_server_t *qs, const char *bind_addr, uint16_t bind_port);

/*
 * Принять пакет от клиента с таймаутом (мс)
 * fill_client_addr заполняется адресом клиента
 * Возвращает количество принятых байт, 0 при таймауте, -1 при ошибке
 */
ssize_t quic_server_recv(quic_server_t *qs, uint8_t *buf, size_t max_len,
                         struct sockaddr_in *client_addr, socklen_t *addr_len,
                         int timeout_ms);

/*
 * Отправить ответ клиенту
 */
ssize_t quic_server_send(quic_server_t *qs, const struct sockaddr_in *client_addr,
                         socklen_t addr_len, const uint8_t *data, size_t len);

/*
 * Закрыть QUIC-сервер
 */
void quic_server_close(quic_server_t *qs);

#endif /* QUIC_LAYER_H */
