#ifndef SOCKS5_H
#define SOCKS5_H

#include <stdint.h>
#include "quic_layer.h"

#define SOCKS5_PORT 1080

/* Запуск локального SOCKS5-прокси */
int socks5_start(uint16_t port, const char *server_ip, uint16_t server_port,
                 const uint8_t *expanded_key, const uint8_t *nonce,
                 uint64_t session_id,
                 quic_client_t *quic_client,
                 uint32_t *session_counter);

/* Остановка */
void socks5_stop(void);

#endif /* SOCKS5_H */
