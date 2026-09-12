#ifndef SOCKS5_SERVER_H
#define SOCKS5_SERVER_H

#include <stdint.h>

typedef struct s5_conn_t {
    int tcp_fd;
    uint32_t conn_id;
    uint32_t send_ctr;
    uint32_t recv_ctr;
    uint64_t session_id;
    int active;
    uint8_t expanded_key[160];
    uint8_t nonce[12];
} s5_conn_t;

int socks5_server_start(uint16_t port, const char *key);
void socks5_server_stop(void);
void s5_init_session(s5_conn_t *conn, uint64_t session_id, const uint8_t *ek, const uint8_t *nonce);
void s5_set_session_id(s5_conn_t *conn, uint64_t session_id);

#endif
