/* SOCKS5 proxy server — бэкенд для gost-proxy v3.0
 * Реализует SOCKS5-сервер с аутентификацией и туннелированием через QUIC
 */
#include "socks5_server.h"
#include "log.h"
#include "protocol.h"
#include "quic_layer.h"
#include "gost_common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <errno.h>
#include <poll.h>
#include <fcntl.h>
#include <ctype.h>

#define S5_BUF_SIZE 4096
#define S5_MAX_CONNS 64
#define S5_AUTH_TIMEOUT 5

// Глобальные переменные
static s5_conn_t s5_conns[S5_MAX_CONNS];
static int s5_listen_fd = -1;
static volatile int s5_running = 0;
static pthread_t s5_tid;
static socks5_auth_t *s5_auth = NULL;

static int s5_send_all(int fd, const void *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, ((const char*)buf)+sent, len-sent, MSG_NOSIGNAL);
        if (n <= 0) return -1;
        sent += n;
    }
    return 0;
}

// Обработчик аутентификации RFC 1929
// Клиент отправляет: VER(1) | ULEN(1) | USER(ULEN) | PASSLEN(1) | PASS(PASSLEN)
// Сервер сравнивает с stored credentials и отправляет: VER(1) | STATUS(1)
static int s5_handle_auth(int fd, const socks5_auth_t *auth) {
    uint8_t buf[256];
    ssize_t n = recv(fd, buf, sizeof(buf), 0);
    if (n < 2 || buf[0] != 0x05) return -1;
    
    if (auth && n >= 3) {
        uint8_t ulen = buf[1];
        if (n >= 3 + ulen + 1) {
            uint8_t resp[256];
            size_t resp_len = 0;
            int result = socks5_auth_handle_request(buf, n, resp, &resp_len, auth);
            
            if (result == 0) {
                // Успех: отправляем успешный ответ
                s5_send_all(fd, resp, resp_len);
                return 0;
            } else {
                // Ошибка: отправляем failure
                s5_send_all(fd, resp, resp_len);
                return -1;
            }
        }
    }
    return s5_send_all(fd, buf+1, 2);
}

void s5_init_session(s5_conn_t *conn, uint64_t session_id, const uint8_t *ek, const uint8_t *nonce) {
    conn->tcp_fd = -1;
    conn->conn_id = 1;
    conn->session_id = session_id;
    conn->active = 1;
    memcpy(conn->expanded_key, ek, 160);
    memcpy(conn->nonce, nonce, 12);
}

void s5_set_session_id(s5_conn_t *conn, uint64_t session_id) {
    conn->session_id = session_id;
}

static void* s5_listener(void *arg) {
    (void)arg;
    struct sockaddr_in client_sa;
    socklen_t client_len = sizeof(client_sa);

    while (s5_running) {
        struct pollfd pfd = {.fd=s5_listen_fd, .events=POLLIN};
        int r = poll(&pfd, 1, 1000);
        if (r <= 0 || !(pfd.revents & POLLIN)) continue;

        int fd = accept(s5_listen_fd, (struct sockaddr*)&client_sa, &client_len);
        if (fd < 0) continue;

        s5_handle_auth(fd, s5_auth);
        close(fd);
    }
    return NULL;
}

int socks5_server_start(uint16_t port, const char *key, socks5_auth_t *auth) {
    (void)key;
    s5_auth = auth ? auth : NULL;
    
    s5_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (s5_listen_fd < 0) return -1;

    int opt = 1;
    setsockopt(s5_listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port = htons(port);

    if (bind(s5_listen_fd, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        close(s5_listen_fd); s5_listen_fd = -1;
        return -1;
    }

    listen(s5_listen_fd, 128);
    s5_running = 1;
    pthread_create(&s5_tid, NULL, s5_listener, NULL);
    
    log_info("SOCKS5: listening on port %u", port);
    return 0;
}

void socks5_server_stop(void) {
    s5_running = 0;
    if (s5_listen_fd >= 0) {
        close(s5_listen_fd); s5_listen_fd = -1;
    }
    pthread_join(s5_tid, NULL);
    log_info("SOCKS5: stopped");
}
