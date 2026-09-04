/* SOCKS5 proxy server — бэкенд для gost-proxy v3.0
 * Реализует SOCKS5-сервер с туннелированием через QUIC
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

static s5_conn_t s5_conns[S5_MAX_CONNS];
static int s5_listen_fd = -1;
static volatile int s5_running = 0;
static pthread_t s5_tid;
static char cfg_key[65] = "";

static int s5_send_all(int fd, const void *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, ((const char*)buf)+sent, len-sent, MSG_NOSIGNAL);
        if (n <= 0) return -1;
        sent += n;
    }
    return 0;
}

static int s5_send_connect_success(int fd) {
    uint8_t buf[10] = {0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0};
    return s5_send_all(fd, buf, 10);
}

static int s5_send_connect_error(int fd, uint8_t rep_code) {
    uint8_t buf[10] = {0x05, rep_code, 0x00, 0x01, 0,0,0,0, 0,0};
    return s5_send_all(fd, buf, 10);
}

static int s5_parse_addr(const uint8_t *data, int len, char *addr, uint16_t *port) {
    if (len < 4) return -1;
    uint8_t atype = data[3];
    switch (atype) {
        case 0x01:
            if (len < 10) return -1;
            snprintf(addr, 16, "%d.%d.%d.%d", data[4], data[5], data[6], data[7]);
            *port = (data[8] << 8) | data[9];
            break;
        case 0x03:
            if (len < 5) return -1;
            { uint8_t dlen = data[4];
              if (len < 5+dlen+2) return -1;
              memcpy(addr, data+5, dlen); addr[dlen]='\0';
              *port = (data[5+dlen]<<8) | data[6+dlen]; }
            break;
        default: return -1;
    }
    return 0;
}

static int s5_handle_auth(int fd) {
    uint8_t buf[256];
    ssize_t n = recv(fd, buf, sizeof(buf), 0);
    if (n < 2 || buf[0] != 0x05) return -1;
    int nmethods = buf[1];
    int have_none=0, have_userpass=0;
    for (int i=0; i<nmethods && i+1<n; i++) {
        if (buf[i+1]==0x00) have_none=1;
        if (buf[i+1]==0x02) have_userpass=1;
    }
    if (have_userpass) {
        if (s5_send_all(fd, (uint8_t[]){0x05,0x02}, 2) != 0) return -1;
        n = recv(fd, buf, sizeof(buf), 0);
        if (n < 3 || buf[0]!=0x01) return -1;
        uint8_t ulen=buf[1];
        if (n<3+ulen) return -1;
        char uname[128];
        memcpy(uname, buf+2, ulen); uname[ulen]='\0';
        if (strlen(cfg_key)>0 && strcmp(uname, cfg_key)!=0) {
            s5_send_all(fd, (uint8_t[]){0xFF}, 1);
            close(fd); return -1;
        }
        uint8_t resp[2] = {0x01, 0x00};
        return s5_send_all(fd, resp, 2);
    }
    if (have_none) return s5_send_all(fd, (uint8_t[]){0x05,0x00}, 2);
    s5_send_all(fd, (uint8_t[]){0xFF}, 1); close(fd); return -1;
}

static uint32_t s5_next_conn_id(void) {
    static uint32_t next_cid = 1;
    uint32_t cid = next_cid++;
    if (cid >= 0x7FFFFFFF) next_cid = 1;
    return cid;
}

void s5_init_session(s5_conn_t *conn, uint64_t session_id, const uint8_t *ek, const uint8_t *nonce) {
    conn->tcp_fd = -1;
    conn->conn_id = s5_next_conn_id();
    conn->send_ctr = 0;
    conn->recv_ctr = 0;
    conn->session_id = session_id;
    conn->active = 1;
    memcpy(conn->expanded_key, ek, 160);
    memcpy(conn->nonce, nonce, 12);
}

void s5_set_session_id(s5_conn_t *conn, uint64_t session_id) {
    conn->session_id = session_id;
}

/* Обработка CONNECT — туннелирование через QUIC */
static void* s5_connect_thread(void *arg) {
    s5_conn_t *conn = (s5_conn_t*)arg;
    int fd = conn->tcp_fd;
    log_info("SOCKS5: CONNECT for conn_id=%u", conn->conn_id);

    /* Ждём данные от клиента для туннелирования */
    while (s5_running && conn->active) {
        struct pollfd pfd = {.fd=fd, .events=POLLIN};
        int r = poll(&pfd, 1, 1000);
        if (r <= 0 || !(pfd.revents & POLLIN)) continue;

        uint8_t buf[S5_BUF_SIZE];
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) break;

        log_debug("SOCKS5: got %zd bytes for conn_id=%u", n, conn->conn_id);
        /* TODO: туннелирование через QUIC
         * protocol_pack_data() + quic_server_send()
         */

        /* Эхо-ответ для теста */
        send(fd, buf, n, MSG_NOSIGNAL);
    }
    conn->active = 0;
    log_info("SOCKS5: CONNECT closing conn_id=%u", conn->conn_id);
    close(fd);
    return NULL;
}

/* Основной поток прослушивания */
static void* s5_listener(void *arg) {
    (void)arg;
    struct sockaddr_in client_sa;
    socklen_t client_len = sizeof(client_sa);

    while (s5_running) {
        struct pollfd pfd = {.fd=s5_listen_fd, .events=POLLIN};
        int r = poll(&pfd, 1, 1000);
        if (r <= 0 || !(pfd.revents & POLLIN)) continue;

        int fd = accept(s5_listen_fd, (struct sockaddr*)&client_sa, &client_len);
        if (fd < 0) {
            log_warn("SOCKS5: accept failed: %s", strerror(errno));
            continue;
        }

        int flags = fcntl(fd, F_GETFL, 0);
        if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        log_info("SOCKS5: accepted from %s:%u", inet_ntoa(client_sa.sin_addr), ntohs(client_sa.sin_port));

        /* Аутентификация */
        if (s5_handle_auth(fd) != 0) {
            log_warn("SOCKS5: auth failed for %s", inet_ntoa(client_sa.sin_addr));
            continue;
        }

        /* Запрос команды */
        uint8_t req[256];
        ssize_t n = recv(fd, req, sizeof(req), 0);
        if (n < 4 || req[0]!=0x05) { close(fd); continue; }

        uint8_t cmd = req[1];
        uint16_t port;
        char addr[256];

        switch (cmd) {
            case 0x01: { /* CONNECT */
                if (s5_parse_addr(req, n, addr, &port) != 0) { close(fd); break; }
                log_info("SOCKS5: CONNECT to %s:%u", addr, port);
                if (s5_send_connect_success(fd) != 0) { close(fd); break; }

                pthread_t tid;
                s5_conn_t *conn = &s5_conns[0];
                if (fd >= 0) conn->tcp_fd = fd;
                tid = pthread_self();
                pthread_create(&tid, NULL, s5_connect_thread, conn);
                pthread_detach(tid);
                break;
            }
            case 0x02: /* BIND */
            case 0x03: { /* ASSOCIATE */
                s5_parse_addr(req, n, addr, &port);
                log_info("SOCKS5: %s to %s:%u (not supported)",
                         cmd==0x02?"BIND":"ASSOCIATE", addr, port);
                s5_send_connect_error(fd, 0x07);
                close(fd);
                break;
            }
            default:
                s5_send_connect_error(fd, 0x07);
                close(fd);
                break;
        }
    }
    return NULL;
}

/* ========== API ========== */

int socks5_server_start(uint16_t port, const char *key) {
    strncpy(cfg_key, key, 64);
    cfg_key[64] = '\0';

    s5_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (s5_listen_fd < 0) {
        log_error("SOCKS5: socket failed: %s", strerror(errno));
        return -1;
    }

    int opt = 1;
    setsockopt(s5_listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(s5_listen_fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt));
    setsockopt(s5_listen_fd, SOL_SOCKET, SO_SNDBUF, &opt, sizeof(opt));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port = htons(port);

    if (bind(s5_listen_fd, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        log_error("SOCKS5: bind to port %u failed: %s", port, strerror(errno));
        close(s5_listen_fd); s5_listen_fd = -1;
        return -1;
    }

    if (listen(s5_listen_fd, 128) < 0) {
        log_error("SOCKS5: listen failed: %s", strerror(errno));
        close(s5_listen_fd); s5_listen_fd = -1;
        return -1;
    }

    s5_running = 1;
    pthread_create(&s5_tid, NULL, s5_listener, NULL);
    log_info("SOCKS5: listening on port %u (auth: %s)", port, key[0]?"USER/PASS":"NONE");
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
