/*
 * QUIC-слой — простая обёртка UDP с мультиплексированием сессий.
 * Реализует handshke и keepalive поверх UDP.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/random.h>
#include "quic_layer.h"
#include "protocol.h"
#include "gost_common.h"
#include "log.h"

static int create_udp_socket(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    int buf = 1024*1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf, sizeof(buf));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf));
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    return fd;
}

int quic_client_connect(quic_client_t *qc, const char *server_addr, uint16_t server_port,
                        const uint8_t *key) {
    memset(qc, 0, sizeof(quic_client_t));
    qc->server_fd = create_udp_socket();
    if (qc->server_fd < 0) { log_error("QUIC: socket failed"); return -1; }
    strncpy(qc->server_addr, server_addr, QUIC_SERVER_ADDR_MAX-1);
    qc->server_port = server_port;

    /* Handshake: отправляем PKT_HANDSHAKE с HMAC-аутентификацией */
    gost_packet_t hs_pkt;
    memset(&hs_pkt, 0, sizeof(hs_pkt));
    hs_pkt.magic = htonl(GOST_PROXY_MAGIC);
    hs_pkt.type = PKT_HANDSHAKE;

    /* Генерация session_id из /dev/urandom вместо rand() */
    uint64_t sid;
    ssize_t rnd_ret = getrandom(&sid, sizeof(sid), 0);
    if (rnd_ret < 0) {
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd >= 0) {
            ssize_t rd = read(fd, &sid, sizeof(sid));
            close(fd);
            if (rd < (ssize_t)sizeof(sid)) { close(qc->server_fd); qc->server_fd = -1; return -1; }
        } else {
            close(qc->server_fd); qc->server_fd = -1; return -1;
        }
    }
    /* session_id в host byte order, конвертируем при отправке */
    hs_pkt.session_id = htonll(sid);

    /* HMAC-аутентификация: шифруем session_id расширенным ключом */
    if (key) {
        uint8_t expanded_key[160];
        uint8_t hmac_block[16] = {0};
        memcpy(hmac_block, &sid, 8);
        kuznyechik_set_key(key, expanded_key);
        kuznyechik_encrypt_block(hmac_block, expanded_key);
        memcpy(hs_pkt.auth_tag, hmac_block, 4);
    }

    /* Создаём sockaddr — поддержка IPv4 и IPv6 */
    struct sockaddr_storage srv;
    socklen_t srv_len = sizeof(srv);
    memset(&srv, 0, srv_len);
    if (strchr(server_addr, ':')) {
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&srv;
        s6->sin6_family = AF_INET6;
        s6->sin6_port = htons(server_port);
        inet_pton(AF_INET6, server_addr, &s6->sin6_addr);
    } else {
        struct sockaddr_in *s4 = (struct sockaddr_in *)&srv;
        s4->sin_family = AF_INET;
        s4->sin_port = htons(server_port);
        inet_pton(AF_INET, server_addr, &s4->sin_addr);
    }

    ssize_t sent = sendto(qc->server_fd, &hs_pkt, sizeof(hs_pkt), 0,
                          (struct sockaddr*)&srv, srv_len);
    if (sent < (ssize_t)sizeof(hs_pkt)) {
        log_error("QUIC: handshake send failed");
        close(qc->server_fd); qc->server_fd = -1; return -1;
    }

    struct pollfd pfd = { .fd = qc->server_fd, .events = POLLIN };
    if (poll(&pfd, 1, 5000) <= 0) {
        log_error("QUIC: handshake timeout");
        close(qc->server_fd); qc->server_fd = -1; return -1;
    }

    uint8_t resp[MAX_PAYLOAD + 32 + 1];
    socklen_t rlen = sizeof(srv);
    ssize_t n = recvfrom(qc->server_fd, resp, sizeof(resp), 0,
                         (struct sockaddr*)&srv, &rlen);
    if (n < (ssize_t)(4 + 1 + 4 + 8)) {
        log_error("QUIC: handshake response short");
        close(qc->server_fd); qc->server_fd = -1; return -1;
    }

    gost_packet_t *r = (gost_packet_t*)resp;
    if (ntohl(r->magic) != GOST_PROXY_MAGIC || r->type != PKT_HANDSHAKE) {
        log_error("QUIC: invalid handshake response");
        close(qc->server_fd); qc->server_fd = -1; return -1;
    }
    qc->active = 1;
    /* session_id — конвертируем из сетевого в хост-порядок */
    uint64_t sid_net;
    memcpy(&sid_net, &r->session_id, 8);
    *(uint64_t*)qc->session_id = ntohll(sid_net);
    log_info("QUIC: handshake OK (session_id=%llu)", (unsigned long long)ntohll(r->session_id));
    return 0;
}

ssize_t quic_client_send(quic_client_t *qc, const uint8_t *data, size_t len) {
    if (!qc || !qc->active || qc->server_fd < 0) return QUIC_ERROR;
    /* Определяем адрес по наличию ':' в адресе */
    struct sockaddr_storage srv;
    socklen_t srv_len = sizeof(srv);
    memset(&srv, 0, srv_len);
    if (strchr(qc->server_addr, ':')) {
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&srv;
        s6->sin6_family = AF_INET6;
        s6->sin6_port = htons(qc->server_port);
        inet_pton(AF_INET6, qc->server_addr, &s6->sin6_addr);
    } else {
        struct sockaddr_in *s4 = (struct sockaddr_in *)&srv;
        s4->sin_family = AF_INET;
        s4->sin_port = htons(qc->server_port);
        inet_pton(AF_INET, qc->server_addr, &s4->sin_addr);
    }
    ssize_t sent = sendto(qc->server_fd, data, len, 0,
                          (struct sockaddr*)&srv, srv_len);
    if (sent < 0) return QUIC_ERROR;
    return sent;
}

ssize_t quic_client_recv(quic_client_t *qc, uint8_t *buf, size_t maxlen, int timeout_ms) {
    if (!qc || !qc->active || qc->server_fd < 0) return QUIC_ERROR;
    struct pollfd pfd = { .fd = qc->server_fd, .events = POLLIN };
    int ret = poll(&pfd, 1, timeout_ms);
    if (ret == 0) return 0;
    if (ret < 0) return QUIC_ERROR;
    ssize_t n = recvfrom(qc->server_fd, buf, maxlen, 0, NULL, NULL);
    if (n <= 0) { if (n == 0) return QUIC_CLOSED; if (errno==EAGAIN) return 0; return QUIC_ERROR; }
    return n;
}

int quic_client_keepalive(quic_client_t *qc) {
    if (!qc || !qc->active) return QUIC_ERROR;
    struct sockaddr_storage srv;
    socklen_t srv_len = sizeof(srv);
    memset(&srv, 0, srv_len);
    if (strchr(qc->server_addr, ':')) {
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&srv;
        s6->sin6_family = AF_INET6;
        s6->sin6_port = htons(qc->server_port);
        inet_pton(AF_INET6, qc->server_addr, &s6->sin6_addr);
    } else {
        struct sockaddr_in *s4 = (struct sockaddr_in *)&srv;
        s4->sin_family = AF_INET;
        s4->sin_port = htons(qc->server_port);
        inet_pton(AF_INET, qc->server_addr, &s4->sin_addr);
    }
    gost_packet_t ka;
    memset(&ka, 0, sizeof(ka));
    ka.magic = htonl(GOST_PROXY_MAGIC);
    ka.type = PKT_KEEPALIVE;
    uint64_t sid; memcpy(&sid, qc->session_id, 8);
    ka.session_id = htonll(sid);
    ssize_t s = sendto(qc->server_fd, &ka, sizeof(ka), 0,
                       (struct sockaddr*)&srv, srv_len);
    return (s > 0) ? QUIC_OK : QUIC_ERROR;
}

void quic_client_close(quic_client_t *qc) {
    if (!qc) return;
    qc->active = 0;
    if (qc->server_fd >= 0) { close(qc->server_fd); qc->server_fd = -1; }
}

int quic_server_start(quic_server_t *qs, const char *bind_addr, uint16_t bind_port) {
    memset(qs, 0, sizeof(quic_server_t));
    qs->server_fd = create_udp_socket();
    if (qs->server_fd < 0) return -1;
    strncpy(qs->bind_addr, bind_addr, sizeof(qs->bind_addr)-1);
    qs->bind_port = bind_port;
    qs->active = 1;
    log_info("QUIC: server started on %s:%d", bind_addr, bind_port);
    return 0;
}

ssize_t quic_server_recv(quic_server_t *qs, uint8_t *buf, size_t max_len,
                         struct sockaddr_in *client_addr, socklen_t *addr_len,
                         int timeout_ms) {
    if (!qs || !qs->active || qs->server_fd < 0) return QUIC_ERROR;
    struct pollfd pfd = { .fd = qs->server_fd, .events = POLLIN };
    int ret = poll(&pfd, 1, timeout_ms);
    if (ret == 0) return 0;  /* timeout */
    if (ret < 0) return QUIC_ERROR;
    if (!(pfd.revents & POLLIN)) return 0;  /* не POLLIN — нет данных */
    *addr_len = sizeof(struct sockaddr_in);
    ssize_t n = recvfrom(qs->server_fd, buf, max_len, 0,
                         (struct sockaddr*)client_addr, addr_len);
    if (n <= 0) { if (n == 0) return QUIC_CLOSED; if (errno==EAGAIN) return 0; return QUIC_ERROR; }
    return n;
}

ssize_t quic_server_send(quic_server_t *qs, const struct sockaddr_in *client_addr,
                         socklen_t addr_len, const uint8_t *data, size_t len) {
    if (!qs || !qs->active || qs->server_fd < 0) return QUIC_ERROR;
    ssize_t sent = sendto(qs->server_fd, data, len, 0,
                          (const struct sockaddr*)client_addr, addr_len);
    if (sent < 0) { log_debug("QUIC sendto: %s", strerror(errno)); return QUIC_ERROR; }
    return sent;
}

void quic_server_close(quic_server_t *qs) {
    if (!qs) return;
    qs->active = 0;
    if (qs->server_fd >= 0) { close(qs->server_fd); qs->server_fd = -1; }
}
