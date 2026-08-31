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
#include <sys/epoll.h>
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

    /* session_id = 0 — сервер сгенерирует его в handshake-ack
     * prevent: client-chosen session_id allows session hijacking */
    hs_pkt.session_id = 0;

    /* Усиленная аутентификация: CMAC(PSK, client_nonce || server_nonce) */
    uint8_t expanded_key[160] = {0};
    uint8_t client_nonce[8] = {0}, server_nonce[8] = {0};
    int has_auth = 0;
    if (key) {
        ssize_t rnd_ret2 = getrandom(client_nonce, sizeof(client_nonce), 0);
        if (rnd_ret2 < 0) {
            int fd2 = open("/dev/urandom", O_RDONLY);
            if (fd2 >= 0) {
                ssize_t _r = read(fd2, client_nonce, sizeof(client_nonce)); (void)_r;
                close(fd2);
            }
        }
        /* Сохраняем client_nonce в payload[1..8] для сервера */
        hs_pkt.payload[0] = 1;  /* маркер наличия nonce */
        memcpy(hs_pkt.payload + 1, client_nonce, 8);
        kuznyechik_set_key(key, expanded_key);
        /* Аутентификация клиента: auth_tag = CMAC(PSK, client_nonce) */
        kuznyechik_compute_auth(expanded_key, client_nonce, server_nonce, hs_pkt.auth_tag);
        has_auth = 1;
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

    int epfd = epoll_create1(0);
    if (epfd < 0) { close(qc->server_fd); qc->server_fd = -1; return -1; }
    struct epoll_event ev = { .events = EPOLLIN };
    ev.data.fd = qc->server_fd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, qc->server_fd, &ev);
    struct epoll_event events;
    if (epoll_wait(epfd, &events, 1, 5000) <= 0) {
        log_error("QUIC: handshake timeout");
        close(epfd); close(qc->server_fd); qc->server_fd = -1; return -1;
    }
    close(epfd);

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

    /* Проверяем ответ сервера: CMAC(PSK, client_nonce || server_nonce) */
    if (has_auth && r->payload[0] == 1) {
        uint8_t exp_server_nonce[8], exp_auth[AUTH_TAG_SIZE];
        /* Извлекаем server_nonce из ответа */
        memcpy(exp_server_nonce, r->payload + 1, 8);
        kuznyechik_compute_auth(expanded_key, client_nonce, exp_server_nonce, exp_auth);
        /* Сравниваем auth_tag сервера */
        if (memcmp(r->auth_tag, exp_auth, AUTH_TAG_SIZE) != 0) {
            log_error("QUIC: server auth failed (CMAC mismatch)");
            close(qc->server_fd); qc->server_fd = -1; return -1;
        }
        qc->active = 1;
        uint64_t sid_net;
        memcpy(&sid_net, &r->session_id, 8);
        *(uint64_t*)qc->session_id = ntohll(sid_net);
        /* Извлекаем session_nonce (12 байт) из payload[1..12] */
        memcpy(qc->nonce, r->payload + 1, NONCE_SIZE);
        log_info("QUIC: handshake OK (sid=%llu, nonce=%02x..%02x)",
                (unsigned long long)ntohll(r->session_id), qc->nonce[0], qc->nonce[11]);
    } else {
        qc->active = 1;
        uint64_t sid_net;
        memcpy(&sid_net, &r->session_id, 8);
        *(uint64_t*)qc->session_id = ntohll(sid_net);
        log_info("QUIC: handshake OK (sid=%llu, no auth)", (unsigned long long)ntohll(r->session_id));
    }
    return 0;
}

ssize_t quic_client_send(quic_client_t *qc, const uint8_t *data, size_t len) {
    if (!qc || !qc->active || qc->server_fd < 0) {
        log_error("QUIC send: qc=%p active=%d fd=%d", qc, qc?qc->active:0, qc?qc->server_fd:-1);
        return QUIC_ERROR;
    }
    log_info("QUIC send: fd=%d, len=%zu, addr=%s:%d", qc->server_fd, len, qc->server_addr, qc->server_port);
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
    if (sent < 0) { log_error("QUIC sendto: %s", strerror(errno)); return QUIC_ERROR; }
    log_info("QUIC send: sent %zd bytes", sent);
    return sent;
}

ssize_t quic_client_recv(quic_client_t *qc, uint8_t *buf, size_t maxlen, int timeout_ms) {
    if (!qc || !qc->active || qc->server_fd < 0) return QUIC_ERROR;
    int epfd = epoll_create1(0);
    if (epfd < 0) return QUIC_ERROR;
    struct epoll_event ev = { .events = EPOLLIN };
    ev.data.fd = qc->server_fd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, qc->server_fd, &ev);
    struct epoll_event events;
    int ret = epoll_wait(epfd, &events, 1, timeout_ms);
    close(epfd);
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
    int epfd = epoll_create1(0);
    if (epfd < 0) return QUIC_ERROR;
    struct epoll_event ev = { .events = EPOLLIN };
    ev.data.fd = qs->server_fd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, qs->server_fd, &ev);
    struct epoll_event events;
    ssize_t n = 0;
    int remaining = timeout_ms;
    int total_waited = 0;
    while (remaining > 0) {
        int chunk = remaining;
        int ret = epoll_wait(epfd, &events, 1, chunk);
        if (!qs->active) { log_debug("QUIC: shutdown detected, active=%d", qs->active); close(epfd); return QUIC_ERROR; }  /* shutdown */
        if (ret < 0) { close(epfd); return QUIC_ERROR; }
        if (ret == 0) { total_waited += chunk; remaining = timeout_ms - total_waited; if (remaining < 0) remaining = 0; continue; }
        if (!(events.events & EPOLLIN)) { total_waited += chunk; remaining = timeout_ms - total_waited; if (remaining < 0) remaining = 0; continue; }
        close(epfd);
        *addr_len = sizeof(struct sockaddr_in);
        n = recvfrom(qs->server_fd, buf, max_len, 0,
                     (struct sockaddr*)client_addr, addr_len);
        if (n <= 0) { if (n == 0) return QUIC_CLOSED; if (errno==EAGAIN) return 0; return QUIC_ERROR; }
        return n;
    }
    close(epfd);
    return 0;  /* timeout */
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
