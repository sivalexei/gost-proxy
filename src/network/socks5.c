#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <stdatomic.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <errno.h>

#include "quic_layer.h"
#include "kuznyechik.h"
#include "gost_common.h"
#include "protocol.h"
#include "log.h"
#include "socks5.h"

#define SOCKS5_BUF_SIZE 4096
#define DNS_CACHE_SIZE 256
#define DNS_CACHE_TTL 300  /* секунд */
#define MAX_SIMULTANEOUS_CONNS 64  /* backpressure: макс. одновременных соединений */

static atomic_int active_conns = ATOMIC_VAR_INIT(0);

typedef struct {
    char host[256];
    uint32_t addr;
    time_t expiry;
    int valid;
} dns_cache_entry_t;

static dns_cache_entry_t dns_cache[DNS_CACHE_SIZE];
static pthread_mutex_t dns_cache_lock = PTHREAD_MUTEX_INITIALIZER;

static inline uint32_t dns_cache_hash(const char *host) {
    uint32_t hash = 5381;
    int c;
    while ((c = *host++))
        hash = ((hash << 5) + hash) + c;
    return hash % DNS_CACHE_SIZE;
}

static int dns_cache_lookup(const char *host, struct in_addr *out_addr) {
    pthread_mutex_lock(&dns_cache_lock);
    uint32_t h = dns_cache_hash(host);
    for (int i = 0; i < DNS_CACHE_SIZE; i++, h = (h + 1) % DNS_CACHE_SIZE) {
        dns_cache_entry_t *e = &dns_cache[h];
        if (!e->valid) continue;
        if (strcmp(e->host, host) != 0) continue;
        if (time(NULL) < e->expiry) {
            out_addr->s_addr = e->addr;
            pthread_mutex_unlock(&dns_cache_lock);
            return 0;
        }
        e->valid = 0;
        break;
    }
    pthread_mutex_unlock(&dns_cache_lock);
    return -1;
}

static void dns_cache_store(const char *host, struct in_addr *addr) {
    pthread_mutex_lock(&dns_cache_lock);
    uint32_t h = dns_cache_hash(host);
    dns_cache_entry_t *e = &dns_cache[h];
    strncpy(e->host, host, sizeof(e->host) - 1);
    e->host[sizeof(e->host) - 1] = '\0';
    e->addr = addr->s_addr;
    e->expiry = time(NULL) + DNS_CACHE_TTL;
    e->valid = 1;
    pthread_mutex_unlock(&dns_cache_lock);
}

static volatile int socks5_running = 0;
static int socks5_listen_fd = -1;
static gost_session_t proxy_session;
static quic_client_t *proxy_quic_client = NULL;
static uint32_t *shared_counter = NULL;
static uint32_t next_conn_id = 1;

static int tunnel_send(const uint8_t *data, size_t len, uint32_t conn_id, uint32_t *counter) {
    size_t offset = 0;
    while (offset < len) {
        size_t chunk = len - offset;
        if (chunk > MAX_PAYLOAD - 4) chunk = MAX_PAYLOAD - 4;
        gost_packet_t pkt;
        memset(&pkt, 0, sizeof(pkt));
        if (protocol_pack_data(&pkt, proxy_session.session_id, conn_id,
                              data + offset, chunk, proxy_session.expanded_key,
                              proxy_session.nonce, counter) != 0) {
            return -1;
        }
        ssize_t sent = quic_client_send(proxy_quic_client, (const uint8_t*)&pkt, sizeof(gost_packet_t));
        if (sent < 0) {
            log_debug("tunnel_send failed");
            return -1;
        }
        offset += chunk;
    }
    return 0;
}

static int tunnel_recv(uint8_t *data, size_t maxlen, int timeout_ms, uint32_t expect_conn_id, uint32_t *counter) {
    (void)maxlen;
    uint8_t buffer[SOCKS5_BUF_SIZE];
    ssize_t n = quic_client_recv(proxy_quic_client, buffer, sizeof(buffer), timeout_ms);
    if (n > 0 && n >= (ssize_t)sizeof(gost_packet_t)) {
        const gost_packet_t *pkt = (const gost_packet_t *)buffer;
        if (ntohl(pkt->magic) == GOST_PROXY_MAGIC && pkt->type == PKT_DATA) {
            uint32_t pkt_conn_id = ntohl(pkt->conn_id);
            if (pkt_conn_id != expect_conn_id) return -1;
            size_t data_len;
            if (protocol_unpack_data(pkt, data, &data_len, NULL,
                                     proxy_session.expanded_key,
                                     proxy_session.nonce, counter) == 0) {
                return (int)data_len;
            }
        }
    }
    return -1;
}

static void* proxy_data_thread(void *arg) {
    typedef struct { int fd; uint32_t conn_id; } proxy_arg_t;
    proxy_arg_t *parg = (proxy_arg_t *)arg;
    int client_fd = parg->fd;
    uint32_t my_conn_id = parg->conn_id;
    free(parg);
    uint32_t send_counter = 0;
    uint32_t recv_counter = 1;
    uint8_t buf[SOCKS5_BUF_SIZE];
    while (socks5_running) {
        struct pollfd pfd = { .fd = client_fd, .events = POLLIN };
        int ret = poll(&pfd, 1, 100);
        if (ret > 0 && (pfd.revents & POLLIN)) {
            ssize_t n = recv(client_fd, buf, sizeof(buf), 0);
            if (n <= 0) break;
            if (tunnel_send(buf, n, my_conn_id, &send_counter) != 0) break;
        }
        uint8_t resp[SOCKS5_BUF_SIZE];
        int resp_len = tunnel_recv(resp, sizeof(resp), 50, my_conn_id, &recv_counter);
        if (resp_len > 0) {
            size_t total_sent = 0;
            while (total_sent < (size_t)resp_len) {
                ssize_t s = send(client_fd, resp + total_sent, resp_len - total_sent, MSG_NOSIGNAL);
                if (s <= 0) goto close_client;
                total_sent += s;
            }
            while (socks5_running) {
                int extra_len = tunnel_recv(resp, sizeof(resp), 10, my_conn_id, &recv_counter);
                if (extra_len <= 0) break;
                size_t extra_sent = 0;
                while (extra_sent < (size_t)extra_len) {
                    ssize_t s = send(client_fd, resp + extra_sent, extra_len - extra_sent, MSG_NOSIGNAL);
                    if (s <= 0) goto close_client;
                    extra_sent += s;
                }
            }
        }
    }
close_client:
    close(client_fd);
    atomic_fetch_sub(&active_conns, 1);
    return NULL;
}

static void* socks5_client_thread(void *arg) {
    /* Backpressure: ждём если нет свободных слотов */
    int wait_count = 0;
    while (atomic_load(&active_conns) >= MAX_SIMULTANEOUS_CONNS) {
        if (wait_count++ > 100) {  /* 10 сек — таймаут */
            int *p = (int *)arg;
            int fd = *p;
            free(p);
            close(fd); log_warn("Backpressure: rejecting new client");
            return NULL;
        }
        usleep(100000);  /* 100ms */
    }
    atomic_fetch_add(&active_conns, 1);

    int client_fd = *(int *)arg;
    free(arg);
    uint8_t buf[SOCKS5_BUF_SIZE];
    ssize_t n = recv(client_fd, buf, sizeof(buf), 0);
    if (n < 2 || buf[0] != 0x05) { close(client_fd); return NULL; }
    uint8_t auth_reply[] = { 0x05, 0x00 };
    send(client_fd, auth_reply, 2, 0);
    n = recv(client_fd, buf, sizeof(buf), 0);
    if (n < 4 || buf[0] != 0x05 || buf[1] != 0x01) { close(client_fd); return NULL; }
    char target_host[256] = {0};
    uint16_t target_port = 0;
    switch (buf[3]) {
        case 0x01: {
            struct in_addr addr;
            memcpy(&addr, &buf[4], 4);
            inet_ntop(AF_INET, &addr, target_host, sizeof(target_host));
            target_port = (buf[8] << 8) | buf[9];
            break;
        }
        case 0x03: {
            uint8_t dlen = buf[4];
            memcpy(target_host, &buf[5], dlen);
            target_host[dlen] = '\0';
            target_port = (buf[5 + dlen] << 8) | buf[5 + dlen + 1];
            break;
        }
        default: {
            uint8_t err[] = { 0x05, 0x08, 0x00, 0x01, 0,0,0,0, 0,0 };
            send(client_fd, err, 10, 0);
            close(client_fd);
            return NULL;
        }
    }
    log_info("SOCKS5 CONNECT %s:%u", target_host, target_port);
    uint32_t my_conn_id = __sync_fetch_and_add(&next_conn_id, 1);
    struct in_addr target_addr;
    memset(&target_addr, 0, sizeof(target_addr));

    /* Resolve hostname */
    if (dns_cache_lookup(target_host, &target_addr) != 0) {
        struct hostent *he = gethostbyname(target_host);
        if (!he) {
            uint8_t err[] = { 0x05, 0x04, 0x00, 0x01, 0,0,0,0, 0,0 };
            send(client_fd, err, 10, 0);
            close(client_fd);
            return NULL;
        }
        target_addr = *(struct in_addr *)he->h_addr_list[0];
        dns_cache_store(target_host, &target_addr);
    }

    uint8_t connect_data[8];
    connect_data[0] = 0x01;
    connect_data[1] = 0x01;
    memcpy(&connect_data[2], &target_addr.s_addr, 4);
    connect_data[6] = (target_port >> 8) & 0xFF;
    connect_data[7] = target_port & 0xFF;
    uint32_t conn_send_counter = 0;
    if (tunnel_send(connect_data, 8, my_conn_id, &conn_send_counter) != 0) {
        uint8_t err[] = { 0x05, 0x01, 0x00, 0x01, 0,0,0,0, 0,0 };
        send(client_fd, err, 10, 0);
        close(client_fd);
        return NULL;
    }
    uint32_t conn_recv_counter = 1;
    uint8_t resp[SOCKS5_BUF_SIZE];
    int resp_len = tunnel_recv(resp, sizeof(resp), 5000, my_conn_id, &conn_recv_counter);
    if (resp_len < 2 || resp[0] != 0x02 || resp[1] != 0x00) {
        uint8_t err[] = { 0x05, 0x05, 0x00, 0x01, 0,0,0,0, 0,0 };
        send(client_fd, err, 10, 0);
        close(client_fd);
        return NULL;
    }
    uint8_t reply[] = { 0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0 };
    send(client_fd, reply, 10, 0);
    pthread_t thread;
    typedef struct { int fd; uint32_t conn_id; } proxy_arg_t;
    proxy_arg_t *parg = malloc(sizeof(proxy_arg_t));
    parg->fd = client_fd;
    parg->conn_id = my_conn_id;
    pthread_create(&thread, NULL, proxy_data_thread, parg);
    pthread_detach(thread);
    return NULL;
}

static void* socks5_server_thread(void *arg) {
    (void)arg;
    log_info("SOCKS5-прокси запущен на 127.0.0.1:%d", SOCKS5_PORT);
    while (socks5_running) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_fd = accept(socks5_listen_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (client_fd < 0) {
            if (socks5_running) log_error("SOCKS5 accept: %s", strerror(errno));
            continue;
        }
        int *fd_ptr = malloc(sizeof(int));
        *fd_ptr = client_fd;
        pthread_t thread;
        if (pthread_create(&thread, NULL, socks5_client_thread, fd_ptr) != 0) {
            log_error("SOCKS5 pthread_create: %s", strerror(errno));
            close(client_fd);
            free(fd_ptr);
        } else {
            pthread_detach(thread);
        }
    }
    return NULL;
}

int socks5_start(uint16_t port, const char *server_ip, uint16_t server_port,
                 const uint8_t *expanded_key, const uint8_t *nonce,
                 uint64_t session_id,
                 quic_client_t *quic_client,
                 uint32_t *session_counter) {
    (void)server_ip;
    (void)server_port;
    memset(&proxy_session, 0, sizeof(gost_session_t));
    proxy_session.session_id = session_id;
    proxy_session.active = 1;
    proxy_session.counter = 0;
    memcpy(proxy_session.nonce, nonce, NONCE_SIZE);
    memcpy(proxy_session.expanded_key, expanded_key, 160);
    proxy_quic_client = quic_client;
    shared_counter = session_counter;
    socks5_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socks5_listen_fd < 0) {
        perror("[SOCKS5] socket");
        return -1;
    }
    int opt = 1;
    setsockopt(socks5_listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    if (bind(socks5_listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("[SOCKS5] bind");
        close(socks5_listen_fd);
        return -1;
    }
    if (listen(socks5_listen_fd, 16) < 0) {
        perror("[SOCKS5] listen");
        close(socks5_listen_fd);
        return -1;
    }
    socks5_running = 1;
    pthread_t thread;
    if (pthread_create(&thread, NULL, socks5_server_thread, NULL) != 0) {
        perror("[SOCKS5] pthread_create");
        close(socks5_listen_fd);
        return -1;
    }
    pthread_detach(thread);
    return 0;
}

void socks5_stop(void) {
    socks5_running = 0;
    if (socks5_listen_fd >= 0) {
        close(socks5_listen_fd);
        socks5_listen_fd = -1;
    }
}
