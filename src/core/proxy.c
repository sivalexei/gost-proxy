#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <time.h>
#include <netinet/tcp.h>

#include "kuznyechik.h"
#include "gost_common.h"
#include "protocol.h"
#include "config.h"
#include "log.h"

#define BUFFER_SIZE 8192
#define DEFAULT_CONFIG "/etc/gost-proxy/proxy.json"
#define SOCKS5_PORT 1080
#define MAX_PROXY_CONNS 256

static volatile int running = 1;
static uint8_t expanded_key[160];
static uint8_t nonce[NONCE_SIZE];
static uint64_t session_id = 0;
static _Atomic uint32_t server_counter = 0;
static int udp_fd = -1;
static struct sockaddr_in server_addr;
static socklen_t server_addr_len;

typedef struct {
    int      tcp_fd;
    uint32_t conn_id;
    int      active;
    int      state;
    char     target_host[256];
    uint16_t target_port;
    uint64_t bytes_sent;
    uint64_t bytes_recv;
} proxy_conn_t;

static proxy_conn_t proxy_conns[MAX_PROXY_CONNS];
static pthread_mutex_t proxy_lock = PTHREAD_MUTEX_INITIALIZER;

static void signal_handler(int sig) { (void)sig; running = 0; }

static proxy_conn_t* find_free_conn(void) {
    for (int i = 0; i < MAX_PROXY_CONNS; i++) {
        if (!proxy_conns[i].active) {
            memset(&proxy_conns[i], 0, sizeof(proxy_conn_t));
            proxy_conns[i].active = 1;
            proxy_conns[i].conn_id = (uint32_t)(i + 1);
            return &proxy_conns[i];
        }
    }
    return NULL;
}

static proxy_conn_t* find_conn_by_id(uint32_t conn_id) {
    for (int i = 0; i < MAX_PROXY_CONNS; i++) {
        if (proxy_conns[i].active && proxy_conns[i].conn_id == conn_id)
            return &proxy_conns[i];
    }
    return NULL;
}

static int send_to_server(uint32_t conn_id, const uint8_t *data, size_t data_len) {
    gost_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    if (protocol_pack_data(&pkt, session_id, conn_id, data, data_len,
                          expanded_key, nonce, &server_counter) != 0) {
        log_error("protocol_pack_data failed");
        return -1;
    }
    ssize_t sent = sendto(udp_fd, &pkt, sizeof(gost_packet_t),
                          0, (struct sockaddr *)&server_addr, server_addr_len);
    if (sent != (ssize_t)sizeof(gost_packet_t)) {
        log_error("sendto failed: %s", strerror(errno));
        return -1;
    }
    return 0;
}

static ssize_t recv_from_server(uint8_t *out, size_t out_len, uint32_t *out_conn_id) {
    uint8_t buf[BUFFER_SIZE];
    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    setsockopt(udp_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ssize_t recv_len = recvfrom(udp_fd, buf, sizeof(buf), 0, NULL, NULL);
    if (recv_len < (ssize_t)sizeof(gost_packet_t)) return -1;
    const gost_packet_t *pkt = (const gost_packet_t *)buf;
    if (ntohl(pkt->magic) != GOST_PROXY_MAGIC) return -1;
    uint8_t decrypted[MAX_PAYLOAD];
    size_t data_len;
    uint32_t pkt_conn_id;
    if (protocol_unpack_data(pkt, decrypted, &data_len, &pkt_conn_id,
                            expanded_key, nonce, &server_counter) != 0) {
        log_debug("Failed to unpack data");
        return -1;
    }
    if (data_len > out_len) data_len = out_len;
    memcpy(out, decrypted, data_len);
    *out_conn_id = pkt_conn_id;
    return (ssize_t)data_len;
}

static ssize_t tcp_write_all(int fd, const void *buf, size_t len) {
    ssize_t total = 0;
    const uint8_t *p = (const uint8_t *)buf;
    while (total < (ssize_t)len) {
        ssize_t n = write(fd, p + total, len - total);
        if (n <= 0) return (total > 0) ? total : -1;
        total += n;
    }
    return total;
}

static int parse_socks5_connect(const uint8_t *buf, size_t len,
                                char *host, uint16_t *port) {
    if (len < 4) return -1;
    uint8_t addr_type = buf[3];
    if (addr_type == 0x01) {
        if (len < 10) return -1;
        char addr_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &buf[4], addr_str, sizeof(addr_str));
        strncpy(host, addr_str, 255);
        host[255] = '\0';
        *port = (buf[8] << 8) | buf[9];
    } else if (addr_type == 0x03) {
        if (len < 7) return -1;
        size_t dlen = buf[4];
        if (len < 7 + dlen) return -1;
        memcpy(host, &buf[5], dlen);
        host[dlen] = '\0';
        *port = (buf[5 + dlen] << 8) | buf[6 + dlen];
    } else if (addr_type == 0x04) {
        if (len < 26) return -1;
        char addr_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &buf[4], addr_str, sizeof(addr_str));
        strncpy(host, addr_str, 255);
        host[255] = '\0';
        *port = (buf[20] << 8) | buf[21];
    } else {
        return -1;
    }
    return 0;
}

static void send_socks5_response(int tcp_fd, uint8_t reply_code) {
    uint8_t resp[] = { 0x05, reply_code, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    tcp_write_all(tcp_fd, resp, sizeof(resp));
}

static int send_connect(proxy_conn_t *conn) {
    uint8_t connect_data[256];
    memset(connect_data, 0, sizeof(connect_data));
    size_t dlen = 0;
    if (strchr(conn->target_host, '.')) {
        connect_data[0] = 0x01;
        inet_pton(AF_INET, conn->target_host, &connect_data[1]);
    } else {
        dlen = strlen(conn->target_host);
        connect_data[0] = 0x03;
        connect_data[1] = (uint8_t)dlen;
        memcpy(&connect_data[2], conn->target_host, dlen);
    }
    connect_data[2 + dlen + 1] = (conn->target_port >> 8) & 0xFF;
    connect_data[2 + dlen + 2] = conn->target_port & 0xFF;
    return send_to_server(conn->conn_id, connect_data, 2 + dlen + 3);
}

static void* udp_listener_thread(void *arg) {
    (void)arg;
    uint8_t buf[BUFFER_SIZE];
    log_info("UDP listener started");
    while (running) {
        struct pollfd pfd = { .fd = udp_fd, .events = POLLIN };
        int ret = poll(&pfd, 1, 1000);
        if (ret > 0 && (pfd.revents & POLLIN)) {
            uint32_t pkt_conn_id;
            ssize_t data_len = recv_from_server(buf, sizeof(buf), &pkt_conn_id);
            if (data_len <= 0) continue;
            pthread_mutex_lock(&proxy_lock);
            proxy_conn_t *conn = find_conn_by_id(pkt_conn_id);
            if (conn && conn->active && conn->state == 1) {
                ssize_t written = tcp_write_all(conn->tcp_fd, buf, data_len);
                if (written > 0) conn->bytes_recv += written;
                else { log_info("Client disconnected, conn_id=%u", pkt_conn_id); conn->active = 0; }
            }
            pthread_mutex_unlock(&proxy_lock);
        }
    }
    log_info("UDP listener stopped");
    return NULL;
}

static void* client_thread(void *arg) {
    proxy_conn_t *conn = (proxy_conn_t *)arg;
    uint8_t buf[BUFFER_SIZE];
    log_info("Client thread started, conn_id=%u, target=%s:%u",
             conn->conn_id, conn->target_host, conn->target_port);
    if (send_connect(conn) != 0) {
        log_error("Failed to send CONNECT, conn_id=%u", conn->conn_id);
        send_socks5_response(conn->tcp_fd, 0x01);
        conn->active = 0;
        return NULL;
    }
    uint8_t resp[4];
    uint32_t resp_conn_id;
    ssize_t n = recv_from_server(resp, sizeof(resp), &resp_conn_id);
    if (n < 4 || resp_conn_id != conn->conn_id) {
        log_error("No response from server, conn_id=%u", conn->conn_id);
        send_socks5_response(conn->tcp_fd, 0x01);
        conn->active = 0;
        return NULL;
    }
    uint8_t reply_code = resp[1];
    if (reply_code != 0x00) {
        log_info("Server rejected connection, conn_id=%u, code=%u", conn->conn_id, reply_code);
        send_socks5_response(conn->tcp_fd, reply_code);
        conn->active = 0;
        return NULL;
    }
    send_socks5_response(conn->tcp_fd, 0x00);
    conn->state = 1;
    log_info("Connection established, conn_id=%u, target=%s:%u",
             conn->conn_id, conn->target_host, conn->target_port);
    while (running && conn->active && conn->state == 1) {
        struct pollfd pfd = { .fd = conn->tcp_fd, .events = POLLIN };
        int ret = poll(&pfd, 1, 5000);
        if (ret > 0 && (pfd.revents & POLLIN)) {
            ssize_t n = read(conn->tcp_fd, buf, sizeof(buf));
            if (n <= 0) { log_info("Client disconnected, conn_id=%u", conn->conn_id); conn->active = 0; break; }
            if (send_to_server(conn->conn_id, buf, n) != 0) {
                log_error("Failed to send to server, conn_id=%u", conn->conn_id);
                conn->active = 0; break;
            }
            conn->bytes_sent += n;
        }
    }
    if (conn->tcp_fd >= 0) { shutdown(conn->tcp_fd, SHUT_WR); close(conn->tcp_fd); }
    conn->active = 0;
    log_info("Client thread closed, conn_id=%u, sent=%lu, recv=%lu",
             conn->conn_id, conn->bytes_sent, conn->bytes_recv);
    return NULL;
}

int main(int argc, char *argv[]) {
    const char *config_path = DEFAULT_CONFIG;
    if (argc > 1) config_path = argv[1];

    gost_config_t cfg;
    config_defaults(&cfg);
    if (config_load(&cfg, config_path) == 0)
        log_info("Config loaded: %s", config_path);
    else
        log_info("Using default config");

    log_init(cfg.log_level, cfg.log_file);

    printf("=== GOST Proxy (Client Side) ===\n");
    printf("SOCKS5: 127.0.0.1:%d\n", SOCKS5_PORT);
    printf("UDP Tunnel: %s:%d\n", cfg.server_ip, cfg.server_port);
    fflush(stdout);

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    uint8_t key[32] = {0};
    for (int i = 0; i < 32 && cfg.key[i*2] && cfg.key[i*2+1]; i++) {
        unsigned int byte;
        sscanf(&cfg.key[i*2], "%2x", &byte);
        key[i] = (uint8_t)byte;
    }
    kuznyechik_set_key(key, expanded_key);

    udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_fd < 0) { perror("socket"); return 1; }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(cfg.server_port);
    if (inet_pton(AF_INET, cfg.server_ip, &server_addr.sin_addr) <= 0) {
        printf("Invalid server IP\n"); return 1;
    }
    server_addr_len = sizeof(server_addr);

    log_info("Sending handshake to %s:%d", cfg.server_ip, cfg.server_port);
    gost_packet_t handshake;
    memset(&handshake, 0, sizeof(handshake));
    handshake.magic = htonl(GOST_PROXY_MAGIC);
    handshake.type = PKT_HANDSHAKE;
    ssize_t sent = sendto(udp_fd, &handshake, sizeof(handshake), 0,
                          (struct sockaddr *)&server_addr, server_addr_len);
    if (sent < 0) { perror("sendto handshake"); return 1; }

    uint8_t handshake_resp[BUFFER_SIZE];
    uint32_t h_conn_id = 0;
    ssize_t hlen = recv_from_server(handshake_resp, sizeof(handshake_resp), &h_conn_id);
    if (hlen < 0) { log_error("No handshake response"); return 1; }

    const gost_packet_t *h_pkt = (const gost_packet_t *)handshake_resp;
    if (ntohl(h_pkt->magic) != GOST_PROXY_MAGIC) { log_error("Bad handshake magic"); return 1; }
    if (h_pkt->type != PKT_HANDSHAKE) { log_error("Bad handshake type: %u", h_pkt->type); return 1; }

    session_id = ntohll(h_pkt->session_id);
    server_counter = 0;
    log_info("Handshake OK: session_id=%lu, server_counter=%u",
             session_id, server_counter);

    /* TCP listener для SOCKS5 */
    int tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_fd < 0) { perror("socket tcp"); return 1; }
    int opt = 1;
    setsockopt(tcp_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in local_addr = {
        .sin_family = AF_INET, .sin_port = htons(SOCKS5_PORT),
        .sin_addr.s_addr = inet_addr("127.0.0.1")
    };
    if (bind(tcp_fd, (struct sockaddr *)&local_addr, sizeof(local_addr)) < 0) {
        perror("bind"); return 1;
    }
    if (listen(tcp_fd, 128) < 0) { perror("listen"); return 1; }
    log_info("SOCKS5 listener on 127.0.0.1:%d", SOCKS5_PORT);

    pthread_t udp_tid;
    if (pthread_create(&udp_tid, NULL, udp_listener_thread, NULL) != 0) {
        perror("pthread_create udp"); return 1;
    }

    while (running) {
        struct pollfd pfd = { .fd = tcp_fd, .events = POLLIN };
        int ret = poll(&pfd, 1, 1000);
        if (ret > 0 && (pfd.revents & POLLIN)) {
            struct sockaddr_in client_addr;
            socklen_t client_addr_len = sizeof(client_addr);
            int client_fd = accept(tcp_fd, (struct sockaddr *)&client_addr, &client_addr_len);
            if (client_fd < 0) continue;
            log_info("New client connection from %s",
                     inet_ntoa(client_addr.sin_addr));

            /* Прочитать версию SOCKS5 и методы */
            uint8_t req[256];
            struct timeval tv = { .tv_sec = 3, .tv_usec = 0 };
            setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            ssize_t n = read(client_fd, req, sizeof(req));
            if (n < 2 || req[0] != 0x05) { close(client_fd); continue; }

            uint8_t resp_ver[] = { 0x05, req[1] };
            write(client_fd, resp_ver, 2);
            if (req[1] != 0x00) { close(client_fd); continue; }

            /* Прочитать CONNECT */
            ssize_t method_len = 0;
            if (n > 2) method_len = n - 2;
            if (method_len > 0) {
                ssize_t m = read(client_fd, req + 2, (size_t)(n - 2));
                if (m > 0) method_len += m;
            } else {
                n = read(client_fd, req + 2, sizeof(req) - 2);
                if (n < 0) { close(client_fd); continue; }
                method_len = n;
            }

            char host[256];
            uint16_t port;
            if (parse_socks5_connect(req, (size_t)method_len, host, &port) != 0) {
                log_info("Invalid CONNECT request");
                send_socks5_response(client_fd, 0x01);
                close(client_fd);
                continue;
            }

            proxy_conn_t *conn = find_free_conn();
            if (!conn) { send_socks5_response(client_fd, 0x06); close(client_fd); continue; }
            conn->tcp_fd = client_fd;
            strncpy(conn->target_host, host, 255);
            conn->target_port = port;

            pthread_t tid;
            if (pthread_create(&tid, NULL, client_thread, conn) != 0) {
                conn->active = 0; close(client_fd);
                log_error("pthread_create failed");
            } else {
                pthread_detach(tid);
            }
        }
    }

    log_info("Shutting down...");
    if (udp_fd >= 0) close(udp_fd);
    if (tcp_fd >= 0) close(tcp_fd);
    config_free(&cfg);
    return 0;
}
