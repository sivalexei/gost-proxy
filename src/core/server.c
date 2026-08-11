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
#include <pthread.h>
#include <time.h>
#include <poll.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <sys/random.h>

#include "quic_layer.h"
#include "kuznyechik.h"
#include "gost_common.h"
#include "protocol.h"
#include "config.h"
#include "log.h"
#include <ctype.h>

/* Поддержка IPv4 и IPv6 */
static int bind_to_addr(int fd, const char *addr, uint16_t port, int family) {
    struct sockaddr_storage sa;
    socklen_t slen = sizeof(sa);
    memset(&sa, 0, slen);

    if (family == AF_INET6 || (family == AF_UNSPEC && strchr(addr, ':'))) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&sa;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(port);
        inet_pton(AF_INET6, addr, &sin6->sin6_addr);
    } else {
        struct sockaddr_in *sin4 = (struct sockaddr_in *)&sa;
        sin4->sin_family = AF_INET;
        sin4->sin_port = htons(port);
        inet_pton(AF_INET, addr, &sin4->sin_addr);
    }
    return bind(fd, (struct sockaddr *)&sa, slen);
}

extern ssize_t tcp_write_all(int fd, const void *buf, size_t len);

#define BUFFER_SIZE 2048
#define DEFAULT_CONFIG "/etc/gost-proxy/server.json"
#define MAX_PROXY_CONNS 256

static volatile int running = 1;
static gost_session_t *sessions;
static int max_sessions;
static pthread_mutex_t sessions_lock = PTHREAD_MUTEX_INITIALIZER;
#define SESSION_HASH_SIZE 512
static int session_hash[SESSION_HASH_SIZE];
static _Atomic int free_slot_next = 0;
static uint8_t expanded_key[160];
static gost_config_t cfg;

typedef struct {
    int      tcp_fd;
    uint64_t session_id;
    uint32_t conn_id;
    struct sockaddr_in client_addr;
    socklen_t addr_len;
    int      active;
    uint32_t send_counter;
} proxy_conn_t;
static proxy_conn_t proxy_conns[MAX_PROXY_CONNS];
static pthread_mutex_t proxy_lock = PTHREAD_MUTEX_INITIALIZER;

static inline uint32_t session_hash_func(uint64_t sid) { return (uint32_t)(sid % SESSION_HASH_SIZE); }
static inline void session_hash_add(uint64_t sid, int idx) { session_hash[session_hash_func(sid)] = idx; }
static inline void session_hash_remove(uint64_t sid) { session_hash[session_hash_func(sid)] = -1; }

/* Удаление сессии по индексу — переиспользование слотов */
static void session_remove(int idx) {
    if (idx < 0 || idx >= max_sessions) return;
    uint64_t sid = sessions[idx].session_id;
    session_hash_remove(sid);
    sessions[idx].active = 0;
    sessions[idx].session_id = 0;
    memset(sessions[idx].nonce, 0, NONCE_SIZE);
}

/* Поиск свободных слотов начиная с free_slot_next, с wrap-around */
static inline void session_reset_free_slot(void) {
    int cur = atomic_load(&free_slot_next);
    for (int i = 0; i < cur; i++) {
        if (!sessions[i].active) {
            atomic_store(&free_slot_next, i);
            return;
        }
    }
}
static void signal_handler(int sig) { (void)sig; running = 0; }
static inline gost_session_t* find_session_by_id(uint64_t sid) {
    int idx = session_hash[session_hash_func(sid)];
    if (idx >= 0 && idx < max_sessions && sessions[idx].active && sessions[idx].session_id == sid) return &sessions[idx];
    return NULL;
}
static gost_session_t* find_session(uint64_t sid) { return find_session_by_id(sid); }
static inline gost_session_t* create_session(uint64_t sid) {
    for (int i = atomic_load(&free_slot_next); i < max_sessions; i++) {
        if (!sessions[i].active) {
            atomic_store(&free_slot_next, i + 1);
            sessions[i].active = 1; sessions[i].session_id = sid;
            sessions[i].counter = 0; memset(sessions[i].nonce, 0, NONCE_SIZE);
            /* Генерация случайного nonce (96 бит) для каждого соединения */
            ssize_t nr = getrandom(sessions[i].nonce, NONCE_SIZE, 0);
            if (nr < NONCE_SIZE) {
                int fd = open("/dev/urandom", O_RDONLY);
                if (fd >= 0) {
                    ssize_t rd = read(fd, sessions[i].nonce, NONCE_SIZE);
                    close(fd);
                    if (rd < NONCE_SIZE) {
                        sessions[i].active = 0;
                        return NULL;
                    }
                } else {
                    sessions[i].active = 0;
                    return NULL;
                }
            }
            memcpy(sessions[i].expanded_key, expanded_key, 160);
            session_hash_add(sid, i); return &sessions[i];
        }
    }
    return NULL;
}
static proxy_conn_t* find_proxy_conn(uint64_t sid, uint32_t cid) {
    for (int i = 0; i < MAX_PROXY_CONNS; i++)
        if (proxy_conns[i].active && proxy_conns[i].session_id == sid && proxy_conns[i].conn_id == cid) return &proxy_conns[i];
    return NULL;
}
static proxy_conn_t* create_proxy_conn(uint64_t sid) {
    for (int i = 0; i < MAX_PROXY_CONNS; i++)
        if (!proxy_conns[i].active) { proxy_conns[i].active = 1; proxy_conns[i].session_id = sid; return &proxy_conns[i]; }
    return NULL;
}
static void* tcp_to_udp_thread(void *arg) {
    proxy_conn_t *conn = (proxy_conn_t *)arg;
    uint8_t buf[BUFFER_SIZE];
    quic_server_t qs; memset(&qs, 0, sizeof(qs));
    qs.server_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (qs.server_fd < 0) { conn->active = 0; return NULL; }
    int opt = 1;
    setsockopt(qs.server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    int bs = 1024*1024;
    setsockopt(qs.server_fd, SOL_SOCKET, SO_RCVBUF, &bs, sizeof(bs));
    setsockopt(qs.server_fd, SOL_SOCKET, SO_SNDBUF, &bs, sizeof(bs));
    fcntl(qs.server_fd, F_SETFL, fcntl(qs.server_fd, F_GETFL, 0) | O_NONBLOCK);
    qs.active = 1;
    while (running && conn->active) {
        struct pollfd pfd = { .fd = conn->tcp_fd, .events = POLLIN };
        int ret = poll(&pfd, 1, 1000);
        if (ret > 0 && (pfd.revents & POLLIN)) {
            ssize_t n = read(conn->tcp_fd, buf, sizeof(buf));
            if (n <= 0) { conn->active = 0; break; }
            gost_session_t *session = find_session(conn->session_id);
            if (!session) break;
            size_t off = 0;
            while (off < (size_t)n) {
                size_t chunk = (size_t)n - off;
                if (chunk > MAX_PAYLOAD - 4) chunk = MAX_PAYLOAD - 4;
                gost_packet_t pkt;
                if (protocol_pack_data(&pkt, conn->session_id, conn->conn_id, buf + off, chunk, session->expanded_key, session->nonce, &conn->send_counter) == 0) {
                    quic_server_send(&qs, &conn->client_addr, conn->addr_len, (const uint8_t*)&pkt, sizeof(gost_packet_t));
                }
                off += chunk;
            }
        } else if (ret < 0 && errno != EINTR) { break; }
    }
    if (conn->tcp_fd >= 0) close(conn->tcp_fd);
    if (qs.server_fd >= 0) close(qs.server_fd);
    conn->active = 0; return NULL;
}
static int connect_to_target(const char *host, uint16_t port) {
    struct addrinfo hints = {0}, *result;
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    char ps[8]; snprintf(ps, sizeof(ps), "%u", port);
    if (getaddrinfo(host, ps, &hints, &result) != 0) { log_error("getaddrinfo %s:%u", host, port); return -1; }
    int fd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (fd < 0) { freeaddrinfo(result); return -1; }
    int flag = 1; setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    struct timeval tv = { .tv_sec = 5 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (connect(fd, result->ai_addr, result->ai_addrlen) < 0) {
        log_error("connect %s:%u: %s", host, port, strerror(errno));
        close(fd); freeaddrinfo(result); return -1;
    }
    freeaddrinfo(result); log_info("TCP %s:%u", host, port); return fd;
}
static void handle_data_packet(quic_server_t *qs, const struct sockaddr_in *client_addr, socklen_t addr_len,
                               const gost_packet_t *pkt, uint64_t session_id) {
    uint8_t decrypted[MAX_PAYLOAD]; size_t data_len; uint32_t pkt_conn_id = 0;
    pthread_mutex_lock(&sessions_lock);
    gost_session_t *session = find_session(session_id);
    if (!session) { pthread_mutex_unlock(&sessions_lock); return; }
    if (protocol_unpack_data(pkt, decrypted, &data_len, &pkt_conn_id, session->expanded_key, session->nonce, &session->counter) != 0) { pthread_mutex_unlock(&sessions_lock); return; }
    if (data_len < 1) { pthread_mutex_unlock(&sessions_lock); return; }
    /* Сервер трактует все DATA-пакеты как данные туннеля.
     * CONNECT-запросы передаются как данные с префиксом:
     * [0]=0x01 (CONNECT), [1]=ATYP, далее адрес и порт.
     * Это не конфликтует с проксируемым трафиком — проксируемые данные
     * приходят уже после установления соединения и не начинаются с 0x01.
     * Для надёжности: если данные начинаются с 0x01 и длина >= 8,
     * это CONNECT-запрос (формат SOCKS5 CONNECT).
     * Но мы проверяем, что это не уже установленное соединение. */
    if (pkt_conn_id == 0 && data_len >= 8 && decrypted[0] == 0x01) {
        uint8_t addr_type = decrypted[1]; char target_host[256] = {0}; uint16_t target_port = 0;
        if (addr_type == 0x01 && data_len >= 8) {
            struct in_addr addr; memcpy(&addr, &decrypted[2], 4);
            inet_ntop(AF_INET, &addr, target_host, sizeof(target_host));
            target_port = (decrypted[6] << 8) | decrypted[7];
        } else if (addr_type == 0x03 && data_len >= 3) {
            size_t dlen = decrypted[2];
            if (data_len >= 3 + dlen + 2) {
                memcpy(target_host, &decrypted[3], dlen); target_host[dlen] = '\0';
                target_port = (decrypted[3 + dlen] << 8) | decrypted[3 + dlen + 1];
            }
        }
        if (target_host[0] && target_port > 0) {
            log_info("CONNECT %s:%u (cid=%u)", target_host, target_port, pkt_conn_id);
            int tcp_fd = connect_to_target(target_host, target_port);
            if (tcp_fd < 0) {
                uint8_t err_data[] = { 0x02, 0x01 };
                gost_packet_t err_pkt; memset(&err_pkt, 0, sizeof(err_pkt));
                protocol_pack_data(&err_pkt, session_id, pkt_conn_id, err_data, 2, session->expanded_key, session->nonce, &session->counter);
                quic_server_send(qs, client_addr, addr_len, (const uint8_t*)&err_pkt, sizeof(gost_packet_t));
                pthread_mutex_unlock(&sessions_lock); return;
            }
            pthread_mutex_lock(&proxy_lock);
            proxy_conn_t *conn = create_proxy_conn(session_id);
            if (!conn) { close(tcp_fd); pthread_mutex_unlock(&proxy_lock); pthread_mutex_unlock(&sessions_lock); return; }
            conn->tcp_fd = tcp_fd; conn->session_id = session_id; conn->conn_id = pkt_conn_id;
            conn->client_addr = *client_addr; conn->addr_len = addr_len; conn->send_counter = 0;
            pthread_mutex_unlock(&proxy_lock);
            pthread_t thread; pthread_create(&thread, NULL, tcp_to_udp_thread, conn); pthread_detach(thread);
            uint8_t ok_data[] = { 0x02, 0x00 };
            gost_packet_t ok_pkt; memset(&ok_pkt, 0, sizeof(ok_pkt));
            protocol_pack_data(&ok_pkt, session_id, pkt_conn_id, ok_data, 2, session->expanded_key, session->nonce, &session->counter);
            quic_server_send(qs, client_addr, addr_len, (const uint8_t*)&ok_pkt, sizeof(gost_packet_t));
            pthread_mutex_unlock(&sessions_lock);
            return;
        }
    }
    pthread_mutex_unlock(&sessions_lock);
    /* Проверяем, есть ли уже установленное соединение */
    pthread_mutex_lock(&proxy_lock);
    proxy_conn_t *conn = find_proxy_conn(session_id, pkt_conn_id);
    pthread_mutex_unlock(&proxy_lock);
    if (conn && conn->active && conn->tcp_fd >= 0) {
        ssize_t written = tcp_write_all(conn->tcp_fd, decrypted, data_len);
        if (written < 0) conn->active = 0;
    } else if (pkt_conn_id != 0) {
        /* Пакет для неизвестного conn_id — просто игнорируем */
        log_debug("DATA: no connection for cid=%u", pkt_conn_id);
    }
}
static void handle_packet(quic_server_t *qs, const struct sockaddr_in *client_addr, socklen_t addr_len, const uint8_t *data, size_t len) {
    if (len < sizeof(gost_packet_t)) { log_debug("handle_packet: too short (%zu)", len); return; }
    const gost_packet_t *pkt = (const gost_packet_t *)data;
    uint32_t magic = ntohl(pkt->magic);
    if (magic != GOST_PROXY_MAGIC) { log_debug("handle_packet: bad magic 0x%08x", magic); return; }
    log_debug("handle_packet: type=%u, magic=0x%08x, len=%zu", pkt->type, magic, len);
    pthread_mutex_lock(&sessions_lock);
    switch (pkt->type) {
        case PKT_HANDSHAKE: {
            /* Проверка HMAC-подписи handshake (аутентификация клиента) */
            if (len < sizeof(gost_packet_t) - AUTH_TAG_SIZE + 4) {
                log_debug("HANDSHAKE: too short for auth (%zu)", len); break;
            }
            const gost_packet_t *hs_pkt = (const gost_packet_t *)data;
            uint64_t client_sid = ntohll(hs_pkt->session_id);

            /* Клиент шифрует session_id расширенным ключом и кладёт в auth_tag */
            uint8_t temp_block[16] = {0};
            memcpy(temp_block, &client_sid, 8);
            kuznyechik_encrypt_block(temp_block, expanded_key);

            /* Сравниваем первые 4 байта auth_tag с ожидаемыми */
            if (memcmp(hs_pkt->auth_tag, temp_block, 4) != 0) {
                log_warn("HANDSHAKE auth failed from %s", inet_ntoa(client_addr->sin_addr));
                break;  /* аутентификация не пройдена — отклоняем */
            }

            /* Генерация session_id из /dev/urandom вместо rand() */
            uint64_t session_id;
            ssize_t rnd_ret = getrandom(&session_id, sizeof(session_id), 0);
            if (rnd_ret < 0) {
                int fd = open("/dev/urandom", O_RDONLY);
                if (fd >= 0) {
                    ssize_t rd = read(fd, &session_id, sizeof(session_id));
                    close(fd);
                    if (rd < (ssize_t)sizeof(session_id)) break;
                } else { break; }
            }
            gost_session_t *session = create_session(session_id);
            if (!session) {
                /* Слоты кончились — сбрасываем и пробуем заново */
                session_reset_free_slot();
                session = create_session(session_id);
                if (!session) { pthread_mutex_unlock(&sessions_lock); return; }
            }
            gost_packet_t response; protocol_create_handshake(&response, session_id, session->expanded_key);
            ssize_t sent = quic_server_send(qs, client_addr, addr_len, (const uint8_t*)&response, sizeof(response));
            (void)sent;
            log_info("HANDSHAKE OK: client=%s, sid=%llu", inet_ntoa(client_addr->sin_addr), (unsigned long long)session_id);
            break;
        }
        case PKT_DATA: {
            uint64_t session_id = ntohll(pkt->session_id);
            handle_data_packet(qs, client_addr, addr_len, pkt, session_id);
            break;
        }
        case PKT_KEEPALIVE: break;
        case PKT_SIM_CHALLENGE: {
            uint64_t session_id = ntohll(pkt->session_id);
            /* Если слотов нет — сбрасываем free_slot_next и ищем заново */
            gost_session_t *session = find_session(session_id);
            if (!session) { session_reset_free_slot(); session = find_session(session_id); }
            if (!session) break;
            uint8_t answer[32] = {0};
            if (protocol_verify_cps_challenge(pkt, answer, sizeof(answer)) == 0) {
                session->cps_enabled = 1;
                memcpy(session->cps_response, answer, 32);
                gost_packet_t resp;
                memset(&resp, 0, sizeof(resp));
                resp.magic = htonl(GOST_PROXY_MAGIC);
                resp.type = PKT_SIM_CHALLENGE;
                resp.session_id = htonll(session_id);
                memcpy(resp.payload, answer, 32);
                quic_server_send(qs, client_addr, addr_len, (const uint8_t*)&resp, sizeof(resp));
                log_info("CPS challenge verified (sid=%llu)", (unsigned long long)session_id);
            }
            break;
        }
        case PKT_DISCONNECT: {
            uint64_t session_id = ntohll(pkt->session_id);
            uint32_t dc_cid = ntohl(pkt->conn_id);
            gost_session_t *session = find_session(session_id);
            if (session) {
                int idx = session_hash[session_hash_func(session_id)];
                session_remove(idx);
            }
            pthread_mutex_lock(&proxy_lock);
            proxy_conn_t *conn = find_proxy_conn(session_id, dc_cid);
            if (conn) { conn->active = 0; if (conn->tcp_fd >= 0) close(conn->tcp_fd); conn->tcp_fd = -1; }
            pthread_mutex_unlock(&proxy_lock);
            session_reset_free_slot();
            break;
        }
        default: break;
    }
    pthread_mutex_unlock(&sessions_lock);
}
static void* server_thread(void *arg) {
    quic_server_t *qs = (quic_server_t *)arg;
    uint8_t buffer[BUFFER_SIZE]; struct sockaddr_in client_addr; socklen_t addr_len;
    while (running) {
        addr_len = sizeof(client_addr);
        ssize_t recv_len = quic_server_recv(qs, buffer, BUFFER_SIZE, &client_addr, &addr_len, 1000);
        if (recv_len > 0) handle_packet(qs, &client_addr, addr_len, buffer, recv_len);
    }
    return NULL;
}
int main(int argc, char *argv[]) {
    const char *config_path = DEFAULT_CONFIG;
    if (argc > 1) config_path = argv[1];
    config_defaults(&cfg);
    if (config_load(&cfg, config_path) == 0) printf("[CONFIG] Loaded: %s\n", config_path);
    else printf("[CONFIG] Default config\n");
    log_init(cfg.log_level, cfg.log_file);
    printf("=== ГОСТ Прокси-Сервер ===\n");
    printf("Address: %s:%d\n", cfg.bind_addr, cfg.port);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    /* Проверка: ключ должен быть задан явно (env или JSON) */
    if (cfg.key[0] == '\0') {
        fprintf(stderr, "[ERROR] Ключ не задан! Используйте GOST_PROXY_KEY или поле 'key' в JSON\n");
        return 1;
    }
    uint8_t server_key[32] = {0};
    size_t key_len = strlen(cfg.key);
    for (size_t i = 0; i < key_len/2 && i < 32; i++) {
        unsigned int byte; sscanf(&cfg.key[i*2], "%2x", &byte); server_key[i] = (uint8_t)byte;
    }
    kuznyechik_set_key(server_key, expanded_key);
    max_sessions = cfg.max_sessions;
    sessions = calloc(max_sessions, sizeof(gost_session_t));
    if (!sessions) { perror("calloc"); return 1; }
    memset(session_hash, -1, sizeof(session_hash));
    atomic_store(&free_slot_next, 0);
    memset(proxy_conns, 0, sizeof(proxy_conns));
    quic_server_t qs;
    memset(&qs, 0, sizeof(qs));
    /* Поддержка IPv6: определяем family из адреса */
    int family = AF_INET;
    if (strchr(cfg.bind_addr, ':')) family = AF_INET6;
    else if (strcmp(cfg.bind_addr, "::") == 0) family = AF_INET6;

    qs.server_fd = socket(family, SOCK_DGRAM, 0);
    if (qs.server_fd < 0) { perror("socket"); return 1; }
    int opt = 1; setsockopt(qs.server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    int buf = 1024*1024;
    setsockopt(qs.server_fd, SOL_SOCKET, SO_RCVBUF, &buf, sizeof(buf));
    setsockopt(qs.server_fd, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf));
    int flags = fcntl(qs.server_fd, F_GETFL, 0);
    if (flags >= 0) fcntl(qs.server_fd, F_SETFL, flags | O_NONBLOCK);
    if (bind_to_addr(qs.server_fd, cfg.bind_addr, cfg.port, family) < 0) {
        perror("bind"); close(qs.server_fd); return 1;
    }
    printf("[SERVER] Listening on %s:%d...\n", cfg.bind_addr, cfg.port);
    log_info("Server started on %s:%d", cfg.bind_addr, cfg.port);
    qs.active = 1;
    pthread_t thread; pthread_create(&thread, NULL, server_thread, &qs);
    while (running) sleep(1);
    log_info("Server exiting...");
    /* Graceful shutdown: shutdown() пробуждает阻塞的 recvfrom */
    shutdown(qs.server_fd, SHUT_RDWR);
    qs.active = 0; close(qs.server_fd);
    /* Ждём завершения потока с таймаутом */
    for (int i = 0; i < 10 && pthread_kill(thread, 0) == 0; i++) sleep(1);
    pthread_cancel(thread); pthread_join(thread, NULL);
    /* Отключаем все сессии */
    for (int i = 0; i < max_sessions; i++) sessions[i].active = 0;
    free(sessions); log_close(); return 0;
}
