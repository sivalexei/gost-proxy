#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/select.h>
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
#include "dns_cache.h"
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
#define DEFAULT_LOG_FILE "/tmp/gost-proxy/server.log"
#define MAX_PROXY_CONNS 256
#define RATE_BURST_DEFAULT 20    /* макс. пакетов в burst */
#define RATE_WINDOW_DEFAULT 60   /* окно очистки записей в секундах */

/* Глобальный указатель на UDP-сокет сервера (для reuse в tcp_to_udp_thread) */
static quic_server_t qs_global_obj;
static quic_server_t *qs_global = &qs_global_obj;

static volatile int running = 1;
static gost_session_t *sessions;
static int max_sessions;
static pthread_mutex_t sessions_lock = PTHREAD_MUTEX_INITIALIZER;
#define SESSION_HASH_SIZE 512
static int session_hash[SESSION_HASH_SIZE];
static _Atomic int free_slot_next = 0;
static uint8_t expanded_key[160];
static gost_config_t cfg;

/* Per-IP session limit: хеш IP -> счётчик активных сессий */
#define IP_HASH_SIZE 256
static int ip_session_count[IP_HASH_SIZE];
static pthread_mutex_t ip_count_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    int      tcp_fd;
    uint64_t session_id;
    uint32_t conn_id;
    struct sockaddr_in client_addr;
    socklen_t addr_len;
    int      active;
    uint32_t send_counter;
    int      connect_fd;  /* fd для async connect (отдельно от tcp_fd) */
} proxy_conn_t;
static proxy_conn_t proxy_conns[MAX_PROXY_CONNS];
static pthread_mutex_t proxy_lock = PTHREAD_MUTEX_INITIALIZER;

static inline uint32_t session_hash_func(uint64_t sid) { return (uint32_t)(sid % SESSION_HASH_SIZE); }

static inline void session_hash_add(uint64_t sid, int idx) {
    uint32_t h = session_hash_func(sid);
    sessions[idx].next_slot = session_hash[h];
    session_hash[h] = idx;
}

static inline void session_hash_remove(uint64_t sid, int idx) {
    uint32_t h = session_hash_func(sid);
    int prev = -1;
    for (int cur = session_hash[h]; cur != -1; cur = sessions[cur].next_slot) {
        if (cur == idx) {
            if (prev == -1) session_hash[h] = sessions[idx].next_slot;
            else sessions[prev].next_slot = sessions[idx].next_slot;
            return;
        }
        prev = cur;
    }
}

/* Per-IP session tracking */
static inline uint32_t ip_hash_func(const struct sockaddr_in *addr) {
    return (uint32_t)(addr->sin_addr.s_addr % IP_HASH_SIZE);
}
static inline void ip_count_inc(const struct sockaddr_in *addr) {
    int h = ip_hash_func(addr);
    pthread_mutex_lock(&ip_count_lock); ip_session_count[h]++; pthread_mutex_unlock(&ip_count_lock);
}
static inline void ip_count_dec(const struct sockaddr_in *addr) {
    int h = ip_hash_func(addr);
    pthread_mutex_lock(&ip_count_lock); if(ip_session_count[h]>0) ip_session_count[h]--; pthread_mutex_unlock(&ip_count_lock);
}
static inline int ip_count_get(const struct sockaddr_in *addr) {
    int h = ip_hash_func(addr), c;
    pthread_mutex_lock(&ip_count_lock); c = ip_session_count[h]; pthread_mutex_unlock(&ip_count_lock);
    return c;
}

/* Удаление сессии по индексу */
static void session_remove(int idx) {
    if (idx < 0 || idx >= max_sessions) return;
    uint64_t sid = sessions[idx].session_id;
    if (sid != 0) {
        session_hash_remove(sid, idx);
        /* Помечаем все proxy_conns для этой session — prevent: use-after-free */
        pthread_mutex_lock(&proxy_lock);
        for (int i = 0; i < MAX_PROXY_CONNS; i++) {
            if (proxy_conns[i].active && proxy_conns[i].session_id == sid) {
                if (proxy_conns[i].tcp_fd >= 0) {
                    log_debug("Expire: close tcp_fd=%d for expired session %llu",
                        proxy_conns[i].tcp_fd, (unsigned long long)sid);
                    close(proxy_conns[i].tcp_fd);
                    proxy_conns[i].tcp_fd = -1;
                }
                proxy_conns[i].active = 0;
            }
        }
        pthread_mutex_unlock(&proxy_lock);
    }
    sessions[idx].active = 0;
    sessions[idx].session_id = 0;
    sessions[idx].next_slot = -1;
    memset(sessions[idx].nonce, 0, NONCE_SIZE);
}

/* Поиск свободных слотов начиная с free_slot_next, с wrap-around */
static inline void session_reset_free_slot(void) {
    for (int i = 0; i < max_sessions; i++) {
        if (!sessions[i].active) {
            atomic_store(&free_slot_next, i);
            return;
        }
    }
    atomic_store(&free_slot_next, 0);
}

/* Проверка и очистка старых сессий */
static void expire_sessions(void) {
    time_t now = time(NULL);
    for (int i = 0; i < max_sessions; i++) {
        if (sessions[i].active &&
            sessions[i].last_activity > 0 &&
            now - sessions[i].last_activity > cfg.session_timeout) {
            log_debug("Expire session %llu", (unsigned long long)sessions[i].session_id);
            ip_count_dec(&sessions[i].client_addr);
            session_remove(i);
        }
    }
    session_reset_free_slot();
}

/* Forward declarations */
static void expire_rate_entries(void);

/* Token bucket rate limiter per IP */
typedef struct {
    struct sockaddr_in addr;
    double tokens;          /* текущие токены */
    double max_tokens;      /* размер бакета (burst) */
    double refill_rate;     /* токенов в секунду */
    double last_refill;     /* последнее время пополнения */
    int active;
} rate_bucket_t;
static rate_bucket_t rate_buckets[MAX_PROXY_CONNS];

/* Получить текущее время в секундах (миллисекундная точность) */
static double get_time_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

/* Добавить токены в бакет (refill) */
static void refill_bucket(rate_bucket_t *b, double now) {
    if (b->refill_rate <= 0) return;
    double elapsed = now - b->last_refill;
    if (elapsed > 0) {
        b->tokens = b->max_tokens < b->tokens + elapsed * b->refill_rate
                    ? b->max_tokens
                    : b->tokens + elapsed * b->refill_rate;
        b->last_refill = now;
    }
}

/* Проверка rate limit: возвращает 0 если разрешено, -1 если превышен лимит */
static int check_rate_limit(const struct sockaddr_in *addr) {
    double now = get_time_sec();
    /* Ищем запись для этого IP */
    for (int i = 0; i < MAX_PROXY_CONNS; i++) {
        if (rate_buckets[i].addr.sin_addr.s_addr == addr->sin_addr.s_addr) {
            /* Нашли — пополняем токены */
            refill_bucket(&rate_buckets[i], now);
            if (rate_buckets[i].tokens >= 1.0) {
                rate_buckets[i].tokens -= 1.0;
                return 0; /* разрешаем */
            }
            log_warn("Rate limit exceeded: %s (%.1f tokens remaining)",
                     inet_ntoa(addr->sin_addr), rate_buckets[i].tokens);
            return -1; /* отклоняем */
        }
    }
    /* Не нашли — создаём новую запись */
    int burst = cfg.rate_burst > 0 ? cfg.rate_burst : RATE_BURST_DEFAULT;
    double rate = cfg.rate_limit > 0 ? cfg.rate_limit : 10.0;
    /* Ищем свободную запись */
    for (int i = 0; i < MAX_PROXY_CONNS; i++) {
        if (!rate_buckets[i].active) {
            rate_buckets[i].addr = *addr;
            rate_buckets[i].active = 1;
            rate_buckets[i].max_tokens = (double)burst;
            rate_buckets[i].tokens = (double)(burst - 1); /* первый пакет уже использован */
            rate_buckets[i].refill_rate = rate;
            rate_buckets[i].last_refill = now;
            return 0;
        }
    }
    /* Все заняты — чистим старые */
    expire_rate_entries();
    for (int i = 0; i < MAX_PROXY_CONNS; i++) {
        if (!rate_buckets[i].active) {
            rate_buckets[i].addr = *addr;
            rate_buckets[i].active = 1;
            rate_buckets[i].max_tokens = (double)burst;
            rate_buckets[i].tokens = (double)(burst - 1);
            rate_buckets[i].refill_rate = rate;
            rate_buckets[i].last_refill = now;
            return 0;
        }
    }
    log_warn("Rate limit: no free bucket slots for %s", inet_ntoa(addr->sin_addr));
    return -1;
}

/* Очистка старых записей */
static void expire_rate_entries(void) {
    double now = get_time_sec();
    for (int i = 0; i < MAX_PROXY_CONNS; i++) {
        if (rate_buckets[i].active &&
            now - rate_buckets[i].last_refill > RATE_WINDOW_DEFAULT) {
            memset(&rate_buckets[i], 0, sizeof(rate_bucket_t));
        }
    }
}
static void signal_handler(int sig) {
    (void)sig;
    running = 0;
    if (sig == SIGUSR1) {
        /* Пробуждение epoll_wait — закрываем серверный FD */
        return;
    }
    /* Пробуждаем epoll_wait через SIGUSR1, но только после запуска потока */
    if (qs_global) {
        qs_global->active = 0;  /* устанавливаем active ПЕРЕД отправкой SIGUSR1 */
        fprintf(stderr, "DEBUG: qs_global->active=0, sending SIGUSR1\n");
        signal(SIGUSR1, signal_handler);
        kill(getpid(), SIGUSR1);
    }
}

/* Поиск сессии с цепочками */
static inline gost_session_t* find_session_by_id(uint64_t sid) {
    uint32_t h = session_hash_func(sid);
    for (int idx = session_hash[h]; idx != -1; idx = sessions[idx].next_slot) {
        if (idx >= 0 && idx < max_sessions && sessions[idx].active && sessions[idx].session_id == sid)
            return &sessions[idx];
    }
    return NULL;
}
static gost_session_t* find_session(uint64_t sid) { return find_session_by_id(sid); }
static inline gost_session_t* create_session(uint64_t sid) {
    for (int i = atomic_load(&free_slot_next); i < max_sessions; i++) {
        if (!sessions[i].active) {
            atomic_store(&free_slot_next, i + 1);
            sessions[i].active = 1; sessions[i].session_id = sid;
            sessions[i].counter = 0;
            memset(sessions[i].nonce, 0, NONCE_SIZE);
            sessions[i].last_activity = time(NULL);
            /* Случайный nonce 12 байт (getrandom) — уникальный для каждой сессии */
            {
                ssize_t nr = getrandom(sessions[i].nonce, NONCE_SIZE, 0);
                if (nr < NONCE_SIZE) {
                    int fd = open("/dev/urandom", O_RDONLY);
                    if (fd >= 0) { ssize_t r = read(fd, sessions[i].nonce, NONCE_SIZE); (void)r; close(fd); }
                }
            }
            memcpy(sessions[i].expanded_key, expanded_key, 160);
            /* Остальные 8 байт = 0 */
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
    while (running && conn->active) {
        struct pollfd pfd = { .fd = conn->tcp_fd, .events = POLLIN };
        int ret = poll(&pfd, 1, 1000);
        log_info("Server: tcp_to_udp poll returned %d", ret);
        if (ret > 0 && (pfd.revents & POLLIN)) {
            ssize_t n = read(conn->tcp_fd, buf, sizeof(buf));
            if (n <= 0) { conn->active = 0; break; }
            gost_session_t *session = find_session(conn->session_id);
            if (!session || !conn->active) break;
            /* Prevent: use-after-free — проверяем fd перед записью */
            if (conn->tcp_fd < 0 || !conn->active) break;
            size_t off = 0;
            while (off < (size_t)n) {
                size_t chunk = (size_t)n - off;
                if (chunk > MAX_PAYLOAD - 4) chunk = MAX_PAYLOAD - 4;
                gost_packet_t pkt;
                if (protocol_pack_data(&pkt, conn->session_id, conn->conn_id, buf + off, chunk, session->expanded_key, session->nonce, &conn->send_counter, 1) == 0) {
                    /* Отправляем через тот же UDP-сокет сервера (port reuse) */
                    if (conn->active) quic_server_send(qs_global, &conn->client_addr, conn->addr_len, (const uint8_t*)&pkt, sizeof(gost_packet_t));
                }
                off += chunk;
            }
        } else if (ret < 0 && errno != EINTR) { break; }
    }
    if (conn->tcp_fd >= 0) close(conn->tcp_fd);
    conn->active = 0; return NULL;
}
/* Синхронный connect для CONNECT-запросов (клиент ждёт ответ <=5с) */
static int connect_to_target(const char *host, uint16_t port) {
    dns_af_t af;
    union { struct sockaddr_in in4; struct sockaddr_in6 in6; } addr;
    if (dns_cache_lookup(host, &af, &addr) != 0) {
        log_error("DNS lookup failed %s:%u", host, port); return -1;
    }
    int fd = socket(af==DNS_AF_INET ? AF_INET : AF_INET6, SOCK_STREAM, 0);
    if (fd < 0) { log_error("socket: %s", strerror(errno)); return -1; }
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    int flag = 1; setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    struct timeval tv = { .tv_sec = 5 };
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    socklen_t addrlen = af==DNS_AF_INET ? sizeof(addr.in4) : sizeof(addr.in6);
    if (connect(fd, (struct sockaddr *)&addr, addrlen) < 0) {
        log_error("connect %s:%u: %s", host, port, strerror(errno));
        close(fd); return -1;
    }
    log_info("TCP %s:%u", host, port); return fd;
}

static void handle_data_packet(quic_server_t *qs, const struct sockaddr_in *client_addr, socklen_t addr_len,
                               const gost_packet_t *pkt, uint64_t session_id) {
    uint8_t decrypted[MAX_PAYLOAD]; size_t data_len = 0; uint32_t pkt_conn_id = 0;
    /* hex-dump first 20 payload bytes */
    log_info("RECV_PAYLOAD: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
            pkt->payload[0], pkt->payload[1], pkt->payload[2], pkt->payload[3],
            pkt->payload[4], pkt->payload[5], pkt->payload[6], pkt->payload[7],
            pkt->payload[8], pkt->payload[9], pkt->payload[10], pkt->payload[11],
            pkt->payload[12], pkt->payload[13], pkt->payload[14], pkt->payload[15],
            pkt->payload[16], pkt->payload[17], pkt->payload[18], pkt->payload[19]);
    /* mutex уже захвачен в handle_packet */
    gost_session_t *session = find_session(session_id);
    if (!session) { log_warn("handle_data_packet: session not found, sid=%llu", (unsigned long long)session_id); return; }
    session->last_activity = time(NULL);
    int up = protocol_unpack_data(pkt, decrypted, &data_len, &pkt_conn_id, session->expanded_key,
                             session->nonce, &session->counter, 0);
    if (up != 0) { log_debug("handle_data_packet: unpack failed, sid=%llu cid=%u", (unsigned long long)session_id, pkt_conn_id); return; }
    if (data_len < 1) { return; }
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
            /* Синхронный connect: клиент ждёт OK в течение 5с */
            int tcp_fd = connect_to_target(target_host, target_port);
            if (tcp_fd < 0) {
                uint8_t err_data[] = { 0x02, 0x01 };
                gost_packet_t err_pkt; memset(&err_pkt, 0, sizeof(err_pkt));
                protocol_pack_data(&err_pkt, session_id, pkt_conn_id, err_data, 2, session->expanded_key, session->nonce, &session->counter, 1);
                quic_server_send(qs, client_addr, addr_len, (const uint8_t*)&err_pkt, sizeof(gost_packet_t));
                return;
            }
            pthread_mutex_lock(&proxy_lock);
            proxy_conn_t *conn = create_proxy_conn(session_id);
            if (!conn) { close(tcp_fd); pthread_mutex_unlock(&proxy_lock); return; }
            conn->tcp_fd = tcp_fd; conn->session_id = session_id; conn->conn_id = pkt_conn_id;
            conn->client_addr = *client_addr; conn->addr_len = addr_len;
            conn->send_counter = 0; conn->connect_fd = -1;
            pthread_mutex_unlock(&proxy_lock);
            /* Запускаем tcp_to_udp_thread и шлём OK */
            pthread_t wthread; pthread_create(&wthread, NULL, tcp_to_udp_thread, conn); pthread_detach(wthread);
            uint8_t ok_data[] = { 0x02, 0x00 };
            gost_packet_t ok_pkt; memset(&ok_pkt, 0, sizeof(ok_pkt));
            protocol_pack_data(&ok_pkt, session_id, pkt_conn_id, ok_data, 2, session->expanded_key, session->nonce, &session->counter, 1);
            quic_server_send(qs, client_addr, addr_len, (const uint8_t*)&ok_pkt, sizeof(gost_packet_t));
            log_info("CONNECT OK cid=%u fd=%d", pkt_conn_id, tcp_fd);
            return;
        }
    }
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
            /* Rate limiting: токеновый бакет per IP */
            expire_rate_entries();
            if (check_rate_limit(client_addr) != 0) { break; }
            /* Извлекаем client_nonce из payload и аутентифицируем клиента */
            const gost_packet_t *hs_pkt = (const gost_packet_t *)data;

            uint8_t client_nonce[8], server_nonce[8] = {0}, expected_auth[AUTH_TAG_SIZE];
            if (hs_pkt->payload[0] != 1) {  /* маркер наличия nonce */
                log_debug("HANDSHAKE: missing client_nonce"); break;
            }
            memcpy(client_nonce, hs_pkt->payload + 1, 8);

            /* Проверка аутентификации клиента: CMAC(PSK, client_nonce || {0..0}) */
            /* server_nonce ещё не сгенерирован — используем 0, как клиент */
            kuznyechik_compute_auth(expanded_key, client_nonce, server_nonce, expected_auth);
            if (memcmp(hs_pkt->auth_tag, expected_auth, AUTH_TAG_SIZE) != 0) {
                log_warn("HANDSHAKE client auth failed (CMAC mismatch) from %s", inet_ntoa(client_addr->sin_addr));
                break;
            }

            /* Генерируем server_nonce из /dev/urandom */
            ssize_t rnd_ret = getrandom(server_nonce, sizeof(server_nonce), 0);
            if (rnd_ret < 0) {
                int fd = open("/dev/urandom", O_RDONLY);
                if (fd >= 0) {
                    ssize_t rret = read(fd, server_nonce, sizeof(server_nonce)); (void)rret;
                    close(fd);
                } else { break; }
            }

            /* Создаём сессию: server-gенерируемый session_id
             * prevent: client-chosen session_id allows session hijacking */
            uint64_t session_id;
            ssize_t sid_ret = getrandom(&session_id, sizeof(session_id), 0);
            if (sid_ret < 0) {
                int fd = open("/dev/urandom", O_RDONLY);
                if (fd >= 0) {
                    ssize_t rd = read(fd, &session_id, sizeof(session_id)); (void)rd;
                    close(fd);
                }
            }
            expire_sessions();
            /* P4-12: per-IP session limit — защита от одного IP */
            if (cfg.max_sessions_per_ip > 0 && ip_count_get(client_addr) >= cfg.max_sessions_per_ip) {
                log_warn("HANDSHAKE: per-IP limit reached (%d) from %s", cfg.max_sessions_per_ip, inet_ntoa(client_addr->sin_addr));
                pthread_mutex_unlock(&sessions_lock); return;
            }
            gost_session_t *session = create_session(session_id);
            if (!session) {
                expire_sessions();
                session = create_session(session_id);
                if (!session) { pthread_mutex_unlock(&sessions_lock); return; }
            }
            session->client_addr = *client_addr;
            session->client_addr_len = addr_len;
            ip_count_inc(client_addr);

            /* Отправляем handshake_ack с session_nonce и auth_tag */
            gost_packet_t response;
            protocol_create_handshake(&response, session_id, session->expanded_key,
                                       client_nonce, server_nonce, session->nonce);
            ssize_t sent = quic_server_send(qs, client_addr, addr_len, (const uint8_t*)&response, sizeof(response));
            (void)sent;
            log_info("HANDSHAKE OK: client=%s, sid=%llu", inet_ntoa(client_addr->sin_addr), (unsigned long long)session_id);
            break;
        }
        case PKT_DATA: {
            /* Rate limiting для данных per IP */
            expire_rate_entries();
            if (check_rate_limit(client_addr) != 0) {
                log_debug("PKT_DATA rate limited, sid=%llu", ntohll(pkt->session_id));
                break;
            }
            uint64_t session_id = ntohll(pkt->session_id);
            handle_data_packet(qs, client_addr, addr_len, pkt, session_id);
            break;
        }
        case PKT_KEEPALIVE: {
            uint64_t ka_sid = ntohll(pkt->session_id);
            gost_session_t *ka_ssn = find_session(ka_sid);
            if (ka_ssn) ka_ssn->last_activity = time(NULL);
            expire_sessions();
            break;
        }
        case PKT_SIM_CHALLENGE: {
            expire_sessions();
            uint64_t session_id = ntohll(pkt->session_id);
            gost_session_t *session = find_session(session_id);
            if (!session) { session_reset_free_slot(); session = find_session(session_id); }
            if (!session) { log_warn("CHALLENGE: session not found for sid=%llu", (unsigned long long)session_id); break; }
            /* Вычисляем answer из expanded_key сессии (P4-10: CPS не на фиксированном ключе) */
            uint8_t answer[32];
            protocol_compute_cps_answer(session_id, session->expanded_key, answer);
            /* Проверяем: client's answer должен совпадать с challenge
             * prevent: answer = CMAC(session_id, expanded_key) — только владелец PSK вычислит правильно */
            int verify_ret = (memcmp(pkt->payload, answer, 32) == 0) ? 0 : -1;
            log_debug("CHALLENGE: verify=%d for sid=%llu", verify_ret, (unsigned long long)session_id);
            if (verify_ret == 0) {
                session->cps_enabled = 1;
                memcpy(session->cps_response, answer, 32);
                gost_packet_t resp;
                memset(&resp, 0, sizeof(resp));
                resp.magic = htonl(GOST_PROXY_MAGIC);
                resp.type = PKT_SIM_CHALLENGE;
                resp.session_id = session_id;
                memcpy(resp.payload, answer, 32);
                memcpy(resp.payload+32, answer, 32);  /* challenge=answer для ответа */
                quic_server_send(qs, client_addr, addr_len, (const uint8_t*)&resp, sizeof(resp));
                log_info("CPS challenge verified (sid=%llu)", (unsigned long long)session_id);
            }
            break;
        }
        case PKT_DISCONNECT: {
            uint64_t session_id = ntohll(pkt->session_id);
            uint32_t dc_cid = ntohl(pkt->conn_id);
            gost_session_t *session = find_session(session_id);
            /* Аутентификация DISCONNECT: проверяем auth_tag через EK */
            uint64_t verify_sid = session_id;
            uint8_t expected_auth[AUTH_TAG_SIZE];
            compute_disconnect_auth(verify_sid, dc_cid, session ? session->expanded_key : NULL, expected_auth);
            if (session && memcmp(pkt->auth_tag, expected_auth, AUTH_TAG_SIZE) != 0) {
                log_warn("DISCONNECT: auth FAIL for sid=%llu", (unsigned long long)session_id);
                break;  /* Отказ — неправильный auth_tag */
            }
            if (session) {
                int idx = session_hash[session_hash_func(session_id)];
                session_remove(idx);
            }
            pthread_mutex_lock(&proxy_lock);
            proxy_conn_t *conn = find_proxy_conn(session_id, dc_cid);
            if (conn) {
                conn->active = 0;
                if (conn->tcp_fd >= 0) close(conn->tcp_fd);
                conn->tcp_fd = -1;
            }
            pthread_mutex_unlock(&proxy_lock);
            /* Подождём tcp_to_udp_thread (prevent: use-after-free) */
            usleep(50000);  /* 50ms */
            session_reset_free_slot();
            break;
        }
        default: break;
    }
    pthread_mutex_unlock(&sessions_lock);
}
/* Отправка KEEPALIVE всем активным сессиям */
/* Копия активных сессий для отправки без блокировки */
typedef struct { uint64_t session_id; struct sockaddr_in addr; socklen_t addr_len; } session_addr_t;
static void send_keepalive_to_sessions(quic_server_t *qs, session_addr_t *saddrs, int *count) {
    *count = 0;
    pthread_mutex_lock(&sessions_lock);
    for (int i = 0; i < max_sessions; i++) {
        if (sessions[i].active && sessions[i].session_id) {
            saddrs[*count].session_id = sessions[i].session_id;
            saddrs[*count].addr = sessions[i].client_addr;
            saddrs[*count].addr_len = sessions[i].client_addr_len;
            (*count)++;
        }
    }
    pthread_mutex_unlock(&sessions_lock);
    /* Отправка вне блокировки — send может блокировать */
    for (int j = 0; j < *count; j++) {
        gost_packet_t ka;
        memset(&ka, 0, sizeof(ka));
        ka.magic = htonl(GOST_PROXY_MAGIC);
        ka.type = PKT_KEEPALIVE;
        ka.session_id = saddrs[j].session_id;
        ssize_t sent = quic_server_send(qs, &saddrs[j].addr, saddrs[j].addr_len,
                                        (const uint8_t*)&ka, sizeof(ka));
        if (sent < 0) log_debug("KEEPALIVE send failed: %s", strerror(errno));
    }
}

static void* server_thread(void *arg) {
    quic_server_t *qs = (quic_server_t *)arg;
    uint8_t buffer[BUFFER_SIZE]; struct sockaddr_in client_addr; socklen_t addr_len;
    session_addr_t saddrs[MAX_PROXY_CONNS];
    time_t last_keepalive = 0;
    while (qs->active && running) {
        addr_len = sizeof(client_addr);
        ssize_t recv_len = quic_server_recv(qs, buffer, BUFFER_SIZE, &client_addr, &addr_len, 100);
        log_info("Server: recv returned %zd, active=%d, running=%d", recv_len, qs->active, running);
        if (recv_len > 0) {
            handle_packet(qs, &client_addr, addr_len, buffer, recv_len);
        } else if (recv_len == QUIC_ERROR) {
            log_info("Server: recv failed, shutting down");
            break;  /* shutdown signal */
        }
        time_t now = time(NULL);
        if (now - last_keepalive >= 30) {  /* каждые 30 сек */
            int count;
            send_keepalive_to_sessions(qs, saddrs, &count);
            if (count > 0) log_debug("KEEPALIVE sent to %d sessions", count);
            last_keepalive = now;
            expire_sessions();
            dns_cache_expire();  /* чистим истёкшие DNS-записи */
        }
    }
    log_info("Server thread: exiting, qs->active=%d, running=%d", qs->active, running);
    return NULL;
}
int main(int argc, char *argv[]) {
    const char *config_path = DEFAULT_CONFIG;
    if (argc > 1) config_path = argv[1];
    config_defaults(&cfg);
    if (config_load(&cfg, config_path) == 0) printf("[CONFIG] Loaded: %s\n", config_path);
    else printf("[CONFIG] Default config\n");
    /* Лог по умолчанию в /tmp/gost-proxy/server.log */
    if (cfg.log_file[0] == '\0' || strcmp(cfg.log_file, "/var/log/gost-proxy/server.log") == 0) {
        strncpy(cfg.log_file, DEFAULT_LOG_FILE, sizeof(cfg.log_file));
    }
    log_init(cfg.log_level, cfg.log_file);
    protocol_prng_init();
    dns_cache_init();
    printf("=== ГОСТ Прокси-Сервер ===\n");
    printf("Address: %s:%d\n", cfg.bind_addr, cfg.port);
    signal(SIGPIPE, SIG_IGN);
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;  /* SA_RESTART не ставим — select прерывается сигналом */
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    /* Проверка: ключ должен быть задан явно (env или JSON) */
    if (cfg.key[0] == '\0') {
        fprintf(stderr, "[ERROR] Ключ не задан! Используйте GOST_PROXY_KEY или поле 'key' в JSON\n");
        return 1;
    }
    /* Валидация hex-ключа: ровно 64 символа [0-9a-fA-F] */
    size_t key_len = strlen(cfg.key);
    if (key_len != 64) {
        fprintf(stderr, "[ERROR] Длина ключа: %zu (ожидалось 64 hex-символа = 32 байта)\n", key_len);
        return 1;
    }
    for (size_t i = 0; i < key_len; i++) {
        if (!isxdigit((unsigned char)cfg.key[i])) {
            fprintf(stderr, "[ERROR] Некорректный hex-символ в ключе на позиции %zu: '%c'\n", i, cfg.key[i]);
            return 1;
        }
    }
    uint8_t server_key[32] = {0};
    for (size_t i = 0; i < key_len/2 && i < 32; i++) {
        unsigned int byte; sscanf(&cfg.key[i*2], "%2x", &byte); server_key[i] = (uint8_t)byte;
    }
    kuznyechik_set_key(server_key, expanded_key);
    log_debug("Server expanded_key: %02x%02x%02x%02x...%02x%02x", expanded_key[0],expanded_key[1],expanded_key[2],expanded_key[3], expanded_key[155],expanded_key[159]);

    /* Инициализация сессий с хеш-таблицей и цепочками */
    max_sessions = cfg.max_sessions;
    sessions = calloc(max_sessions, sizeof(gost_session_t));
    if (!sessions) { perror("calloc"); return 1; }
    memset(session_hash, -1, sizeof(session_hash));
    for (int i = 0; i < max_sessions; i++) {
        sessions[i].active = 0;
        sessions[i].session_id = 0;
        sessions[i].next_slot = -1;
    }
    atomic_store(&free_slot_next, 0);

    memset(proxy_conns, 0, sizeof(proxy_conns));
    quic_server_t qs_obj;
    memset(&qs_obj, 0, sizeof(qs_obj));
    /* Поддержка IPv6: определяем family из адреса */
    int family = AF_INET;
    if (strchr(cfg.bind_addr, ':')) family = AF_INET6;
    else if (strcmp(cfg.bind_addr, "::") == 0) family = AF_INET6;

    qs_obj.server_fd = socket(family, SOCK_DGRAM, 0);
    if (qs_obj.server_fd < 0) { perror("socket"); return 1; }
    int opt = 1; setsockopt(qs_obj.server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    int buf = 1024*1024;
    setsockopt(qs_obj.server_fd, SOL_SOCKET, SO_RCVBUF, &buf, sizeof(buf));
    setsockopt(qs_obj.server_fd, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf));
    int flags = fcntl(qs_obj.server_fd, F_GETFL, 0);
    if (flags >= 0) fcntl(qs_obj.server_fd, F_SETFL, flags | O_NONBLOCK);
    if (bind_to_addr(qs_obj.server_fd, cfg.bind_addr, cfg.port, family) < 0) {
        perror("bind"); close(qs_obj.server_fd); return 1;
    }
    printf("[SERVER] Listening on %s:%d...\n", cfg.bind_addr, cfg.port);
    log_info("Server started on %s:%d", cfg.bind_addr, cfg.port);
    qs_obj.active = 1;
    qs_global = &qs_obj;  /* для reuse UDP-сокета в tcp_to_udp_thread и signal_handler */
    /* Запускаем UDP-сервер */
    pthread_t thread; pthread_create(&thread, NULL, server_thread, &qs_obj);

    while (running) { struct timeval tv = { .tv_usec = 100000 }; select(0, NULL, NULL, NULL, &tv); }
    log_info("Server shutting down...");
    log_info("Server: waiting for server_thread to exit...");
    /* Graceful shutdown — signal handler уже закрыл socket и qs_obj.active=0 */
    /* Ждём завершения UDP-потока (макс. 5 сек) */
    for (int i = 0; i < 10; i++) {
        int ret = pthread_tryjoin_np(thread, NULL);
        if (ret == EAGAIN) {
            log_info("Server: waiting for thread %d", i);
            sleep(1);
        } else {
            log_info("Server: thread %d joined, ret=%d", i, ret);
            break;
        }
    }
    /* Принудительно прерываем epoll_wait закрытием stream-сокет-сокры */
    if (qs_global && qs_global->server_fd >= 0) {
        log_info("Server: closing stream socket to unblock epoll_wait");
        close(qs_global->server_fd);
    }
    /* Отправка DISCONNECT всем активным сессиям */
    gost_packet_t dis_pkt;
    memset(&dis_pkt, 0, sizeof(dis_pkt));
    dis_pkt.magic = htonl(GOST_PROXY_MAGIC);
    dis_pkt.type = PKT_DISCONNECT;
    for (int i = 0; i < max_sessions; i++) {
        if (sessions[i].active && sessions[i].session_id &&
            sessions[i].client_addr.sin_addr.s_addr != 0) {
            ssize_t sent = quic_server_send(&qs_obj, &sessions[i].client_addr,
                                            sessions[i].client_addr_len,
                                            (const uint8_t*)&dis_pkt, sizeof(gost_packet_t));
            if (sent >= 0) {
                log_debug("DISPACK sent to sid=%llu", (unsigned long long)sessions[i].session_id);
            }
        }
    }
    /* Закрываем все stream-сокет-сокры */
    for (int i = 0; i < MAX_PROXY_CONNS; i++) {
        if (proxy_conns[i].tcp_fd >= 0) {
            close(proxy_conns[i].tcp_fd);
            proxy_conns[i].active = 0;
        }
    }
    /* Отменяем поток (если ещё жив) и присоединяем */
    if (pthread_kill(thread, 0) == 0) {
        log_info("Server: sending cancel to UDP thread");
        pthread_cancel(thread);
    }
    pthread_join(thread, NULL);
    log_info("Server: UDP thread joined");
    /* Отключаем все сессии */
    for (int i = 0; i < max_sessions; i++) sessions[i].active = 0;
    free(sessions); log_close(); return 0;
}
