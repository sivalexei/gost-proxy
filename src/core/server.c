#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

#include "kuznyechik.h"
#include "gost_common.h"
#include "protocol.h"
#include "config.h"

#define BUFFER_SIZE 2048
#define DEFAULT_CONFIG "/etc/gost-proxy/server.json"
#define MAX_PROXY_CONNS 256

static volatile int running = 1;
static gost_session_t *sessions;
static int max_sessions;
static pthread_mutex_t sessions_lock = PTHREAD_MUTEX_INITIALIZER;

static uint8_t expanded_key[160];
static gost_config_t cfg;

/* TCP-соединения для проксирования */
typedef struct {
    int      tcp_fd;
    uint64_t session_id;
    uint32_t conn_id;       /* ID соединения клиента */
    struct sockaddr_in client_addr;
    socklen_t addr_len;
    int      active;
    int      client_udp_fd;
    uint32_t send_counter;  /* нечётные: 1, 3, 5... */
} proxy_conn_t;

static proxy_conn_t proxy_conns[MAX_PROXY_CONNS];
static pthread_mutex_t proxy_lock = PTHREAD_MUTEX_INITIALIZER;

static void signal_handler(int sig) {
    (void)sig;
    running = 0;
}

static gost_session_t* find_session(uint64_t session_id) {
    for (int i = 0; i < max_sessions; i++) {
        if (sessions[i].active && sessions[i].session_id == session_id)
            return &sessions[i];
    }
    return NULL;
}

static gost_session_t* create_session(uint64_t session_id) {
    for (int i = 0; i < max_sessions; i++) {
        if (!sessions[i].active) {
            sessions[i].active = 1;
            sessions[i].session_id = session_id;
            sessions[i].counter = 0;
            memset(sessions[i].nonce, 0, NONCE_SIZE);
            memcpy(sessions[i].nonce, &session_id, 8);
            memcpy(sessions[i].expanded_key, expanded_key, 160);
            printf("[SERVER] Новая сессия: %lu\n", session_id);
            return &sessions[i];
        }
    }
    return NULL;
}

static proxy_conn_t* find_proxy_conn(uint64_t session_id, uint32_t conn_id) {
    for (int i = 0; i < MAX_PROXY_CONNS; i++) {
        if (proxy_conns[i].active && proxy_conns[i].session_id == session_id
            && proxy_conns[i].conn_id == conn_id)
            return &proxy_conns[i];
    }
    return NULL;
}

static proxy_conn_t* create_proxy_conn(uint64_t session_id) {
    for (int i = 0; i < MAX_PROXY_CONNS; i++) {
        if (!proxy_conns[i].active) {
            proxy_conns[i].active = 1;
            proxy_conns[i].session_id = session_id;
            return &proxy_conns[i];
        }
    }
    return NULL;
}

/* Поток чтения из TCP и отправки клиенту через UDP-туннель */
static void* tcp_to_udp_thread(void *arg) {
    proxy_conn_t *conn = (proxy_conn_t *)arg;
    uint8_t buf[BUFFER_SIZE];

    while (running && conn->active) {
        struct pollfd pfd = { .fd = conn->tcp_fd, .events = POLLIN };
        int ret = poll(&pfd, 1, 1000);

        if (ret > 0 && (pfd.revents & POLLIN)) {
            ssize_t n = read(conn->tcp_fd, buf, sizeof(buf));
            if (n <= 0) {
                printf("[PROXY] TCP read returned %zd (errno=%d)\n", n, errno);
                fflush(stdout);
                printf("[PROXY] TCP соединение закрыто: %s:%d\n",
                       inet_ntoa(conn->client_addr.sin_addr),
                       ntohs(conn->client_addr.sin_port));
                conn->active = 0;
                break;
            }

            printf("[PROXY] TCP read %zd bytes from target, first=%02x%02x%02x%02x\n",
                   n, buf[0], buf[1], buf[2], buf[3]);
            fflush(stdout);

            /* Отправляем данные клиенту через зашифрованный туннель (порциями) */
            gost_session_t *session = find_session(conn->session_id);
            if (!session) break;

            size_t offset = 0;
            while (offset < (size_t)n) {
                size_t chunk = (size_t)n - offset;
                if (chunk > MAX_PAYLOAD - 4) chunk = MAX_PAYLOAD - 4;

                gost_packet_t pkt;
                if (protocol_pack_data(&pkt, conn->session_id, conn->conn_id,
                                      buf + offset, chunk, session->expanded_key,
                                      session->nonce,
                                      &conn->send_counter) == 0) {
                    sendto(conn->client_udp_fd, &pkt, sizeof(gost_packet_t),
                           0, (struct sockaddr *)&conn->client_addr, conn->addr_len);
                }
                offset += chunk;
            }
        } else if (ret < 0 && errno != EINTR) {
            break;
        }
    }

    if (conn->tcp_fd >= 0) close(conn->tcp_fd);
    conn->active = 0;
    printf("[PROXY] Поток TCP→UDP завершён\n");
    return NULL;
}

/* Открытие TCP-соединения к целевому хосту */
static int connect_to_target(const char *host, uint16_t port) {
    struct addrinfo hints = {0}, *result;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", port);

    if (getaddrinfo(host, port_str, &hints, &result) != 0) {
        printf("[PROXY] getaddrinfo не удалось для %s:%u\n", host, port);
        return -1;
    }

    int fd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (fd < 0) {
        freeaddrinfo(result);
        return -1;
    }

    /* Отключаем алгоритм Нагла — данные отправляются сразу */
    int flag = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

    /* Таймауты для подключения и I/O */
    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(fd, result->ai_addr, result->ai_addrlen) < 0) {
        printf("[PROXY] connect к %s:%u не удался: %s\n", host, port, strerror(errno));
        close(fd);
        freeaddrinfo(result);
        return -1;
    }

    freeaddrinfo(result);
    printf("[PROXY] TCP подключение к %s:%u установлено\n", host, port);
    return fd;
}

/* Обработка пакета данных — проксирование */
static void handle_data_packet(int sockfd, struct sockaddr_in *client_addr,
                               socklen_t addr_len, const gost_packet_t *pkt,
                               uint64_t session_id) {
    gost_session_t *session = find_session(session_id);
    if (!session) {
        return;
    }

    uint8_t decrypted[MAX_PAYLOAD];
    size_t data_len;
    uint32_t pkt_conn_id = 0;
    if (protocol_unpack_data(pkt, decrypted, &data_len, &pkt_conn_id,
                             session->expanded_key, session->nonce,
                             &session->counter) != 0) {
        printf("[SERVER] Ошибка расшифрования\n");
        fflush(stdout);
        return;
    }

    if (data_len < 1) return;

    /* Проверяем команду: 0x01 = CONNECT */
    if (decrypted[0] == 0x01 && data_len >= 8) {
        uint8_t addr_type = decrypted[1];
        char target_host[256] = {0};
        uint16_t target_port = 0;

        if (addr_type == 0x01 && data_len >= 8) {
            /* IPv4 */
            struct in_addr addr;
            memcpy(&addr, &decrypted[2], 4);
            inet_ntop(AF_INET, &addr, target_host, sizeof(target_host));
            target_port = (decrypted[6] << 8) | decrypted[7];
        } else if (addr_type == 0x03 && data_len >= 5) {
            /* Domain */
            size_t dlen = decrypted[2];
            if (data_len >= 3 + dlen + 2) {
                memcpy(target_host, &decrypted[3], dlen);
                target_host[dlen] = '\0';
                target_port = (decrypted[3 + dlen] << 8) | decrypted[3 + dlen + 1];
            }
        }

        if (target_host[0] && target_port > 0) {
            printf("[PROXY] CONNECT %s:%u (conn_id=%u)\n", target_host, target_port, pkt_conn_id);

            int tcp_fd = connect_to_target(target_host, target_port);
            if (tcp_fd < 0) {
                /* Отправляем ошибку клиенту */
                uint8_t err_data[] = { 0x02, 0x01 }; /* FAIL */
                gost_packet_t err_pkt;
                memset(&err_pkt, 0, sizeof(err_pkt));
                protocol_pack_data(&err_pkt, session_id, pkt_conn_id, err_data, 2,
                                  session->expanded_key, session->nonce,
                                  &session->counter);
                sendto(sockfd, &err_pkt, sizeof(gost_packet_t),
                       0, (struct sockaddr *)client_addr, addr_len);
                return;
            }

            /* Создаём прокси-соединение */
            pthread_mutex_lock(&proxy_lock);
            proxy_conn_t *conn = create_proxy_conn(session_id);
            if (!conn) {
                close(tcp_fd);
                pthread_mutex_unlock(&proxy_lock);
                return;
            }
            conn->tcp_fd = tcp_fd;
            conn->session_id = session_id;
            conn->conn_id = pkt_conn_id;
            conn->client_addr = *client_addr;
            conn->addr_len = addr_len;
            conn->client_udp_fd = sockfd;
            conn->send_counter = 1; /* нечётные для сервера */
            pthread_mutex_unlock(&proxy_lock);

            /* Запускаем поток TCP→UDP */
            pthread_t thread;
            pthread_create(&thread, NULL, tcp_to_udp_thread, conn);
            pthread_detach(thread);

            /* Отправляем успех клиенту (с conn_id) */
            uint8_t ok_data[] = { 0x02, 0x00 }; /* OK */
            gost_packet_t ok_pkt;
            memset(&ok_pkt, 0, sizeof(ok_pkt));
            protocol_pack_data(&ok_pkt, session_id, pkt_conn_id, ok_data, 2,
                              session->expanded_key, session->nonce,
                              &session->counter);
            sendto(sockfd, &ok_pkt, sizeof(gost_packet_t),
                   0, (struct sockaddr *)client_addr, addr_len);
            return;
        }
    }

    /* Обычные данные — пересылаем в TCP */
    pthread_mutex_lock(&proxy_lock);
    proxy_conn_t *conn = find_proxy_conn(session_id, pkt_conn_id);
    pthread_mutex_unlock(&proxy_lock);

    if (conn && conn->active && conn->tcp_fd >= 0) {
        printf("[PROXY] TCP write: %zu bytes, first=%02x%02x%02x%02x%02x%02x%02x%02x\n",
               data_len, decrypted[0], decrypted[1], decrypted[2], decrypted[3],
               decrypted[4], decrypted[5], decrypted[6], decrypted[7]);
        fflush(stdout);
        /* Гарантируем отправку ВСЕХ байтов через цикл write */
        size_t total = 0;
        while (total < data_len) {
            ssize_t written = write(conn->tcp_fd, decrypted + total, data_len - total);
            if (written <= 0) {
                if (written < 0 && errno == EINTR) continue;
                printf("[PROXY] Ошибка записи в TCP: %zd errno=%d\n", written, errno);
                conn->active = 0;
                break;
            }
            total += written;
        }
    }
}

static void handle_packet(int sockfd, struct sockaddr_in *client_addr,
                          socklen_t addr_len, const uint8_t *data, size_t len) {
    if (len < 10) return; /* Минимальный размер: magic(4) + type(1) + session_id(8) + min */

    const gost_packet_t *pkt = (const gost_packet_t *)data;
    if (ntohl(pkt->magic) != GOST_PROXY_MAGIC) return;

    pthread_mutex_lock(&sessions_lock);

    switch (pkt->type) {
        case PKT_HANDSHAKE: {
            printf("[SERVER] HANDSHAKE от клиента\n");
            uint64_t session_id = ((uint64_t)rand() << 32) | rand();
            gost_session_t *session = create_session(session_id);
            if (!session) {
                printf("[SERVER] Ошибка: нет свободных сессий\n");
                pthread_mutex_unlock(&sessions_lock);
                return;
            }
            gost_packet_t response;
            protocol_create_handshake(&response, session_id, session->expanded_key);
            sendto(sockfd, &response, sizeof(response), 0,
                   (struct sockaddr *)client_addr, addr_len);
            printf("[SERVER] Handshake ответ, session_id=%lu\n", session_id);
            break;
        }
        case PKT_DATA: {
            uint64_t session_id = ntohll(pkt->session_id);
            printf("[SERVER] DATA от сессии %lu\n", session_id);
            handle_data_packet(sockfd, client_addr, addr_len, pkt, session_id);
            break;
        }
        case PKT_KEEPALIVE:
            break;
        case PKT_DISCONNECT: {
            uint64_t session_id = ntohll(pkt->session_id);
            uint32_t dc_conn_id = ntohl(pkt->conn_id);
            gost_session_t *session = find_session(session_id);
            if (session) {
                printf("[SERVER] Отключение сессии %lu\n", session->session_id);
                session->active = 0;
            }
            /* Закрываем прокси-соединение */
            pthread_mutex_lock(&proxy_lock);
            proxy_conn_t *conn = find_proxy_conn(session_id, dc_conn_id);
            if (conn) {
                conn->active = 0;
                if (conn->tcp_fd >= 0) close(conn->tcp_fd);
                conn->tcp_fd = -1;
            }
            pthread_mutex_unlock(&proxy_lock);
            break;
        }
        default:
            break;
    }
    pthread_mutex_unlock(&sessions_lock);
}

static void* server_thread(void *arg) {
    int sockfd = *(int *)arg;
    uint8_t buffer[BUFFER_SIZE];
    struct sockaddr_in client_addr;
    socklen_t addr_len;

    printf("[SERVER] Поток обработки запущен\n");
    while (running) {
        addr_len = sizeof(client_addr);
        ssize_t recv_len = recvfrom(sockfd, buffer, BUFFER_SIZE, 0,
                                    (struct sockaddr *)&client_addr, &addr_len);
        if (recv_len > 0)
            handle_packet(sockfd, &client_addr, addr_len, buffer, recv_len);
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    const char *config_path = DEFAULT_CONFIG;

    if (argc > 1)
        config_path = argv[1];

    config_defaults(&cfg);
    if (config_load(&cfg, config_path) == 0)
        printf("[CONFIG] Загружен: %s\n", config_path);
    else
        printf("[CONFIG] Файл не найден, используются значения по умолчанию\n");

    printf("=== ГОСТ Прокси-Сервер ===\n");
    printf("Адрес: %s:%d\n", cfg.bind_addr, cfg.port);
    printf("Макс. сессий: %d\n", cfg.max_sessions);

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    uint8_t server_key[32] = {0};
    for (int i = 0; i < 32 && cfg.key[i*2] && cfg.key[i*2+1]; i++) {
        unsigned int byte;
        sscanf(&cfg.key[i*2], "%2x", &byte);
        server_key[i] = (uint8_t)byte;
    }
    kuznyechik_set_key(server_key, expanded_key);
    printf("[INIT] Ключ расширен успешно\n");

    max_sessions = cfg.max_sessions;
    sessions = calloc(max_sessions, sizeof(gost_session_t));
    if (!sessions) { perror("calloc"); return 1; }

    memset(proxy_conns, 0, sizeof(proxy_conns));

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    inet_pton(AF_INET, cfg.bind_addr, &server_addr.sin_addr);
    server_addr.sin_port = htons(cfg.port);

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(sockfd);
        return 1;
    }

    printf("[SERVER] Слушаем на %s:%d...\n", cfg.bind_addr, cfg.port);

    pthread_t thread;
    if (pthread_create(&thread, NULL, server_thread, &sockfd) != 0) {
        perror("pthread_create");
        close(sockfd);
        return 1;
    }

    while (running) sleep(1);

    printf("\n[SERVER] Завершение...\n");
    close(sockfd);
    pthread_cancel(thread);
    pthread_join(thread, NULL);
    free(sessions);
    return 0;
}
