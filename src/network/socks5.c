#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <errno.h>

#include "kuznyechik.h"
#include "gost_common.h"
#include "protocol.h"
#include "socks5.h"

#define SOCKS5_BUF_SIZE 4096

static volatile int socks5_running = 0;
static int socks5_listen_fd = -1;

static gost_session_t proxy_session;
static char proxy_server_ip[64];
static uint16_t proxy_server_port;
static int proxy_udp_fd = -1;
static struct sockaddr_in proxy_server_addr;
static uint32_t *shared_counter = NULL;
static uint32_t send_counter = 0;
static uint32_t recv_counter = 0;
static uint32_t next_conn_id = 1;

/* Отправка данных через gost-proxy туннель (с чанкированием) */
static int tunnel_send(const uint8_t *data, size_t len, uint32_t conn_id) {
    size_t offset = 0;
    while (offset < len) {
        size_t chunk = len - offset;
        if (chunk > MAX_PAYLOAD - 4) chunk = MAX_PAYLOAD - 4;

        gost_packet_t pkt;
        memset(&pkt, 0, sizeof(pkt));
        if (protocol_pack_data(&pkt, proxy_session.session_id, conn_id,
                              data + offset, chunk, proxy_session.expanded_key,
                              proxy_session.nonce,
                              &send_counter) != 0) {
            printf("[SOCKS5] Ошибка pack_data offset=%zu chunk=%zu\n", offset, chunk);
            fflush(stdout);
            return -1;
        }

        ssize_t sent = sendto(proxy_udp_fd, &pkt, sizeof(gost_packet_t),
                              0, (struct sockaddr *)&proxy_server_addr,
                              sizeof(proxy_server_addr));
        if (sent <= 0) {
            printf("[SOCKS5] Ошибка sendto offset=%zu\n", offset);
            fflush(stdout);
            return -1;
        }
        offset += chunk;
    }
    return 0;
}

/* Приём данных из gost-proxy туннеля (фильтрация по conn_id) */
static int tunnel_recv(uint8_t *data, size_t max_len, int timeout_ms, uint32_t expect_conn_id) {
    uint8_t buffer[SOCKS5_BUF_SIZE];
    struct sockaddr_in from;
    socklen_t from_len;

    int elapsed = 0;
    while (elapsed < timeout_ms) {
        from_len = sizeof(from);
        ssize_t n = recvfrom(proxy_udp_fd, buffer, sizeof(buffer), MSG_DONTWAIT,
                             (struct sockaddr *)&from, &from_len);
        if (n > 0) {
            if (n >= (ssize_t)sizeof(gost_packet_t)) {
                const gost_packet_t *pkt = (const gost_packet_t *)buffer;
                if (ntohl(pkt->magic) == GOST_PROXY_MAGIC && pkt->type == PKT_DATA) {
                    uint32_t pkt_conn_id = ntohl(pkt->conn_id);
                    /* Пропускаем пакеты для другого соединения */
                    if (pkt_conn_id != expect_conn_id) {
                        usleep(1000);
                        elapsed += 1;
                        continue;
                    }
                    size_t data_len;
                    if (protocol_unpack_data(pkt, data, &data_len, NULL,
                                             proxy_session.expanded_key,
                                             proxy_session.nonce,
                                             &recv_counter) == 0) {
                        return (int)data_len;
                    }
                }
            }
        }
        usleep(10000); /* 10ms */
        elapsed += 10;
    }
    return -1;
}

/* Поток проксирования данных: Firefox ↔ gost-proxy */
static void* proxy_data_thread(void *arg) {
    typedef struct { int fd; uint32_t conn_id; } proxy_arg_t;
    proxy_arg_t *parg = (proxy_arg_t *)arg;
    int client_fd = parg->fd;
    uint32_t my_conn_id = parg->conn_id;
    free(parg);

    printf("[SOCKS5] Проксирование данных... conn_id=%u\n", my_conn_id);
    fflush(stdout);

    uint8_t buf[SOCKS5_BUF_SIZE];

    while (socks5_running) {
        /* Ждём данных на TCP-сокете от Firefox */
        struct pollfd pfd = { .fd = client_fd, .events = POLLIN };
        int ret = poll(&pfd, 1, 100);

        /* Данные от Firefox → отправляем через туннель */
        if (ret > 0 && (pfd.revents & POLLIN)) {
            ssize_t n = recv(client_fd, buf, sizeof(buf), 0);
            if (n <= 0) {
                printf("[SOCKS5] recv from client returned %zd, closing\n", n);
                fflush(stdout);
                break;
            }

            printf("[SOCKS5] Got %zd bytes from client, sending through tunnel (conn_id=%u)\n", n, my_conn_id);
            printf("[SOCKS5] Send first=%02x%02x%02x%02x%02x%02x%02x%02x\n",
                   buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]);
            fflush(stdout);
            if (tunnel_send(buf, n, my_conn_id) != 0) {
                printf("[SOCKS5] Ошибка отправки\n");
                fflush(stdout);
                break;
            }
        }

        /* Проверяем данные от сервера (с коротким таймаутом, фильтр по conn_id) */
        uint8_t resp[SOCKS5_BUF_SIZE];
        int resp_len = tunnel_recv(resp, sizeof(resp), 50, my_conn_id);
        if (resp_len > 0) {
            printf("[SOCKS5] Got %d bytes (conn_id=%u), first=%02x%02x%02x%02x%02x%02x%02x%02x\n",
                   resp_len, my_conn_id,
                   resp[0], resp[1], resp[2], resp[3], resp[4], resp[5], resp[6], resp[7]);
            fflush(stdout);

            /* Гарантируем отправку ВСЕХ байтов клиенту */
            {
                size_t total_sent = 0;
                while (total_sent < (size_t)resp_len) {
                    ssize_t s = send(client_fd, resp + total_sent, resp_len - total_sent, MSG_NOSIGNAL);
                    if (s <= 0) {
                        printf("[SOCKS5] send to client failed: %zd errno=%d (%s)\n",
                               s, errno, strerror(errno));
                        goto close_client;
                    }
                    total_sent += s;
                }
            }

            /* Считываем все доступные чанки с сервера (фильтр по conn_id) */
            while (socks5_running) {
                int extra_len = tunnel_recv(resp, sizeof(resp), 10, my_conn_id);
                if (extra_len <= 0) break;
                printf("[SOCKS5] Got extra %d bytes, first=%02x%02x%02x%02x\n", extra_len,
                       resp[0], resp[1], resp[2], resp[3]);
                fflush(stdout);
                size_t extra_sent = 0;
                while (extra_sent < (size_t)extra_len) {
                    ssize_t s = send(client_fd, resp + extra_sent, extra_len - extra_sent, MSG_NOSIGNAL);
                    if (s <= 0) {
                        printf("[SOCKS5] send extra to client failed: %zd errno=%d (%s)\n",
                               s, errno, strerror(errno));
                        goto close_client;
                    }
                    extra_sent += s;
                }
            }
        }
    }

close_client:
    close(client_fd);
    printf("[SOCKS5] Клиент отключён\n");
    fflush(stdout);
    return NULL;
}

/* Поток обработки SOCKS5-клиента */
static void* socks5_client_thread(void *arg) {
    int client_fd = *(int *)arg;
    free(arg);

    uint8_t buf[SOCKS5_BUF_SIZE];

    /* SOCKS5 handshake: читаем методы аутентификации */
    ssize_t n = recv(client_fd, buf, sizeof(buf), 0);
    if (n < 2 || buf[0] != 0x05) {
        close(client_fd);
        return NULL;
    }

    /* Отвечаем: без аутентификации */
    uint8_t auth_reply[] = { 0x05, 0x00 };
    send(client_fd, auth_reply, 2, 0);

    /* SOCKS5 CONNECT запрос */
    n = recv(client_fd, buf, sizeof(buf), 0);
    if (n < 4 || buf[0] != 0x05 || buf[1] != 0x01) {
        close(client_fd);
        return NULL;
    }

    /* Разбираем адрес назначения */
    char target_host[256] = {0};
    uint16_t target_port = 0;

    switch (buf[3]) {
        case 0x01: { /* IPv4 */
            struct in_addr addr;
            memcpy(&addr, &buf[4], 4);
            inet_ntop(AF_INET, &addr, target_host, sizeof(target_host));
            target_port = (buf[8] << 8) | buf[9];
            break;
        }
        case 0x03: { /* Domain */
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

    printf("[SOCKS5] Запрос: %s:%u\n", target_host, target_port);

    /* Генерируем conn_id для этого соединения */
    uint32_t my_conn_id = __sync_fetch_and_add(&next_conn_id, 1);

    /* Резолвим домен через DNS (клиентский резолв) */
    struct hostent *he = gethostbyname(target_host);
    if (!he) {
        printf("[SOCKS5] DNS не удался: %s\n", target_host);
        uint8_t err[] = { 0x05, 0x04, 0x00, 0x01, 0,0,0,0, 0,0 };
        send(client_fd, err, 10, 0);
        close(client_fd);
        return NULL;
    }

    struct in_addr *target_addr = (struct in_addr *)he->h_addr_list[0];

    /* Формируем CONNECT-запрос для gost-proxy */
    uint8_t connect_data[8];
    connect_data[0] = 0x01; /* CMD_CONNECT */
    connect_data[1] = 0x01; /* IPv4 */
    memcpy(&connect_data[2], target_addr, 4);
    connect_data[6] = (target_port >> 8) & 0xFF;
    connect_data[7] = target_port & 0xFF;

    /* Отправляем CONNECT через туннель с conn_id */
    if (tunnel_send(connect_data, 8, my_conn_id) != 0) {
        printf("[SOCKS5] Ошибка отправки CONNECT\n");
        uint8_t err[] = { 0x05, 0x01, 0x00, 0x01, 0,0,0,0, 0,0 };
        send(client_fd, err, 10, 0);
        close(client_fd);
        return NULL;
    }

    /* Ждём ответ от сервера (фильтр по conn_id) */
    uint8_t resp[SOCKS5_BUF_SIZE];
    int resp_len = tunnel_recv(resp, sizeof(resp), 5000, my_conn_id);
    if (resp_len < 2 || resp[0] != 0x02 || resp[1] != 0x00) {
        printf("[SOCKS5] CONNECT отклонён сервером (conn_id=%u)\n", my_conn_id);
        uint8_t err[] = { 0x05, 0x05, 0x00, 0x01, 0,0,0,0, 0,0 };
        send(client_fd, err, 10, 0);
        close(client_fd);
        return NULL;
    }

    /* SOCKS5 успех */
    uint8_t reply[] = { 0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0 };
    send(client_fd, reply, 10, 0);

    printf("[SOCKS5] Подключено к %s:%u (conn_id=%u)\n", target_host, target_port, my_conn_id);

    /* Запускаем проксирование данных (передаём conn_id) */
    pthread_t thread;
    typedef struct { int fd; uint32_t conn_id; } proxy_arg_t;
    proxy_arg_t *parg = malloc(sizeof(proxy_arg_t));
    parg->fd = client_fd;
    parg->conn_id = my_conn_id;
    pthread_create(&thread, NULL, proxy_data_thread, parg);
    pthread_detach(thread);

    return NULL;
}

/* Поток прослушивания SOCKS5 */
static void* socks5_server_thread(void *arg) {
    (void)arg;

    printf("[SOCKS5] SOCKS5-прокси запущен на 127.0.0.1:%d\n", SOCKS5_PORT);

    while (socks5_running) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);

        int client_fd = accept(socks5_listen_fd,
                               (struct sockaddr *)&client_addr, &addr_len);
        if (client_fd < 0) {
            if (socks5_running) perror("[SOCKS5] accept");
            continue;
        }

        int *fd_ptr = malloc(sizeof(int));
        *fd_ptr = client_fd;

        pthread_t thread;
        if (pthread_create(&thread, NULL, socks5_client_thread, fd_ptr) != 0) {
            perror("[SOCKS5] pthread_create");
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
                 int existing_udp_fd, struct sockaddr_in *server_addr,
                 uint32_t *session_counter) {
    strncpy(proxy_server_ip, server_ip, sizeof(proxy_server_ip) - 1);
    proxy_server_port = server_port;

    memset(&proxy_session, 0, sizeof(gost_session_t));
    proxy_session.session_id = session_id;
    proxy_session.active = 1;
    proxy_session.counter = 0;
    memcpy(proxy_session.nonce, nonce, NONCE_SIZE);
    memcpy(proxy_session.expanded_key, expanded_key, 160);

    /* Используем существующий UDP-сокет от handshake */
    proxy_udp_fd = existing_udp_fd;
    proxy_server_addr = *server_addr;
    shared_counter = session_counter;
    send_counter = 0;   /* клиент: чётные 0, 2, 4... */
    recv_counter = 0;

    /* TCP-сокет для SOCKS5 */
    socks5_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socks5_listen_fd < 0) {
        perror("[SOCKS5] socket");
        close(proxy_udp_fd);
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
        close(proxy_udp_fd);
        return -1;
    }

    if (listen(socks5_listen_fd, 16) < 0) {
        perror("[SOCKS5] listen");
        close(socks5_listen_fd);
        close(proxy_udp_fd);
        return -1;
    }

    socks5_running = 1;

    pthread_t thread;
    if (pthread_create(&thread, NULL, socks5_server_thread, NULL) != 0) {
        perror("[SOCKS5] pthread_create");
        close(socks5_listen_fd);
        close(proxy_udp_fd);
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
    if (proxy_udp_fd >= 0) {
        close(proxy_udp_fd);
        proxy_udp_fd = -1;
    }
}
