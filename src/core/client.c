#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "kuznyechik.h"
#include "gost_common.h"
#include "protocol.h"
#include "config.h"
#include "log.h"
#include "socks5.h"

#define BUFFER_SIZE 2048
#define DEFAULT_CONFIG "/etc/gost-proxy/client.json"

static volatile int running = 1;
static gost_session_t session;
static uint8_t expanded_key[160];
static gost_config_t cfg;

static void signal_handler(int sig) {
    (void)sig;
    running = 0;
}

static int send_handshake(int sockfd, struct sockaddr_in *server_addr) {
    gost_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.magic = htonl(GOST_PROXY_MAGIC);
    pkt.type = PKT_HANDSHAKE;

    ssize_t sent = sendto(sockfd, &pkt, sizeof(pkt), 0,
                          (struct sockaddr *)server_addr, sizeof(*server_addr));
    if (sent < 0) { perror("sendto handshake"); return -1; }

    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sockfd, &fds);
    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    int ret = select(sockfd + 1, &fds, NULL, NULL, &tv);
    if (ret <= 0) {
        return -1;
    }

    uint8_t buffer[BUFFER_SIZE];
    socklen_t addr_len = sizeof(*server_addr);
    ssize_t recv_len = recvfrom(sockfd, buffer, BUFFER_SIZE, 0,
                                (struct sockaddr *)server_addr, &addr_len);

    if (recv_len < (ssize_t)sizeof(gost_packet_t)) {
        return -1;
    }

    const gost_packet_t *resp = (const gost_packet_t *)buffer;
    if (ntohl(resp->magic) != GOST_PROXY_MAGIC || resp->type != PKT_HANDSHAKE) {
        return -1;
    }

    session.session_id = ntohll(resp->session_id);
    session.active = 1;
    session.counter = 0;
    memset(session.nonce, 0, NONCE_SIZE);
    memcpy(session.nonce, &session.session_id, 8);
    memcpy(session.expanded_key, expanded_key, 160);

    return 0;
}

int main(int argc, char *argv[]) {
    const char *config_path = DEFAULT_CONFIG;

    if (argc > 1)
        config_path = argv[1];

    config_defaults(&cfg);
    strcpy(cfg.server_ip, "109.122.195.152");
    cfg.server_port = 10443;

    if (config_load(&cfg, config_path) == 0)
        printf("[CONFIG] Загружен: %s\n", config_path);
    else
        printf("[CONFIG] Файл не найден, используются значения по умолчанию\n");

    /* Инициализация логирования */
    log_init(cfg.log_level, cfg.log_file);

    printf("=== ГОСТ Прокси-Клиент ===\n");
    printf("Сервер: %s:%d\n", cfg.server_ip, cfg.server_port);
    log_info("Клиент запущен, сервер: %s:%d", cfg.server_ip, cfg.server_port);

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    uint8_t client_key[32] = {0};
    for (int i = 0; i < 32 && cfg.key[i*2] && cfg.key[i*2+1]; i++) {
        unsigned int byte;
        sscanf(&cfg.key[i*2], "%2x", &byte);
        client_key[i] = (uint8_t)byte;
    }
    kuznyechik_set_key(client_key, expanded_key);

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) { perror("socket"); return 1; }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(cfg.server_port);
    if (inet_pton(AF_INET, cfg.server_ip, &server_addr.sin_addr) <= 0) {
        printf("Ошибка: неверный IP-адрес сервера\n");
        close(sockfd);
        return 1;
    }

    if (send_handshake(sockfd, &server_addr) != 0) {
        printf("Ошибка handshake\n");
        close(sockfd);
        return 1;
    }

    /* Запускаем SOCKS5-прокси */
    printf("\n");
    printf("========================================\n");
    printf("  SOCKS5 прокси готов к работе!\n");
    printf("  Адрес:  127.0.0.1:%d\n", SOCKS5_PORT);
    printf("  Тип:    SOCKS v5\n");
    printf("========================================\n");
    printf("\n");
    printf("Настройте Firefox:\n");
    printf("  1. Откройте Настройки → Сеть → Настройка подключения\n");
    printf("  2. Выберите: Ручная настройка прокси\n");
    printf("  3. SOCKS Host: 127.0.0.1\n");
    printf("  4. Порт: %d\n", SOCKS5_PORT);
    printf("  5. Версия: SOCKS v5\n");
    printf("  6. Галочка: Прокси для DNS при использовании SOCKS v5\n");
    printf("\n");

    if (socks5_start(SOCKS5_PORT, cfg.server_ip, cfg.server_port, expanded_key,
                     session.nonce, session.session_id, sockfd, &server_addr,
                     &session.counter) != 0) {
        printf("Ошибка запуска SOCKS5-прокси\n");
        close(sockfd);
        return 1;
    }

    /* Основной цикл — ждём завершения */
    while (running) {
        sleep(1);
    }

    socks5_stop();

    gost_packet_t disconnect;
    memset(&disconnect, 0, sizeof(disconnect));
    disconnect.magic = htonl(GOST_PROXY_MAGIC);
    disconnect.type = PKT_DISCONNECT;
    disconnect.session_id = htonll(session.session_id);
    sendto(sockfd, &disconnect, sizeof(disconnect), 0,
           (struct sockaddr *)&server_addr, sizeof(server_addr));
    log_info("Клиент завершается...");
    log_close();
    close(sockfd);
    return 0;
}
