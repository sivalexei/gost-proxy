#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/random.h>

#include "quic_layer.h"
#include "kuznyechik.h"
#include "gost_common.h"
#include "socks5.h"

static void* keepalive_thread(void *arg);
#include "protocol.h"
#include "config.h"
#include "log.h"
#include "socks5.h"

#define BUFFER_SIZE 2048
#define DEFAULT_CONFIG "/etc/gost-proxy/client.json"
#define KEEPALIVE_INTERVAL 30  /* секунд */

static volatile int running = 1;
static gost_session_t session;

static quic_client_t quic_client;
static uint8_t expanded_key[160];
static gost_config_t cfg;

static void signal_handler(int sig) {
    (void)sig;
    running = 0;
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

    /* Подключаемся через QUIC */
    if (quic_client_connect(&quic_client, cfg.server_ip, cfg.server_port, client_key) != 0) {
        printf("Ошибка QUIC подключения\n");
        log_error("QUIC connect failed");
        return 1;
    }

    /* session_id получен из handshake в quic_client_connect */
    memcpy(&session.session_id, quic_client.session_id, 8);
    session.active = 1;
    session.counter = 0;
    memset(session.nonce, 0, NONCE_SIZE);
    memcpy(session.nonce, &session.session_id, 8);
    memcpy(session.expanded_key, expanded_key, 160);
    log_info("QUIC session_id=%llu", (unsigned long long)session.session_id);

    /* === CPS handshake === */
    printf("\n[SECURITY] Инициализация CPS (Chaffing/Pretense System)...\n");

    /* Генерируем seed из session_id */
    uint8_t cps_seed[HEADER_SEED_SIZE];
    protocol_generate_header_seed(session.session_id, cps_seed, HEADER_SEED_SIZE);

    /* Отправляем fake пакеты для chaffing */
    gost_packet_t fake_pkt;
    memset(&fake_pkt, 0, sizeof(fake_pkt));
    protocol_make_fake_quic(&fake_pkt, cps_seed, HEADER_SEED_SIZE);
    fake_pkt.session_id = htonll(session.session_id);
    quic_client_send(&quic_client, (const uint8_t*)&fake_pkt, sizeof(fake_pkt));
    log_info("CPS: fake QUIC packet sent");

    memset(&fake_pkt, 0, sizeof(fake_pkt));
    protocol_make_fake_dns(&fake_pkt, cps_seed, HEADER_SEED_SIZE);
    fake_pkt.session_id = htonll(session.session_id);
    quic_client_send(&quic_client, (const uint8_t*)&fake_pkt, sizeof(fake_pkt));
    log_info("CPS: fake DNS packet sent");

    memset(&fake_pkt, 0, sizeof(fake_pkt));
    protocol_make_fake_tls(&fake_pkt, cps_seed, HEADER_SEED_SIZE);
    fake_pkt.session_id = htonll(session.session_id);
    quic_client_send(&quic_client, (const uint8_t*)&fake_pkt, sizeof(fake_pkt));
    log_info("CPS: fake TLS packet sent");

    /* Отправляем CPS challenge */
    gost_packet_t pkt;
    gost_packet_t cps_challenge;
    uint8_t cps_challenge_out[32] = {0}, cps_answer[32] = {0};
    memset(&cps_challenge, 0, sizeof(cps_challenge));
    protocol_make_cps_challenge(&cps_challenge, cps_seed, HEADER_SEED_SIZE,
                                 cps_challenge_out, cps_answer);
    cps_challenge.session_id = htonll(session.session_id);
    quic_client_send(&quic_client, (const uint8_t*)&cps_challenge, sizeof(cps_challenge));
    log_info("CPS: challenge sent");

    /* Ждём CPS response от сервера */
    memset(&pkt, 0, sizeof(pkt));
    ssize_t cps_recv_len = quic_client_recv(&quic_client, (uint8_t*)&pkt, sizeof(pkt), 3000);
    if (cps_recv_len >= (ssize_t)sizeof(gost_packet_t) &&
        ntohl(pkt.magic) == GOST_PROXY_MAGIC &&
        pkt.type == PKT_SIM_CHALLENGE) {
        /* Верифицируем challenge */
        if (protocol_verify_cps_challenge(&pkt, cps_answer, sizeof(cps_answer)) == 0) {
            session.cps_enabled = 1;
            memcpy(session.cps_response, cps_answer, 32);
            log_info("CPS: challenge verified successfully");
            printf("[SECURITY] CPS handshake завершён успешно\n");
        } else {
            log_info("CPS: challenge verification failed (non-critical)");
            printf("[SECURITY] CPS верификация не пройдена (не критично)\n");
        }
    } else {
        log_info("CPS: no response received (non-critical)");
        printf("[SECURITY] CPS ответ не получен (не критично)\n");
    }

    /* Инициализируем сессию с динамическими заголовками */
    protocol_init_session(&session, expanded_key);
    log_info("Session initialized with dynamic headers");

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
                     session.nonce, session.session_id,
                     &quic_client, &session.counter) != 0) {
        printf("Ошибка запуска SOCKS5-прокси\n");
        quic_client_close(&quic_client);
        return 1;
    }

    /* Запуск keepalive-потока */
    pthread_t ka_thread;
    if (pthread_create(&ka_thread, NULL, keepalive_thread, &quic_client) != 0) {
        perror("[KEEPALIVE] pthread_create");
    } else {
        pthread_detach(ka_thread);
        log_info("Keepalive thread started (every %d сек)", KEEPALIVE_INTERVAL);
    }

    /* Основной цикл — ждём завершения */
    while (running) {
        sleep(1);
    }

    socks5_stop();

    /* Отправляем disconnect */
    gost_packet_t disconnect;
    memset(&disconnect, 0, sizeof(disconnect));
    disconnect.magic = htonl(GOST_PROXY_MAGIC);
    disconnect.type = PKT_DISCONNECT;
    disconnect.session_id = htonll(session.session_id);
    quic_client_send(&quic_client, (const uint8_t*)&disconnect, sizeof(disconnect));

    log_info("Клиент завершается...");
    quic_client_close(&quic_client);
    log_close();
    return 0;
}

/* Периодическая отправка keepalive */
static void* keepalive_thread(void *arg) {
    quic_client_t *qc = (quic_client_t *)arg;
    while (running) {
        sleep(KEEPALIVE_INTERVAL);
        if (!running) break;
        gost_packet_t pkt;
        memset(&pkt, 0, sizeof(pkt));
        pkt.magic = htonl(GOST_PROXY_MAGIC);
        pkt.type = PKT_KEEPALIVE;
        pkt.session_id = htonll(session.session_id);
        ssize_t sent = quic_client_send(qc, (const uint8_t*)&pkt, sizeof(pkt));
        if (sent < 0) {
            log_debug("keepalive send failed: %s", strerror(errno));
        }
    }
    return NULL;
}
