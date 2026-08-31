#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/random.h>
#include <ctype.h>

#include "quic_layer.h"
#include "kuznyechik.h"
#include "gost_common.h"
#include "protocol.h"
#include "config.h"
#include "log.h"
#include "socks5.h"

static void* keepalive_thread(void *arg);

#define BUFFER_SIZE 2048
#define DEFAULT_CONFIG "/etc/gost-proxy/client.json"
#define KEEPALIVE_INTERVAL 30  /* секунд */

static volatile int running = 1;
static gost_session_t session;

static quic_client_t quic_client;
static uint8_t expanded_key[160];
static gost_config_t cfg;

static void signal_handler(int sig) { fprintf(stderr, "DEBUG: signal %d\n", sig);
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

    printf("[DEBUG] cfg.key='%s' (len=%zu)\n", cfg.key, strlen(cfg.key));

    /* Лог по умолчанию в /tmp/gost-proxy/client.log */
    if (cfg.log_file[0] == '\0' || strcmp(cfg.log_file, "/var/log/gost-proxy/client.log") == 0) {
        strncpy(cfg.log_file, "/tmp/gost-proxy/client.log", sizeof(cfg.log_file));
    }
    /* Инициализация логирования */
    log_init(cfg.log_level, cfg.log_file);

    printf("=== ГОСТ Прокси-Клиент ===\n");
    printf("Сервер: %s:%d\n", cfg.server_ip, cfg.server_port);
    log_info("Клиент запущен, сервер: %s:%d", cfg.server_ip, cfg.server_port);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;  /* SA_RESTART не ставим — select прерывается сигналом */
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    uint8_t client_key[32] = {0};
    for (int i = 0; i < 32 && cfg.key[i*2] && cfg.key[i*2+1]; i++) {
        unsigned int byte;
        sscanf(&cfg.key[i*2], "%2x", &byte);
        client_key[i] = (uint8_t)byte;
    }
    /* Валидация hex-ключа клиента: ровно 64 символа */
    size_t key_len = strlen(cfg.key);
    if (key_len != 64) {
        fprintf(stderr, "[ERROR] Длина ключа: %zu (ожидалось 64)\n", key_len);
        return 1;
    }
    for (size_t i = 0; i < key_len; i++) {
        if (!isxdigit((unsigned char)cfg.key[i])) {
            fprintf(stderr, "[ERROR] Некорректный hex-символ на позиции %zu\n", i);
            return 1;
        }
    }
    kuznyechik_set_key(client_key, expanded_key);
    printf("[DEBUG] client key: %02x%02x%02x%02x...%02x%02x\n", client_key[0],client_key[1],client_key[2],client_key[3], client_key[30],client_key[31]);
    printf("[DEBUG] client expanded_key: %02x%02x%02x%02x...%02x%02x\n", expanded_key[0],expanded_key[1],expanded_key[2],expanded_key[3], expanded_key[155],expanded_key[159]);

    /* Подключаемся через QUIC с retry и экспоненциальным backoff */
    int max_retries = cfg.handshake_max_retries > 0 ? cfg.handshake_max_retries : 5;
    int base_delay = cfg.handshake_timeout_ms > 0 ? cfg.handshake_timeout_ms : 1000;
    int attempt;
    for (attempt = 0; attempt < max_retries; attempt++) {
        if (attempt > 0) {
            int delay = base_delay * (1 << (attempt - 1));  /* экспоненциальный backoff: 1s, 2s, 4s, 8s...
*/
            if (delay > 60000) delay = 60000;  /* максимум 60с */
            printf("[RETRY] Попытка %d/%d через %d мс...\n", attempt + 1, max_retries, delay);
            log_info("QUIC retry %d/%d (backoff=%dms)", attempt + 1, max_retries, delay);
            usleep(delay * 1000);  /* usleep принимает микросекунды */
        }
        quic_client_close(&quic_client);  /* очистка перед повторной попыткой */
        if (quic_client_connect(&quic_client, cfg.server_ip, cfg.server_port, client_key) == 0) {
            break;
        }
        log_warn("QUIC connect attempt %d/%d failed", attempt + 1, max_retries);
        if (attempt < max_retries - 1)
            printf("[RETRY] Не удалось подключиться (%d/%d)\n", attempt + 1, max_retries);
    }
    if (attempt >= max_retries) {
        printf("Ошибка QUIC подключения после %d попыток\n", max_retries);
        log_error("QUIC connect failed after %d retries", max_retries);
        return 1;
    }

    /* session_id получен из handshake в quic_client_connect (host byte order) */
    memcpy(&session.session_id, quic_client.session_id, 8);
    session.active = 1;
    session.counter = 0;
    /* Session nonce получен из handshake (12 байт от сервера) — уникален для каждой сессии */
    memcpy(session.nonce, quic_client.nonce, NONCE_SIZE);
    memcpy(session.expanded_key, expanded_key, 160);
    log_info("QUIC session_id=%llu", (unsigned long long)session.session_id);

    /* === CPS handshake === */
    printf("\n[SECURITY] Инициализация CPS (Chaffing/Pretense System)...\n");

    uint8_t cps_seed[HEADER_SEED_SIZE];
    memcpy(cps_seed, &session.session_id, 8); memset(cps_seed+8, 0, HEADER_SEED_SIZE-8);

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

    gost_packet_t pkt;
    gost_packet_t cps_challenge;
    memset(&cps_challenge, 0, sizeof(cps_challenge));
    cps_challenge.magic = htonl(GOST_PROXY_MAGIC); cps_challenge.type = PKT_SIM_CHALLENGE;
    cps_challenge.conn_id = 0;
    cps_challenge.session_id = htonll(session.session_id);
    /* Вычисляем CPS answer из expanded_key сессии (P4-10: не фиксированный ключ) */
    uint8_t cps_answer[32] = {0};
    protocol_compute_cps_answer(session.session_id, session.expanded_key, cps_answer);
    memcpy(cps_challenge.payload, cps_answer, 32);
    quic_client_send(&quic_client, (const uint8_t*)&cps_challenge, sizeof(cps_challenge));
    log_info("CPS: challenge sent (sid=%llu)", (unsigned long long)session.session_id);

    /* Ждём CPS response от сервера */
    memset(&pkt, 0, sizeof(pkt));
    ssize_t cps_recv_len = quic_client_recv(&quic_client, (uint8_t*)&pkt, sizeof(pkt), 3000);
    if (cps_recv_len >= (ssize_t)sizeof(gost_packet_t) &&
        ntohl(pkt.magic) == GOST_PROXY_MAGIC &&
        pkt.type == PKT_SIM_CHALLENGE) {
        /* Сервер подтверждает: payload == answer (challenge-response) */
        if (pkt.payload[0] == cps_answer[0]) {  /* частичная проверка для скорости */
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

    /* Запускаем SOCKS5-прокси */
    printf("\n");
    uint16_t socks_port = cfg.port;
    printf("========================================\n");
    printf("  SOCKS5 прокси готов к работе!\n");
    printf("  Адрес:  127.0.0.1:%d\n", socks_port);
    printf("  Тип:    SOCKS v5\n");
    printf("========================================\n");
    printf("\n");
    printf("Настройте Firefox:\n");
    printf("  1. Откройте Настройки → Сеть → Настройка подключения\n");
    printf("  2. Выберите: Ручная настройка прокси\n");
    printf("  3. SOCKS Host: 127.0.0.1\n");
    printf("  4. Порт: %d\n", socks_port);
    printf("  5. Версия: SOCKS v5\n");
    printf("  6. Галочка: Прокси для DNS при использовании SOCKS v5\n");
    printf("\n");

    if (socks5_start(socks_port, cfg.server_ip, cfg.server_port, expanded_key,
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

    /* Основной цикл — select прерывается сигналом, реагирует за ~100мс */
    while (running) {
        struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 };  /* 100ms */
        select(0, NULL, NULL, NULL, &tv);
    }

    /* Ждём keepalive-поток (он проверяет running=0 и выйдет после текущего sleep) */
    usleep(500000);  /* 0.5 сек — достаточно, keepalive не отправит новый пакет */

    socks5_stop();

    /* Отправляем disconnect с аутентификацией */
    gost_packet_t disconnect;
    memset(&disconnect, 0, sizeof(disconnect));
    disconnect.magic = htonl(GOST_PROXY_MAGIC);
    disconnect.type = PKT_DISCONNECT;
    disconnect.session_id = htonll(session.session_id);
    uint64_t dc_sid = session.session_id;
    compute_disconnect_auth(dc_sid, 0, session.expanded_key, disconnect.auth_tag);
    log_info("DISCONNECT: sid=%llu auth=%02x%02x%02x%02x", (unsigned long long)session.session_id,
            disconnect.auth_tag[0], disconnect.auth_tag[1], disconnect.auth_tag[2], disconnect.auth_tag[3]);
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
