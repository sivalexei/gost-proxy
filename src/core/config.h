#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <time.h>

/* Структура конфигурации сервера */
typedef struct {
    char server_ip[256];    /* IP сервера для связи с прокси */
    uint16_t server_port;   /* Порт сервера */
    char bind_addr[256];    /* Адрес bind для UDP-сокета сервера */
    uint16_t port;          /* Порт для UDP-сокета */
    char socks5_bind[256];  /* Адрес bind для SOCKS5 */
    uint16_t socks5_port;   /* Порт для SOCKS5 */
    char socks5_user[256];  /* Пользователь SOCKS5 */
    char socks5_pass[256];  /* Пароль SOCKS5 */
    int max_sessions;       /* Максимальное число сессий */
    int max_sessions_per_ip;/* Максимальное число сессий на IP */
    int session_timeout;    /* Таймаут сессии в секундах */
    double rate_limit;      /* Лимит скорости (пакетов/сек) */
    int rate_burst;         /* Burst для rate limiting */
    int handshake_timeout_ms; /* Таймаут handshake */
    int handshake_max_retries; /* Макс. повторов handshake */
    char key[65];           /* Hex-ключ 32 байта */
    char log_level[16];     /* Уровень логирования */
    char log_file[256];     /* Файл логов */
} gost_config_t;

/* Загрузка конфигурации из JSON */
int config_load(gost_config_t *cfg, const char *path);

/* Инициализация defaults */
void config_defaults(gost_config_t *cfg);

/* Освобождение ресурсов */
void config_free(gost_config_t *cfg);

#endif /* CONFIG_H */
