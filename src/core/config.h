#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>

typedef struct {
    char     server_ip[64];
    uint16_t server_port;
    char     bind_addr[64];
    uint16_t port;
    int      max_sessions;
    int      session_timeout;
    double   rate_limit;    /* токенов в секунду */
    int      rate_burst;    /* макс. burst (размер бакета) */
    int      handshake_timeout_ms;  /* timeout handshake в мс */
    int      handshake_max_retries; /* макс. попыток handshake */
    char     key[128];  /* hex-key: 64 символа = 32 байт + запас */
    char     log_level[16];
    char     log_file[256];
} gost_config_t;

/* Загрузка конфигурации из JSON-файла */
int config_load(gost_config_t *cfg, const char *path);

/* Значения по умолчанию */
void config_defaults(gost_config_t *cfg);

/* Освобождение памяти конфигурации */
void config_free(gost_config_t *cfg);

#endif /* CONFIG_H */
