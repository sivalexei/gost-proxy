#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "config.h"

/* Простой JSON-парсер: ищет "key": "value" и "key": number */

/* Извлечь строковое значение: "key": "value"
 * Проверка границ ключа: пробел/скобка до и после имени */
static int json_get_string(const char *json, const char *key, char *out, size_t out_size) {
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    size_t needle_len = strlen(needle);

    const char *p = strstr(json, needle);
    while (p) {
        /* Проверяем границы ключа: символ ДО ключа — не буква/цифра/" */
        if (p > json) {
            char prev = *(p - 1);
            if (isalnum((unsigned char)prev) || prev == '_' || prev == '"') {
                p = strstr(p + 1, needle);  /* пропуск совпадения в середине другого ключа */
                continue;
            }
        }
        /* Символ ПОСЛЕ ключа — должен быть " или пробел */
        char after = *(p + needle_len);
        if (after != ' ' && after != '\t' && after != '\n' && after != '"') {
            p = strstr(p + 1, needle);  /* пропуск */
            continue;
        }
        break;  /* нашли корректный ключ */
    }
    if (!p) return -1;

    p = strchr(p + needle_len, ':');
    if (!p) return -1;
    p++;

    /* Пропускаем пробелы */
    while (*p == ' ' || *p == '\t') p++;

    if (*p == '"') {
        p++;
        const char *end = strchr(p, '"');
        if (!end) return -1;
        size_t len = end - p;
        if (len >= out_size) len = out_size - 1;
        memcpy(out, p, len);
        out[len] = '\0';
        return 0;
    }

    return -1;
}

/* Извлечь числовое значение: "key": 123 */
static int json_get_int(const char *json, const char *key, int *out) {
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\"", key);

    const char *p = strstr(json, needle);
    if (!p) return -1;

    p = strchr(p + strlen(needle), ':');
    if (!p) return -1;
    p++;

    while (*p == ' ' || *p == '\t') p++;

    if (*p == '-' || (*p >= '0' && *p <= '9')) {
        *out = atoi(p);
        return 0;
    }

    return -1;
}

void config_defaults(gost_config_t *cfg) {
    memset(cfg, 0, sizeof(gost_config_t));
    strcpy(cfg->server_ip, "127.0.0.1");
    cfg->server_port = 10443;
    strcpy(cfg->bind_addr, "0.0.0.0");
    cfg->port = 10443;
    cfg->max_sessions = 256;
    cfg->session_timeout = 300;
    cfg->rate_limit = 1000;
    /* Ключ по умолчанию НЕ задаётся — должен быть указан явно или в GOST_PROXY_KEY */
    strcpy(cfg->log_level, "info");
    strcpy(cfg->log_file, "/var/log/gost-proxy/server.log");

    /* Поддержка env-переменной GOST_PROXY_KEY */
    const char *env_key = getenv("GOST_PROXY_KEY");
    if (env_key && env_key[0]) {
        strncpy(cfg->key, env_key, sizeof(cfg->key) - 1);
        cfg->key[sizeof(cfg->key) - 1] = '\0';
    }
}

int config_load(gost_config_t *cfg, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size <= 0 || size > 65536) {
        fclose(f);
        return -1;
    }

    char *json = malloc(size + 1);
    if (!json) {
        fclose(f);
        return -1;
    }

    if (fread(json, 1, (size_t)size, f) != (size_t)size) {
        free(json);
        fclose(f);
        return -1;
    }
    json[size] = '\0';
    fclose(f);

    /* Значения по умолчанию, затем перезаписываем из JSON */
    config_defaults(cfg);

    char tmp[256];
    int ival;

    if (json_get_string(json, "server_ip", tmp, sizeof(tmp)) == 0) {
        strncpy(cfg->server_ip, tmp, sizeof(cfg->server_ip) - 1);
        cfg->server_ip[sizeof(cfg->server_ip) - 1] = '\0';
    }

    if (json_get_int(json, "server_port", &ival) == 0)
        cfg->server_port = (uint16_t)ival;

    if (json_get_string(json, "bind", tmp, sizeof(tmp)) == 0) {
        strncpy(cfg->bind_addr, tmp, sizeof(cfg->bind_addr) - 1);
        cfg->bind_addr[sizeof(cfg->bind_addr) - 1] = '\0';
    }

    if (json_get_int(json, "port", &ival) == 0)
        cfg->port = (uint16_t)ival;

    if (json_get_int(json, "max_sessions", &ival) == 0)
        cfg->max_sessions = ival;

    if (json_get_int(json, "session_timeout", &ival) == 0)
        cfg->session_timeout = ival;

    if (json_get_int(json, "rate_limit", &ival) == 0)
        cfg->rate_limit = ival;

    if (json_get_string(json, "key", tmp, sizeof(tmp)) == 0) {
        strncpy(cfg->key, tmp, sizeof(cfg->key) - 1);
        cfg->key[sizeof(cfg->key) - 1] = '\0';
    }

    if (json_get_string(json, "log_level", tmp, sizeof(tmp)) == 0) {
        strncpy(cfg->log_level, tmp, sizeof(cfg->log_level) - 1);
        cfg->log_level[sizeof(cfg->log_level) - 1] = '\0';
    }

    if (json_get_string(json, "log_file", tmp, sizeof(tmp)) == 0) {
        strncpy(cfg->log_file, tmp, sizeof(cfg->log_file) - 1);
        cfg->log_file[sizeof(cfg->log_file) - 1] = '\0';
    }

    free(json);
    return 0;
}

/* Освобождение памяти конфигурации */
void config_free(gost_config_t *cfg) {
    (void)cfg;  /* В текущей реализации нет динамических выделений */
}
