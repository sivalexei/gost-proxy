#ifndef LOG_H
#define LOG_H

#include <stdarg.h>

typedef enum {
    LOG_ERROR = 0,
    LOG_WARN  = 1,
    LOG_INFO  = 2,
    LOG_DEBUG = 3
} log_level_t;

/* Инициализация: открыть файл, установить уровень */
int log_init(const char *level_str, const char *file_path);

/* Закрыть файл лога */
void log_close(void);

/* Лог-функции */
void log_error(const char *fmt, ...);
void log_warn(const char *fmt, ...);
void log_info(const char *fmt, ...);
void log_debug(const char *fmt, ...);

#endif /* LOG_H */
