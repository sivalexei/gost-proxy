#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <pthread.h>
#include <sys/stat.h>

#include "log.h"

#define LOG_MAX_SIZE  (10 * 1024 * 1024)  /* 10MB */
#define LOG_MAX_FILES  5

static FILE *log_fp = NULL;
static log_level_t current_level = LOG_INFO;
static char log_file_path[512] = {0};
static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;

static const char *level_names[] = {
    "ERROR", "WARN", "INFO", "DEBUG"
};

/* Ротация логов: если файл больше LOG_MAX_SIZE — переименовываем */
static void rotate_log(const char *path) {
    struct stat st;
    if (stat(path, &st) < 0 || st.st_size < LOG_MAX_SIZE) return;

    /* Удаляем самый старый архив */
    char oldest[600];
    snprintf(oldest, sizeof(oldest), "%s.%d", path, LOG_MAX_FILES);
    remove(oldest);

    /* Сдвигаем все архивы: .4 → .5, .3 → .4, ..., .1 → .2 */
    for (int i = LOG_MAX_FILES - 1; i >= 1; i--) {
        char src[600], dst[600];
        snprintf(src, sizeof(src), "%s.%d", path, i);
        snprintf(dst, sizeof(dst), "%s.%d", path, i + 1);
        rename(src, dst);
    }
    char rotated_name[600];
    snprintf(rotated_name, sizeof(rotated_name), "%s.1", path);
    rename(path, rotated_name);
}

/* Создание директории рекурсивно (mkdir -p) */
static void mkdirs(const char *path) {
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
}

int log_init(const char *level_str, const char *file_path) {
    /* Определяем уровень */
    current_level = LOG_INFO;
    if (level_str) {
        if (strcmp(level_str, "error") == 0) current_level = LOG_ERROR;
        else if (strcmp(level_str, "warn") == 0) current_level = LOG_WARN;
        else if (strcmp(level_str, "info") == 0) current_level = LOG_INFO;
        else if (strcmp(level_str, "debug") == 0) current_level = LOG_DEBUG;
    }

    /* Открываем файл лога (если указан) */
    if (file_path && file_path[0]) {
        strncpy(log_file_path, file_path, sizeof(log_file_path) - 1);
        log_file_path[sizeof(log_file_path) - 1] = '\0';
        /* Создаём директорию если не существует */
        char dir[512];
        snprintf(dir, sizeof(dir), "%s", file_path);
        char *slash = strrchr(dir, '/');
        if (slash) {
            *slash = '\0';
            mkdirs(dir);
        }
        rotate_log(log_file_path);
        log_fp = fopen(file_path, "a");
        if (!log_fp) {
            /* Fallback: /tmp если /var/log недоступен */
            const char *fallback = "/tmp/gost-proxy.log";
            fprintf(stderr, "[LOG] Не удалось открыть %s, fallback: %s\n", file_path, fallback);
            log_fp = fopen(fallback, "a");
            if (!log_fp) {
                fprintf(stderr, "[LOG] Не удалось открыть %s: ", fallback);
                perror("");
                return -1;
            }
        }
    }

    return 0;
}

void log_close(void) {
    if (log_fp) {
        fclose(log_fp);
        log_fp = NULL;
    }
}

static void log_write(log_level_t level, const char *fmt, va_list args) {
    if (level > current_level) return;

    pthread_mutex_lock(&log_lock);

    /* Время */
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);

    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tm);

    /* Формируем сообщение */
    char msg[2048];
    vsnprintf(msg, sizeof(msg), fmt, args);

    /* Пишем в stderr */
    fprintf(stderr, "%s [%-5s] %s\n", timestamp, level_names[level], msg);
    fflush(stderr);

    /* Пишем в файл (если открыт) */
    if (log_fp) {
        fprintf(log_fp, "%s [%-5s] %s\n", timestamp, level_names[level], msg);
        fflush(log_fp);
    }

    pthread_mutex_unlock(&log_lock);
}

void log_error(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_write(LOG_ERROR, fmt, args);
    va_end(args);
}

void log_warn(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_write(LOG_WARN, fmt, args);
    va_end(args);
}

void log_info(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_write(LOG_INFO, fmt, args);
    va_end(args);
}

void log_debug(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_write(LOG_DEBUG, fmt, args);
    va_end(args);
}
