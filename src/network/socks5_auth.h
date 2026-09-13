#ifndef SOCKS5_AUTH_H
#define SOCKS5_AUTH_H

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// Структура для хранения учётных данных пользователя
typedef struct socks5_auth_t {
    char username[256];
    char password[256];
} socks5_auth_t;

// Инициализация учётных данных по умолчанию (не аутентифицирован)
void socks5_auth_init(socks5_auth_t *creds);

// Установка учётных данных
void socks5_auth_set_credentials(socks5_auth_t *creds, const char *username, const char *password);

// Обработка запроса аутентификации SOCKS5 (RFC 1929)
int socks5_auth_handle_request(const uint8_t *request, size_t request_len,
                              uint8_t *response, size_t *response_len,
                              const socks5_auth_t *creds);

// Обработка запроса на установку соединения после аутентификации
int socks5_auth_establish_connection(uint8_t *response, size_t *response_len);

// Обновление учётных данных пользователя
void socks5_auth_update_credentials(socks5_auth_t *creds,
                                     const char *new_username,
                                     const char *new_password);

#endif /* SOCKS5_AUTH_H */
