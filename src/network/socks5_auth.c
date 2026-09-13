#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include "socks5_auth.h"
#include "socks5.h"

// Инициализация учётных данных по умолчанию (не аутентифицирован)
void socks5_auth_init(socks5_auth_t *creds) {
    memset(creds->username, 0, sizeof(creds->username));
    memset(creds->password, 0, sizeof(creds->password));
}

// Установка учётных данных
void socks5_auth_set_credentials(socks5_auth_t *creds, const char *username, const char *password) {
    if (username) {
        strncpy(creds->username, username, sizeof(creds->username) - 1);
    }
    if (password) {
        strncpy(creds->password, password, sizeof(creds->password) - 1);
    }
}

// Обработка запроса аутентификации SOCKS5 (RFC 1929)
int socks5_auth_handle_request(const uint8_t *request, size_t request_len,
                              uint8_t *response, size_t *response_len,
                              const socks5_auth_t *creds) {
    (void)creds;
    (void)request;
    (void)request_len;
    
    response[0] = 0x00; response[1] = 0xFF; *response_len = 2;
    return -1;
}

// Обработка запроса на установку соединения после аутентификации
int socks5_auth_establish_connection(uint8_t *response, size_t *response_len) {
    response[0] = 0x00; response[1] = 0x00; response[2] = 0x00;
    *response_len = 3;
    return 0;
}

// Обновление учётных данных пользователя
void socks5_auth_update_credentials(socks5_auth_t *creds,
                                     const char *new_username,
                                     const char *new_password) {
    if (creds) {
        if (new_username) {
            strncpy(creds->username, new_username, sizeof(creds->username) - 1);
        }
        if (new_password) {
            strncpy(creds->password, new_password, sizeof(creds->password) - 1);
        }
    }
}
