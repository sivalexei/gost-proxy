#ifndef SOCKS5_AUTH_H
#define SOCKS5_AUTH_H

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "socks5.h"

// Структура для хранения учётных данных пользователя
typedef struct {
    char username[256];
    char password[256];
} socks5_user_credentials_t;

// Инициализация учётных данных по умолчанию (не аутентифицирован)
void socks5_auth_init(socks5_user_credentials_t *creds) {
    memset(creds->username, 0, sizeof(creds->username));
    memset(creds->password, 0, sizeof(creds->password));
}

// Установка учётных данных
void socks5_auth_set_credentials(socks5_user_credentials_t *creds, const char *username, const char *password) {
    if (username) {
        strncpy(creds->username, username, sizeof(creds->username) - 1);
    }
    if (password) {
        strncpy(creds->password, password, sizeof(creds->password) - 1);
    }
}

#endif /* SOCKS5_AUTH_H */
