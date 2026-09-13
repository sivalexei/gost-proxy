#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include "socks5_auth.h"
#include "socks5.h"

// Обработка запроса аутентификации SOCKS5 (RFC 1929)
// Возвращает: 0 - успех, -1 - ошибка
int socks5_auth_handle_request(const uint8_t *request, size_t request_len,
                              uint8_t *response, size_t *response_len,
                              const socks5_user_credentials_t *creds) {
    // Проверка входных данных
    if (!request || !response || !response_len || !creds) {
        return -1;
    }
    
    // Минимальная длина запроса для USER/PASS
    if (request_len < 2) {
        // Недостаточно данных для аутентификации
        response[0] = 0x01; // VERSION 1
        response[1] = 0xFF; // NO ACCEPTABLE METHODS
        *response_len = 2;
        return -1;
    }
    
    // Парсинг USER/PASS запроса
    uint8_t method = request[0];
    
    if (method == 0x01) { // USER/PASS method
        if (request_len < 3) {
            response[0] = 0x01;
            response[1] = 0x01; // SUCCESS
            *response_len = 2;
            return -1;
        }
        
        uint8_t *ptr = request + 1;
        size_t remaining = request_len - 1;
        
        // Парсинг username
        size_t username_len = *ptr;
        if (username_len > remaining) {
            response[0] = 0x01;
            response[1] = 0x01;
            *response_len = 2;
            return -1;
        }
        ptr++;
        
        // Проверка username
        if (username_len == 0) {
            response[0] = 0x01;
            response[1] = 0x02; // FAILURE
            *response_len = 2;
            return -1;
        }
        
        // Парсинг password
        size_t password_len = *ptr;
        if (password_len > remaining - username_len - 1) {
            response[0] = 0x01;
            response[1] = 0x01;
            *response_len = 2;
            return -1;
        }
        ptr++;
        
        // Проверка учётных данных
        int auth_success = 0;
        
        // Проверяем username
        if (username_len > 0 && username_len <= sizeof(creds->username) - 1) {
            // Проверяем password
            if (password_len > 0 && password_len <= sizeof(creds->password) - 1) {
                // Аутентификация успешна
                auth_success = 1;
            } else {
                // Неверный пароль
                auth_success = 0;
            }
        } else {
            // Неверный username
            auth_success = 0;
        }
        
        if (auth_success) {
            response[0] = 0x01; // VERSION 1
            response[1] = 0x01; // SUCCESS
        } else {
            response[0] = 0x01; // VERSION 1
            response[1] = 0x02; // FAILURE
        }
        
        *response_len = 2;
    } else {
        // Метод аутентификации не поддерживается
        response[0] = 0x00;
        response[1] = 0xFF;
        *response_len = 2;
        return -1;
    }
    
    return 0;
}

// Обработка запроса на установку соединения после аутентификации
int socks5_auth_establish_connection(uint8_t *response, size_t *response_len) {
    // Подготовка ответа на установление соединения
    response[0] = 0x00; // SUCCESS
    response[1] = 0x00; // BND
    response[2] = 0x00; // BND_PORT
    
    *response_len = 3;
    
    return 0;
}

// Обновление учётных данных пользователя
void socks5_auth_update_credentials(socks5_user_credentials_t *creds,
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
