#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <netdb.h>

#include "dns_cache.h"
#include "log.h"

extern void dns_cache_expire(void);

static pthread_mutex_t cache_lock = PTHREAD_MUTEX_INITIALIZER;
static int cache_initialized = 0;
static dns_entry_t *dns_hash_table[DNS_CACHE_MAX];
static dns_entry_t *dns_lru_head = NULL;
static int dns_count = 0;

int dns_cache_init(void) {
    cache_initialized = 1;
    dns_count = 0;
    memset(dns_hash_table, 0, sizeof(dns_hash_table));
    dns_lru_head = NULL;
    pthread_mutex_init(&cache_lock, NULL);
    log_info("DNS cache initialized");
    return 0;
}

int dns_cache_lookup(const char *hostname, dns_af_t *af, void *out_addr) {
    if (!cache_initialized) return -1;
    
    // Ищем в кеше
    pthread_mutex_lock(&cache_lock);
    
    // Проверка хеш-таблицы
    unsigned int hash = 0;
    for (const char *p = hostname; *p; p++) hash += *p;
    hash %= DNS_CACHE_MAX;
    
    dns_entry_t *entry = dns_hash_table[hash];
    while (entry) {
        if (strcmp(entry->host, hostname) == 0) {
            if (time(NULL) < entry->expires) {
                // Кэш активен — используем
                *af = entry->af;
                if (out_addr) {
                    memcpy(out_addr, &entry->addr, 
                           entry->af == DNS_AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
                }
                pthread_mutex_unlock(&cache_lock);
                return 0;
            }
            // Истек — удалить
            entry->next = entry->next ? entry->next : entry; // circular
            entry->lru_prev = entry->lru_prev ? entry->lru_prev : entry;
            entry->lru_next = entry->lru_next ? entry->lru_next : entry;
        }
        entry = entry->next;
    }
    pthread_mutex_unlock(&cache_lock);
    
    // DNS lookup
    struct addrinfo hints, *result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    int ret = getaddrinfo(hostname, NULL, &hints, &result);
    
    pthread_mutex_lock(&cache_lock);
    if (ret == 0 && result) {
        // Добавляем в кеш
        if (dns_count < DNS_CACHE_MAX) {
            dns_entry_t *new_entry = calloc(1, sizeof(dns_entry_t));
            if (new_entry) {
                strncpy(new_entry->host, hostname, DNS_CACHE_HOST_MAX - 1);
                new_entry->af = (result->ai_family == AF_INET) ? DNS_AF_INET : DNS_AF_INET6;
                memcpy(&new_entry->addr, result->ai_addr, 
                       new_entry->af == DNS_AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
                new_entry->expires = time(NULL) + DNS_CACHE_TTL;
                
                // Вставляем в хеш-таблицу
                unsigned int h = hash % DNS_CACHE_MAX;
                new_entry->next = dns_hash_table[h];
                dns_hash_table[h] = new_entry;
                
                // В LRU-список
                if (dns_lru_head) {
                    new_entry->lru_prev = dns_lru_head->lru_prev;
                    new_entry->lru_next = dns_lru_head;
                    dns_lru_head->lru_prev = new_entry;
                    new_entry->lru_prev->lru_next = new_entry;
                } else {
                    dns_lru_head = new_entry->lru_prev = new_entry->lru_next = new_entry;
                }
                
                dns_count++;
            }
        }
        
        *af = dns_hash_table[hash % DNS_CACHE_MAX]->af;
        if (out_addr) {
            memcpy(out_addr, &dns_hash_table[hash % DNS_CACHE_MAX]->addr, 
                   *af == DNS_AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
        }
        
        freeaddrinfo(result);
        log_info("DNS lookup: %s", hostname);
        pthread_mutex_unlock(&cache_lock);
        return 0;
    }
    pthread_mutex_unlock(&cache_lock);
    
    return -1;
}

void dns_cache_destroy(void) {
    pthread_mutex_destroy(&cache_lock);
    cache_initialized = 0;
    dns_count = 0;
    memset(dns_hash_table, 0, sizeof(dns_hash_table));
    log_info("DNS cache destroyed");
}

void dns_cache_expire(void) {
    time_t now = time(NULL);
    pthread_mutex_lock(&cache_lock);
    for (int i = 0; i < DNS_CACHE_MAX; i++) {
        dns_entry_t *entry = dns_hash_table[i];
        while (entry) {
            dns_entry_t *next = entry->next;
            if (entry->expires <= now) {
                // Удаляем из хеш-таблицы
                if (entry->next == entry) {
                    dns_hash_table[i] = NULL;
                } else {
                    dns_hash_table[i] = entry->next;
                }
                // Удаляем из LRU
                entry->lru_next->lru_prev = entry->lru_prev;
                entry->lru_prev->lru_next = entry->lru_next;
                if (dns_lru_head == entry) dns_lru_head = entry->lru_next;
                free(entry);
                if (dns_count > 0) dns_count--;
            }
            entry = next;
        }
    }
    pthread_mutex_unlock(&cache_lock);
    log_info("DNS cache expired old entries");
}