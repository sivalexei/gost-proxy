#define _GNU_SOURCE
#include "dns_cache.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "log.h"

static dns_entry_t *hash[1024];
static dns_entry_t  lru_head, lru_tail;  /* doubly-linked LRU */
static pthread_mutex_t dns_lock = PTHREAD_MUTEX_INITIALIZER;
static int cache_size = 0;

static inline unsigned int hash_key(const char *host) {
    unsigned int h = 5381;
    for (const char *p = host; *p; p++)
        h = ((h << 5) + h) + (unsigned char)(*p);
    return h % 1024;
}

/* Удаление записи из LRU-списка */
static void lru_remove(dns_entry_t *e) {
    if (e->lru_prev) e->lru_prev->lru_next = e->lru_next;
    else             lru_head.lru_next = e->lru_next;
    if (e->lru_next) e->lru_next->lru_prev = e->lru_prev;
    else             lru_tail.lru_prev = e->lru_prev;
}

/* Перемещение в конец LRU (самый новый) */
static void lru_touch(dns_entry_t *e) {
    lru_remove(e);
    e->lru_next = &lru_head;
    e->lru_prev = lru_head.lru_prev;
    if (lru_head.lru_prev) lru_head.lru_prev->lru_next = e;
    else                   lru_tail.lru_prev = e;
    lru_head.lru_prev = e;
}

int dns_cache_init(void) {
    lru_head.lru_next = &lru_tail;
    lru_head.lru_prev = NULL;
    lru_tail.lru_next = NULL;
    lru_tail.lru_prev = &lru_head;
    memset(hash, 0, sizeof(hash));
    cache_size = 0;
    return 0;
}

void dns_cache_destroy(void) {
    dns_entry_t *e, *next;
    for (int i = 0; i < 1024; i++) {
        for (e = hash[i]; e; e = next) {
            next = e->next;
            free(e);
        }
    }
    memset(hash, 0, sizeof(hash));
    cache_size = 0;
}

static void __attribute__((unused)) evict_lru(void) {
    dns_entry_t *victim = lru_tail.lru_prev;
    if (victim == &lru_head) return; /* пусто */
    lru_remove(victim);
    unsigned int h = hash_key(victim->host);
    dns_entry_t *prev = NULL, *cur = hash[h];
    for (; cur; prev = cur, cur = cur->next) {
        if (cur == victim) {
            if (prev) prev->next = cur->next;
            else      hash[h] = cur->next;
            break;
        }
    }
    free(victim);
    cache_size--;
    log_debug("DNS cache: evict LRU entry (size=%d)", cache_size);
}

int dns_cache_lookup(const char *host, dns_af_t *out_af, void *out_addr) {
    if (!host || !out_af || !out_addr) return -1;

    pthread_mutex_lock(&dns_lock);

    unsigned int h = hash_key(host);
    dns_entry_t *e;
    for (e = hash[h]; e; e = e->next) {
        if (strcmp(e->host, host) == 0) {
            if (time(NULL) >= e->expires) {
                /* истёк — удаляем */
                lru_remove(e);
                dns_entry_t *prev = NULL, *cur = hash[h];
                for (; cur && cur != e; cur = cur->next) prev = cur;
                if (prev) prev->next = e->next; else hash[h] = e->next;
                free(e);
                cache_size--;
                log_debug("DNS cache: expired entry for %s", host);
                pthread_mutex_unlock(&dns_lock);
                return -1;
            } else {
                /* кэш-попадание */
                *out_af = e->af;
                if (e->af == DNS_AF_INET)
                    memcpy(out_addr, &e->addr.in4, sizeof(struct sockaddr_in));
                else
                    memcpy(out_addr, &e->addr.in6, sizeof(struct sockaddr_in6));
                lru_touch(e);
                pthread_mutex_unlock(&dns_lock);
                return 0;
            }
            break;
        }
    }

    /* Нет в кэше или истёк — resolv (AF_UNSPEC — и IPv4 и IPv6) */
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG;

    int gai = getaddrinfo(host, NULL, &hints, &res);
    if (gai != 0 || !res) {
        log_error("DNS cache: resolve failed for %s: %s", host, gai_strerror(gai));
        pthread_mutex_unlock(&dns_lock);
        return -1;
    }

    /* Берём первый результат (предпочитаем IPv6 если есть) */
    dns_entry_t *ne = malloc(sizeof(dns_entry_t));
    if (!ne) { log_error("DNS cache: malloc failed"); freeaddrinfo(res); pthread_mutex_unlock(&dns_lock); return -1; }

    strncpy(ne->host, host, DNS_CACHE_HOST_MAX - 1);
    ne->host[DNS_CACHE_HOST_MAX - 1] = '\0';
    ne->expires = time(NULL) + DNS_CACHE_TTL;
    ne->lru_next = &lru_head;
    ne->lru_prev = lru_head.lru_prev;
    if (lru_head.lru_prev) lru_head.lru_prev->lru_next = ne;
    else                   lru_tail.lru_prev = ne;
    lru_head.lru_prev = ne;
    ne->next = hash[h];
    hash[h] = ne;
    cache_size++;

    if (res->ai_family == AF_INET6) {
        ne->af = DNS_AF_INET6;
        memcpy(&ne->addr.in6, res->ai_addr, sizeof(struct sockaddr_in6));
        char ipbuf[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &((struct sockaddr_in6*)res->ai_addr)->sin6_addr, ipbuf, sizeof(ipbuf));
        log_debug("DNS cache: resolved %s -> %s (size=%d, TTL=%d)", host, ipbuf, cache_size, DNS_CACHE_TTL);
    } else {
        ne->af = DNS_AF_INET;
        memcpy(&ne->addr.in4, res->ai_addr, sizeof(struct sockaddr_in));
        log_debug("DNS cache: resolved %s -> %s (size=%d, TTL=%d)",
                  host, inet_ntoa(((struct sockaddr_in*)res->ai_addr)->sin_addr), cache_size, DNS_CACHE_TTL);
    }
    freeaddrinfo(res);

    *out_af = ne->af;
    if (ne->af == DNS_AF_INET)
        memcpy(out_addr, &ne->addr.in4, sizeof(struct sockaddr_in));
    else
        memcpy(out_addr, &ne->addr.in6, sizeof(struct sockaddr_in6));
    pthread_mutex_unlock(&dns_lock);
    return 0;
}

void dns_cache_expire(void) {
    pthread_mutex_lock(&dns_lock);
    time_t now = time(NULL);
    for (int i = 0; i < 1024; i++) {
        dns_entry_t *prev = NULL, *cur = hash[i];
        while (cur) {
            dns_entry_t *next = cur->next;
            if (now >= cur->expires) {
                lru_remove(cur);
                if (prev) prev->next = next;
                else      hash[i] = next;
                free(cur);
                cache_size--;
                cur = next;
            } else {
                prev = cur;
                cur = next;
            }
        }
    }
    pthread_mutex_unlock(&dns_lock);
}
