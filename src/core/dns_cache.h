#ifndef DNS_CACHE_H
#define DNS_CACHE_H

#include <stdint.h>
#include <netinet/in.h>

/* Кэш DNS-запросов: TTL 1 день, LRU-вытеснение */
#define DNS_CACHE_TTL      86400   /* 1 сутки в секундах */
#define DNS_CACHE_MAX      4096    /* макс. записей в кэше */
#define DNS_CACHE_HOST_MAX 256

/* Один узел кэша */
typedef struct dns_entry {
    char           host[DNS_CACHE_HOST_MAX];
    struct sockaddr_in addr;      /* resolved IP */
    time_t         expires;       /* время истечения */
    struct dns_entry *next;       /* для хеш-таблицы */
    struct dns_entry *lru_next;   /* для LRU-списка */
    struct dns_entry *lru_prev;
} dns_entry_t;

/* Инициализация / уничтожение */
int   dns_cache_init(void);
void  dns_cache_destroy(void);

/* Получить IP по hostname (из кэша или resolve) */
int dns_cache_lookup(const char *host, struct sockaddr_in *out_addr);

/* Очистка просроченных записей */
void dns_cache_expire(void);

#endif /* DNS_CACHE_H */
