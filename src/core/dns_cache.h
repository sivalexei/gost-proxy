#ifndef DNS_CACHE_H
#define DNS_CACHE_H

#include <stdint.h>
#include <netinet/in.h>

/* Кэш DNS-запросов: TTL 1 день, LRU-вытеснение */
#define DNS_CACHE_TTL      86400   /* 1 сутки в секундах */
#define DNS_CACHE_MAX      4096    /* макс. записей в кэше */
#define DNS_CACHE_HOST_MAX 256

/* Тип IP-адреса */
typedef enum { DNS_AF_INET=1, DNS_AF_INET6=2 } dns_af_t;

/* Один узел кэша */
typedef struct dns_entry {
    char           host[DNS_CACHE_HOST_MAX];
    dns_af_t       af;            /* AF_INET или AF_INET6 */
    union {
        struct sockaddr_in in4;
        struct sockaddr_in6 in6;
    } addr;                       /* resolved IP */
    time_t         expires;       /* время истечения */
    struct dns_entry *next;       /* для хеш-таблицы */
    struct dns_entry *lru_next;   /* для LRU-списка */
    struct dns_entry *lru_prev;
} dns_entry_t;

/* Инициализация / уничтожение */
int   dns_cache_init(void);
void  dns_cache_destroy(void);

/* Получить IP по hostname (из кэша или resolve, возвращает AF_INET или AF_INET6) */
int dns_cache_lookup(const char *host, dns_af_t *out_af, void *out_addr);

/* Очистка просроченных записей */
void dns_cache_expire(void);

#endif /* DNS_CACHE_H */
