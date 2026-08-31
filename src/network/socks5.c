#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <stdatomic.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <errno.h>
#include "quic_layer.h"
#include "dns_cache.h"
#include "kuznyechik.h"
#include "gost_common.h"
#include "protocol.h"
#include "dns_cache.h"
#include "log.h"
#include "socks5.h"

#define SOCKS5_BUF_SIZE 4096
#define MAX_SIMUL_CONNS 64
#define QUEUE_SIZE 256

/* Очередь пакетов для одного conn_id */
typedef struct {
    gost_packet_t pkts[QUEUE_SIZE];
    int head, tail, count;
    pthread_mutex_t lock;
    pthread_cond_t  cond;
    int closed;
} packet_queue_t;

static atomic_int active_conns = ATOMIC_VAR_INIT(0);

static volatile int socks5_running = 0;
static int socks5_listen_fd = -1;
static gost_session_t proxy_session;
static quic_client_t *proxy_quic = NULL;
static uint32_t *shared_ctr = NULL;
static uint32_t next_cid = 1;

/* Демультиплексор */
static packet_queue_t queues[MAX_SIMUL_CONNS];
static int demux_running = 0;
static pthread_t demux_tid;

static inline packet_queue_t* queue_get(uint32_t cid) {
    if (cid >= MAX_SIMUL_CONNS) return NULL;
    return &queues[cid];
}

static inline void queue_push(packet_queue_t *q, const gost_packet_t *pkt) {
    pthread_mutex_lock(&q->lock);
    if (q->count < QUEUE_SIZE) {
        q->pkts[q->tail] = *pkt;
        q->tail = (q->tail + 1) % QUEUE_SIZE;
        q->count++;
        pthread_cond_signal(&q->cond);
    }
    pthread_mutex_unlock(&q->lock);
}

static inline int queue_pop(packet_queue_t *q, gost_packet_t *out, int timeout_ms) {
    pthread_mutex_lock(&q->lock);
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += timeout_ms / 1000;
    ts.tv_nsec += (timeout_ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
    while (q->count == 0 && !q->closed) {
        if (pthread_cond_timedwait(&q->cond, &q->lock, &ts) != 0) {
            pthread_mutex_unlock(&q->lock);
            return 0;
        }
    }
    if (q->count == 0) { pthread_mutex_unlock(&q->lock); return -1; }
    *out = q->pkts[q->head];
    q->head = (q->head + 1) % QUEUE_SIZE;
    q->count--;
    pthread_mutex_unlock(&q->lock);
    return sizeof(gost_packet_t);
}

static inline int queue_init(packet_queue_t *q) {
    pthread_mutex_init(&q->lock, NULL);
    pthread_cond_init(&q->cond, NULL);
    q->head = q->tail = q->count = q->closed = 0;
    return 0;
}

static inline void queue_destroy(packet_queue_t *q) {
    q->closed = 1;
    pthread_cond_broadcast(&q->cond);
    pthread_mutex_destroy(&q->lock);
    pthread_cond_destroy(&q->cond);
}

/* Демультиплексор: читает из UDP, разбрасывает по очередям */
static void* demux_thread_func(void *arg) {
    quic_client_t *qc = (quic_client_t *)arg;
    uint8_t buf[4096];
    while (demux_running) {
        struct pollfd pfd = { .fd = qc->server_fd, .events = POLLIN };
        int ret = poll(&pfd, 1, 200);
        if (ret <= 0) continue;
        if (!(pfd.revents & POLLIN)) continue;
        ssize_t n = recvfrom(qc->server_fd, buf, sizeof(buf), 0, NULL, NULL);
        if (n <= 0 || n < (ssize_t)sizeof(gost_packet_t)) continue;
        const gost_packet_t *pkt = (const gost_packet_t *)buf;
        if (ntohl(pkt->magic) != GOST_PROXY_MAGIC) continue;
        uint32_t cid = ntohl(pkt->conn_id);
        if (cid == 0) continue; /* handshake/keepalive без conn_id */
        packet_queue_t *q = queue_get(cid);
        if (q) queue_push(q, pkt);
    }
    return NULL;
}

static int tunnel_send(const uint8_t *data, size_t len, uint32_t cid, uint32_t *ctr) {
    if (!data || !ctr || len == 0) { log_info("tunnel_send: bad params"); return -1; }
    log_info("tunnel_send: len=%zu, cid=%u, quic=%p fd=%d", len, cid, proxy_quic, proxy_quic?proxy_quic->server_fd:-1);
    size_t off = 0;
    while (off < len) {
        size_t chunk = len - off;
        if (chunk > MAX_PAYLOAD - 4 - PADDING_MIN_BYTES) chunk = MAX_PAYLOAD - 4 - PADDING_MIN_BYTES;
        gost_packet_t pkt; memset(&pkt, 0, sizeof(pkt));
        if (protocol_pack_data(&pkt, proxy_session.session_id, cid, data+off, chunk,
                              proxy_session.expanded_key, proxy_session.nonce, ctr, 0) != 0) {
            log_error("tunnel_send: protocol_pack_data failed");
            return -1;
        }
        ssize_t sent = quic_client_send(proxy_quic, (const uint8_t*)&pkt, sizeof(gost_packet_t));
        log_info("tunnel_send: quic sent=%zd (chunk=%zu)", sent, chunk);
        if (sent < 0) return -1;
        off += chunk;
    }
    return 0;
}

static int tunnel_recv(uint8_t *out, size_t maxlen, int tmo, uint32_t ecid, uint32_t *ctr) {
    if (!out || !ctr || maxlen < 1) return -1;
    gost_packet_t pkt;
    int n = queue_pop(queue_get(ecid), &pkt, tmo);
    log_info("tunnel_recv: queue_pop returned %d, cid=%u, magic=%u, type=%u, conn_id=%u", n, ecid, ntohl(pkt.magic), pkt.type, ntohl(pkt.conn_id));
    if (n > 0) {
        if (ntohl(pkt.magic)==GOST_PROXY_MAGIC && pkt.type==PKT_DATA && ntohl(pkt.conn_id)==ecid) {
            size_t dl;
            if (protocol_unpack_data(&pkt, out, &dl, NULL, proxy_session.expanded_key,
                                    proxy_session.nonce, ctr, 0)==0) {
                if (dl > maxlen) dl = maxlen;
                log_info("tunnel_recv: unpacked %zu bytes", dl);
                return (int)dl;
            }
        }
    }
    return -1;
}

static void* proxy_data_thread(void *arg) {
    typedef struct { int fd; uint32_t cid; } parg_t;
    parg_t *p = (parg_t*)arg; int fd=p->fd; uint32_t mcid=p->cid; free(p);
    uint32_t sc=0, rc=1; uint8_t buf[SOCKS5_BUF_SIZE];
    while (socks5_running) {
        struct pollfd pf={.fd=fd,.events=POLLIN}; int r=poll(&pf,1,100);
        if (r>0&&(pf.revents&POLLIN)) {
            ssize_t n=recv(fd,buf,sizeof(buf),0); if (n<=0)break;
            if (tunnel_send(buf,n,mcid,&sc)!=0)break;
        }
        uint8_t resp[SOCKS5_BUF_SIZE];
        int rl=tunnel_recv(resp,sizeof(resp),50,mcid,&rc);
        if (rl>0) {
            size_t ts=0;
            while (ts<(size_t)rl) { ssize_t s=send(fd,resp+ts,rl-ts,MSG_NOSIGNAL); if (s<=0)goto cc; ts+=s; }
            while (socks5_running) {
                int el=tunnel_recv(resp,sizeof(resp),10,mcid,&rc); if (el<=0)break;
                size_t es=0;
                while (es<(size_t)el) { ssize_t s=send(fd,resp+es,el-es,MSG_NOSIGNAL); if (s<=0)goto cc; es+=s; }
            }
        }
    }
cc: close(fd); atomic_fetch_sub(&active_conns,1); return NULL;
}

static void* socks5_client_thread(void *arg) {
    int wc=0;
    while (atomic_load(&active_conns)>=MAX_SIMUL_CONNS) {
        if (wc++>100){int *p=(int*)arg; int fd=*p; free(p); close(fd); log_warn("Backpressure");return NULL;}
        usleep(100000);
    }
    atomic_fetch_add(&active_conns,1);
    int fd=*(int*)arg; free(arg); uint8_t buf[SOCKS5_BUF_SIZE];
    ssize_t n=recv(fd,buf,sizeof(buf),0);
    if (n<2||buf[0]!=0x05){close(fd);return NULL;}
    uint8_t ar[]={0x05,0x00}; send(fd,ar,2,0);
    n=recv(fd,buf,sizeof(buf),0);
    if (n<4||buf[0]!=0x05||buf[1]!=0x01){close(fd);return NULL;}
    char th[256]={0}; uint16_t tp=0;
    switch(buf[3]){
        case 0x01:{ /* IP v4: ATYP(1) + ADDR(4) + PORT(2) = 7 байт */
            if (n < 10){close(fd);return NULL;}
            struct in_addr a;memcpy(&a,&buf[4],4);inet_ntop(AF_INET,&a,th,sizeof(th));tp=(buf[8]<<8)|buf[9];break;}
        case 0x03:{ /* Domain: ATYP(1) + DLEN(1) + ADDR(dlen) + PORT(2) = 4+dlen */
            uint8_t d=buf[4];
            if (d < 1 || n < 5 + d + 2){close(fd);return NULL;}
            memcpy(th,&buf[5],d);th[d]='\0';tp=(buf[5+d]<<8)|buf[5+d+1];break;}
        case 0x04:{ /* IP v6: ATYP(1) + ADDR(16) + PORT(2) = 19 */
            if (n < 22){close(fd);return NULL;}
            struct in6_addr a6;memcpy(&a6,&buf[4],16);inet_ntop(AF_INET6,&a6,th,sizeof(th));tp=(buf[20]<<8)|buf[21];break;}
        default:{uint8_t e[]={0x05,0x08,0,1,0,0,0,0,0,0};send(fd,e,10,0);close(fd);return NULL;}
    }
    log_info("SOCKS5 CONNECT %s:%u",th,tp);
    uint32_t mcid=__sync_fetch_and_add(&next_cid,1);
    log_info("SOCKS5: sending CONNECT, session_id=%llu, cid=%u", (unsigned long long)proxy_session.session_id, mcid);
    /* DNS-кэш с LRU и TTL 1 сутки, поддержка IPv6 */
    dns_af_t af;
    union { struct sockaddr_in in4; struct sockaddr_in6 in6; } sin;
    if (dns_cache_lookup(th, &af, &sin)!=0) {
        uint8_t e[]={0x05,0x04,0,1,0,0,0,0,0,0};send(fd,e,10,0);close(fd);return NULL;
    }
    uint8_t cd[16+2]; uint8_t dlen=0;
    if (af==DNS_AF_INET) {
        cd[0]=1;cd[1]=1;memcpy(&cd[2],&sin.in4.sin_addr.s_addr,4);dlen=10;
    } else {
        cd[0]=1;cd[1]=4;memcpy(&cd[2],&sin.in6.sin6_addr.s6_addr,16);dlen=22;
    }
    cd[dlen-2]=(uint8_t)(tp>>8);cd[dlen-1]=(uint8_t)tp;
    uint32_t csc=0;
    log_info("SOCKS5: calling tunnel_send, dlen=8, cid=%u", mcid);
    int ts = tunnel_send(cd,8,mcid,&csc);
    log_info("SOCKS5: tunnel_send returned %d", ts);
    if (ts!=0){uint8_t e[]={0x05,0x1,0,1,0,0,0,0,0,0};send(fd,e,10,0);close(fd);return NULL;}
    uint32_t crc=1; uint8_t resp[SOCKS5_BUF_SIZE];
    log_info("SOCKS5: waiting for CONNECT response, mcid=%u", mcid);
    int rl=tunnel_recv(resp,sizeof(resp),5000,mcid,&crc);
    log_info("SOCKS5: tunnel_recv returned %d", rl);
    if (rl<2||resp[0]!=0x02||resp[1]!=0x00){uint8_t e[]={0x05,0x5,0,1,0,0,0,0,0,0};send(fd,e,10,0);close(fd);return NULL;}
    uint8_t rep[]={0x05,0,0,1,0,0,0,0,0,0};send(fd,rep,10,0);
    typedef struct { int fd; uint32_t cid; } parg_t;
    parg_t *pa=malloc(sizeof(parg_t));pa->fd=fd;pa->cid=mcid;
    pthread_t t;pthread_create(&t,NULL,proxy_data_thread,pa);pthread_detach(t);
    return NULL;
}

static void* socks5_server_thread(void *arg) {
    (void)arg;
    while (socks5_running) {
        struct sockaddr_storage ca; socklen_t al=sizeof(ca);
        int fd=accept(socks5_listen_fd,(struct sockaddr*)&ca,&al);
        if (fd<0){if(socks5_running)log_error("accept: %s",strerror(errno));continue;}
        int *fp=malloc(sizeof(int));*fp=fd;
        pthread_t t;
        if (pthread_create(&t,NULL,socks5_client_thread,fp)!=0){log_error("pthread: %s",strerror(errno));close(fd);free(fp);}
        else pthread_detach(t);
    }
    return NULL;
}

int socks5_start(uint16_t port, const char *sip, uint16_t sport,
                 const uint8_t *ek, const uint8_t *nonce,
                 uint64_t sid, quic_client_t *qc, uint32_t *sc) {
    (void)sip;(void)sport;
    memset(&proxy_session,0,sizeof(gost_session_t));
    proxy_session.session_id=sid;proxy_session.active=1;proxy_session.counter=0;
    memcpy(proxy_session.nonce,nonce,NONCE_SIZE);
    memcpy(proxy_session.expanded_key,ek,160);
    proxy_quic=qc;shared_ctr=sc;
    /* Инициализация очередей */
    for (int i = 0; i < MAX_SIMUL_CONNS; i++) queue_init(&queues[i]);
    socks5_listen_fd=socket(AF_INET6,SOCK_STREAM,0);
    if (socks5_listen_fd<0){perror("socket");return -1;}
    int opt=1;setsockopt(socks5_listen_fd,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));
    int ipv6only=0;setsockopt(socks5_listen_fd,IPPROTO_IPV6,IPV6_V6ONLY,&ipv6only,sizeof(ipv6only));
    struct sockaddr_in6 a6;memset(&a6,0,sizeof(a6));a6.sin6_family=AF_INET6;
    a6.sin6_addr=in6addr_any;a6.sin6_port=htons(port);
    if (bind(socks5_listen_fd,(struct sockaddr*)&a6,sizeof(a6))<0){
        /* Fallback: IPv6 не сработал, пробуем AF_INET */
        close(socks5_listen_fd);
        socks5_listen_fd=socket(AF_INET,SOCK_STREAM,0);
        if (socks5_listen_fd<0){perror("socket");return -1;}
        setsockopt(socks5_listen_fd,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));
        struct sockaddr_in a;memset(&a,0,sizeof(a));a.sin_family=AF_INET;
        a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);a.sin_port=htons(port);
        if (bind(socks5_listen_fd,(struct sockaddr*)&a,sizeof(a))<0){perror("bind");close(socks5_listen_fd);return -1;}
    }
    if (listen(socks5_listen_fd,16)<0){perror("listen");close(socks5_listen_fd);return -1;}
    socks5_running=1;
    demux_running=1;
    if (pthread_create(&demux_tid,NULL,demux_thread_func,proxy_quic)!=0){perror("demux pthread");close(socks5_listen_fd);return -1;}
    pthread_detach(demux_tid);
    pthread_t t;
    if (pthread_create(&t,NULL,socks5_server_thread,NULL)!=0){perror("pthread");close(socks5_listen_fd);return -1;}
    pthread_detach(t);
    return 0;
}

void socks5_stop(void) {
    socks5_running=0;
    demux_running=0;
    pthread_join(demux_tid, NULL);
    for (int i = 0; i < MAX_SIMUL_CONNS; i++) queue_destroy(&queues[i]);
    if (socks5_listen_fd>=0){close(socks5_listen_fd);socks5_listen_fd=-1;}
}
