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
#include "kuznyechik.h"
#include "gost_common.h"
#include "protocol.h"
#include "log.h"
#include "socks5.h"

#define SOCKS5_BUF_SIZE 4096
#define DNS_CACHE_SIZE 256
#define DNS_CACHE_TTL 300
#define MAX_SIMUL_CONNS 64

static atomic_int active_conns = ATOMIC_VAR_INIT(0);

static volatile int socks5_running = 0;
static int socks5_listen_fd = -1;
static gost_session_t proxy_session;
static quic_client_t *proxy_quic = NULL;
static uint32_t *shared_ctr = NULL;
static uint32_t next_cid = 1;

static int tunnel_send(const uint8_t *data, size_t len, uint32_t cid, uint32_t *ctr) {
    log_info("tunnel_send: len=%zu, cid=%u, quic=%p fd=%d", len, cid, proxy_quic, proxy_quic?proxy_quic->server_fd:-1);
    size_t off = 0;
    while (off < len) {
        size_t chunk = len - off;
        if (chunk > MAX_PAYLOAD) chunk = MAX_PAYLOAD;
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
    (void)maxlen;
    uint8_t buf[SOCKS5_BUF_SIZE];
    log_info("tunnel_recv: tmo=%d, expect_cid=%u", tmo, ecid);
    ssize_t n = quic_client_recv(proxy_quic, buf, sizeof(buf), tmo);
    log_info("tunnel_recv: quic returned %zd", n);
    if (n > 0 && n >= (ssize_t)sizeof(gost_packet_t)) {
        const gost_packet_t *pkt = (const gost_packet_t*)buf;
        log_info("tunnel_recv: magic=0x%08x, type=%u, conn_id=%u", ntohl(pkt->magic), pkt->type, ntohl(pkt->conn_id));
        if (ntohl(pkt->magic)==GOST_PROXY_MAGIC && pkt->type==PKT_DATA) {
            if (ntohl(pkt->conn_id)!=ecid) { log_info("tunnel_recv: cid mismatch"); return -1; }
            size_t dl;
            if (protocol_unpack_data(pkt, out, &dl, NULL, proxy_session.expanded_key,
                                    proxy_session.nonce, ctr, 0)==0) {
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
        case 0x01:{struct in_addr a;memcpy(&a,&buf[4],4);inet_ntop(AF_INET,&a,th,sizeof(th));tp=(buf[8]<<8)|buf[9];break;}
        case 0x03:{uint8_t d=buf[4];memcpy(th,&buf[5],d);th[d]='\0';tp=(buf[5+d]<<8)|buf[5+d+1];break;}
        default:{uint8_t e[]={0x05,0x08,0,1,0,0,0,0,0,0};send(fd,e,10,0);close(fd);return NULL;}
    }
    log_info("SOCKS5 CONNECT %s:%u",th,tp);
    uint32_t mcid=__sync_fetch_and_add(&next_cid,1);
    log_info("SOCKS5: sending CONNECT, session_id=%llu, cid=%u", (unsigned long long)proxy_session.session_id, mcid);
    struct in_addr ta;memset(&ta,0,sizeof(ta));
    /* Resolve */
    struct addrinfo hints={0},*res=NULL;hints.ai_family=AF_INET;hints.ai_socktype=SOCK_STREAM;
    if (getaddrinfo(th,NULL,&hints,&res)!=0) {
        uint8_t e[]={0x05,0x04,0,1,0,0,0,0,0,0};send(fd,e,10,0);close(fd);return NULL;
    }
    struct sockaddr_in *sin=(struct sockaddr_in*)res->ai_addr;ta=sin->sin_addr;freeaddrinfo(res);
    uint8_t cd[8];cd[0]=1;cd[1]=1;memcpy(&cd[2],&ta.s_addr,4);cd[6]=(uint8_t)(tp>>8);cd[7]=(uint8_t)tp;
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
        struct sockaddr_in ca; socklen_t al=sizeof(ca);
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
    socks5_listen_fd=socket(AF_INET,SOCK_STREAM,0);
    if (socks5_listen_fd<0){perror("socket");return -1;}
    int opt=1;setsockopt(socks5_listen_fd,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));
    struct sockaddr_in a;memset(&a,0,sizeof(a));a.sin_family=AF_INET;
    a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);a.sin_port=htons(port);
    if (bind(socks5_listen_fd,(struct sockaddr*)&a,sizeof(a))<0){perror("bind");close(socks5_listen_fd);return -1;}
    if (listen(socks5_listen_fd,16)<0){perror("listen");close(socks5_listen_fd);return -1;}
    socks5_running=1;
    pthread_t t;
    if (pthread_create(&t,NULL,socks5_server_thread,NULL)!=0){perror("pthread");close(socks5_listen_fd);return -1;}
    pthread_detach(t);
    return 0;
}

void socks5_stop(void) {
    socks5_running=0;
    if (socks5_listen_fd>=0){close(socks5_listen_fd);socks5_listen_fd=-1;}
}
