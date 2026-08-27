#define _GNU_SOURCE
#include <sys/random.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include "kuznyechik.h"
#include "gost_common.h"
#include "protocol.h"
#include "obfuscation.h"
#include "log.h"

static uint32_t prng_state;
static int prng_initialized = 0;
static void prng_init(void) {
    uint32_t rnd;
    ssize_t nr = getrandom(&rnd, sizeof(rnd), 0);
    if (nr < 0) { rnd = (uint32_t)time(NULL) ^ ((uint32_t)(uintptr_t)&prng_init); }
    prng_state = rnd;
    if (prng_state == 0) prng_state = 0xDEADBEEF;
    prng_initialized = 1;
}
static void prng_seed_u64(uint64_t sv) {
    if (!prng_initialized) {
        prng_init();
        prng_initialized = 0; /* прудет прng_init() */
    }
    prng_state = (uint32_t)(sv ^ (sv >> 32) ^ prng_state);
    if (prng_state == 0) prng_state = 0xDEADBEEF;
}
static uint32_t prng_next(void) {
    uint32_t x = prng_state;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    prng_state = x;
    return x;
}

uint32_t protocol_compute_padding_len(uint64_t sid) {
    /* Фиксированная длина padding для сессии */
    prng_seed_u64(sid);
    return PADDING_MIN_BYTES + (prng_next() % (PADDING_MAX_BYTES - PADDING_MIN_BYTES + 1));
}

void protocol_prng_init(void) {
    /* Инициализация PRNG один раз при запуске из getrandom */
    prng_init();
}

void protocol_insert_padding(uint8_t *p, uint32_t *dl, uint32_t padding_len, uint64_t sid) {
    if (padding_len == 0) return;
    size_t t = (size_t)(*dl) + padding_len;
    if (t > MAX_PAYLOAD - 4) {
        padding_len = (uint32_t)(MAX_PAYLOAD - 4 - (size_t)(*dl));
        if (padding_len == 0) return;
    }
    prng_seed_u64(sid);
    /* Вставляем padding ПОСЛЕ данных, не перед ними */
    memmove(p + 8 + (*dl) + padding_len, p + 8, (size_t)(*dl));
    for (uint32_t i = 0; i < padding_len; i++)
        p[8 + (*dl) + i] = (uint8_t)prng_next();
    *dl += padding_len;
}
static void compute_mac(const uint8_t *pay, size_t plen, const uint8_t *ek, uint8_t *mac) {
    uint8_t b[16]; memset(b,0,16);
    /* Включаем длину в MAC: XOR-им старшие 8 байт с plen */
    uint64_t plen_u64 = plen;
    b[0] ^= (uint8_t)(plen_u64 >> 56);
    b[1] ^= (uint8_t)(plen_u64 >> 48);
    b[2] ^= (uint8_t)(plen_u64 >> 40);
    b[3] ^= (uint8_t)(plen_u64 >> 32);
    b[4] ^= (uint8_t)(plen_u64 >> 24);
    b[5] ^= (uint8_t)(plen_u64 >> 16);
    b[6] ^= (uint8_t)(plen_u64 >> 8);
    b[7] ^= (uint8_t)plen_u64;
    for(size_t o=0;o<plen;o+=16){size_t bl=(plen-o>16)?16:(plen-o);for(size_t i=0;i<bl;i++)b[i]^=pay[o+i];}
    memcpy(mac,b,16); kuznyechik_encrypt_block(mac,ek);
}
static void make_ctr_nonce(const uint8_t *sn, uint32_t c, uint8_t *o16) {
    memcpy(o16,sn,NONCE_SIZE); o16[12]=(c>>24)&0xFF;o16[13]=(c>>16)&0xFF;o16[14]=(c>>8)&0xFF;o16[15]=c&0xFF;
}
int protocol_pack_data(gost_packet_t *pkt, uint64_t session_id, uint32_t conn_id,
    const uint8_t *data, size_t data_len, const uint8_t *ek, const uint8_t *nonce,
    uint32_t *counter, uint8_t obf_dir) {
    if(!pkt||!data||!ek||!nonce||!counter)return -1;
    log_info("PACK_DATA: in_sid=%llu(0x%016llx), out_sid=0x%016llx", (unsigned long long)session_id, (unsigned long long)session_id, (unsigned long long)htonll(session_id));
    if(data_len>MAX_PAYLOAD-4-PADDING_MIN_BYTES)return -1;
    memset(pkt,0,sizeof(gost_packet_t));
    pkt->magic=htonl(GOST_PROXY_MAGIC); pkt->type=PKT_DATA;
    pkt->conn_id=htonl(conn_id); pkt->session_id=htonll(session_id);
    (*counter)+=2; uint32_t pc=*counter;
    pkt->payload[0]=(pc>>24)&0xFF;pkt->payload[1]=(pc>>16)&0xFF;
    pkt->payload[2]=(pc>>8)&0xFF;pkt->payload[3]=pc&0xFF;
    uint32_t plen=protocol_compute_padding_len(session_id);
    memcpy(pkt->payload+8,data,data_len); uint32_t pdl=(uint32_t)data_len;
    uint32_t tl=pdl+plen;
    pkt->payload[4]=(tl>>24)&0xFF;pkt->payload[5]=(tl>>16)&0xFF;
    pkt->payload[6]=(tl>>8)&0xFF;pkt->payload[7]=tl&0xFF;
    protocol_insert_padding(pkt->payload+8,&pdl,plen,session_id);
    uint8_t cn[16]; make_ctr_nonce(nonce,pc,cn);
    kuznyechik_encrypt_ctr(pkt->payload+4,pkt->payload+4,MAX_PAYLOAD-4,ek,cn);
    compute_mac(pkt->payload,8+tl,ek,pkt->auth_tag);
    uint8_t obf_key[OBF_KEY_SIZE];
    obf_key_derive(session_id,obf_dir,obf_key);
    uint32_t h0=ntohl(pkt->magic),h1=ntohl(pkt->conn_id);
    uint64_t h2=htonll(session_id);
    uint8_t hdr[16]={0};
    hdr[0]=(h0>>24)&0xFF;hdr[1]=(h0>>16)&0xFF;hdr[2]=(h0>>8)&0xFF;hdr[3]=h0&0xFF;
    hdr[4]=0x02;hdr[8]=(h1>>24)&0xFF;hdr[9]=(h1>>16)&0xFF;
    hdr[10]=(h1>>8)&0xFF;hdr[11]=h1&0xFF;hdr[12]=(h2>>56)&0xFF;
    hdr[13]=(h2>>48)&0xFF;hdr[14]=(h2>>40)&0xFF;hdr[15]=(h2>>32)&0xFF;
    obfuscate_payload(pkt->payload,8+tl,hdr,obf_key);
    return 0;
}
int protocol_unpack_data(const gost_packet_t *pkt, uint8_t *data, size_t *dl,
    uint32_t *oci, const uint8_t *ek, const uint8_t *nonce, uint32_t *ctr, uint8_t obf_dir) {
    log_info("protocol_unpack_data: START");
    if(!pkt||!data||!dl||!ek||!nonce||!ctr){log_info("protocol_unpack_data: PARAM CHECK FAIL"); return -1;}
    if(oci)*oci=ntohl(pkt->conn_id);
    uint8_t deobf[MAX_PAYLOAD]; memcpy(deobf,pkt->payload,MAX_PAYLOAD);
    uint8_t obf_key[OBF_KEY_SIZE];
    obf_key_derive(ntohll(pkt->session_id),obf_dir,obf_key);
    uint32_t h0=ntohl(pkt->magic),h1=ntohl(pkt->conn_id);
    uint64_t h2=htonll(ntohll(pkt->session_id));
    uint8_t hdr[16]={0};
    hdr[0]=(h0>>24)&0xFF;hdr[1]=(h0>>16)&0xFF;hdr[2]=(h0>>8)&0xFF;hdr[3]=h0&0xFF;
    hdr[4]=pkt->type;hdr[8]=(h1>>24)&0xFF;hdr[9]=(h1>>16)&0xFF;
    hdr[10]=(h1>>8)&0xFF;hdr[11]=h1&0xFF;hdr[12]=(h2>>56)&0xFF;
    hdr[13]=(h2>>48)&0xFF;hdr[14]=(h2>>40)&0xFF;hdr[15]=(h2>>32)&0xFF;
    deobfuscate_payload(deobf,MAX_PAYLOAD-2*AUTH_TAG_SIZE,hdr,obf_key);
    uint32_t pc=((uint32_t)deobf[0]<<24)|((uint32_t)deobf[1]<<16)|((uint32_t)deobf[2]<<8)|(uint32_t)deobf[3];
    if(*ctr!=0&&pc<=*ctr)return -1;
    uint32_t tl=((uint32_t)deobf[4]<<24)|((uint32_t)deobf[5]<<16)|((uint32_t)deobf[6]<<8)|(uint32_t)deobf[7];
    if(tl>MAX_PAYLOAD-4||tl<8)return -1;
    uint8_t emac[AUTH_TAG_SIZE]; compute_mac(deobf,8+tl,ek,emac);
    if(memcmp(pkt->auth_tag,emac,AUTH_TAG_SIZE)!=0)return -1;
    uint32_t rl=tl-8; *dl=rl; memcpy(data,deobf+8,rl); *ctr=pc;
    return 0;
}
int protocol_create_handshake(gost_packet_t *pkt, uint64_t session_id, const uint8_t *ek) {
    if(!pkt||!ek)return -1;
    memset(pkt,0,sizeof(gost_packet_t));
    pkt->magic=htonl(GOST_PROXY_MAGIC);pkt->type=PKT_HANDSHAKE;
    pkt->session_id=htonll(session_id);
    uint8_t sig[16];memset(sig,0,16);memcpy(sig,&session_id,8);
    kuznyechik_encrypt_block(sig,ek);memcpy(pkt->auth_tag,sig,AUTH_TAG_SIZE);
    return 0;
}
static void gen_fake(uint8_t *p, size_t len, uint64_t seed) {
    prng_seed_u64(seed); for(size_t i=0;i<len;i++)p[i]=(uint8_t)prng_next();
}
int protocol_check_counter(uint32_t exp, uint32_t lst) {
    if(exp<=lst){if(lst-exp>COUNTER_WINDOW_SIZE)return -1;return 0;}return 1;
}
int protocol_make_fake_quic(gost_packet_t *p, const uint8_t *s, size_t sl) {
    if(!p||!s)return -1;memset(p,0,sizeof(gost_packet_t));
    p->magic=htonl(GOST_PROXY_MAGIC);p->type=PKT_SIM_QUIC;p->conn_id=htonl(0xDEAD0001);p->session_id=0;
    size_t fl=64+(sl>0?sl:0);if(fl>MAX_PAYLOAD-4)fl=MAX_PAYLOAD-4;
    uint8_t *b=p->payload;b[0]=1;b[1]=0;b[2]=(uint8_t)(fl>>8);b[3]=(uint8_t)fl;b[4]=b[5]=b[6]=0;b[7]=1;
    gen_fake(b+8,fl-8,*(uint64_t*)s);return 0;
}
int protocol_make_fake_dns(gost_packet_t *p, const uint8_t *s, size_t sl) {
    if(!p||!s)return -1;memset(p,0,sizeof(gost_packet_t));
    p->magic=htonl(GOST_PROXY_MAGIC);p->type=PKT_SIM_DNS;p->conn_id=htonl(0xBEEF0002);p->session_id=0;
    size_t fl=128+(sl>0?sl:0);if(fl>MAX_PAYLOAD-4)fl=MAX_PAYLOAD-4;
    uint8_t *b=p->payload;b[0]=0x12;b[1]=0x34;b[2]=1;b[3]=0;b[4]=b[5]=0;b[6]=b[7]=0;b[8]=b[9]=0;b[10]=b[11]=0;
    b[12]=7;memcpy(b+13,"example",7);b[21]=3;memcpy(b+22,"com",3);b[26]=0;
    b[27]=0;b[28]=1;b[29]=0;b[30]=1;gen_fake(b+31,fl-31,*(uint64_t*)s);return 0;
}
int protocol_make_fake_tls(gost_packet_t *p, const uint8_t *s, size_t sl) {
    if(!p||!s)return -1;memset(p,0,sizeof(gost_packet_t));
    p->magic=htonl(GOST_PROXY_MAGIC);p->type=PKT_SIM_TLS;p->conn_id=htonl(0x16030003);p->session_id=0;
    size_t fl=256+(sl>0?sl:0);if(fl>MAX_PAYLOAD-4)fl=MAX_PAYLOAD-4;
    uint8_t *b=p->payload;b[0]=0x16;b[1]=3;b[2]=1;b[3]=(uint8_t)(fl>>8);b[4]=(uint8_t)fl;
    b[5]=1;size_t hl=fl-5;b[6]=(uint8_t)(hl>>16);b[7]=(uint8_t)(hl>>8);b[8]=(uint8_t)hl;
    b[9]=3;b[10]=3;b[11]=(uint8_t)(time(NULL)>>24);b[12]=(uint8_t)(time(NULL)>>16);
    b[13]=(uint8_t)(time(NULL)>>8);b[14]=(uint8_t)time(NULL);
    gen_fake(b+15,43,*(uint64_t*)s);b[58]=32;gen_fake(b+59,32,*(uint64_t*)s);
    size_t co=59+32;b[co]=0;b[co+1]=0x20;gen_fake(b+co+2,32,*(uint64_t*)s);return 0;
}
int protocol_make_cps_challenge(gost_packet_t *p, const uint8_t *s, size_t sl, uint8_t *co, uint8_t *ao) {
    if(!p||!s||!co||!ao)return -1;memset(p,0,sizeof(gost_packet_t));
    p->magic=htonl(GOST_PROXY_MAGIC);p->type=PKT_SIM_CHALLENGE;p->conn_id=0;p->session_id=0;
    uint8_t ch[32];memset(ch,0,32);memcpy(ch,s,sl>32?32:sl);
    uint8_t ek[160],ck[32];memset(ck,0,32);for(int i=0;i<32;i++)ck[i]=(uint8_t)(i*0xAA);
    kuznyechik_set_key(ck,ek);kuznyechik_encrypt_block(ch,ek);
    memcpy(co,ch,32);memcpy(ao,ch,32);memcpy(p->payload,ch,32);memcpy(p->payload+32,ao,32);
    return 0;
}
int protocol_verify_cps_challenge(const gost_packet_t *p, uint8_t *a, size_t al) {
    if(!p||!a||al<32)return -1;
    uint8_t cc[32],ca[32];memcpy(cc,p->payload,32);memcpy(ca,p->payload+32,32);
    uint8_t ek[160],cs[32];memset(cs,0,32);uint64_t sid=ntohll(p->session_id);memcpy(cs,&sid,8);
    uint8_t zb[16]={0};
    for(int i=0;i<4;i++){kuznyechik_set_key(cs,ek);kuznyechik_encrypt_block(zb,ek);memcpy(cs,zb,16);}
    kuznyechik_set_key(cs,ek);uint8_t ea[32];memcpy(ea,cc,32);kuznyechik_encrypt_block(ea,ek);
    if(memcmp(ca,ea,32)==0){memcpy(a,cc,32);return 0;}return -1;
}
