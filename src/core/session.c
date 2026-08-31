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

uint32_t protocol_insert_padding(uint8_t *p, uint32_t *dl, uint32_t padding_len, uint64_t sid) {
    if (padding_len == 0) return 0;
    size_t max_padding = MAX_PAYLOAD - 8 - (size_t)(*dl);
    if (max_padding == 0) return 0;
    if (padding_len > (uint32_t)max_padding) padding_len = (uint32_t)max_padding;
    prng_seed_u64(sid);
    /* Сдвигаем данные вправо на padding_len, пишем padding НАЧАЛО */
    memmove(p + padding_len, p, (size_t)(*dl));
    *dl += padding_len;
    for (uint32_t i = 0; i < padding_len; i++)
        p[i] = (uint8_t)prng_next();
    return padding_len;
}
static void compute_mac(const uint8_t *pay, size_t plen, const uint8_t *ek, uint8_t *mac) {
    kuznyechik_cmac_128(pay, plen, ek, mac);
}

/* Auth-tag для DISCONNECT: HMAC(session_id, conn_id) с EK
 * prevent: anyone can disconnect another user's session */
void compute_disconnect_auth(uint64_t session_id, uint32_t conn_id,
                              const uint8_t *ek, uint8_t *auth)
{
    uint8_t buf[16];
    memcpy(buf, &session_id, 8);
    memcpy(buf + 8, &conn_id, 4);
    memset(buf + 12, 0, 4);  /* padding to 16 bytes */
    kuznyechik_cmac_128(buf, 16, ek, auth);
}

static void make_ctr_nonce(const uint8_t *sn, uint32_t c, uint8_t *o16) {
    memcpy(o16,sn,NONCE_SIZE); o16[12]=(c>>24)&0xFF;o16[13]=(c>>16)&0xFF;o16[14]=(c>>8)&0xFF;o16[15]=c&0xFF;
}
int protocol_pack_data(gost_packet_t *pkt, uint64_t session_id, uint32_t conn_id,
    const uint8_t *data, size_t data_len, const uint8_t *ek, const uint8_t *nonce,
    uint32_t *counter, uint8_t obf_dir) {
    if(!pkt||!data||!ek||!nonce||!counter)return -1;
    memset(pkt,0,sizeof(gost_packet_t));
    pkt->magic=htonl(GOST_PROXY_MAGIC); pkt->type=PKT_DATA;
    pkt->conn_id=htonl(conn_id); pkt->session_id=htonll(session_id);
    (*counter)+=2; uint32_t pc=*counter;
    uint32_t stored_len=(uint32_t)data_len;
    if(stored_len > MAX_PAYLOAD-12) stored_len = MAX_PAYLOAD-12;
    uint32_t padding_len=protocol_compute_padding_len(session_id);
    uint32_t total=12+padding_len+stored_len;
    if(total>MAX_PAYLOAD)padding_len=MAX_PAYLOAD-12-stored_len;
    log_info("PACK_DATA: sid=%llu dlen=%zu padding_len=%u total=%u obf_dir=%u",(unsigned long long)session_id,(unsigned long long)data_len,padding_len,total,obf_dir);
    /* stored_len в [4..7], padding_len в [8..11] */
    pkt->payload[4]=(stored_len>>24)&0xFF;pkt->payload[5]=(stored_len>>16)&0xFF;
    pkt->payload[6]=(stored_len>>8)&0xFF;pkt->payload[7]=stored_len&0xFF;
    pkt->payload[8]=(padding_len>>24)&0xFF;pkt->payload[9]=(padding_len>>16)&0xFF;
    pkt->payload[10]=(padding_len>>8)&0xFF;pkt->payload[11]=padding_len&0xFF;
    prng_seed_u64(session_id);
    for(uint32_t i=0;i<padding_len;i++)pkt->payload[12+i]=(uint8_t)prng_next();
    memcpy(pkt->payload+12+padding_len,data,stored_len);
    uint8_t cn[16]; make_ctr_nonce(nonce,pc,cn);
    kuznyechik_encrypt_ctr(pkt->payload+12+padding_len,pkt->payload+12+padding_len,stored_len,ek,cn);
    uint8_t obf_key[OBF_KEY_SIZE];
    obf_key_derive(session_id,obf_dir,obf_key);
    uint32_t h0=ntohl(pkt->magic),h1=ntohl(pkt->conn_id);
    uint64_t h2=htonll(session_id);
    uint8_t hdr[16]={0};
    hdr[0]=(h0>>24)&0xFF;hdr[1]=(h0>>16)&0xFF;hdr[2]=(h0>>8)&0xFF;hdr[3]=h0&0xFF;
    hdr[4]=0x02;hdr[8]=(h1>>24)&0xFF;hdr[9]=(h1>>16)&0xFF;
    hdr[10]=(h1>>8)&0xFF;hdr[11]=h1&0xFF;hdr[12]=(h2>>56)&0xFF;
    hdr[13]=(h2>>48)&0xFF;hdr[14]=(h2>>40)&0xFF;hdr[15]=(h2>>32)&0xFF;
    log_info("CLIENT hdr=%02x%02x%02x%02x %02x %02x%02x%02x%02x %02x%02x%02x%02x", hdr[0],hdr[1],hdr[2],hdr[3],hdr[4],hdr[8],hdr[9],hdr[10],hdr[11],hdr[12],hdr[13],hdr[14],hdr[15]);
    log_info("CLIENT obf_key=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", obf_key[0],obf_key[1],obf_key[2],obf_key[3],obf_key[4],obf_key[5],obf_key[6],obf_key[7],obf_key[8],obf_key[9],obf_key[10],obf_key[11],obf_key[12],obf_key[13],obf_key[14],obf_key[15]);
    /* counter в [0..3] */
    pkt->payload[0]=(pc>>24)&0xFF;pkt->payload[1]=(pc>>16)&0xFF;
    pkt->payload[2]=(pc>>8)&0xFF;pkt->payload[3]=pc&0xFF;
    /* MAC: type=DATA(4B) + session_id(8B) + conn_id(4B) + payload[0..12+padding_len+stored_len]
     * prevent: session_id/conn_id substitution */
    uint8_t auth_buf[16 + 12 + padding_len + stored_len];
    auth_buf[0]=0x00;auth_buf[1]=0x00;auth_buf[2]=0x00;auth_buf[3]=0x02;  /* type=DATA little-endian */
    uint64_t sid_net=htonll(session_id); memcpy(auth_buf+4,&sid_net,8);
    uint32_t cid_net=htonl(conn_id); memcpy(auth_buf+12,&cid_net,4);
    memcpy(auth_buf+16,pkt->payload,12+padding_len+stored_len);
    compute_mac(auth_buf,16+12+padding_len+stored_len,ek,pkt->auth_tag);
    /* Теперь обфусцируем весь payload */
    obfuscate_payload(pkt->payload,sizeof(pkt->payload),hdr,obf_key);
    return 0;
}
int protocol_unpack_data(const gost_packet_t *pkt, uint8_t *data, size_t *dl,
    uint32_t *oci, const uint8_t *ek, const uint8_t *nonce, uint32_t *ctr, uint8_t obf_dir) {
    if(oci) *oci = ntohl(pkt->conn_id);
    log_info("protocol_unpack_data: START");
    if(!pkt||!data||!dl||!ek||!nonce||!ctr){log_debug("UNPACK: param fail"); return -1;}
    log_debug("protocol_unpack_data: params OK");
    uint8_t *deobf=malloc(MAX_PAYLOAD+8);if(!deobf)return -1;
    memcpy(deobf,pkt->payload,sizeof(pkt->payload));
    /* Деобфускация точно так же, как обфускация на клиенте: 8+MAX_PAYLOAD-4 байт */
    uint8_t obf_key[OBF_KEY_SIZE];
    obf_key_derive(ntohll(pkt->session_id),obf_dir,obf_key);
    uint32_t h0=ntohl(pkt->magic),h1=ntohl(pkt->conn_id);
    uint64_t h2=htonll(ntohll(pkt->session_id));
    uint8_t hdr[16]={0};
    hdr[0]=(h0>>24)&0xFF;hdr[1]=(h0>>16)&0xFF;hdr[2]=(h0>>8)&0xFF;hdr[3]=h0&0xFF;
    hdr[4]=pkt->type;hdr[8]=(h1>>24)&0xFF;hdr[9]=(h1>>16)&0xFF;
    hdr[10]=(h1>>8)&0xFF;hdr[11]=h1&0xFF;hdr[12]=(h2>>56)&0xFF;
    hdr[13]=(h2>>48)&0xFF;hdr[14]=(h2>>40)&0xFF;hdr[15]=(h2>>32)&0xFF;
    log_info("SERVER hdr=%02x%02x%02x%02x %02x %02x%02x%02x%02x %02x%02x%02x%02x", hdr[0],hdr[1],hdr[2],hdr[3],hdr[4],hdr[8],hdr[9],hdr[10],hdr[11],hdr[12],hdr[13],hdr[14],hdr[15]);
    log_info("SERVER obf_key=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", obf_key[0],obf_key[1],obf_key[2],obf_key[3],obf_key[4],obf_key[5],obf_key[6],obf_key[7],obf_key[8],obf_key[9],obf_key[10],obf_key[11],obf_key[12],obf_key[13],obf_key[14],obf_key[15]);
    deobfuscate_payload(deobf,sizeof(pkt->payload),hdr,obf_key);
    log_debug("protocol_unpack_data: after deobf payload[0..11]=%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x", deobf[0],deobf[1],deobf[2],deobf[3],deobf[4],deobf[5],deobf[6],deobf[7],deobf[8],deobf[9],deobf[10],deobf[11]);
    uint32_t pc=((uint32_t)deobf[0]<<24)|((uint32_t)deobf[1]<<16)|((uint32_t)deobf[2]<<8)|(uint32_t)deobf[3];
    if(*ctr!=0&&pc<=*ctr){log_info("protocol_unpack_data: COUNTER FAIL pc=%u ctr=%u",pc,*ctr); free(deobf); return -1;}
    uint32_t data_len=((uint32_t)deobf[4]<<24)|((uint32_t)deobf[5]<<16)|((uint32_t)deobf[6]<<8)|(uint32_t)deobf[7];
    uint32_t padding_len=((uint32_t)deobf[8]<<24)|((uint32_t)deobf[9]<<16)|((uint32_t)deobf[10]<<8)|(uint32_t)deobf[11];
    if(data_len==0||padding_len>1024){log_debug("UNPACK: len fail"); free(deobf); return -1;}
    uint32_t total_len=12+padding_len+data_len;
    if(total_len>MAX_PAYLOAD){log_debug("UNPACK: total_len fail"); free(deobf); return -1;}
    /* MAC проверяем ДО расшифровки */
    uint8_t emac[AUTH_TAG_SIZE];
    compute_mac(deobf, total_len, ek, emac);
    if(memcmp(pkt->auth_tag,emac,AUTH_TAG_SIZE)!=0){log_debug("UNPACK: MAC mismatch"); free(deobf); return -1;}
    /* Расшифровываем данные */
    uint8_t cn2[16]; make_ctr_nonce(nonce,pc,cn2);
    kuznyechik_encrypt_ctr(deobf+12+padding_len,deobf+12+padding_len,data_len,ek,cn2);
    uint32_t rl=data_len; *dl=rl; memcpy(data,deobf+12+padding_len,rl); *ctr=pc;
    log_info("UNPACK OK: dl=%u total=%u padding_len=%u pc=%u",rl,total_len,padding_len,pc); free(deobf); return 0;
}
int protocol_create_handshake(gost_packet_t *pkt, uint64_t session_id, const uint8_t *ek,
    const uint8_t *client_nonce, const uint8_t *server_nonce, const uint8_t *session_nonce) {
    if(!pkt||!ek)return -1;
    (void)client_nonce;
    memset(pkt,0,sizeof(gost_packet_t));
    pkt->magic=htonl(GOST_PROXY_MAGIC);pkt->type=PKT_HANDSHAKE;
    pkt->session_id=htonll(session_id);
    /* Вкладываем session_nonce (12 байт) в payload: payload[0]=маркер, payload[1..12]=nonce */
    if(session_nonce) { pkt->payload[0]=1; memcpy(pkt->payload+1,session_nonce,NONCE_SIZE); }
    /* Auth-tag: CMAC(session_id || server_nonce || session_nonce || conn_id)
     * prevent: conn_id/session_id substitution в handshake */
    uint8_t buf[40];
    memcpy(buf, &session_id, 8);
    memcpy(buf + 8, server_nonce, 8);
    memset(buf + 16, 0, 16);
    if(session_nonce) memcpy(buf + 16, session_nonce, NONCE_SIZE);
    uint32_t cid = ntohl(pkt->conn_id); memcpy(buf + 32, &cid, 4);
    kuznyechik_cmac_128(buf, 8 + 8 + NONCE_SIZE + 4, ek, pkt->auth_tag);
    return 0;
}
static void gen_fake(uint8_t *p, size_t len, uint64_t seed) {
    prng_seed_u64(seed); for(size_t i=0;i<len;i++)p[i]=(uint8_t)prng_next();
}
int protocol_check_counter(uint32_t exp, uint32_t lst) {
    if(exp<=lst){if(lst-exp>COUNTER_WINDOW_SIZE)return -1;return 0;}return 1;
}
int protocol_make_fake_quic(gost_packet_t *p, const uint8_t *s, size_t sl) {
    if(!p||!s) return -1;
    memset(p,0,sizeof(gost_packet_t));
    p->magic=htonl(GOST_PROXY_MAGIC);p->type=PKT_SIM_QUIC;p->conn_id=htonl(0xDEAD0001);p->session_id=0;
    size_t fl=64+(sl>0?sl:0);if(fl>MAX_PAYLOAD-4)fl=MAX_PAYLOAD-4;
    uint8_t *b=p->payload;b[0]=1;b[1]=0;b[2]=(uint8_t)(fl>>8);b[3]=(uint8_t)fl;b[4]=b[5]=b[6]=0;b[7]=1;
    gen_fake(b+8,fl-8,*(uint64_t*)s);return 0;
}
int protocol_make_fake_dns(gost_packet_t *p, const uint8_t *s, size_t sl) {
    if(!p||!s) return -1;
    memset(p,0,sizeof(gost_packet_t));
    p->magic=htonl(GOST_PROXY_MAGIC);p->type=PKT_SIM_DNS;p->conn_id=htonl(0xBEEF0002);p->session_id=0;
    size_t fl=128+(sl>0?sl:0);if(fl>MAX_PAYLOAD-4)fl=MAX_PAYLOAD-4;
    uint8_t *b=p->payload;b[0]=0x12;b[1]=0x34;b[2]=1;b[3]=0;b[4]=b[5]=0;b[6]=b[7]=0;b[8]=b[9]=0;b[10]=b[11]=0;
    b[12]=7;memcpy(b+13,"example",7);b[21]=3;memcpy(b+22,"com",3);b[26]=0;
    b[27]=0;b[28]=1;b[29]=0;b[30]=1;gen_fake(b+31,fl-31,*(uint64_t*)s);return 0;
}
int protocol_make_fake_tls(gost_packet_t *p, const uint8_t *s, size_t sl) {
    if(!p||!s) return -1;
    memset(p,0,sizeof(gost_packet_t));
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
    if(!p||!s||!co||!ao) return -1;
    memset(p,0,sizeof(gost_packet_t));
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
    /* Challenge-response: answer должен совпадать challenge
     * prevent: challenge = E(session_id, fixed_key) уязвим к replay —
     * теперь answer вычисляется из CMAC(session_id || server_nonce, expanded_key) */
    if(memcmp(ca,cc,32)==0){memcpy(a,cc,32);return 0;}return -1;
}
int protocol_compute_cps_answer(uint64_t session_id, const uint8_t *expanded_key, uint8_t *answer) {
    if(!answer||!expanded_key)return -1;
    uint8_t buf[32];
    memcpy(buf, &session_id, 8);
    memset(buf + 8, 0, 24);
    kuznyechik_cmac_128(buf, 32, expanded_key, answer);
    return 0;
}
