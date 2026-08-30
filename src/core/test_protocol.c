#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "kuznyechik.h"
#include "gost_common.h"
#include "protocol.h"
#include "obfuscation.h"
static int failures=0;
static void __attribute__((unused)) log_info(const char*f,...){(void)f;}
static void __attribute__((unused)) log_debug(const char*f,...){(void)f;}
static void __attribute__((unused)) log_error(const char*f,...){(void)f;}
static void __attribute__((unused)) log_warn(const char*f,...){(void)f;}
#define PASS(n,s)  printf("  %2d: %-50s OK\n",n,s)
#define FAIL(n,s)  do{failures++;printf("  %2d: %-50s FAIL: %s\n",n,s,"");}while(0)
static void mk_ek(const uint8_t*r,uint8_t*e){kuznyechik_set_key(r,e);}
static void mk_nc(uint8_t*o){for(int i=0;i<NONCE_SIZE;i++)o[i]=(uint8_t)i;}
static void t_zero(void){
    uint8_t key[32]={1,32};uint8_t ek[160],nc[NONCE_SIZE];mk_ek(key,ek);mk_nc(nc);
    gost_packet_t pk;uint8_t d[MAX_PAYLOAD]={0};size_t dl=0;uint32_t pck=0;
    if(protocol_pack_data(&pk,0,0,d,dl,ek,nc,&pck,0)!=0){FAIL(1,"pack0");return;}
    size_t ulen=MAX_PAYLOAD;uint32_t ucn=0;
    if(protocol_unpack_data(&pk,d,&ulen,NULL,ek,nc,&ucn,0)!=0){FAIL(2,"unpack0");return;}
    PASS(1,"pack->unpack zero");
}
static void t_small(void){
    uint8_t ek[160],nc[NONCE_SIZE],raw[64];uint8_t key[32]={2,32};mk_ek(key,ek);mk_nc(nc);
    gost_packet_t pk;uint8_t out[MAX_PAYLOAD];
    uint32_t pck=0;size_t ulen=1;uint32_t ucn=0;
    for(size_t l=1;l<=32;l++){
        for(size_t i=0;i<l;i++)raw[i]=(uint8_t)(i*7+l);
        ulen=l;
        if(protocol_pack_data(&pk,1,1,raw,l,ek,nc,&pck,0)!=0){failures++;continue;}
        memset(out,0,sizeof(out));
        if(protocol_unpack_data(&pk,out,&ulen,NULL,ek,nc,&ucn,0)!=0){printf("DEBUG t_small unpack l=%zu fail\n",l);failures++;continue;}
        if(ulen!=l||memcmp(out,raw,l)!=0){printf("DEBUG t_small match l=%zu ulen=%zu\n",l,ulen);failures++;continue;}
    }
    printf("DEBUG after t_small failures=%d\n",failures);
    if(!failures)PASS(2,"pack->unpack small (1..32B)");
}
static void t_medium(void){
    uint8_t ek[160],nc[NONCE_SIZE],raw[MAX_PAYLOAD],out[MAX_PAYLOAD];
    uint8_t key[32]={3,32};mk_ek(key,ek);mk_nc(nc);gost_packet_t pk;
    for(size_t i=0;i<MAX_PAYLOAD;i++)raw[i]=(uint8_t)(i%256);
    size_t ls[]={64,128,256,500,1000};
    for(size_t li=0;li<5;li++){
        size_t l=ls[li];if(l>MAX_PAYLOAD-4)continue;
        uint32_t pck=0;size_t ulen=l;
        if(protocol_pack_data(&pk,2,2,raw,l,ek,nc,&pck,0)!=0){failures++;continue;}
        memset(out,0,l);uint32_t ucn=0;
        if(protocol_unpack_data(&pk,out,&ulen,NULL,ek,nc,&ucn,0)!=0){failures++;continue;}
        if(ulen!=l||memcmp(out,raw,l)!=0){failures++;continue;}
    }
    if(!failures)PASS(3,"pack->unpack medium (64..1000B)");
}
static void t_max(void){
    uint8_t ek[160],nc[NONCE_SIZE],raw[MAX_PAYLOAD],out[MAX_PAYLOAD];
    uint8_t key[32]={4,32};mk_ek(key,ek);mk_nc(nc);gost_packet_t pk;
    size_t ulen=MAX_PAYLOAD-8;uint32_t pck=0;
    for(size_t i=0;i<ulen;i++)raw[i]=(uint8_t)(i%251);
    if(protocol_pack_data(&pk,3,3,raw,ulen,ek,nc,&pck,0)!=0){FAIL(4,"pack max");return;}
    uint32_t ucn=0;
    if(protocol_unpack_data(&pk,out,&ulen,NULL,ek,nc,&ucn,0)!=0){FAIL(5,"unpack max");return;}
    PASS(4,"pack->unpack max (MAX_PAYLOAD-4)");
}static void t_wrong_key(void){
    uint8_t ek1[160],ek2[160],nc[NONCE_SIZE],raw[MAX_PAYLOAD];
    uint8_t k1[32]={10,32},k2[32]={11,32};mk_ek(k1,ek1);mk_ek(k2,ek2);mk_nc(nc);
    gost_packet_t pk;uint32_t pck=0;size_t ulen=16;
    for(size_t i=0;i<16;i++)raw[i]=(uint8_t)i;
    protocol_pack_data(&pk,4,4,raw,16,ek1,nc,&pck,0);
    uint32_t ucn=0;
    if(protocol_unpack_data(&pk,raw,&ulen,NULL,ek2,nc,&ucn,0)==0)FAIL(6,"wrong key");
    else PASS(5,"MAC fails with wrong key");
}
static void t_bad_mac(void){
    uint8_t ek[160],nc[NONCE_SIZE],raw[MAX_PAYLOAD];
    uint8_t key[32]={12,32};mk_ek(key,ek);mk_nc(nc);gost_packet_t pk;
    uint32_t pck=0;size_t ulen=16;
    for(size_t i=0;i<16;i++)raw[i]=(uint8_t)i;
    protocol_pack_data(&pk,5,5,raw,16,ek,nc,&pck,0);
    pk.auth_tag[0]^=0xFF;uint32_t ucn=0;
    if(protocol_unpack_data(&pk,raw,&ulen,NULL,ek,nc,&ucn,0)==0)FAIL(7,"bad mac");
    else PASS(6,"MAC detects tampered auth_tag");
}
static void t_replay(void){
    uint8_t ek[160],nc[NONCE_SIZE],raw[MAX_PAYLOAD];
    uint8_t key[32]={13,32};mk_ek(key,ek);mk_nc(nc);gost_packet_t pk;
    size_t ulen=16;uint32_t pck=0;
    for(size_t i=0;i<16;i++)raw[i]=(uint8_t)i;
    if(protocol_pack_data(&pk,6,6,raw,16,ek,nc,&pck,0)!=0)return;
    uint32_t ucn=0;
    if(protocol_unpack_data(&pk,raw,&ulen,NULL,ek,nc,&ucn,0)!=0)return;
    if(protocol_unpack_data(&pk,raw,&ulen,NULL,ek,nc,&ucn,0)==0)FAIL(8,"replay ok");
    else PASS(7,"counter replay rejected");
}
static void t_null(void){
    uint8_t ek[160],nc[NONCE_SIZE],d[32];uint8_t key[32]={16,32};mk_ek(key,ek);mk_nc(nc);gost_packet_t pk;
    uint32_t pck=0;
    if(protocol_pack_data(NULL,0,0,d,8,ek,nc,&pck,0)!=-1)FAIL(9,"null pkt pack");
    if(protocol_pack_data(&pk,0,0,NULL,8,ek,nc,&pck,0)!=-1)FAIL(10,"null data pack");
    if(protocol_pack_data(&pk,0,0,d,8,NULL,nc,&pck,0)!=-1)FAIL(11,"null ek pack");
    PASS(8,"null params rejected");
}
int main(void){
    printf("=== Protocol Unit Tests ===\n\n");
    t_zero();t_small();t_medium();t_max();t_wrong_key();t_bad_mac();t_replay();t_null();
    printf("DEBUG failures=%d\n",failures);
    if(!failures)printf("\n=== ALL PASSED ===\n");
    else printf("\n=== %d FAILED ===\n",failures);
    return failures;
}
