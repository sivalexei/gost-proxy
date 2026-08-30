#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "kuznyechik.h"
#include "gost_common.h"
#include "protocol.h"
#include "obfuscation.h"
static void log_info(const char*f,...){}
static void log_debug(const char*f,...){}
static void log_error(const char*f,...){}
static void log_warn(const char*f,...){}

static void compute_mac(const uint8_t *pay, size_t plen, const uint8_t *ek, uint8_t *mac) {
    uint8_t b[16]; memset(b,0,16);
    uint64_t plen_u64 = plen;
    b[0] ^= (uint8_t)(plen_u64 >> 56);
    b[1] ^= (uint8_t)(plen_u64 >> 48);
    b[2] ^= (uint8_t)(plen_u64 >> 40);
    b[3] ^= (uint8_t)(plen_u64 >> 32);
    b[4] ^= (uint8_t)(plen_u64 >> 24);
    b[5] ^= (uint8_t)(plen_u64 >> 16);
    b[6] ^= (uint8_t)(plen_u64 >> 8);
    b[7] ^= (uint8_t)plen_u64;
    for(size_t i=0;i<plen;i+=16){
        uint8_t block[16];
        memset(block,0,16);
        memcpy(block,pay+i,(plen-i>16)?16:(plen-i));
        for(int j=0;j<16;j++)b[j]^=block[j];
    }
    memcpy(mac,b,16); kuznyechik_encrypt_block(mac,ek);
}
int main(void){
    uint8_t ek[160],nc[NONCE_SIZE],raw[16]={1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    kuznyechik_set_key((uint8_t[]){1,32},ek);
    for(int i=0;i<NONCE_SIZE;i++)nc[i]=(uint8_t)i;
    
    printf("=== DEBUG: pack->unpack ===\n");
    
    gost_packet_t pk;
    memset(&pk,0,sizeof(gost_packet_t));
    uint32_t counter=0;
    size_t dlen=16;
    int rc=protocol_pack_data(&pk,0x1234567890ABULL,1,raw,dlen,ek,nc,&counter,0);
    printf("pack returned: %d\n",rc);
    printf("counter after pack: %u\n",counter);
    
    /* Сохраним копию payload до деобфускации */
    uint8_t payload_after_pack[1500];
    memcpy(payload_after_pack,pk.payload,8+MAX_PAYLOAD-4);
    
    printf("pkt->payload[0..7]: ");
    for(int i=0;i<8;i++)printf("%02x ",pk.payload[i]);
    printf(" pkt->auth_tag[0..7]: ");
    for(int i=0;i<8;i++)printf("%02x ",pk.auth_tag[i]);
    printf("\n");
    
    /* Попробуем вручную вычислить MAC на payload_after_pack */
    uint32_t h0=ntohl(pk.magic),h1=ntohl(pk.conn_id);
    uint64_t h2=0x1234567890ABULL;
    uint8_t hdr[16]={0};
    hdr[0]=(h0>>24)&0xFF;hdr[1]=(h0>>16)&0xFF;hdr[2]=(h0>>8)&0xFF;hdr[3]=h0&0xFF;
    hdr[4]=0x02;hdr[8]=(h1>>24)&0xFF;hdr[9]=(h1>>16)&0xFF;
    hdr[10]=(h1>>8)&0xFF;hdr[11]=h1&0xFF;hdr[12]=(h2>>56)&0xFF;
    hdr[13]=(h2>>48)&0xFF;hdr[14]=(h2>>40)&0xFF;hdr[15]=(h2>>32)&0xFF;
    
    uint8_t obf_key[OBF_KEY_SIZE];
    obf_key_derive(0x1234567890ABULL,0,obf_key);
    
    /* Деобфусцируем вручную */
    uint8_t deobf[1500];
    memcpy(deobf,payload_after_pack,8+MAX_PAYLOAD-4);
    deobfuscate_payload(deobf,8+MAX_PAYLOAD-4,hdr,obf_key);
    
    uint32_t pc=((uint32_t)deobf[0]<<24)|((uint32_t)deobf[1]<<16)|((uint32_t)deobf[2]<<8)|(uint32_t)deobf[3];
    uint32_t tl=((uint32_t)deobf[4]<<24)|((uint32_t)deobf[5]<<16)|((uint32_t)deobf[6]<<8)|(uint32_t)deobf[7];
    printf("Extracted: pc=%u tl=%u\n",pc,tl);
    
    /* Сравним payload_after_pack и deobf */
    printf("Comparing payload_after_pack[0..tl+7] vs deobf[0..tl+7]:\n");
    int match=1;
    for(int i=0;i<8+tl&&i<1500;i++){
        if(payload_after_pack[i]!=deobf[i]){
            printf("  MISMATCH at %d: pack=%02x deobf=%02x\n",i,payload_after_pack[i],deobf[i]);
            match=0;
            if(match==0)break;
        }
    }
    if(match)printf("  ALL MATCH!\n");
    
    /* Вычислим MAC на deobf и на payload_after_pack */
    uint8_t mac1[16],mac2[16];
    compute_mac(deobf,8+tl,ek,mac1);
    compute_mac(payload_after_pack,8+tl,ek,mac2);
    printf("MAC(deobf):   "); for(int i=0;i<16;i++)printf("%02x",mac1[i]);printf("\n");
    printf("MAC(pack):    "); for(int i=0;i<16;i++)printf("%02x",mac2[i]);printf("\n");
    printf("auth_tag:     "); for(int i=0;i<16;i++)printf("%02x",pk.auth_tag[i]);printf("\n");
    
    /* Full unpack */
    uint8_t out[2000]={0};
    size_t ulen=2000;uint32_t ucn=0;
    rc=protocol_unpack_data(&pk,out,&ulen,NULL,ek,nc,&ucn,0);
    printf("unpack returned: %d ucn=%u ulen=%zu\n",rc,ucn,ulen);
    
    return 0;
}
