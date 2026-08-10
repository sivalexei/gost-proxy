#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "src/crypto/kuznyechik.h"
#include "src/crypto/gost_common.h"

#define MAX_PAYLOAD 1400
#define NONCE_SIZE 12
#define HEADER_SEED_SIZE 8

static void compute_mac(const uint8_t *p, size_t len, const uint8_t *ek, uint8_t *mac) {
    uint8_t block[16];
    memset(block, 0, 16);
    for (size_t o = 0; o < len; o += 16) {
        size_t bl = (len - o > 16) ? 16 : (len - o);
        for (size_t i = 0; i < bl; i++) block[i] ^= p[o + i];
    }
    memcpy(mac, block, 16);
    kuznyechik_encrypt_block(mac, ek);
}

static void make_ctr_nonce(const uint8_t *n, uint32_t c, uint8_t *out) {
    memcpy(out, n, NONCE_SIZE);
    out[12] = (c >> 24) & 0xFF; out[13] = (c >> 16) & 0xFF;
    out[14] = (c >> 8) & 0xFF; out[15] = c & 0xFF;
}

void protocol_generate_header_seed(uint64_t session_id, uint8_t *seed, size_t seed_len);
uint32_t protocol_compute_padding(const uint8_t *seed, uint32_t seed_len);
void protocol_generate_header_permutation(const uint8_t *seed, uint8_t *perm, size_t perm_len);
void protocol_insert_padding(uint8_t *payload, uint32_t *data_len, uint32_t padding_len, const uint8_t *seed);

int main() {
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = i;
    uint64_t session_id = 0xDEAD0000BEFF1234ULL;
    uint8_t nonce[12] = {1,2,3,4,5,6,7,8,9,10,11,12};
    uint8_t expanded[160];
    kuznyechik_set_key(key, expanded);
    
    uint8_t data[] = "Hello, GOST Proxy!";
    size_t data_len = sizeof(data) - 1;
    uint8_t payload[MAX_PAYLOAD];
    memset(payload, 0, MAX_PAYLOAD);
    
    uint32_t pkt_counter = 0;
    payload[0]=(pkt_counter>>24)&0xFF; payload[1]=(pkt_counter>>16)&0xFF;
    payload[2]=(pkt_counter>>8)&0xFF; payload[3]=pkt_counter&0xFF;
    
    uint8_t seed[HEADER_SEED_SIZE];
    protocol_generate_header_seed(session_id, seed, HEADER_SEED_SIZE);
    uint32_t padding_len = protocol_compute_padding(seed, HEADER_SEED_SIZE);
    printf("padding_len=%u\n", padding_len);
    
    memcpy(payload + 8, data, data_len);
    uint32_t total_data_len = (uint32_t)data_len + padding_len;
    payload[4]=(total_data_len>>24)&0xFF; payload[5]=(total_data_len>>16)&0xFF;
    payload[6]=(total_data_len>>8)&0xFF; payload[7]=total_data_len&0xFF;
    
    protocol_insert_padding(payload + 8, &total_data_len, padding_len, seed);
    printf("total_data_len after padding=%u\n", total_data_len);
    
    uint8_t perm[4];
    protocol_generate_header_permutation(seed, perm, 4);
    printf("perm=[%u,%u,%u,%u]\n", perm[0], perm[1], perm[2], perm[3]);
    
    /* Apply permutation */
    {
        uint8_t tmp[MAX_PAYLOAD];
        for (size_t i = 0; i < total_data_len; i++) {
            size_t src = i % 4;
            tmp[i] = payload[8 + perm[src] % total_data_len];
        }
        memcpy(payload + 8, tmp, total_data_len);
    }
    
    /* Encrypt payload[4..] */
    uint8_t ctr[16];
    make_ctr_nonce(nonce, pkt_counter, ctr);
    kuznyechik_encrypt_ctr(payload + 4, payload + 4, MAX_PAYLOAD - 4, expanded, ctr);
    
    /* Compute MAC */
    uint8_t auth_tag[16];
    compute_mac(payload, MAX_PAYLOAD, expanded, auth_tag);
    
    /* === UNPACK === */
    printf("\n=== UNPACK ===\n");
    uint32_t read_ctr = (payload[0]<<24)|(payload[1]<<16)|(payload[2]<<8)|payload[3];
    printf("read_ctr=%u\n", read_ctr);
    
    uint8_t exp_mac[16];
    compute_mac(payload, MAX_PAYLOAD, expanded, exp_mac);
    printf("MAC match: %s\n", memcmp(auth_tag, exp_mac, 16)==0 ? "OK" : "FAIL");
    
    uint8_t dec[MAX_PAYLOAD - 4];
    make_ctr_nonce(nonce, read_ctr, ctr);
    kuznyechik_encrypt_ctr(payload + 4, dec, MAX_PAYLOAD - 4, expanded, ctr);
    
    uint32_t read_total = (dec[0]<<24)|(dec[1]<<16)|(dec[2]<<8)|dec[3];
    printf("read_total_len=%u (expected %u)\n", read_total, total_data_len);
    
    if (read_total != total_data_len) {
        printf("FAIL: total_len mismatch!\n");
        printf("dec[0..3]=%02X %02X %02X %02X\n", dec[0], dec[1], dec[2], dec[3]);
        printf("orig[4..7]=%02X %02X %02X %02X\n",
               (total_data_len>>24)&0xFF, (total_data_len>>16)&0xFF,
               (total_data_len>>8)&0xFF, total_data_len&0xFF);
        return 1;
    }
    
    printf("UNPACK SUCCESS (partial)\n");
    return 0;
}
