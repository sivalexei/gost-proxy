#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "src/crypto/kuznyechik.h"
#include "src/crypto/gost_common.h"
#include "src/core/protocol.h"

/* Прототипы из session.c */
int protocol_pack_data(
    gost_packet_t *pkt,
    uint64_t session_id,
    uint32_t conn_id,
    const uint8_t *data,
    size_t data_len,
    const uint8_t *expanded_key,
    const uint8_t *nonce,
    uint32_t *counter
);

int protocol_unpack_data(
    const gost_packet_t *pkt,
    uint8_t *data,
    size_t *data_len,
    uint32_t *out_conn_id,
    const uint8_t *expanded_key,
    const uint8_t *nonce,
    uint32_t *counter
);

int main() {
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = i;
    
    uint64_t session_id = 0xDEAD0000BEFF1234ULL;
    uint32_t conn_id = 42;
    uint8_t nonce[12] = {1,2,3,4,5,6,7,8,9,10,11,12};
    
    uint8_t expanded[160];
    kuznyechik_set_key(key, expanded);
    
    printf("key set OK\n");
    
    uint8_t data[] = "Hello, GOST Proxy!";
    size_t data_len = sizeof(data) - 1;
    
    gost_packet_t *pkt = malloc(sizeof(gost_packet_t));
    if (!pkt) { printf("malloc failed\n"); return 1; }
    uint32_t counter = 0;
    
    printf("=== Pack ===\n");
    int ret = protocol_pack_data(pkt, session_id, conn_id, data, data_len,
                                  expanded, nonce, &counter);
    printf("pack ret=%d, counter=%u\n", ret, counter);
    
    if (ret == 0) {
        printf("payload[4..7] (data_len): %02X %02X %02X %02X\n",
               pkt->payload[4], pkt->payload[5], pkt->payload[6], pkt->payload[7]);
        uint32_t hdr_len = ((uint32_t)pkt->payload[4] << 24) |
                           ((uint32_t)pkt->payload[5] << 16) |
                           ((uint32_t)pkt->payload[6] << 8)  |
                           ((uint32_t)pkt->payload[7]);
        printf("hdr_len=%u (expected %zu)\n", hdr_len, data_len);
    }
    
    if (ret == 0) {
        printf("\n=== Unpack ===\n");
        uint8_t out_data[MAX_PAYLOAD];
        size_t out_len = sizeof(out_data);
        uint32_t out_counter = 0;
        
        int unpack_ret = protocol_unpack_data(pkt, out_data, &out_len, NULL,
                                               expanded, nonce, &out_counter);
        printf("unpack ret=%d, out_len=%zu, out_counter=%u\n", unpack_ret, out_len, out_counter);
        
        if (unpack_ret == 0) {
            printf("out data: ");
            for (size_t i = 0; i < out_len; i++) printf("%02X ", out_data[i]);
            printf("\nexpected: ");
            for (size_t i = 0; i < data_len; i++) printf("%02X ", data[i]);
            printf("\n");
            
            if (out_len == data_len && memcmp(out_data, data, data_len) == 0) {
                printf("SUCCESS: roundtrip OK\n");
            } else {
                printf("FAIL: data mismatch\n");
            }
        } else {
            printf("FAIL: unpack returned %d\n", unpack_ret);
        }
    }
    
    free(pkt);
    return 0;
}
