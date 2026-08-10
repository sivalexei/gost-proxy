#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "src/crypto/kuznyechik.h"
#include "src/crypto/gost_common.h"
#include "src/core/protocol.h"

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
    
    printf("key set OK, expanded[0..3]=%02X %02X %02X %02X\n", expanded[0], expanded[1], expanded[2], expanded[3]);
    
    uint8_t data[] = "Hello, GOST Proxy!";
    size_t data_len = sizeof(data) - 1;
    printf("data_len=%zu\n", data_len);
    
    gost_packet_t *pkt = malloc(sizeof(gost_packet_t));
    if (!pkt) { printf("malloc failed\n"); return 1; }
    memset(pkt, 0, sizeof(gost_packet_t));
    
    printf("\n=== Before pack ===\n");
    printf("pkt->payload[4..7] (before) = %02X %02X %02X %02X\n",
           pkt->payload[4], pkt->payload[5], pkt->payload[6], pkt->payload[7]);
    
    uint32_t counter = 0;
    
    /* Test prng */
    uint8_t test_seed[8];
    protocol_generate_header_seed(session_id, test_seed, HEADER_SEED_SIZE);
    printf("test_seed = %02X %02X %02X %02X %02X %02X %02X %02X\n",
           test_seed[0], test_seed[1], test_seed[2], test_seed[3],
           test_seed[4], test_seed[5], test_seed[6], test_seed[7]);
    
    int ret = protocol_pack_data(pkt, session_id, conn_id, data, data_len,
                                  expanded, nonce, &counter);
    printf("pack ret=%d, counter=%u (expected 2)\n", ret, counter);
    
    printf("\n=== After pack ===\n");
    printf("pkt->payload[0..3] (counter) = %02X %02X %02X %02X\n",
           pkt->payload[0], pkt->payload[1], pkt->payload[2], pkt->payload[3]);
    printf("pkt->payload[4..7] (data_len) = %02X %02X %02X %02X\n",
           pkt->payload[4], pkt->payload[5], pkt->payload[6], pkt->payload[7]);
    printf("pkt->payload[8..15] = %02X %02X %02X %02X %02X %02X %02X %02X\n",
           pkt->payload[8], pkt->payload[9], pkt->payload[10], pkt->payload[11],
           pkt->payload[12], pkt->payload[13], pkt->payload[14], pkt->payload[15]);
    
    /* Теперь unpack */
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
