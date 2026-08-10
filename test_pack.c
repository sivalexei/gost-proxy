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
    
    uint8_t data[] = "Hello, GOST Proxy!";
    size_t data_len = sizeof(data) - 1;
    
    gost_packet_t pkt;
    uint32_t counter = 0;
    
    printf("=== Pack ===\n");
    int ret = protocol_pack_data(&pkt, session_id, conn_id, data, data_len,
                                  expanded, nonce, &counter);
    printf("pack ret=%d, counter after=%u\n", ret, counter);
    printf("magic=0x%08X type=0x%02X conn_id=%u\n",
           ntohl(pkt.magic), pkt.type, ntohl(pkt.conn_id));
    printf("payload[0..3] (counter): %02X %02X %02X %02X\n",
           pkt.payload[0], pkt.payload[1], pkt.payload[2], pkt.payload[3]);
    printf("payload[4..7] (data_len): %02X %02X %02X %02X\n",
           pkt.payload[4], pkt.payload[5], pkt.payload[6], pkt.payload[7]);
    printf("payload[8..15]: %02X %02X %02X %02X %02X %02X %02X %02X\n",
           pkt.payload[8], pkt.payload[9], pkt.payload[10], pkt.payload[11],
           pkt.payload[12], pkt.payload[13], pkt.payload[14], pkt.payload[15]);
    printf("auth_tag: %02X %02X %02X %02X %02X %02X %02X %02X\n",
           pkt.auth_tag[0], pkt.auth_tag[1], pkt.auth_tag[2], pkt.auth_tag[3],
           pkt.auth_tag[4], pkt.auth_tag[5], pkt.auth_tag[6], pkt.auth_tag[7]);
    
    printf("\n=== Unpack ===\n");
    uint8_t out_data[MAX_PAYLOAD];
    size_t out_len = sizeof(out_data);
    uint32_t out_counter = 0;
    
    int unpack_ret = protocol_unpack_data(&pkt, out_data, &out_len, NULL,
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
    
    /* Test 2: tampered packet rejection */
    printf("\n=== Tamper test ===\n");
    pkt.payload[8] ^= 0xFF;  /* corrupt */
    uint8_t out_data2[16];
    size_t out_len2 = 16;
    uint32_t counter2 = 0;
    int tamper_ret = protocol_unpack_data(&pkt, out_data2, &out_len2, NULL,
                                           expanded, nonce, &counter2);
    printf("tamper unpack ret=%d (expected -1): %s\n", tamper_ret,
           tamper_ret == -1 ? "OK" : "FAIL");
    
    /* Test 3: larger data */
    printf("\n=== Larger data test ===\n");
    uint8_t big_data[256];
    for (int i = 0; i < 256; i++) big_data[i] = (uint8_t)(i * 7 + 3);
    size_t big_len = 256;
    uint32_t counter3 = 2;
    
    if (protocol_pack_data(&pkt, session_id, conn_id, big_data, big_len,
                           expanded, nonce, &counter3) == 0) {
        uint8_t out_big[MAX_PAYLOAD];
        size_t out_big_len = sizeof(out_big);
        uint32_t out_ctr3 = 0;
        
        if (protocol_unpack_data(&pkt, out_big, &out_big_len, NULL,
                                 expanded, nonce, &out_ctr3) == 0) {
            if (out_big_len == big_len && memcmp(out_big, big_data, big_len) == 0) {
                printf("LARGE DATA roundtrip OK (len=%zu)\n", big_len);
            } else {
                printf("FAIL: large data mismatch (got %zu)\n", out_big_len);
            }
        } else {
            printf("FAIL: large data unpack error\n");
        }
    } else {
        printf("FAIL: large data pack error\n");
    }
    
    return 0;
}
