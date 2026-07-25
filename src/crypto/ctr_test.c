#include <stdio.h>
#include <string.h>
#include "kuznyechik.h"

int main(void) {
    uint8_t key[32] = {
        0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
        0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10,
        0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
        0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10
    };
    uint8_t expanded[160];
    kuznyechik_set_key(key, expanded);

    uint8_t nonce[12] = {0xc6,0x23,0x7b,0x32,0x67,0x45,0x8b,0x6b,0,0,0,0};

    /* Test: full pack/unpack cycle with counter=3, data_len=652 */
    uint8_t pkt_payload[1400];
    memset(pkt_payload, 0, sizeof(pkt_payload));
    uint32_t ctr_val = 3;
    pkt_payload[0] = (ctr_val >> 24); pkt_payload[1] = (ctr_val >> 16);
    pkt_payload[2] = (ctr_val >> 8); pkt_payload[3] = (ctr_val);
    uint32_t dl = 652;
    pkt_payload[4] = (dl >> 24); pkt_payload[5] = (dl >> 16);
    pkt_payload[6] = (dl >> 8); pkt_payload[7] = (dl);
    for (int i = 0; i < 652; i++) pkt_payload[8+i] = (uint8_t)(i * 5 + 11);
    
    /* Encrypt payload[4..] */
    uint8_t ctr[16];
    memcpy(ctr, nonce, 12); ctr[12]=0; ctr[13]=0; ctr[14]=0; ctr[15]=3;
    kuznyechik_encrypt_ctr(pkt_payload + 4, pkt_payload + 4, 1396, expanded, ctr);
    
    /* Read counter from packet */
    uint32_t read_ctr = ((uint32_t)pkt_payload[0] << 24) | ((uint32_t)pkt_payload[1] << 16) |
                        ((uint32_t)pkt_payload[2] << 8) | ((uint32_t)pkt_payload[3]);
    
    /* Decrypt */
    uint8_t result[1396];
    uint8_t ctr2[16];
    memcpy(ctr2, nonce, 12); ctr2[12]=(read_ctr>>24); ctr2[13]=(read_ctr>>16);
    ctr2[14]=(read_ctr>>8); ctr2[15]=(read_ctr);
    kuznyechik_encrypt_ctr(pkt_payload + 4, result, 1396, expanded, ctr2);
    
    uint32_t rdl = ((uint32_t)result[0] << 24) | ((uint32_t)result[1] << 16) |
                   ((uint32_t)result[2] << 8) | ((uint32_t)result[3]);
    
    printf("read_ctr=%u (expected 3)\n", read_ctr);
    printf("data_len=%u (expected 652)\n", rdl);
    printf("first 8 data bytes: ");
    for (int i = 0; i < 8; i++) printf("%02x ", result[4+i]);
    printf("\nexpected: ");
    for (int i = 0; i < 8; i++) printf("%02x ", (uint8_t)(i*5+11));
    printf("\n");
    
    int ok = (read_ctr == 3) && (rdl == 652);
    for (int i = 0; i < 652; i++) {
        if (result[4+i] != (uint8_t)(i*5+11)) { ok = 0; break; }
    }
    printf("Result: %s\n", ok ? "OK" : "FAIL");
    
    return 0;
}
