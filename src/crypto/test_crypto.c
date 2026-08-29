#include <stdio.h>
#include <string.h>
#include "kuznyechik.h"
#include "gost_common.h"

static void compute_mac(
    const uint8_t *payload, size_t payload_len,
    const uint8_t *expanded_key,
    uint8_t *mac_out
) {
    uint8_t block[16];
    memset(block, 0, 16);
    /* CBC-MAC: шифруем каждый блок перед XOR'ом со следующим */
    for (size_t offset = 0; offset < payload_len; offset += 16) {
        size_t block_len = (payload_len - offset > 16) ? 16 : (payload_len - offset);
        for (size_t i = 0; i < 16; i++) {
            if (i < block_len) block[i] ^= payload[offset + i];
        }
        kuznyechik_encrypt_block(block, expanded_key);
    }
    /* Включаем длину в MAC: encrypt(accumulator || length) */
    uint64_t plen_u64 = payload_len;
    for (int i = 0; i < 8; i++) block[i + 8] = (uint8_t)(plen_u64 >> (i * 8));
    kuznyechik_encrypt_block(block, expanded_key);
    memcpy(mac_out, block, 16);
}

int main() {
    int failures = 0;
    
    /* Тест 1: MAC вычисление */
    printf("Тест 1: MAC вычисление... ");
    {
        uint8_t key[32];
        for (int i = 0; i < 32; i++) key[i] = i;
        uint8_t expanded[160];
        kuznyechik_set_key(key, expanded);
        
        uint8_t payload[16] = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
                               0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00};
        uint8_t mac[16];
        compute_mac(payload, 16, expanded, mac);
        
        int ok = (mac[0] != 0) && (memcmp(mac, payload, 16) != 0);
        printf(ok ? "OK (MAC=%02X%02X)\n" : "FAIL\n", mac[0], mac[1]);
        if (!ok) failures++;
    }
    
    /* Тест 2: MAC tamper detection */
    printf("Тест 2: MAC tamper detection... ");
    {
        uint8_t key[32];
        for (int i = 0; i < 32; i++) key[i] = i;
        uint8_t expanded[160];
        kuznyechik_set_key(key, expanded);
        
        uint8_t payload1[16] = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
                                0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00};
        uint8_t payload2[16] = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
                                0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x01};
        uint8_t mac1[16], mac2[16];
        compute_mac(payload1, 16, expanded, mac1);
        compute_mac(payload2, 16, expanded, mac2);
        
        int ok = (memcmp(mac1, mac2, 16) != 0);
        printf(ok ? "OK\n" : "FAIL\n");
        if (!ok) failures++;
    }
    
    /* Тест 3: CTR nonce generation */
    printf("Тест 3: CTR nonce generation... ");
    {
        uint8_t nonce[12] = {1,2,3,4,5,6,7,8,9,10,11,12};
        uint32_t counter = 42;
        uint8_t ctr[16];
        memcpy(ctr, nonce, 12);
        ctr[12] = (counter >> 24) & 0xFF;
        ctr[13] = (counter >> 16) & 0xFF;
        ctr[14] = (counter >> 8)  & 0xFF;
        ctr[15] = (counter >> 0)  & 0xFF;
        
        int ok = (ctr[12] == 0 && ctr[13] == 0 && ctr[14] == 0 && ctr[15] == 42);
        printf(ok ? "OK\n" : "FAIL\n");
        if (!ok) failures++;
    }
    
    /* Тест 4: Key expansion determinism */
    printf("Тест 4: Key expansion determinism... ");
    {
        uint8_t key[32];
        for (int i = 0; i < 32; i++) key[i] = i * 0x11;
        uint8_t expanded1[160], expanded2[160];
        
        kuznyechik_set_key(key, expanded1);
        kuznyechik_set_key(key, expanded2);
        
        int ok = (memcmp(expanded1, expanded2, 160) == 0);
        printf(ok ? "OK\n" : "FAIL\n");
        if (!ok) failures++;
    }
    
    /* Тест 5: MAC consistency */
    printf("Тест 5: MAC consistency... ");
    {
        uint8_t key[32];
        for (int i = 0; i < 32; i++) key[i] = i;
        uint8_t expanded[160];
        kuznyechik_set_key(key, expanded);
        
        uint8_t payload[32];
        for (int i = 0; i < 32; i++) payload[i] = i;
        uint8_t mac1[16], mac2[16];
        compute_mac(payload, 32, expanded, mac1);
        compute_mac(payload, 32, expanded, mac2);
        
        int ok = (memcmp(mac1, mac2, 16) == 0);
        printf(ok ? "OK\n" : "FAIL\n");
        if (!ok) failures++;
    }
    
    /* Тест 6: CBC-MAC не инвариантен к перестановке блоков */
    printf("Тест 6: CBC-MAC order-sensitive... ");
    {
        uint8_t key[32];
        for (int i = 0; i < 32; i++) key[i] = i;
        uint8_t expanded[160];
        kuznyechik_set_key(key, expanded);
        
        uint8_t p1[32], p2[32];
        for (int i = 0; i < 16; i++) p1[i] = p2[i] = i;
        for (int i = 16; i < 32; i++) p1[i] = p2[i] = i + 1;
        /* p1: [0..15][17..32]  p2: [17..32][0..15] */
        memcpy(p2, p1 + 16, 16);
        memcpy(p2 + 16, p1, 16);
        uint8_t mac1[16], mac2[16];
        compute_mac(p1, 32, expanded, mac1);
        compute_mac(p2, 32, expanded, mac2);
        
        int ok = (memcmp(mac1, mac2, 16) != 0);
        printf(ok ? "OK (MAC различаются)\n" : "FAIL (MAC одинаковы!)\n");
        if (!ok) failures++;
    }
    
    if (failures == 0) {
        printf("\n=== Все тесты пройдены ===\n");
        return 0;
    }
    printf("\n=== ПРОВАЛЕНО: %d ===\n", failures);
    return 1;
}
