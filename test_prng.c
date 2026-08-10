#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "src/crypto/kuznyechik.h"

extern uint32_t protocol_compute_padding(const uint8_t *seed, uint32_t seed_len);
extern void protocol_generate_header_seed(uint64_t session_id, uint8_t *seed, size_t seed_len);

int main() {
    uint64_t session_id = 0xDEAD0000BEFF1234ULL;
    uint8_t seed[8];
    
    protocol_generate_header_seed(session_id, seed, 8);
    printf("seed = ");
    for (int i = 0; i < 8; i++) printf("%02X ", seed[i]);
    printf("\n");
    
    uint32_t padding = protocol_compute_padding(seed, 8);
    printf("padding_len = %u (should be 4-256)\n", padding);
    
    return 0;
}
