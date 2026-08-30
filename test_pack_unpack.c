#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "protocol.h"

int main() {
    uint8_t ek[32];
    memset(ek, 0x42, 32);
    uint8_t nonce[12] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c};
    uint32_t counter = 100;
    uint64_t session_id = 0xDEADBEEFCAFEBABE;
    uint32_t conn_id = 42;
    uint8_t data[] = "Hello, Gost-Proxy!";
    size_t data_len = sizeof(data)-1;
    uint8_t out[4096];
    size_t out_len = sizeof(out);
    gost_packet_t pkt;
    
    int r = protocol_pack_data(&pkt, session_id, conn_id, data, data_len, ek, nonce, &counter, 0);
    printf("pack: %d, counter now=%u\n", r, counter);
    
    uint32_t oci = 0, pc = 0;
    r = protocol_unpack_data(&pkt, out, &out_len, &oci, ek, nonce, &pc, 0);
    printf("unpack: %d, data_len=%zu, pc=%u, data=%.*s\n", r, out_len, (int)out_len, out);
    
    return (r == 0 && out_len == data_len && memcmp(out, data, data_len) == 0) ? 0 : 1;
}
