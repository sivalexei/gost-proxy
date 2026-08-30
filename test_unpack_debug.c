#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "protocol.h"

int main() {
    uint8_t ek[32]; memset(ek, 0x42, 32);
    uint8_t nonce[12] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c};
    uint32_t counter = 100;
    uint64_t session_id = 0xDEADBEEFCAFEBABE;
    uint32_t conn_id = 42;
    uint8_t data[] = "Hello";
    size_t data_len = sizeof(data)-1;
    uint8_t out[4096]; size_t out_len = sizeof(out);
    gost_packet_t pkt;
    
    protocol_pack_data(&pkt, session_id, conn_id, data, data_len, ek, nonce, &counter, 0);
    
    // После деобфускации payload должен иметь:
    // [0..3] = pc=102, [4..7] = stored_len=5, [8..11] = padding_len
    printf("BEFORE unpack, pkt.payload[0..11]:");
    for(int i=0;i<12;i++) printf(" %02x",pkt.payload[i]);
    printf("\n");
    
    uint32_t oci=0, pc=0;
    int r = protocol_unpack_data(&pkt, out, &out_len, &oci, ek, nonce, &pc, 0);
    printf("unpack: %d, pc=%u, out_len=%zu, data=%.*s\n", r, pc, out_len, (int)out_len, out);
    return 0;
}
