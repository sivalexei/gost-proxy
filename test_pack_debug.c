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
    gost_packet_t pkt;
    
    int r = protocol_pack_data(&pkt, session_id, conn_id, data, data_len, ek, nonce, &counter, 0);
    printf("pack: %d, counter=%u\n", r, counter);
    printf("payload[0..15]:");
    for(int i=0;i<16;i++) printf(" %02x",pkt.payload[i]);
    printf("\n");
    printf("pc=[%02x %02x %02x %02x]=%u\n", pkt.payload[0],pkt.payload[1],pkt.payload[2],pkt.payload[3],
        (pkt.payload[0]<<24)|(pkt.payload[1]<<16)|(pkt.payload[2]<<8)|pkt.payload[3]);
    printf("sl=[%02x %02x %02x %02x]=%u\n", pkt.payload[4],pkt.payload[5],pkt.payload[6],pkt.payload[7],
        (pkt.payload[4]<<24)|(pkt.payload[5]<<16)|(pkt.payload[6]<<8)|pkt.payload[7]);
    printf("pl=[%02x %02x %02x %02x]=%u\n", pkt.payload[8],pkt.payload[9],pkt.payload[10],pkt.payload[11],
        (pkt.payload[8]<<24)|(pkt.payload[9]<<16)|(pkt.payload[10]<<8)|pkt.payload[11]);
    return 0;
}
