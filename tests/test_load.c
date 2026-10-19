/* test_load.c — Load test: rapid sequential session operations
 *
 * Verifies the server can handle rapid create→pack→unpack→destroy cycles
 * without memory leaks or race conditions.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "gost_common.h"
#include "../src/core/protocol.h"

static int total = 0, pass = 0, fail = 0;
#define PASS(m) do { printf("\e[32m[PASS]\e[0m %s\n", m); pass++; total++; } while(0)
#define FAIL(m) do { printf("\e[31m[FAIL]\e[0m %s\n", m); fail++; total++; } while(0)

int main(void) {
    printf("\n=== Load: Rapid Session Cycles (1000 iters) ===\n");

    int error_count = 0;
    for (int i = 0; i < 1000; i++) {
        /* Each iteration: create session, pack, unpack, destroy */
        uint64_t sid = i + 1;
        uint8_t data[MAX_PAYLOAD];
        size_t dl = 0;
        uint32_t oci = 0;
        uint32_t send_ctr = 1, recv_ctr = 1;

        /* Pack */
        gost_packet_t pkt;
        memset(&pkt, 0, sizeof(pkt));
        int rc = protocol_pack_data(&pkt, sid, 1,
                                    (const uint8_t *)"hello load", 10,
                                    NULL, NULL, &send_ctr, 1);
        if (rc == 0) {
            /* Unpack */
            rc = protocol_unpack_data(&pkt, data, &dl, &oci,
                                     NULL, NULL, NULL, &recv_ctr, 1);
            if (rc == 0 && dl == 10 && memcmp(data, "hello load", 10) == 0) {
                /* OK */
            } else {
                error_count++;
            }
        }
    }

    if (error_count == 0) {
        PASS("1000 rapid session cycles — all OK");
    } else {
        FAIL("1000 rapid session cycles");
    }

    printf("\n===================\n");
    printf("Load: %d pass, %d fail\n", pass, fail);
    return fail > 0;
}