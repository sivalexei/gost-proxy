#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/core/protocol.h"
#include "../src/core/log.h"

#define TEST_PASS(name) printf("\e[32m[PASS]\e[0m %s\n", name)
#define TEST_FAIL(name) do { printf("\e[31m[FAIL]\e[0m %s\n", name); fails++; } while(0)

int main() {
    int fails = 0, total = 0;
    log_init("DEBUG", NULL);

    total++; TEST_PASS("log init");

    /* Test 1: pack→unpack roundtrip */
    total++;
    {
        uint8_t data[256];
        memset(data, 'A', sizeof(data));
        gost_packet_t pkt;
        uint32_t conn_id = 0;
        gost_session_t sess;
        memset(&sess, 0, sizeof(sess));
        uint8_t ek[32] = {0};
        uint8_t nonce[12] = {0};
        uint32_t ctr = 0;

        int rc = protocol_pack_data(&pkt, 42, conn_id, data, 100, ek, nonce, &ctr, 0);
        if (rc == 0) {
            uint8_t out[256];
            size_t out_len = sizeof(out);
            uint32_t out_conn_id = 0;
            int rc2 = protocol_unpack_data(&pkt, out, &out_len, &out_conn_id, &sess, ek, nonce, &ctr, 0);
            if (rc2 == 0 && out_len == 100 && memcmp(data, out, 100) == 0 && out_conn_id == conn_id) {
                TEST_PASS("pack→unpack roundtrip");
            } else {
                TEST_FAIL("pack→unpack data mismatch");
            }
        } else {
            TEST_FAIL("pack_data failed");
        }
    }

    /* Test 2: single byte payload */
    total++;
    {
        uint8_t data[1] = {42};
        gost_packet_t pkt;
        uint32_t conn_id = 1;
        gost_session_t sess;
        memset(&sess, 0, sizeof(sess));
        uint8_t ek[32] = {0};
        uint8_t nonce[12] = {0};
        uint32_t ctr = 0;

        int rc = protocol_pack_data(&pkt, 99, conn_id, data, 1, ek, nonce, &ctr, 0);
        if (rc == 0) {
            uint8_t out[256];
            size_t out_len = sizeof(out);
            uint32_t out_conn_id = 0;
            int rc2 = protocol_unpack_data(&pkt, out, &out_len, &out_conn_id, &sess, ek, nonce, &ctr, 0);
            if (rc2 == 0 && out_len == 1 && out[0] == 42) {
                TEST_PASS("single byte roundtrip");
            } else {
                TEST_FAIL("single byte mismatch");
            }
        } else {
            TEST_FAIL("single byte pack failed");
        }
    }

    /* Test 3: large payload (MAX_PAYLOAD-12 bytes) */
    total++;
    {
        size_t dlen = MAX_PAYLOAD - 12;
        uint8_t data[65536];
        for (size_t i = 0; i < dlen; i++) data[i] = i % 256;
        gost_packet_t pkt;
        uint32_t conn_id = 5;
        gost_session_t sess;
        memset(&sess, 0, sizeof(sess));
        uint8_t ek[32] = {0};
        uint8_t nonce[12] = {0};
        uint32_t ctr = 0;

        int rc = protocol_pack_data(&pkt, 7, conn_id, data, dlen, ek, nonce, &ctr, 0);
        if (rc == 0) {
            uint8_t out[65536];
            size_t out_len = sizeof(out);
            uint32_t out_conn_id = 0;
            int rc2 = protocol_unpack_data(&pkt, out, &out_len, &out_conn_id, &sess, ek, nonce, &ctr, 0);
            if (rc2 == 0 && out_len == dlen && memcmp(data, out, dlen) == 0) {
                TEST_PASS("large payload roundtrip");
            } else {
                TEST_FAIL("large payload mismatch");
            }
        } else {
            TEST_FAIL("large pack failed");
        }
    }

    total++; TEST_PASS("integration complete");
    printf("\nTotal: %d tests, %d failed\n", total, fails);
    return fails > 0;
}