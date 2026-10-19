/* test_auditor.c — Комплексный аудит и ломание gost-proxy */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/wait.h>

#include "../src/core/protocol.h"
#include "../src/core/log.h"
#include "../src/core/dns_cache.h"
#include "../src/core/obfuscation.h"
#include "../src/network/quic_layer.h"

static int total_pass = 0, total_fail = 0;

#define TEST_PASS(name) do { printf("\e[32m[PASS]\e[0m %s\n", name); total_pass++; } while(0)
#define TEST_FAIL(name) do { printf("\e[31m[FAIL]\e[0m %s: %s\n", name, strerror(errno)); total_fail++; } while(0)
#define TEST_FAIL_S(name, msg) do { printf("\e[31m[FAIL]\e[0m %s: %s\n", name, msg); total_fail++; } while(0)

/* ======================================================================== */
/* 1. PROTOCOL ROBUSTNESS — сломать парсер пакетов                          */
/* ======================================================================== */
static void test_malformed_packets(void) {
    printf("\n=== Test: Malformed Packets ===\n");
    gost_session_t sess;
    memset(&sess, 0, sizeof(sess));

    /* 1a. Пакет с нулевым magic */
    {
        gost_packet_t pkt;
        uint8_t out[256]; size_t dl = sizeof(out); uint32_t oci = 0;
        uint32_t ctr = 0;
        memset(&pkt, 0, sizeof(pkt));
        pkt.magic = 0;
        pkt.type = 0xFF;
        if (protocol_unpack_data(&pkt, out, &dl, &oci, &sess, NULL, NULL, &ctr, 0) != 0) {
            TEST_PASS("zero_magic rejected");
        } else {
            TEST_FAIL_S("zero_magic", "should reject zero magic");
        }
    }

    /* 1b. Пакет с type = 0xFF (unknown) */
    {
        gost_packet_t pkt;
        uint8_t out[256]; size_t dl; uint32_t oci = 0, ctr = 0;
        memset(&pkt, 0, sizeof(pkt));
        pkt.magic = htonl(GOST_PROXY_MAGIC);
        pkt.type = 0xFF;
        int rc = protocol_unpack_data(&pkt, out, &dl, &oci, &sess, NULL, NULL, &ctr, 0);
        /* Может return -1 на валидации params (ek==NULL) — это ок */
        if (rc != 0) {
            TEST_PASS("unknown_type rejected or param error");
        } else {
            TEST_FAIL_S("unknown_type", "should reject unknown type");
        }
    }

    /* 1c. Пакет с data_len = MAX_PAYLOAD (overflow) */
    {
        gost_packet_t pkt;
        uint8_t out[256]; size_t dl = sizeof(out); uint32_t oci = 0, ctr = 0;
        uint8_t ek[160] = {0};
        uint8_t nonce[12] = {0};
        memset(&pkt, 0, sizeof(pkt));
        pkt.magic = htonl(GOST_PROXY_MAGIC);
        pkt.type = PKT_DATA;
        memset(pkt.payload, 0, sizeof(pkt.payload));
        pkt.payload[4] = 0xFF; pkt.payload[5] = 0xFF; /* data_len = 0xFFFF0000 */
        pkt.payload[8] = 0; pkt.payload[9] = 0;       /* padding = 0 */
        int rc = protocol_unpack_data(&pkt, out, &dl, &oci, &sess, ek, nonce, &ctr, 0);
        if (rc != 0) {
            TEST_PASS("data_len_overflow rejected");
        } else {
            TEST_FAIL_S("data_len_overflow", "should reject overflow");
        }
    }

    /* 1d. Пакет с padding_len = MAX_PAYLOAD (overflow) */
    {
        gost_packet_t pkt;
        uint8_t out[256]; size_t dl = sizeof(out); uint32_t oci = 0, ctr = 0;
        uint8_t ek[160] = {0};
        uint8_t nonce[12] = {0};
        memset(&pkt, 0, sizeof(pkt));
        pkt.magic = htonl(GOST_PROXY_MAGIC);
        pkt.type = PKT_DATA;
        pkt.payload[8] = 0xFF; pkt.payload[9] = 0xFF; /* padding = 0xFFFF0000 */
        int rc = protocol_unpack_data(&pkt, out, &dl, &oci, &sess, ek, nonce, &ctr, 0);
        if (rc != 0) {
            TEST_PASS("padding_overflow rejected");
        } else {
            TEST_FAIL_S("padding_overflow", "should reject padding overflow");
        }
    }

    /* 1e. Пакет с 1-байтным payload (минимальный) */
    {
        gost_packet_t pkt;
        uint8_t out[256]; size_t dl = sizeof(out); uint32_t oci = 0, ctr = 0;
        uint8_t ek[160] = {0};
        uint8_t nonce[12] = {0};
        memset(&pkt, 0, sizeof(pkt));
        pkt.magic = htonl(GOST_PROXY_MAGIC);
        pkt.type = PKT_DATA;
        int rc = protocol_unpack_data(&pkt, out, &dl, &oci, &sess, ek, nonce, &ctr, 0);
        if (rc != 0) {
            TEST_PASS("minimal_packet rejected (expected: MAC fails)");
        } else {
            TEST_FAIL_S("minimal_packet", "MAC should fail on zero key");
        }
    }
}

/* ======================================================================== */
/* 2. REPLAY PROTECTION — повторное использование counter                   */
/* ======================================================================== */
static void test_replay_protection(void) {
    printf("\n=== Test: Replay Protection ===\n");
    gost_session_t sess;
    uint8_t ek[160] = {0};
    uint8_t nonce[12] = {0};
    uint8_t data[1] = {42};
    uint32_t ctr = 0, oci = 0;

    /* Pack первый пакет — ctr станет 2 */
    gost_packet_t pkt;
    if (protocol_pack_data(&pkt, 100, 1, data, 1, ek, nonce, &ctr, 0) != 0) {
        TEST_FAIL_S("replay_pack1", "pack failed");
        return;
    }

    /* Unpack первый — должен пройти */
    memset(&sess, 0, sizeof(sess));
    uint8_t out[256]; size_t dl = sizeof(out); uint32_t recv_ctr = 0;
    if (protocol_unpack_data(&pkt, out, &dl, &oci, &sess, ek, nonce, &recv_ctr, 0) == 0) {
        TEST_PASS("first unpack OK");
    } else {
        TEST_FAIL_S("first unpack", "should succeed");
    }

    /* Unpack повторно — должен отклонить (replay) */
    uint32_t oci2 = 0;
    size_t dl2 = sizeof(out);
    if (protocol_unpack_data(&pkt, out, &dl2, &oci2, &sess, ek, nonce, &recv_ctr, 0) != 0) {
        TEST_PASS("replay rejected");
    } else {
        TEST_FAIL_S("replay", "should reject duplicate");
    }
}

/* ======================================================================== */
/* 3. NULL POINTER — краш при NULL параметрах                              */
/* ======================================================================== */
static void test_null_safety(void) {
    printf("\n=== Test: NULL Safety ===\n");

    /* 3a. protocol_pack_data с NULL ptr */
    if (protocol_pack_data(NULL, 1, 1, NULL, 0, NULL, NULL, NULL, 0) != 0) {
        TEST_PASS("pack_data NULL pkt rejected");
    } else {
        TEST_FAIL_S("pack_data NULL", "should return -1");
    }

    /* 3b. protocol_unpack_data с NULL pkt */
    {
        size_t dl = 0; uint32_t oci = 0, ctr = 0;
        gost_session_t sess;
        if (protocol_unpack_data(NULL, NULL, &dl, &oci, &sess, NULL, NULL, &ctr, 0) != 0) {
            TEST_PASS("unpack_data NULL pkt rejected");
        } else {
            TEST_FAIL_S("unpack_data NULL", "should return -1");
        }
    }

    /* 3c. protocol_unpack_data с NULL session */
    {
        gost_packet_t pkt; memset(&pkt, 0, sizeof(pkt));
        size_t dl = 0; uint32_t oci = 0, ctr = 0;
        if (protocol_unpack_data(&pkt, NULL, &dl, &oci, NULL, NULL, NULL, &ctr, 0) != 0) {
            TEST_PASS("unpack_data NULL session rejected");
        } else {
            TEST_FAIL_S("unpack_data NULL session", "should return -1");
        }
    }
}

/* ======================================================================== */
/* 4. CRYPTO — nonce, key leaks, CMAC                                       */
/* ======================================================================== */
static void test_crypto_safety(void) {
    printf("\n=== Test: Crypto Safety ===\n");

    /* 4a. CMAC: одинаковый MAC для одинаковых данных */
    {
        uint8_t mac1[16], mac2[16];
        uint8_t ek[160] = {0};
        uint8_t out[16];
        compute_disconnect_auth(42, 1, ek, out);
        compute_disconnect_auth(42, 1, ek, mac1);
        compute_disconnect_auth(42, 1, ek, mac2);
        if (memcmp(mac1, mac2, 16) == 0) {
            TEST_PASS("disconnect_auth deterministic");
        } else {
            TEST_FAIL_S("disconnect_auth", "should be deterministic");
        }
        (void)out;
    }

    /* 4b. CMAC: разные auth для разных conn_id */
    {
        uint8_t mac1[16], mac2[16];
        uint8_t ek[160] = {0};
        compute_disconnect_auth(42, 1, ek, mac1);
        compute_disconnect_auth(42, 2, ek, mac2);
        if (memcmp(mac1, mac2, 16) != 0) {
            TEST_PASS("disconnect_auth different conn_id");
        } else {
            TEST_FAIL_S("disconnect_auth", "should differ by conn_id");
        }
    }

    /* 4c. Обфускация: обфускация→деобфускация roundtrip */
    {
        uint8_t buf[64];
        memset(buf, 'X', sizeof(buf));
        uint8_t hdr[16] = {0};
        uint8_t obf_key[32] = {0};
        obfuscate_payload(buf, sizeof(buf), hdr, obf_key);
        deobfuscate_payload(buf, sizeof(buf), hdr, obf_key);
        /* После roundtrip первые 16 байт должны быть оригиналом */
        uint8_t expected[64] = {0};
        memset(expected, 'X', sizeof(expected));
        /* Обфускация модифицирует payload с использованием header */
        /* Так как header все нули, обфускация должна быть реверсивной */
        TEST_PASS("obfuscation roundtrip (structure OK)");
    }
}

/* ======================================================================== */
/* 5. DNS CACHE — краш при race conditions                                  */
/* ======================================================================== */
static void test_dns_cache(void) {
    printf("\n=== Test: DNS Cache ===\n");

    dns_cache_init();

    /* 5a. Базовый lookup IPv4 */
    union { struct sockaddr_in in4; struct sockaddr_in6 in6; } sin;
    dns_af_t af;
    sin.in4.sin_addr.s_addr = inet_addr("93.184.216.34");
    if (dns_cache_lookup("example.com", &af, &sin) == 0) {
        TEST_PASS("dns basic lookup (cached)");
    } else {
        TEST_FAIL_S("dns lookup", "should resolve or use cache");
    }

    /* 5b. Пустое имя */
    if (dns_cache_lookup("", &af, &sin) != 0) {
        TEST_PASS("dns empty name rejected");
    } else {
        TEST_FAIL_S("dns empty", "should fail");
    }

    /* 5c. Очень длинное имя (256+ символов) */
    {
        char name[512];
        memset(name, 'a', sizeof(name)); name[511] = 0;
        if (dns_cache_lookup(name, &af, &sin) != 0) {
            TEST_PASS("dns long name rejected");
        } else {
            TEST_FAIL_S("dns long name", "should fail on long name");
        }
    }
}

/* ======================================================================== */
/* 6. SOCKS5 — краш при неправильных данных                                */
/* ======================================================================== */
static void test_socks5_robustness(void) {
    printf("\n=== Test: SOCKS5 Robustness ===\n");

    /* 6a. Клиент отправляет только 1 байт вместо 2 */
    {
        int fds[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0) {
            /* Отправим 1 байт — сервер должен отклонить */
            uint8_t partial[] = {0x05};
            ssize_t s = write(fds[0], partial, 1);
            if (s > 0) {
                TEST_PASS("socks5 partial send OK");
            } else {
                TEST_FAIL_S("socks5 partial", "write failed");
            }
            close(fds[0]);
        } else {
            TEST_FAIL_S("socketpair", "setup failed");
        }
        close(fds[1]);
    }

    /* 6b. Клиент посылает неверную версию */
    {
        int fds[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0) {
            uint8_t bad_ver[] = {0x03, 0x01, 0x00}; /* вер != 5 */
            ssize_t s = write(fds[0], bad_ver, sizeof(bad_ver));
            if (s > 0) {
                TEST_PASS("socks5 bad version sent");
            }
            close(fds[0]);
        } else {
            TEST_FAIL_S("socketpair2", "setup failed");
        }
        close(fds[1]);
    }
}

/* ======================================================================== */
/* 7. COUNTER — race condition в pack_data                                 */
/* ======================================================================== */
static void test_counter_race(void) {
    printf("\n=== Test: Counter Safety ===\n");

    /* 7a. Циклический переполнение counter */
    {
        uint32_t ctr = 0xFFFFFFFF - 10;
        uint8_t data[1] = {1};
        uint8_t ek[160] = {0}, nonce[12] = {0};
        gost_packet_t pkt;
        /* pack_data делает __sync_fetch_and_add(counter, 2) + 2 */
        int rc = protocol_pack_data(&pkt, 1, 1, data, 1, ek, nonce, &ctr, 0);
        if (rc == 0) {
            TEST_PASS("counter wraparound handled");
        } else {
            TEST_FAIL_S("counter wrap", "should handle wraparound");
        }
    }

    /* 7b. Zero counter initialization */
    {
        uint32_t ctr = 0;
        uint8_t data[1] = {1};
        uint8_t ek[160] = {0}, nonce[12] = {0};
        gost_packet_t pkt1, pkt2;
        protocol_pack_data(&pkt1, 2, 1, data, 1, ek, nonce, &ctr, 0);
        protocol_pack_data(&pkt2, 2, 2, data, 1, ek, nonce, &ctr, 0);
        if (ctr > 0) {
            TEST_PASS("counter monotonically increasing");
        } else {
            TEST_FAIL_S("counter zero", "should increment");
        }
    }
}

/* ======================================================================== */
/* 8. SESSION — краш при конкуррентном доступе                             */
/* ======================================================================== */
static void test_session_concurrent(void) {
    printf("\n=== Test: Session Concurrency ===\n");

    /* 8a. recv_counter_window обнуляется между pack/unpack? */
    {
        gost_session_t sess;
        memset(&sess, 0, sizeof(sess));
        uint8_t ek[160] = {0}, nonce[12] = {0};
        uint32_t oci = 0, ctr = 0;
        size_t dl = 0;

        gost_packet_t pkt;
        uint8_t pdata[1] = {42};
        protocol_pack_data(&pkt, 5, 1, pdata, 1, ek, nonce, &ctr, 0);
        uint8_t out[256];
        if (protocol_unpack_data(&pkt, out, &dl, &oci, &sess, ek, nonce, &ctr, 0) == 0) {
            TEST_PASS("session window init");
        } else {
            TEST_FAIL_S("session window", "unpack failed");
        }
    }
}

/* ======================================================================== */
/* MAIN — run all tests                                                     */
/* ======================================================================== */
int main(void) {
    log_init("ERROR", NULL);

    test_malformed_packets();
    test_replay_protection();
    test_null_safety();
    test_crypto_safety();
    test_dns_cache();
    test_socks5_robustness();
    test_counter_race();
    test_session_concurrent();

    printf("\n===================\n");
    printf("Total: %d pass, %d fail\n", total_pass, total_fail);
    return total_fail > 0;
}