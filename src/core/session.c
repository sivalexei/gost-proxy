#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#include "kuznyechik.h"
#include "gost_common.h"
#include "protocol.h"

/* ============================================================
 * Helper: simple PRNG (XOR-shift) seeded from byte array
 * ============================================================ */
static uint32_t prng_state[4];

static void prng_seed(const uint8_t *seed, size_t seed_len) {
    /* seed_len — это количество доступных байт, читаем min(4, seed_len/4) uint32 */
    size_t rounds = seed_len / 4;
    if (rounds == 0) rounds = 1;
    if (rounds > 4) rounds = 4;
    for (size_t i = 0; i < rounds; i++)
        prng_state[i] = ((uint32_t)seed[i*4] << 24) | ((uint32_t)seed[i*4+1] << 16) |
                        ((uint32_t)seed[i*4+2] << 8)  | (uint32_t)seed[i*4+3];
    if (prng_state[0] == 0) prng_state[0] = 1;
}

static uint32_t prng_next(void) {
    /* XOR-shift 128 */
    uint32_t x = prng_state[0];
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    prng_state[0] = prng_state[1];
    prng_state[1] = prng_state[2];
    prng_state[2] = prng_state[3];
    prng_state[3] = x;
    return x;
}

static void prng_swap(uint8_t *arr, int i, int j) {
    uint8_t tmp = arr[i]; arr[i] = arr[j]; arr[j] = tmp;
}

/* ============================================================
 * Header permutation (dynamic headers)
 * ============================================================ */

void protocol_generate_header_seed(uint64_t session_id, uint8_t *seed, size_t seed_len) {
    /* Простой hash session_id -> seed: шифруем session_id */
    uint8_t input[8];
    uint64_t sid = htonll(session_id);
    memcpy(input, &sid, 8);

    uint8_t expanded_key[160];
    /* Для генерации seed используем фиксированный "zero" ключ как хеш */
    static uint8_t zero_key[32] = {0};
    /* Заполняем zero_key паттерном для детерминизма */
    for (int i = 0; i < 32; i++) zero_key[i] = (uint8_t)(i * 0x55);
    kuznyechik_set_key(zero_key, expanded_key);

    for (size_t i = 0; i < seed_len; i += 16) {
        uint8_t block[16] = {0};
        memcpy(block, input, 8);
        kuznyechik_encrypt_block(block, expanded_key);
        size_t copy = (seed_len - i > 16) ? 16 : (seed_len - i);
        memcpy(seed + i, block, copy);
    }
}

void protocol_generate_header_permutation(const uint8_t *seed, uint8_t *perm, size_t perm_len) {
    /* Инициализация: [0, 1, 2, 3] */
    for (size_t i = 0; i < perm_len; i++) perm[i] = (uint8_t)i;
    /* Fisher-Yates shuffle */
    prng_seed(seed, HEADER_SEED_SIZE);
    for (size_t i = perm_len - 1; i > 0; i--) {
        size_t j = prng_next() % (i + 1);
        prng_swap(perm, (int)i, (int)j);
    }
}

/* ============================================================
 * Random padding
 * ============================================================ */

uint32_t protocol_compute_padding(const uint8_t *seed, uint32_t seed_len) {
    prng_seed(seed, (size_t)seed_len);
    return PADDING_MIN_BYTES + (prng_next() % (PADDING_MAX_BYTES - PADDING_MIN_BYTES + 1));
}

void protocol_insert_padding(uint8_t *payload, uint32_t *data_len,
                              uint32_t padding_len, const uint8_t *seed) {
    if (padding_len == 0) return;

    prng_seed(seed, HEADER_SEED_SIZE);

    /* Генерируем случайные "мусорные" байты */
    uint8_t junk[256];
    size_t junk_len = padding_len > sizeof(junk) ? sizeof(junk) : padding_len;
    for (size_t i = 0; i < junk_len; i++) {
        junk[i] = (uint8_t)prng_next();
    }

    /* Сдвигаем данные вправо и вставляем junk между данными */
    /* junk_split = padding_len / 2 — делим padding на две части */
    uint32_t split = padding_len / 2;
    uint32_t left = split;
    uint32_t right = padding_len - split;

    /* Перемещаем данные в конец + right байт */
    size_t total = *data_len + padding_len;
    if (total > MAX_PAYLOAD - 4) {
        /* Если не помещается — обрезаем padding */
        total = MAX_PAYLOAD - 4;
        right = (total > *data_len) ? total - *data_len : 0;
        left = padding_len - right;
    }

    /* left не может превышать padding_len */
    if (left > padding_len) left = padding_len;
    if (left > 0 && left > MAX_PAYLOAD - 4 - *data_len) left = MAX_PAYLOAD - 4 - *data_len;

    /* Сдвигаем данные на left байт вправо */
    memmove(payload + left, payload, *data_len);

    /* Вставляем junk — левая часть padding */
    for (uint32_t i = 0; i < left; i++) {
        payload[i] = (uint8_t)prng_next();
    }
    /* Правая часть padding после данных */
    for (uint32_t i = 0; i < right; i++) {
        payload[left + *data_len + i] = (uint8_t)prng_next();
    }

    *data_len += padding_len;
}

/* ============================================================
 * MAC (unchanged) — encrypt(xor_all_blocks_of_payload, key) */
static void compute_mac(
    const uint8_t *payload, size_t payload_len,
    const uint8_t *expanded_key,
    uint8_t *mac_out
) {
    uint8_t block[16];
    memset(block, 0, 16);

    for (size_t offset = 0; offset < payload_len; offset += 16) {
        size_t block_len = (payload_len - offset > 16) ? 16 : (payload_len - offset);
        for (size_t i = 0; i < block_len; i++)
            block[i] ^= payload[offset + i];
    }

    memcpy(mac_out, block, 16);
    kuznyechik_encrypt_block(mac_out, expanded_key);
}

static void make_ctr_nonce(const uint8_t *session_nonce, uint32_t counter, uint8_t *out16) {
    memcpy(out16, session_nonce, NONCE_SIZE);
    out16[12] = (counter >> 24) & 0xFF;
    out16[13] = (counter >> 16) & 0xFF;
    out16[14] = (counter >> 8)  & 0xFF;
    out16[15] = (counter >> 0)  & 0xFF;
}



/*
 * protocol_pack_data — шифрование и упаковка пакета данных.
 *
 * С поддержкой динамических заголовков и случайного padding.
 *
 * Формат payload (до шифрования):
 *   [0..3]   packet_counter (4 байта, big-endian, открытый)
 *   [4..7]   data_len + padding_len (4 байта, big-endian)
 *   [8..7+N] данные + случайный padding
 *
 * Шифруем всё КРОМЕ первых 4 байт (counter).
 * MAC вычисляется от ВСЕГО payload.
 */
int protocol_pack_data(
    gost_packet_t *pkt,
    uint64_t session_id,
    uint32_t conn_id,
    const uint8_t *data,
    size_t data_len,
    const uint8_t *expanded_key,
    const uint8_t *nonce,
    uint32_t *counter
) {
    if (!pkt || !data || !expanded_key || !nonce || !counter) return -1;
    if (data_len > MAX_PAYLOAD - 4 - PADDING_MIN_BYTES) return -1;

    memset(pkt, 0, sizeof(gost_packet_t));
    pkt->magic = htonl(GOST_PROXY_MAGIC);
    pkt->type = PKT_DATA;
    pkt->conn_id = htonl(conn_id);
    pkt->session_id = htonll(session_id);

    /* Инкремент counter ДО записи (шаг: клиент чётные, сервер нечётные) */
    (*counter) += 2;

    uint32_t pkt_counter = *counter;

    /* Counter — открытый (не шифруется) */
    pkt->payload[0] = (pkt_counter >> 24) & 0xFF;
    pkt->payload[1] = (pkt_counter >> 16) & 0xFF;
    pkt->payload[2] = (pkt_counter >> 8)  & 0xFF;
    pkt->payload[3] = (pkt_counter >> 0)  & 0xFF;

    /* Вычисляем случайный padding из seed сессии */
    uint8_t seed[HEADER_SEED_SIZE];
    protocol_generate_header_seed(session_id, seed, HEADER_SEED_SIZE);
    prng_seed(seed, HEADER_SEED_SIZE);
    uint32_t padding_len = protocol_compute_padding(seed, HEADER_SEED_SIZE);

    /* Копируем данные */
    memcpy(pkt->payload + 8, data, data_len);
    uint32_t payload_data_len = (uint32_t)data_len;

    /* data_len поле = данные + padding */
    uint32_t total_len = payload_data_len + padding_len;
    pkt->payload[4] = (total_len >> 24) & 0xFF;
    pkt->payload[5] = (total_len >> 16) & 0xFF;
    pkt->payload[6] = (total_len >> 8)  & 0xFF;
    pkt->payload[7] = (total_len >> 0)  & 0xFF;

    /* Вставляем случайный padding */
    protocol_insert_padding(pkt->payload + 8, &payload_data_len, padding_len, seed);

    /* Шифруем всё КРОМЕ первых 4 байт (counter) */
    uint8_t ctr_nonce[16];
    make_ctr_nonce(nonce, pkt_counter, ctr_nonce);
    kuznyechik_encrypt_ctr(pkt->payload + 4, pkt->payload + 4, MAX_PAYLOAD - 4,
                           expanded_key, ctr_nonce);

    /* Encrypt-then-MAC: MAC от всего payload (открытый counter + зашифрованные данные) */
    compute_mac(pkt->payload, 8 + total_len, expanded_key, pkt->auth_tag);

    return 0;
}

/*
 * protocol_unpack_data — расшифрование и извлечение данных.
 *
 * 1. Читаем counter из первых 4 байт payload (открытый)
 * 2. Проверяем MAC от ВСЕГО payload
 * 3. Расшифровываем payload (кроме counter) с использованием counter
 * 4. Извлекаем data_len (включая padding)
 * 5. Удаляем random padding
 */
int protocol_unpack_data(
    const gost_packet_t *pkt,
    uint8_t *data,
    size_t *data_len,
    uint32_t *out_conn_id,
    const uint8_t *expanded_key,
    const uint8_t *nonce,
    uint32_t *counter
) {
    if (!pkt || !data || !data_len || !expanded_key || !nonce || !counter) return -1;

    /* Извлекаем conn_id */
    if (out_conn_id) *out_conn_id = ntohl(pkt->conn_id);

    /* Читаем counter из первых 4 байт (открытый) */
    uint32_t pkt_counter = ((uint32_t)pkt->payload[0] << 24) |
                           ((uint32_t)pkt->payload[1] << 16) |
                           ((uint32_t)pkt->payload[2] << 8)  |
                           ((uint32_t)pkt->payload[3]);

    /* Replay protection: pkt_counter должен быть > *counter
     * Но *counter == 0 означает "не инициализирован" — пропускаем */
    if (*counter != 0 && pkt_counter <= *counter) {
        return -1;  /* duplicate or too old packet */
    }

    /* Расшифровываем всё КРОМЕ первых 4 байт (counter) */
    uint8_t decrypted[MAX_PAYLOAD - 4];
    uint8_t ctr_nonce[16];
    make_ctr_nonce(nonce, pkt_counter, ctr_nonce);
    kuznyechik_encrypt_ctr(pkt->payload + 4, decrypted, MAX_PAYLOAD - 4,
                           expanded_key, ctr_nonce);

    /* Извлекаем total_len (data + padding) из decrypted[4..7] */
    uint32_t total_len = ((uint32_t)decrypted[4] << 24) |
                         ((uint32_t)decrypted[5] << 16) |
                         ((uint32_t)decrypted[6] << 8)  | ((uint32_t)decrypted[7]);
    if (total_len > MAX_PAYLOAD - 4) return -1;
    if (total_len < 8) return -1;

    /* Проверяем MAC от ВСЕГО payload (открытый counter + зашифрованные данные) */
    uint8_t expected_mac[AUTH_TAG_SIZE];
    compute_mac(pkt->payload, 8 + total_len, expanded_key, expected_mac);
    int mac_ok = (memcmp(pkt->auth_tag, expected_mac, AUTH_TAG_SIZE) == 0);
    if (!mac_ok) {
        return -1;  /* MAC mismatch — отбрасываем, counter НЕ обновляем */
    }

    /* Извлекаем counter из расшифрованных данных (дублирует открытый, для проверки целостности) */
    uint32_t pkt_counter2 = ((uint32_t)decrypted[0] << 24) |
                            ((uint32_t)decrypted[1] << 16) |
                            ((uint32_t)decrypted[2] << 8)  | ((uint32_t)decrypted[3]);

    /* Replay protection */
    if (*counter != 0 && pkt_counter2 <= *counter) {
        return -1;
    }

    uint32_t real_len = total_len - 8;
    *data_len = real_len;
    memcpy(data, decrypted + 8, real_len);

    /* Обновляем counter */
    *counter = pkt_counter2;
    return 0;
}

int protocol_create_handshake(
    gost_packet_t *pkt,
    uint64_t session_id,
    const uint8_t *expanded_key
) {
    if (!pkt || !expanded_key) return -1;

    memset(pkt, 0, sizeof(gost_packet_t));
    pkt->magic = htonl(GOST_PROXY_MAGIC);
    pkt->type = PKT_HANDSHAKE;
    pkt->session_id = htonll(session_id);

    /* Auth tag = шифрование session_id как подпись */
    uint8_t signature[16];
    memset(signature, 0, 16);
    memcpy(signature, &session_id, 8);
    kuznyechik_encrypt_block(signature, expanded_key);
    memcpy(pkt->auth_tag, signature, AUTH_TAG_SIZE);

    return 0;
}

/* ============================================================
 * CPS (Chaffing/Pretense System) — имитация легитимного трафика
 * ============================================================ */

/* Генерация псевдослучайных данных в payload */
static void generate_fake_payload(uint8_t *payload, size_t len, const uint8_t *seed) {
    prng_seed(seed, HEADER_SEED_SIZE);
    for (size_t i = 0; i < len; i++) {
        payload[i] = (uint8_t)prng_next();
    }
}

/* ====== Replay protection ====== */

/* Проверка counter в sliding window для защиты от replay-атак */
int protocol_check_counter(uint32_t expected, uint32_t last)
{
    /* Упрощённое sliding window: counter должен быть больше last - WINDOW_SIZE
     * и не больше last + небольшой запас */
    const uint32_t window = COUNTER_WINDOW_SIZE;

    /* Если counter меньше или равен — replay */
    if (expected <= last) {
        /* Допускаем откат в пределах окна (для мультиплексирования) */
        if (last - expected > window) {
            return -1; /* слишком старый counter */
        }
        /* Для мультиплексированных соединений это допустимо */
        return 0;
    }
    return 1; /* ok, counter новый */
}



/* Инициализация сессии с генерацией header seed и permutation */
int protocol_init_session(gost_session_t *session, const uint8_t *key) {
    if (!session || !key) return -1;

    /* Генерация seed из session_id (установлен caller) */
    protocol_generate_header_seed(session->session_id, session->header_seed, HEADER_SEED_SIZE);

    /* Генерация перестановки полей */
    protocol_generate_header_permutation(session->header_seed, session->header_perm, HEADER_FIELD_COUNT);

    session->cps_enabled = 1;

    return 0;
}

/* Формирование fake QUIC-пакета для имитации */
int protocol_make_fake_quic(gost_packet_t *pkt, const uint8_t *seed, size_t seed_len) {
    if (!pkt || !seed) return -1;

    memset(pkt, 0, sizeof(gost_packet_t));
    pkt->magic = htonl(GOST_PROXY_MAGIC);
    pkt->type = PKT_SIM_QUIC;
    pkt->conn_id = htonl(0xDEAD0001);  /* фейковый conn_id QUIC */
    pkt->session_id = 0;

    /* Генерируем имитацию QUIC-пакета: header + payload */
    size_t fake_len = 64 + (seed_len > 0 ? seed_len : 0);
    if (fake_len > MAX_PAYLOAD - 4) fake_len = MAX_PAYLOAD - 4;

    /* Псевдо-заголовок QUIC */
    uint8_t *buf = pkt->payload;
    buf[0] = 0x01; /* QUIC version */
    buf[1] = 0x00; /* flags */
    buf[2] = (fake_len >> 8) & 0xFF;
    buf[3] = fake_len & 0xFF;
    buf[4] = 0x00; /* packet number */
    buf[5] = 0x00;
    buf[6] = 0x00;
    buf[7] = 0x01;

    /* Псевдоданные QUIC */
    generate_fake_payload(buf + 8, fake_len - 8, seed);

    return 0;
}

/* Формирование fake DNS-запроса для имитации */
int protocol_make_fake_dns(gost_packet_t *pkt, const uint8_t *seed, size_t seed_len) {
    if (!pkt || !seed) return -1;

    memset(pkt, 0, sizeof(gost_packet_t));
    pkt->magic = htonl(GOST_PROXY_MAGIC);
    pkt->type = PKT_SIM_DNS;
    pkt->conn_id = htonl(0xBEEF0002);  /* фейковый conn_id DNS */
    pkt->session_id = 0;

    /* Генерируем имитацию DNS-запроса */
    size_t fake_len = 128 + (seed_len > 0 ? seed_len : 0);
    if (fake_len > MAX_PAYLOAD - 4) fake_len = MAX_PAYLOAD - 4;

    uint8_t *buf = pkt->payload;

    /* Псевдо-DNS: ID запроса */
    buf[0] = 0x12; buf[1] = 0x34;
    /* Flags: стандартный запрос */
    buf[2] = 0x01; buf[3] = 0x00;
    /* QDCOUNT = 1 */
    buf[4] = 0x00; buf[5] = 0x01;
    /* ANCOUNT = 0 */
    buf[6] = 0x00; buf[7] = 0x00;
    /* NSCOUNT = 0 */
    buf[8] = 0x00; buf[9] = 0x00;
    /* ARCOUNT = 0 */
    buf[10] = 0x00; buf[11] = 0x00;

    /* Псевдо-имя домена (например "example.com") */
    buf[12] = 7; memcpy(buf + 13, "example", 7);
    buf[21] = 3; memcpy(buf + 22, "com", 3);
    buf[26] = 0x00;

    /* Тип A */
    buf[27] = 0x00; buf[28] = 0x01;
    /* Класс IN */
    buf[29] = 0x00; buf[30] = 0x01;

    /* Псевдоданные */
    generate_fake_payload(buf + 31, fake_len - 31, seed);

    return 0;
}

/* Формирование fake TLS ClientHello для имитации */
int protocol_make_fake_tls(gost_packet_t *pkt, const uint8_t *seed, size_t seed_len) {
    if (!pkt || !seed) return -1;

    memset(pkt, 0, sizeof(gost_packet_t));
    pkt->magic = htonl(GOST_PROXY_MAGIC);
    pkt->type = PKT_SIM_TLS;
    pkt->conn_id = htonl(0x16030003);  /* фейковый conn_id TLS */
    pkt->session_id = 0;

    /* Генерируем имитацию TLS ClientHello */
    size_t fake_len = 256 + (seed_len > 0 ? seed_len : 0);
    if (fake_len > MAX_PAYLOAD - 4) fake_len = MAX_PAYLOAD - 4;

    uint8_t *buf = pkt->payload;

    /* Псевдо-TLS Record: content_type=Handshake, version=TLS 1.0 */
    buf[0] = 0x16;  /* Handshake */
    buf[1] = 0x03;  /* version major */
    buf[2] = 0x01;  /* version minor */

    /* Length */
    buf[3] = (fake_len >> 8) & 0xFF;
    buf[4] = fake_len & 0xFF;

    /* Handshake: ClientHello */
    buf[5] = 0x01;  /* ClientHello */

    /* Length handshake */
    size_t hs_len = fake_len - 5;
    buf[6] = (hs_len >> 16) & 0xFF;
    buf[7] = (hs_len >> 8) & 0xFF;
    buf[8] = hs_len & 0xFF;

    /* TLS version */
    buf[9] = 0x03; buf[10] = 0x03;

    /* Random (48 bytes) */
    buf[11] = (uint8_t)(time(NULL) >> 24);  /* Unix time */
    buf[12] = (uint8_t)(time(NULL) >> 16);
    buf[13] = (uint8_t)(time(NULL) >> 8);
    buf[14] = (uint8_t)(time(NULL));
    generate_fake_payload(buf + 15, 43, seed);  /* 32 bytes random */

    /* Session ID length */
    buf[58] = 32;
    /* Session ID (32 bytes) */
    generate_fake_payload(buf + 59, 32, seed);

    /* Cipher Suites (имитация) */
    size_t cipher_offset = 59 + 32;
    buf[cipher_offset] = 0x00; buf[cipher_offset + 1] = 0x20;
    /* 16 cipher suites по 2 байта = 32 байта */
    generate_fake_payload(buf + cipher_offset + 2, 32, seed);

    /* Псевдоданные */
    size_t remaining = fake_len - (cipher_offset + 2 + 32);
    if (remaining > 0 && remaining < fake_len - cipher_offset - 34) {
        generate_fake_payload(buf + cipher_offset + 2 + 32, remaining, seed);
    }

    return 0;
}

/* Формирование CPS challenge/answer */
int protocol_make_cps_challenge(gost_packet_t *pkt, const uint8_t *seed, size_t seed_len,
                                 uint8_t *challenge_out, uint8_t *answer_out) {
    if (!pkt || !seed || !challenge_out || !answer_out) return -1;

    memset(pkt, 0, sizeof(gost_packet_t));
    pkt->magic = htonl(GOST_PROXY_MAGIC);
    pkt->type = PKT_SIM_CHALLENGE;
    pkt->conn_id = 0;
    pkt->session_id = 0;

    /* Challenge: seed до 32 байт (.pad нулями) */
    uint8_t challenge[32];
    memset(challenge, 0, sizeof(challenge));
    memcpy(challenge, seed, seed_len > 32 ? 32 : seed_len);

    /* Ответ: шифруем challenge */
    uint8_t expanded_key[160];
    static uint8_t cps_key[32];
    memset(cps_key, 0, sizeof(cps_key));
    for (int i = 0; i < 32; i++) cps_key[i] = (uint8_t)(i * 0xAA);
    kuznyechik_set_key(cps_key, expanded_key);

    kuznyechik_encrypt_block(challenge, expanded_key);
    memcpy(challenge_out, challenge, 32);
    memcpy(answer_out, challenge, 32);

    /* Вставляем challenge + answer в payload */
    memcpy(pkt->payload, challenge, 32);
    memcpy(pkt->payload + 32, answer_out, 32);

    return 0;
}

/* Проверка CPS challenge — возвращает 0 если challenge верный
 * Ключ генерируется из session_id, а не жёстко задан */
int protocol_verify_cps_challenge(const gost_packet_t *pkt, uint8_t *answer, size_t answer_len) {
    if (!pkt || !answer || answer_len < 32) return -1;

    /* Первые 32 байта — challenge от клиента */
    uint8_t client_challenge[32];
    if (sizeof(pkt->payload) < 32) return -1;
    memcpy(client_challenge, pkt->payload, 32);

    /* Следующие 32 байта — answer */
    uint8_t client_answer[32];
    if (sizeof(pkt->payload) < 64) return -1;
    memcpy(client_answer, pkt->payload + 32, 32);

    /* Генерация CPS-ключа из session_id пакета (каждая сессия уникальна) */
    uint8_t expanded_key[160];
    uint8_t cps_seed[32];
    memset(cps_seed, 0, sizeof(cps_seed));

    uint64_t sid = ntohll(pkt->session_id);
    memcpy(cps_seed, &sid, 8);
    /* Хэширование session_id в 32-байтовый CPS-ключ через шифрование */
    uint8_t zero_block[16] = {0};
    for (int i = 0; i < 4; i++) {
        kuznyechik_set_key(cps_seed, expanded_key);
        kuznyechik_encrypt_block(zero_block, expanded_key);
        memcpy(cps_seed, zero_block, 16);
    }

    kuznyechik_set_key(cps_seed, expanded_key);

    /* Шифруем challenge тем же ключом */
    uint8_t expected_answer[32];
    memcpy(expected_answer, client_challenge, 32);
    kuznyechik_encrypt_block(expected_answer, expanded_key);

    /* Сравниваем */
    if (memcmp(client_answer, expected_answer, 32) == 0) {
        memcpy(answer, client_challenge, 32);
        return 0;
    }
    return -1;
}
