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
    for (int i = 0; i < 4 && i < (int)seed_len; i++)
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

void protocol_encrypt_header_seed(const uint8_t *plaintext_seed, size_t seed_len,
                                   const uint8_t *expanded_key, uint8_t *encrypted_seed) {
    for (size_t i = 0; i < seed_len; i += 16) {
        uint8_t block[16] = {0};
        size_t copy = (seed_len - i > 16) ? 16 : (seed_len - i);
        memcpy(block, plaintext_seed + i, copy);
        kuznyechik_encrypt_block(block, expanded_key);
        memcpy(encrypted_seed + i, block, 16);
    }
}

void protocol_decrypt_header_seed(const uint8_t *encrypted_seed, size_t seed_len,
                                   const uint8_t *expanded_key, uint8_t *plaintext_seed) {
    for (size_t i = 0; i < seed_len; i += 16) {
        uint8_t block[16];
        memcpy(block, encrypted_seed + i, 16);
        kuznyechik_decrypt_block(block, expanded_key);
        size_t copy = (seed_len - i > 16) ? 16 : (seed_len - i);
        memcpy(plaintext_seed + i, block, copy);
    }
}

/* ============================================================
 * Random padding
 * ============================================================ */

uint32_t protocol_compute_padding(const uint8_t *seed, uint32_t seed_len) {
    (void)seed_len;
    prng_seed(seed, HEADER_SEED_SIZE);
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

    memmove(payload + left + *data_len, payload + left, *data_len - left);

    /* Вставляем junk */
    /* Левая часть padding */
    for (uint32_t i = 0; i < left; i++) {
        payload[i] = (uint8_t)prng_next();
    }
    /* Правая часть padding после данных */
    for (uint32_t i = 0; i < right; i++) {
        payload[left + *data_len + i] = (uint8_t)prng_next();
    }

    *data_len += padding_len;
}

void protocol_remove_padding(uint8_t *payload, uint32_t *data_len, const uint8_t *seed) {
    if (*data_len < PADDING_MIN_BYTES) return;

    prng_seed(seed, HEADER_SEED_SIZE);
    uint32_t padding_len = protocol_compute_padding(seed, HEADER_SEED_SIZE);

    if (*data_len < padding_len) return;

    uint32_t split = padding_len / 2;
    uint32_t left = split;
    size_t new_len = *data_len - padding_len;

    /* Сдвигаем данные влево, убираем padding */
    memmove(payload, payload + left, new_len);
    *data_len = (uint32_t)new_len;

    /* Очищаем оставшуюся часть буфера */
    memset(payload + new_len, 0, padding_len);
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

/* ============================================================
 * Динамические заголовки — перестановка байтов payload
 * ============================================================ */
static void apply_permutation(uint8_t *data, size_t data_len,
                               const uint8_t *perm, size_t perm_len);
static void inverse_permutation(uint8_t *data, size_t data_len,
                                 const uint8_t *perm, size_t perm_len);

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

    uint32_t pkt_counter = *counter;

    /* Counter — открытый (не шифруется) */
    pkt->payload[0] = (pkt_counter >> 24) & 0xFF;
    pkt->payload[1] = (pkt_counter >> 16) & 0xFF;
    pkt->payload[2] = (pkt_counter >> 8)  & 0xFF;
    pkt->payload[3] = (pkt_counter >> 0)  & 0xFF;

    /* Вычисляем случайный padding из seed сессии */
    uint8_t seed[HEADER_SEED_SIZE];
    protocol_generate_header_seed(session_id, seed, HEADER_SEED_SIZE);
    uint32_t padding_len = protocol_compute_padding(seed, HEADER_SEED_SIZE);

    /* Копируем данные */
    memcpy(pkt->payload + 8, data, data_len);
    uint32_t total_data_len = (uint32_t)data_len + padding_len;

    /* data_len поле = данные + padding */
    pkt->payload[4] = (total_data_len >> 24) & 0xFF;
    pkt->payload[5] = (total_data_len >> 16) & 0xFF;
    pkt->payload[6] = (total_data_len >> 8)  & 0xFF;
    pkt->payload[7] = (total_data_len >> 0)  & 0xFF;

    /* Вставляем случайный padding */
    protocol_insert_padding(pkt->payload + 8, &total_data_len, padding_len, seed);

    /* Применяем динамическую перестановку к payload (данные+padding) */
    uint8_t perm[HEADER_FIELD_COUNT];
    protocol_generate_header_permutation(seed, perm, HEADER_FIELD_COUNT);
    apply_permutation(pkt->payload + 8, total_data_len, perm, HEADER_FIELD_COUNT);

    /* Шифруем всё КРОМЕ первых 4 байт (counter) */
    uint8_t ctr_nonce[16];
    make_ctr_nonce(nonce, pkt_counter, ctr_nonce);
    kuznyechik_encrypt_ctr(pkt->payload + 4, pkt->payload + 4, MAX_PAYLOAD - 4,
                           expanded_key, ctr_nonce);

    /* Encrypt-then-MAC: MAC от ВСЕГО payload (включая открытый counter) */
    compute_mac(pkt->payload, MAX_PAYLOAD, expanded_key, pkt->auth_tag);

    (*counter) += 2; /* шаг 2: клиент чётные, сервер нечётные */
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

    /* Проверяем MAC от ВСЕГО payload */
    uint8_t expected_mac[AUTH_TAG_SIZE];
    compute_mac(pkt->payload, MAX_PAYLOAD, expanded_key, expected_mac);
    if (memcmp(pkt->auth_tag, expected_mac, AUTH_TAG_SIZE) != 0) {
        return -1;  /* MAC mismatch — отбрасываем, counter НЕ обновляем */
    }

    /* Replay protection: counter должен быть больше last_counter - WINDOW_SIZE */
    /* Защита от повторной доставки пакетов с тем же counter */
    if (pkt_counter <= *counter && *counter - pkt_counter > COUNTER_WINDOW_SIZE) {
        return -1;  /* packet too old — replay attack detected */
    }
    if (pkt_counter <= *counter) {
        return -1;  /* duplicate packet (within window) */
    }

    /* Расшифровываем всё КРОМЕ первых 4 байт (counter) */
    uint8_t decrypted[MAX_PAYLOAD - 4];
    uint8_t ctr_nonce[16];
    make_ctr_nonce(nonce, pkt_counter, ctr_nonce);
    kuznyechik_encrypt_ctr(pkt->payload + 4, decrypted, MAX_PAYLOAD - 4,
                           expanded_key, ctr_nonce);

    /* Извлекаем total_len (data + padding) */
    uint32_t total_len = ((uint32_t)decrypted[0] << 24) |
                         ((uint32_t)decrypted[1] << 16) |
                         ((uint32_t)decrypted[2] << 8)  |
                         ((uint32_t)decrypted[3]);
    if (total_len > MAX_PAYLOAD - 4) return -1;

    /* Генерируем seed и permutation из session_id */
    uint64_t sid = ntohll(pkt->session_id);
    uint8_t seed[HEADER_SEED_SIZE];
    protocol_generate_header_seed(sid, seed, HEADER_SEED_SIZE);
    uint8_t perm[HEADER_FIELD_COUNT];
    protocol_generate_header_permutation(seed, perm, HEADER_FIELD_COUNT);
    uint32_t padding_len = protocol_compute_padding(seed, HEADER_SEED_SIZE);

    /* Применяем ОБРАТНУЮ перестановку к данным (undo header scrambling) */
    inverse_permutation(decrypted + 4, total_len, perm, HEADER_FIELD_COUNT);

    /* Извлекаем реальный data_len (убираем padding) */
    uint32_t real_len = total_len - padding_len;
    if (real_len > total_len) return -1;  /* overflow check */

    if (real_len > MAX_PAYLOAD - 4 - 8) return -1;

    *data_len = real_len;
    memcpy(data, decrypted + 4 + padding_len, real_len);

    /* Обновляем counter значением из пакета */
    *counter = pkt_counter;
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

int protocol_verify_handshake(
    const gost_packet_t *pkt,
    const uint8_t *expanded_key
) {
    if (!pkt || !expanded_key) return -1;
    if (pkt->type != PKT_HANDSHAKE) return -1;
    if (ntohl(pkt->magic) != GOST_PROXY_MAGIC) return -1;
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

/* ============================================================
 * Динамические заголовки — перестановка байтов payload
 * ============================================================ */

/* Применить перестановку к данным (shuffle байтов) */
static void apply_permutation(uint8_t *data, size_t data_len,
                               const uint8_t *perm, size_t perm_len) {
    uint8_t tmp[MAX_PAYLOAD];
    for (size_t i = 0; i < data_len; i++) {
        size_t src = i % perm_len;
        tmp[i] = data[perm[src] % data_len];
    }
    memcpy(data, tmp, data_len);
}

/* Обратная перестановка */
static void inverse_permutation(uint8_t *data, size_t data_len,
                                 const uint8_t *perm, size_t perm_len) {
    uint8_t tmp[MAX_PAYLOAD];
    memset(tmp, 0, sizeof(tmp));
    for (size_t i = 0; i < data_len; i++) {
        size_t src = i % perm_len;
        size_t dst_pos = perm[src];
        if (dst_pos < data_len) {
            tmp[dst_pos] = data[i];
        }
    }
    memcpy(data, tmp, data_len);
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

/* Проверка, является ли пакет имитационным */
int protocol_is_fake_packet(const gost_packet_t *pkt) {
    if (!pkt) return 0;
    return (pkt->type == PKT_SIM_QUIC ||
            pkt->type == PKT_SIM_DNS ||
            pkt->type == PKT_SIM_TLS ||
            pkt->type == PKT_SIM_CHALLENGE);
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
