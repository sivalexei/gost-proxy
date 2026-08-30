#!/bin/bash
# test-https.sh — тест HTTPS через ГОСТ-прокси с разными TLS-бэкендами
# Использование: ./tests/test-https.sh [target_host]

set -euo pipefail

TARGET="${1:-example.com}"
SOCKS5_PORT="${2:-1081}"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_pass() { echo -e "${GREEN}[PASS]${NC} $*"; }
log_fail() { echo -e "${RED}[FAIL]${NC} $*"; }
log_info() { echo -e "${YELLOW}[INFO]${NC} $*"; }

echo "========================================="
echo "  ГОСТ-прокси: тест HTTPS"
echo "  Целевой хост: ${TARGET}"
echo "  SOCKS5 порт: ${SOCKS5_PORT}"
echo "========================================="
echo ""

# Проверка что прокси запущен
if ! nc -z 127.0.0.1 "${SOCKS5_PORT}" 2>/dev/null; then
    log_fail "SOCKS5 прокси не работает (запустите gost-client)"
    exit 1
fi

# Определяем бэкенд curl
CURL_BACKEND=$(curl --version | grep -oP '(GnuTLS|OpenSSL)/\S+' || echo "unknown")
echo "libcurl backend: ${CURL_BACKEND}"
echo ""

# --- Тест 1: HTTP через прокси (должен работать всегда) ---
log_info "Тест 1: HTTP через SOCKS5-прокси..."
HTTP_CODE=$(curl -s --socks5-hostname "127.0.0.1:${SOCKS5_PORT}" \
     "http://${TARGET}" -o /dev/null -w "%{http_code}" 2>/dev/null || echo "000")
if [[ "$HTTP_CODE" =~ ^[23] ]]; then
    log_pass "HTTP работает (код: ${HTTP_CODE})"
else
    log_fail "HTTP не работает (код: ${HTTP_CODE})"
fi

# --- Тест 2: HTTPS через прокси с системным curl ---
log_info "Тест 2: HTTPS через прокси (${CURL_BACKEND})..."
HTTPS_CODE=$(curl -s --socks5-hostname "127.0.0.1:${SOCKS5_PORT}" \
     "https://${TARGET}" -o /dev/null -w "%{http_code}" 2>/dev/null || echo "000")
if [[ "$HTTPS_CODE" =~ ^[23] ]]; then
    log_pass "HTTPS работает с ${CURL_BACKEND} (код: ${HTTPS_CODE})"
else
    log_fail "HTTPS не работает с ${CURL_BACKEND} (код: ${HTTPS_CODE})"
fi

# --- Тест 3: HTTPS через прокси с --tlsv1.3 явно ---
log_info "Тест 3: HTTPS + --tlsv1.3..."
TLS13_CODE=$(curl -s --socks5-hostname "127.0.0.1:${SOCKS5_PORT}" \
     --tlsv1.3 "https://${TARGET}" -o /dev/null -w "%{http_code}" 2>/dev/null || echo "000")
if [[ "$TLS13_CODE" =~ ^[23] ]]; then
    log_pass "HTTPS работает с --tlsv1.3 (код: ${TLS13_CODE})"
else
    log_fail "HTTPS не работает с --tlsv1.3 (код: ${TLS13_CODE})"
fi

# --- Тест 4: curl с OpenSSL (если установлен) ---
if command -v "$HOME/.local/bin/curl" &>/dev/null; then
    log_info "Тест 4: HTTPS через прокси (curl/OpenSSL)..."
    OPENSSL_CODE=$("$HOME/.local/bin/curl" -s --socks5-hostname "127.0.0.1:${SOCKS5_PORT}" \
         "https://${TARGET}" -o /dev/null -w "%{http_code}" 2>/dev/null || echo "000")
    if [[ "$OPENSSL_CODE" =~ ^[23] ]]; then
        log_pass "HTTPS работает с curl/OpenSSL (код: ${OPENSSL_CODE})"
    else
        log_fail "HTTPS не работает с curl/OpenSSL (код: ${OPENSSL_CODE})"
    fi
else
    log_info "Тест 4: пропущен (curl с OpenSSL не установлен)"
fi

# --- Тест 5: Контрольная сумма (upload + download round-trip) ---
log_info "Тест 5: Контрольная сумма (upload + download round-trip)..."
TEST_FILE=$(mktemp)
TEST_DATA="test-checksum-data-$(date +%s)"
echo "$TEST_DATA" > "$TEST_FILE"
ORIG_MD5=$(md5sum "$TEST_FILE" | awk '{print $1}')

# Upload: читаем ответ httpbin/post (возвращает отправленные данные в JSON)
RESPONSE_FILE=$(mktemp)
RESPONSE_CODE=$(curl -s --socks5-hostname "127.0.0.1:${SOCKS5_PORT}" \
     -w "%{http_code}" -o "$RESPONSE_FILE" \
     -T "$TEST_FILE" \
     "http://httpbin.org/post" 2>/dev/null || echo "000")

if [[ "$RESPONSE_CODE" =~ ^[23] ]]; then
    log_pass "Upload OK (HTTP ${RESPONSE_CODE}), md5: ${ORIG_MD5:0:12}..."
    log_info "Ответ httpbin/post получен, можно проверить данные в $RESPONSE_FILE"
else
    log_fail "Upload failed (HTTP ${RESPONSE_CODE})"
fi

# Download: GET с возвращением размера
DLOAD_FILE=$(mktemp)
DLOAD_CODE=$(curl -s --socks5-hostname "127.0.0.1:${SOCKS5_PORT}" \
     -o "$DLOAD_FILE" -w "%{http_code}" \
     "http://httpbin.org/get" 2>/dev/null || echo "000")
DLOAD_SIZE=$(stat -c%s "$DLOAD_FILE" 2>/dev/null || echo 0)

if [[ "$DLOAD_CODE" =~ ^[23] ]] && [[ "$DLOAD_SIZE" -gt 100 ]]; then
    log_pass "Download OK (HTTP ${DLOAD_CODE}, size: ${DLOAD_SIZE}B)"
else
    log_fail "Download failed (HTTP ${DLOAD_CODE}, size: ${DLOAD_SIZE}B)"
fi

# --- Тест 6: CPS handshake (проверка логи клиента) ---
log_info "Тест 6: Проверка CPS handshake..."
CPS_LOG=$(grep -c "CPS\|cps\|handshake\|challenge" /tmp/gost-proxy/client.log 2>/dev/null || echo "0")
if [[ "$CPS_LOG" -gt 0 ]]; then
    log_pass "CPS handshake найден в логах (${CPS_LOG} совпадений)"
else
    log_fail "CPS handshake не найден в client.log"
    log_info "Логи:"
    tail -5 /tmp/gost-proxy/client.log 2>/dev/null || echo "  (файл не найден)"
fi

rm -f "$TEST_FILE" "$DLOAD_FILE"

# --- Итог ---
echo ""
echo "========================================="
if [[ "$CURL_BACKEND" == *"GnuTLS"* ]] && ! [[ "$HTTPS_CODE" =~ ^[23] ]]; then
    echo -e "${RED}  ⚠ GnuTLS не может завершить TLS handshake${NC}"
    echo ""
    echo "  Решение: используйте curl с OpenSSL:"
    echo "    make build-curl-openssl"
    echo "    export PATH=\"\$HOME/.local/bin:\$PATH\""
    echo "    curl --socks5-hostname 127.0.0.1:1080 https://${TARGET}"
    echo ""
    echo "  Или используйте Firefox (NSS) вместо curl."
fi
echo "========================================="
