#!/bin/bash
# test-integration.sh — интеграционный тест: upload/download через gost-proxy
# Usage: ./tests/test-integration.sh [socks5_port] [echo_server_port]
set -euo pipefail

SOCKS5_PORT="${1:-11081}"
ECHO_PORT="${2:-19876}"
ECHO_URL="http://127.0.0.1:${ECHO_PORT}"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
log_pass() { echo -e "${GREEN}[PASS]${NC} $*"; }
log_fail() { echo -e "${RED}[FAIL]${NC} $*"; }
log_info() { echo -e "${YELLOW}[INFO]${NC} $*"; }

# Запускаем echo-сервер
log_info "Запуск echo-сервера на порту ${ECHO_PORT}..."
python3 "$(dirname "$0")/http-echo-server.py" "$ECHO_PORT" &
ECHO_PID=$!
sleep 1

# Ждём echo-сервер
for i in $(seq 1 10); do
    if nc -z 127.0.0.1 "$ECHO_PORT" 2>/dev/null; then
        log_info "Echo-сервер готов"
        break
    fi
    sleep 1
done

# Проверяем SOCKS5
if ! nc -z 127.0.0.1 "$SOCKS5_PORT" 2>/dev/null; then
    log_fail "SOCKS5 не работает на порту $SOCKS5_PORT"
    kill "$ECHO_PID" 2>/dev/null || true
    exit 1
fi
log_info "SOCKS5 прокси на порту $SOCKS5_PORT — готов"

# Генерируем тестовый файл
TEST_FILE=$(mktemp)
echo "gost-proxy-integration-test-data-$(date +%s)" > "$TEST_FILE"
# Добавляем случайные данные
head -c 512 /dev/urandom >> "$TEST_FILE"

ORIG_MD5=$(md5sum "$TEST_FILE" | awk '{print $1}')
ORIG_SHA256=$(sha256sum "$TEST_FILE" | awk '{print $1}')
ORIG_SIZE=$(stat -c%s "$TEST_FILE")
log_info "Файл: ${ORIG_SIZE}B, md5=${ORIG_MD5}, sha256=${ORIG_SHA256:0:16}..."

# Upload: POST файл
log_info "Upload через SOCKS5..."
UPLOAD_RESP=$(curl -s --socks5-hostname "127.0.0.1:${SOCKS5_PORT}" \
    -w "\n%{http_code}" -o /tmp/upload_json.json \
    -T "$TEST_FILE" "${ECHO_URL}/upload" 2>/dev/null || echo -e "\n000")
HTTP_CODE=$(echo "$UPLOAD_RESP" | tail -1)

if [[ "$HTTP_CODE" =~ ^[23] ]]; then
    log_pass "Upload OK (HTTP ${HTTP_CODE})"
    # Сверяем sha256 с сервером
    SERVER_SHA256=$(python3 -c "import json; print(json.load(open('/tmp/upload_json.json'))['sha256'])" 2>/dev/null || echo "ERROR")
    if [[ "$ORIG_SHA256" == "$SERVER_SHA256" ]]; then
        log_pass "Upload integrity: sha256 match"
    else
        log_fail "Upload integrity: sha256 mismatch (orig=${ORIG_SHA256:0:16}... srv=${SERVER_SHA256:0:16}...)"
    fi
else
    log_fail "Upload failed (HTTP ${HTTP_CODE})"
    kill "$ECHO_PID" 2>/dev/null || true
    rm -f "$TEST_FILE" /tmp/upload_json.json
    exit 1
fi

# Download: GET /echo
DLOAD_FILE=$(mktemp)
log_info "Download через SOCKS5..."
DOWNLOAD_RESP=$(curl -s --socks5-hostname "127.0.0.1:${SOCKS5_PORT}" \
    -w "\n%{http_code}" -o "$DLOAD_FILE" "${ECHO_URL}/echo" 2>/dev/null || echo -e "\n000")
HTTP_CODE=$(echo "$DOWNLOAD_RESP" | tail -1)
DLOAD_SIZE=$(stat -c%s "$DLOAD_FILE" 2>/dev/null || echo 0)

if [[ "$HTTP_CODE" =~ ^[23] ]] && [[ "$DLOAD_SIZE" -gt 100 ]]; then
    log_pass "Download OK (HTTP ${HTTP_CODE}, size: ${DLOAD_SIZE}B)"
else
    log_fail "Download failed (HTTP ${HTTP_CODE}, size: ${DLOAD_SIZE}B)"
    kill "$ECHO_PID" 2>/dev/null || true
    rm -f "$TEST_FILE" "$DLOAD_FILE" /tmp/upload_json.json
    exit 1
fi

# Сверяем MD5
DLOAD_MD5=$(md5sum "$DLOAD_FILE" | awk '{print $1}')
DLOAD_SHA256=$(sha256sum "$DLOAD_FILE" | awk '{print $1}')

if [[ "$ORIG_MD5" == "$DLOAD_MD5" ]]; then
    log_pass "Download integrity: md5 match"
else
    log_fail "Download integrity: md5 mismatch (orig=${ORIG_MD5}, dload=${DLOAD_MD5})"
fi

if [[ "$ORIG_SHA256" == "$DLOAD_SHA256" ]]; then
    log_pass "Download integrity: sha256 match"
else
    log_fail "Download integrity: sha256 mismatch (orig=${ORIG_SHA256:0:16}... dload=${DLOAD_SHA256:0:16}...)"
fi

# Upload + Download round-trip (POST -> GET echo -> verify)
log_info "Upload/Download round-trip..."
UPLOAD_FILE2=$(mktemp)
echo "gost-proxy-roundtrip-test-$(date +%s)-$(head -c 64 /dev/urandom | md5sum | head -c 16)" > "$UPLOAD_FILE2"
head -c 256 /dev/urandom >> "$UPLOAD_FILE2"

ROUNDTRIP_RESP=$(curl -s --socks5-hostname "127.0.0.1:${SOCKS5_PORT}" \
    -w "\n%{http_code}" -o /tmp/roundtrip_echo.bin \
    -T "$UPLOAD_FILE2" "${ECHO_URL}/upload" 2>/dev/null || echo -e "\n000")
HTTP_CODE=$(echo "$ROUNDTRIP_RESP" | tail -1)

if [[ "$HTTP_CODE" =~ ^[23] ]]; then
    # Скачиваем echo
    ECHO_FILE=$(mktemp)
    ECHO_RESP=$(curl -s --socks5-hostname "127.0.0.1:${SOCKS5_PORT}" \
        -w "\n%{http_code}" -o "$ECHO_FILE" "${ECHO_URL}/echo" 2>/dev/null || echo -e "\n000")
    ECHO_HTTP=$(echo "$ECHO_RESP" | tail -1)
    
    UPLOAD_MD5=$(md5sum "$UPLOAD_FILE2" | awk '{print $1}')
    ECHO_MD5=$(md5sum "$ECHO_FILE" | awk '{print $1}')
    
    if [[ "$UPLOAD_MD5" == "$ECHO_MD5" ]]; then
        log_pass "Round-trip integrity: md5 match"
    else
        log_fail "Round-trip integrity: md5 mismatch"
    fi
    rm -f "$UPLOAD_FILE2" "$ECHO_FILE"
else
    log_fail "Round-trip upload failed (HTTP ${HTTP_CODE})"
fi

# Cleanup
kill "$ECHO_PID" 2>/dev/null || true
wait "$ECHO_PID" 2>/dev/null || true
rm -f "$TEST_FILE" "$DLOAD_FILE" /tmp/upload_json.json /tmp/roundtrip_echo.bin

echo ""
log_pass "Интеграционные тесты завершены успешно"
