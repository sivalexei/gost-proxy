#!/bin/bash
# test-https.sh — тест HTTPS через ГОСТ-прокси с разными TLS-бэкендами
# Использование: ./tests/test-https.sh [target_host]

set -euo pipefail

TARGET="${1:-example.com}"
SOCKS5_PORT=1080

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
