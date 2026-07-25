#!/bin/bash
# build-curl-openssl.sh — сборка curl с OpenSSL вместо GnuTLS
# Для ALT Linux, где системный curl использует GnuTLS по умолчанию

set -euo pipefail

CURL_VER="${CURL_VER:-8.12.0}"
INSTALL_DIR="${HOME}/.local"
TMPDIR=$(mktemp -d)

trap 'rm -rf "$TMPDIR"' EXIT

echo "=== Сборка curl с OpenSSL ==="
echo "Версия: ${CURL_VER}"
echo "Установка в: ${INSTALL_DIR}"
echo "Временная папка: ${TMPDIR}"
echo ""

# Проверка зависимостей
for cmd in gcc make wget tar; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ОШИБКА: не найден $cmd. Установите: apt install build-essential"
        exit 1
    fi
done

# Проверка OpenSSL заголовков
if [ ! -f /usr/include/openssl/ssl.h ]; then
    echo "Устанавливаем openssl-devel..."
    apt install --devel openssl || {
        echo "ОШИБКА: не удалось установить openssl-devel"
        exit 1
    }
fi

cd "$TMPDIR"

# Скачиваем curl
echo "Скачивание curl-${CURL_VER}..."
wget -q "https://github.com/curl/curl/releases/download/curl-${CURL_VER}/curl-${CURL_VER}.tar.xz" \
     -O "curl-${CURL_VER}.tar.xz" 2>/dev/null || \
    curl -sLO "https://github.com/curl/curl/releases/download/curl-${CURL_VER}/curl-${CURL_VER}.tar.xz"

echo "Распаковка..."
tar xf "curl-${CURL_VER}.tar.xz"
cd "curl-${CURL_VER}"

echo "Конфигурация (--with-openssl --without-gnutls)..."
./configure \
    --prefix="$INSTALL_DIR" \
    --with-openssl \
    --without-gnutls \
    --disable-manual \
    CFLAGS="-O2 -Wall" || {
        echo "ОШИБКА: configure не удался. Проверьте /usr/include/openssl/ssl.h"
        exit 1
    }

echo "Сборка (threads=$(nproc))..."
make -j$(nproc) V=0

echo "Установка в ${INSTALL_DIR}..."
mkdir -p "$INSTALL_DIR/bin"
make install

# Проверка результата
if [ -f "$INSTALL_DIR/bin/curl" ]; then
    echo ""
    echo "========================================="
    echo "  ✅ curl с OpenSSL установлен!"
    echo "  Путь: ${INSTALL_DIR}/bin/curl"
    echo "========================================="
    echo ""
    echo "Использование:"
    echo '  export PATH="${HOME}/.local/bin:$PATH"'
    echo "  curl --version | grep libcurl   # проверить backend"
    echo "  curl --socks5-hostname 127.0.0.1:1080 https://example.com"
    echo ""
else
    echo "ОШИБКА: бинарный файл не найден в ${INSTALL_DIR}/bin/"
    exit 1
fi
