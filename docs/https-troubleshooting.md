# Решение проблемы HTTPS через ГОСТ-прокси

## Корень проблемы

Клиентские приложения (curl, Firefox) используют свою TLS-библиотеку для handshake с целевым сервером. Прокси только пересылает байты — он **не участвует** в TLS.

На ALT Linux `curl` по умолчанию использует **GnuTLS 3.8.13**, который не может завершить TLS handshake с некоторыми CDN-серверами (Cloudflare и др.) через прокси.

## Вариант A: OpenSSL вместо GnuTLS (рекомендуется)

### Способ 1: curl, собранный с OpenSSL

На Ubuntu/Debian:
```bash
sudo apt install libcurl4-openssl-dev
# curl из репозитория уже использует OpenSSL
```

На ALT Linux — нет пакета `curl-openssl` в репозитории. Нужно собрать вручную:
```bash
# 1. Установить зависимости
apt install libcurl-devel openssl-devel

# 2. Собрать curl с OpenSSL вместо GnuTLS
git clone https://github.com/curl/curl.git
cd curl
./configure --with-openssl --without-gnutls
make && sudo make install
```

### Способ 2: Прямое использование openssl s_client (для тестов)

Не требует установки дополнительных пакетов. OpenSSL уже есть в системе:

```bash
# Проверка TLS напрямую (без прокси):
openssl s_client -connect example.com:443 -tls1_3 </dev/null

# Через SOCKS5-прокси — openssl не поддерживает SOCKS5 напрямую,
# но можно использовать socat или proxychains:
proxychains openssl s_client -connect example.com:443 -tls1_3
```

### Способ 3: Фиксированные cipher suites для curl GnuTLS

Если нельзя сменить библиотеку, попробуйте ограничить cipher suite:

```bash
# TLS 1.2 с конкретными шифрами
curl --socks5-hostname 127.0.0.1:1080 \
     --tls-max 1.2 \
     --ciphers "TLS_AES_256_GCM_SHA384" \
     https://example.com

# Или TLS 1.3 явно
curl --socks5-hostname 127.0.0.1:1080 \
     --tlsv1.3 \
     https://example.com
```

## Вариант B: Firefox (альтернатива)

Firefox использует собственную библиотеку **NSS** (не GnuTLS и не OpenSSL).
Через SOCKS5 прокси работает стабильнее, чем curl с GnuTLS.

Настройка:
1. Настройки → Сеть → Настройка подключения
2. Ручная настройка прокси → SOCKS Host: 127.0.0.1, Порт: 1080
3. Версия: SOCKS v5
4. **Важно**: галочка "Прокси для DNS при использовании SOCKS v5"

## Вариант C: Сборка curl с OpenSSL на ALT Linux

```bash
#!/bin/bash
# build-curl-openssl.sh — автоматическая сборка
set -e

TMPDIR=$(mktemp -d)
cd "$TMPDIR"

# Зависимости
apt install --devel libcurl openssl zlib brotli nghttp2 || true

# Скачиваем curl
CURL_VER="8.12.0"
wget "https://github.com/curl/curl/releases/download/curl-${CURL_VER}/curl-${CURL_VER}.tar.xz" \
     -O "curl-${CURL_VER}.tar.xz" || \
    curl -LO "https://github.com/curl/curl/releases/download/curl-${CURL_VER}/curl-${CURL_VER}.tar.xz"

tar xf "curl-${CURL_VER}.tar.xz"
cd "curl-${CURL_VER}"

./configure --prefix="$HOME/.local" \
            --with-openssl \
            --without-gnutls \
            --disable-manual \
            CFLAGS="-O2"

make -j$(nproc)
make install

echo ""
echo "========================================="
echo "curl с OpenSSL установлен в $HOME/.local/bin/curl"
echo "Использовать:"
echo "  export PATH=\"$HOME/.local/bin:\$PATH\""
echo "  curl --version | grep libcurl"
echo "========================================="

# Очистка (раскомментируйте)
# rm -rf "$TMPDIR"
```

## Диагностика

### Проверка, какая TLS-библиотека используется:
```bash
curl --version | grep -E 'GnuTLS|OpenSSL'
```

### Тест HTTPS через прокси:
```bash
# С GnuTLS (может не работать):
curl --socks5-hostname 127.0.0.1:1080 https://example.com

# С OpenSSL (должно работать):
$HOME/.local/bin/curl --socks5-hostname 127.0.0.1:1080 https://example.com

# Прямой тест openssl s_client:
openssl s_client -connect example.com:443 -tls1_3 </dev/null
```

### Проверка cipher suites GnuTLS:
```bash
certutil -V -u C -d sql:$HOME/.pki/nssdb \
         https://example.com 2>/dev/null || echo "NSS не доступна"

# Или через gnutls-cli:
gnutls-cli --print-ciphers | grep -i aes_256_gcm
```
