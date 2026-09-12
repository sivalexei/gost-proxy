# ГОСТ Прокси

SOCKS5-прокси с шифрованием ГОСТ Р 34.12-2015 «Кузнечик». Клиент шифрует трафик и отправляет через UDP на сервер; сервер расшифровывает и проксирует на целевые хосты.

## Возможности

- **Шифрование** ГОСТ Р 34.12-2015 (Кузнечик) — C-реализация по RFC 7801
- **QUIC-транспорт** поверх UDP с рукопожатием, keepalive и мультиплексированием
- **CPS обфускация** — маскировка трафика под случайный
- **Двусторонняя CMAC-аутентификация** — client/server nonce
- **Auth-tag** — encrypt-then-MAC для проверки целостности
- **conn_id** — изолированные параллельные соединения
- **SOCKS5-прокси** на клиенте (127.0.0.1:1081)
- **DNS на сервере**, переиспользование сессий, graceful shutdown

## Сборка и тесты

```bash
make                          # сборка gost-server и gost-client
make test                     # все тесты (gost-test + test_protocol + test_pack_roundtrip)
make asan                     # сборка + тесты с AddressSanitizer
make asan MODE=ubsan          # сборка + тесты с UBSan
make sanitize-werror          # проверка на -Werror
make build-curl-openssl       # сборка curl с OpenSSL
make clean                    # очистка
```

## Запуск

### Подготовка ключа

Ключ 256 бит (64 hex-символа):

```bash
export GOST_PROXY_KEY="0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
```

### Сервер

```bash
./build/gost-server /etc/gost-proxy/server.json
```

**Конфиг** (`config/server.json`):

```json
{
    "listen_port": 10443,
    "max_sessions": 1024,
    "session_timeout": 300,
    "rate_limit": 10,
    "rate_burst": 20,
    "key": "0123456789ABCDEF...",
    "log_level": "info",
    "log_file": "/tmp/gost-proxy/server.log"
}
```

| Параметр | Описание | По умолч. |
|----------|----------|-----------|
| `listen_port` | Порт UDP-слушателя | 10443 |
| `max_sessions` | Макс. сессий | 1024 |
| `session_timeout` | Таймаут сессии (сек) | 300 |
| `rate_limit` | Токенов/сек (token bucket) | 10 |
| `rate_burst` | Макс. burst бакета | 20 |
| `key` | 64 hex-символа | обязательный |
| `log_level` | debug / info / warn / error | "info" |
| `log_file` | Путь к логу | "/tmp/gost-proxy/server.log" |

### Клиент

```bash
./build/gost-client /etc/gost-proxy/client.json
```

**Конфиг** (`config/client.json`):

```json
{
    "server_ip": "10.0.0.1",
    "server_port": 10443,
    "bind_addr": "127.0.0.1",
    "port": 1081,
    "handshake_timeout_ms": 1000,
    "handshake_max_retries": 5,
    "key": "0123456789ABCDEF..."
}
```

| Параметр | Описание | По умолч. |
|----------|----------|-----------|
| `server_ip` | IP сервера | обязательный |
| `server_port` | Порт сервера | 10443 |
| `bind_addr` | Локальный адрес SOCKS5 | "127.0.0.1" |
| `port` | Порт SOCKS5-прокси | 1081 |
| `handshake_timeout_ms` | Базовая задержка между попытками (мс) | 1000 |
| `handshake_max_retries` | Макс. попыток handshake | 5 |
| `key` | 64 hex-символа | обязательный |

**Retry с экспоненциальным backoff:** 1s → 2s → 4s → 8s → 16s → 32s (макс. 60s).

### Использование

Клиент запускает SOCKS5 на `127.0.0.1:1081`:

```bash
curl --socks5-hostname 127.0.0.1:1081 http://example.com
curl --socks5-hostname 127.0.0.1:1081 https://example.com
```

Для HTTPS с GnuTLS (ALT Linux) используйте встроенный curl с OpenSSL:
```bash
make build-curl-openssl
export PATH="$HOME/.local/bin:$PATH"
curl --socks5-hostname 127.0.0.1:1081 https://example.com
```

## Интеграционные тесты

```bash
./tests/test-https.sh [target_host]
```

Тестирует: HTTP, HTTPS (GnuTLS/OpenSSL), TLS 1.3, upload/download round-trip, CPS handshake.

## Протокол

```
[ magic(4) | type(1) | conn_id(4) | session_id(8) | payload(1400) | auth_tag(16) ]
```

| Тип | Описание |
|-----|----------|
| 0x01 | HANDSHAKE — аутентификация |
| 0x02 | DATA — зашифрованные данные |
| 0x03 | KEEPALIVE — каждые 30с |
| 0x04 | DISCONNECT — отключение |
| 0x10-0x13 | Fake QUIC/DNS/TLS — CPS обфускация |

Рукопожатие: Client → Server nonce → Server nonce + auth_tag → CMAC(PSK, client_nonce \|\| server_nonce).

## Архитектура

```
src/
├── crypto/           # ГОСТ Р 34.12-2015 (Кузнечик), RFC 7801
├── core/             # сервер, клиент, session, config, obfuscation, DNS
└── network/          # SOCKS5, QUIC-слой
```

## Сборка пакетов

```bash
./build_rpm.sh    # RPM (ALT Linux)
./build_deb.sh    # DEB (Ubuntu/Debian)
```
