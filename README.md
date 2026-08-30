# ГОСТ Прокси

SOCKS5-прокси с шифрованием ГОСТ Р 34.12-2015 "Кузнечик". Клиент шифрует трафик и отправляет через UDP на сервер; сервер расшифровывает и проксирует на целевые хосты.

## Возможности

- **Шифрование** ГОСТ Р 34.12-2015 (Кузнечик) — C-реализация по RFC 7801
- **QUIC-транспорт** поверх UDP с рукопожатием, keepalive от обеих сторон и мультиплексированием
- **CPS (Chaffing/Pretense System)** — обфускация трафика для маскировки под случайный
- **Двусторонняя CMAC-аутентификация** — client/server nonce с проверкой подлинности обеих сторон
- **Auth-tag** — encrypt-then-MAC для проверки целостности данных
- **conn_id** — изолированные параллельные соединения
- **SOCKS5-прокси** на клиенте (127.0.0.1:1081)
- **DNS на сервере** — клиент шлёт домен, сервер резолвит через getaddrinfo()
- **Переиспользование сессий** — free list + тайм-ауты
- **systemd-юниты** для автоматического запуска

## Протокол рукопожатия (QUIC)

1. **Client → Server**: `PKT_HANDSHAKE` с `session_id`, `client_nonce` (8 байт, из `/dev/urandom`)
2. **Server → Client**: `PKT_HANDSHAKE` с `session_id`, `server_nonce` (8 байт, из `/dev/urandom`), `auth_tag`
3. **Auth**: `auth_tag = CMAC(PSK, client_nonce || server_nonce)` — двусторонняя проверка подлинности через ГОСТ-Кузнечик
4. При неверном ключе — соединение отклоняется с `CMAC mismatch`

## Требования

- Linux x86-64
- NASM (для `tcp_helpers.asm` — оптимизация TCP write loop)
- GCC
- glibc

## Сборка

```bash
make              # сборка gost-server и gost-client
make test         # тесты шифрования (все 5 тестов RFC 7801)
make clean        # очистка
```

## Запуск

### Сервер

```bash
./build/gost-server /etc/gost-proxy/server.json
```

Конфиг по умолчанию — `config/server.json` (порт 10443).

### Клиент

```bash
./build/gost-client /etc/gost-proxy/client.json
```

Клиент запускает SOCKS5-прокси на `127.0.0.1:1081`. Настройте curl или браузер:

```bash
curl --socks5-hostname 127.0.0.1:1081 https://example.com
```

### Конфигурация клиента (retry)

```json
{
  "server_ip": "10.0.0.1",
  "server_port": 10443,
  "handshake_timeout_ms": 1000,
  "handshake_max_retries": 5,
  "key": "0123456789ABCDEF..."
}
```

- `handshake_timeout_ms`: базовая задержка между попытками (по умолч. 1000)
- `handshake_max_retries`: макс. попыток (по умолч. 5)
- Экспоненциальный backoff: 1s → 2s → 4s → 8s → 16s → 32s (макс. 60s)

### Конфигурация сервера (rate limiting)

```json
{
  "rate_limit": 10,       /* токенов в секунду (по умолч. 10; prod: 1000) */
  "rate_burst": 20,       /* макс. burst (размер бакета), по умолч. 20 */
  "key": "0123456789ABCDEF..."
}
```

- **Token bucket** per IP: каждый пакет (HANDSHAKE, DATA) отнимает 1 токен
- Refill: `rate_limit` токенов/сек, refill до `rate_burst`
- Превышен лимит — сервер тихо отбрасывает пакет (log: `Rate limit exceeded`)

## Архитектура

```
src/
├── crypto/
│   ├── gost_cipher.c      # Ядро шифрования, C-реализация (RFC 7801)
│   ├── kuznyechik.h       # Интерфейс
│   └── gost_common.h      # Общие определения, структура пакета
├── core/
│   ├── server.c           # Прокси-сервер (UDP → TCP)
│   ├── client.c           # Клиент (SOCKS5 → UDP)
│   ├── session.c          # pack/unpack с CTR + MAC, CPS
│   ├── protocol.h         # Протокол обмена
│   ├── config.c           # JSON-парсер конфигурации
│   ├── log.c              # Логирование
│   ├── obfuscation.c      # Обфускация (Salamander XOR)
│   └── tcp_helpers.asm    # Быстрый TCP write loop (NASM x86-64)
└── network/
    ├── socks5.c           # SOCKS5 CONNECT + relay
    └── quic_layer.c       # QUIC-слой поверх UDP
```

## Протокол

Формат пакета:

```
[ magic(4) | type(1) | conn_id(4) | session_id(8) | payload(1400) | auth_tag(16) ]
```

| Тип | Описание |
|-----|----------|
| 0x01 | HANDSHAKE — аутентификация сессии |
| 0x02 | DATA — зашифрованные данные с conn_id |
| 0x03 | KEEPALIVE — поддержание NAT-сессии (от клиента и сервера, каждые 30с) |
| 0x04 | DISCONNECT — отключение |
| 0x10-0x13 | Fake QUIC/DNS/TLS — обфускация CPS |
| 0x14 | CPS Challenge/Response |

## Сборка пакетов

```bash
# RPM (ALT Linux)
./build_rpm.sh
ls rpmbuild/RPMS/x86_64/*.rpm

# DEB (Ubuntu/Debian)
./build_deb.sh
ls debs/*.deb
```

## HTTPS через прокси

Прокси прозрачно пересылает байты — TLS handshake происходит в клиентском приложении.

**HTTP** работает стабильно. **HTTPS** зависит от TLS-библиотеки клиента:
- curl с **OpenSSL** — работает стабильно
- curl с **GnuTLS** (ALT Linux) — может не работать с некоторыми CDN
- Firefox (NSS) — работает стабильно

Решение — соберите curl с OpenSSL:
```bash
make build-curl-openssl
export PATH="$HOME/.local/bin:$PATH"
curl --socks5-hostname 127.0.0.1:1081 https://example.com
```

Или используйте Firefox (NSS).

Подробнее: `docs/https-troubleshooting.md`

## Безопасность

- Ключ 256 бит, блок 128 бит, 10 раундов
- **Двусторонняя CMAC-аутентификация** — client/server nonce, `CMAC(PSK, client_nonce || server_nonce)`
- CTR-режим, encrypt-then-MAC
- Nonce из `/dev/urandom`
- conn_id изолирует параллельные соединения
- CPS handshake — challenge/response верификация
- При неверном ключе — соединение **отклоняется** (CMAC mismatch)

## Разработка

План развития: `DEVELOPMENT_PLAN.md`
История изменений: `PROGRESS.md`
