# ГОСТ Прокси — Прокси-сервер с шифрованием ГОСТ Р 34.12-2015

**Gost-Proxy** — это высокопроизводительный прокси-сервер, реализующий защищённое туннелирование трафика на базе шифрования ГОСТ Р 34.12-2015 «Кузнечик» и протокола QUIC поверх UDP. Проект обеспечивает:

- Прокси-функции уровня SOCKS5 с RFC1929-аутентификацией
- Шифрование данных на основе ГОСТ Кузнечик (10 раундов) + ChaCha20
- QUIC-транспорт: рукопожатия, keepalive, мультиплексирование
- Каскадные обфускации трафика (CPS-обфускация под случайные пакеты)
- Двустороннюю CMAC-аутентификацию (client/server nonce)
- Auth-tag для проверки целостности (encrypt-then-MAC)
- Изолированные параллельные соединения (conn_id)
- DNS-кеширование на стороне сервера
- Rate limiting с токеновым бакетом (per-IP)
- Graceful shutdown, eventfd для сигналов

## Архитектура

```
┌──────────────────────┐
│  Application Layer    │
├──────────────────────┤
│  Protocol Layer       │  protocol.c/h
│  (gost_packet)        │
├──────────────────────┤
│  Crypto Layer         │  kuznyechik, chacha20, cmac, sha256, hmac
├──────────────────────┤
│  QUIC Layer           │  quic_server, quic_client
├──────────────────────┤
│  Network Layer        │  socks5_server, socks5_auth
├──────────────────────┤
│  DNS Cache Layer      │  dns_cache
├──────────────────────┤
│  Config/Log Layer     │  config, log
├──────────────────────┤
│  Core Server          │  server, session
└──────────────────────┘
```

## Слои проекта

| Слой | Описание |
|------|----------|
| `src/crypto/` | Шифрование: Кuznyechik, ChaCha20, CMAC, SHA256, HMAC, AES fallback |
| `src/core/` | Сервер, клиент, session, config, log, dns_cache, obfuscation, key_derivation |
| `src/network/` | QUIC, SOCKS5, SOCKS5-аутентификация RFC1929 |
| `test_*.c` | Юнит-тесты и интеграционные тесты |

## Протокол

```
[ magic(4) | type(1) | conn_id(4) | session_id(8) | payload(1400) | auth_tag(16) ]
```

| Тип | Описание |
|-----|----------|
| 0x01 | HANDSHAKE — аутентификация (client/server nonce) |
| 0x02 | DATA — зашифрованные данные |
| 0x03 | KEEPALIVE — каждые 30с |
| 0x04 | DISCONNECT — отключение |
| 0x10–0x13 | Fake QUIC/DNS/TLS — CPS обфускация |

## Безопасность

- ГОСТ Кузнечик: 10 раундов, 256 бит ключа
- CMAC-128 для каждой транзакции
- Auth-tag: encrypt-then-MAC
- Replay protection: sliding window + counter + eventfd
- MITM protection: CMAC на каждой транзакции
- Анализ трафика защита: padding + obfuscation (ChaCha20-CTR)
- Side-channel: getrandom() для padding/nonce, eventfd вместо SIGUSR1
- Чувствительные данные в логах: нет паролей/ключей
- Rate limiting: token-bucket per IP
- Session limit per IP

## Сборка

```bash
make                          # сборка сервера и клиента
make test                     # все тесты
make asan                     # с AddressSanitizer
make asan MODE=ubsan          # UBSan
make sanitize-werror          # проверка на -Werror
make clean                    # очистка
```

## Запуск сервера

```bash
./build/gost-server /etc/gost-proxy/server.json
```

Конфигурация (`server.json`):

| Параметр | Описание | По умолчанию |
|----------|----------|-------------|
| `listen_port` | UDP-порт сервера | 10443 |
| `max_sessions` | Макс. сессий | 1024 |
| `session_timeout` | Таймаут сессии (сек) | 300 |
| `rate_limit` | Токены/сек | 10 |
| `rate_burst` | Макс. burst | 20 |
| `key` | Hex-ключ 256 бит | обязателен |
| `log_level` | debug/info/warn/error | info |
| `log_file` | Путь к логу | "/tmp/gost-proxy/server.log" |

## Запуск клиента

```bash
./build/gost-client /etc/gost-proxy/client.json
```

Клиент запускает SOCKS5 на `127.0.0.1:1081` для использования.

## Использование

```bash
curl --socks5-hostname 127.0.0.1:1081 http://example.com
curl --socks5-hostname 127.0.0.1:1081 https://example.com
```

## Интеграционные тесты

```bash
./tests/test-https.sh [target_host]
```

HTTP, HTTPS (GnuTLS/OpenSSL), TLS 1.3, round-trip upload/download, CPS handshake.

## Интеграция

```bash
./build_rpm.sh    # RPM (ALT Linux)
./build_deb.sh    # DEB (Ubuntu/Debian)
```

## Текущее развитие

| Задача | Статус |
|--------|--------|
| Padding PRNG → getrandom() | ✅ Реализовано |
| Packet reordering protection | ✅ Sliding window + bitmap |
| eventfd вместо SIGUSR1 | ✅ Реализовано |
| Чувствительные данные в логах | ✅ Нет паролей/ключей |
| ChaCha20/Кунечик-CTR obfuscation | ✅ Реализовано |
| RFC1929 auth | ✅ Реализовано |

## Авторы и ссылки

- GitHub: https://github.com/sivalexei/gost-proxy.git
- Документация: README.md, PROGRESS.md, DEVELOPMENT_PLAN.md, CRITICAL_FIX_PLAN.md