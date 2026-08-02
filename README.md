# ГОСТ Прокси

SOCKS5-прокси с шифрованием ГОСТ Р 34.12-2015 "Кузнечик". Клиент шифрует трафик и отправляет через UDP на сервер; сервер расшифровывает и проксирует на целевые хосты.

## Возможности

- Шифрование ГОСТ Р 34.12-2015 (Кузнечик) — C-реализация по RFC 7801
- UDP-транспорт, SOCKS5 на клиенте (127.0.0.1:1080)
- Auth-tag (encrypt-then-MAC) для проверки целостности
- CTR-режим для потоковых данных
- conn_id мультиплексирование — параллельные соединения изолированы
- TCP write-loop для гарантированной доставки

## Требования

- Linux x86-64
- NASM (`sudo apt install nasm`)
- GCC (`sudo apt install build-essential`)

## Сборка

```bash
make setup    # установка зависимостей
make          # сборка gost-server и gost-client
make test     # тесты шифрования (RFC 7801)
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

Клиент запускает SOCKS5-прокси на `127.0.0.1:1080`. Настройте Firefox или curl:

```bash
curl --socks5-hostname 127.0.0.1:1080 https://example.com
```

## Архитектура

```
src/
├── crypto/
│   ├── gost_cipher.c      # Ядро шифрования, C-реализация (RFC 7801)
│   ├── kuznyechik.h       # Интерфейс
│   ├── kuznyechik.asm     # НЕ СОБИРАЕТСЯ: сломан, см. AUDIT_REPORT.md §3
│   ├── gost_common.h      # Общие определения, структура пакета
│   └── gost_test.c        # Тесты по RFC 7801
├── core/
│   ├── server.c           # Прокси-сервер (UDP → TCP)
│   ├── client.c           # Клиент (SOCKS5 → UDP)
│   ├── session.c          # pack/unpack с CTR + MAC
│   ├── protocol.h         # Протокол обмена
│   ├── config.c           # JSON-парсер конфигурации
│   └── tcp_helpers.asm    # write loop + hex dump (NASM)
└── network/
    └── socks5.c           # SOCKS5 CONNECT + relay
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
| 0x03 | KEEPALIVE — поддержание сессии |
| 0x04 | DISCONNECT — отключение |

## Сборка пакетов

```bash
# DEB (Ubuntu/Debian)
./build_deb.sh
ls debs/

# RPM (ALT Linux)
./build_rpm.sh
ls rpmbuild/RPMS/
```

## HTTPS через прокси

Прокси прозрачно пересылает байты — TLS handshake происходит в клиентском приложении.

**HTTP** работает стабильно. **HTTPS** может не работать с GnuTLS (ALT Linux curl).

Решение — собрите curl с OpenSSL:
```bash
make build-curl-openssl
export PATH="$HOME/.local/bin:$PATH"
curl --socks5-hostname 127.0.0.1:1080 https://example.com
```

Или используйте Firefox (NSS).

Подробнее: `docs/https-troubleshooting.md`

## Безопасность

- Ключ 256 бит, блок 128 бит, 10 раундов
- CTR-режим, encrypt-then-MAC
- conn_id изолирует параллельные соединения
