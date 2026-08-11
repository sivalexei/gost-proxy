# ГОСТ Прокси

SOCKS5-прокси с шифрованием ГОСТ Р 34.12-2015 "Кузнечик". Клиент шифрует трафик и отправляет через UDP на сервер; сервер расшифровывает и проксирует на целевые хосты.

## Возможности

- Шифрование ГОСТ Р 34.12-2015 (Кузнечик) — C-реализация по RFC 7801
- QUIC-транспорт поверх UDP (рукопожатие, keepalive, мультиплексирование)
- Auth-tag (encrypt-then-MAC) для проверки целостности
- CTR-режим для потоковых данных
- conn_id мультиплексирование — параллельные соединения изолированы
- SOCKS5-прокси на клиенте (127.0.0.1:1081)
- systemd-юниты для автоматического запуска

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
│   ├── session.c          # pack/unpack с CTR + MAC
│   ├── protocol.h         # Протокол обмена
│   ├── config.c           # JSON-парсер конфигурации
│   ├── log.c              # Логирование
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
| 0x03 | KEEPALIVE — поддержание сессии |
| 0x04 | DISCONNECT — отключение |

## Сборка пакетов

```bash
# RPM (ALT Linux)
./build_rpm.sh
ls rpmbuild/RPMS/x86_64/*.rpm
```

## HTTPS через прокси

Прокси прозрачно пересылает байты — TLS handshake происходит в клиентском приложении.

**HTTP** работает стабильно. **HTTPS** может не работать с GnuTLS (ALT Linux curl).

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
- CTR-режим, encrypt-then-MAC
- conn_id изолирует параллельные соединения

## Сборка RPM для ALT Linux

```bash
./build_rpm.sh
```

Создаёт пакеты:
- `gost-proxy-server` — сервер с systemd-юнитом
- `gost-proxy-client` — клиент с systemd-юнитом

```bash
sudo dnf install gost-proxy-server-1.0.0-2.x86_64.rpm
sudo systemctl enable --now gost-proxy-server
```
