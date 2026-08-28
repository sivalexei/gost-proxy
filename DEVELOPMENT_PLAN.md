# План развития gost-proxy v2.0

## Текущее состояние проекта

✅ **Работает:** Сборка, SOCKS5 end-to-end, QUIC handshake, обфускация, CPS handshake, session переиспользование, DNS на сервере
⚠️ **Осталось:** IPv6, epoll, аутентификация handshake, keepalive от сервера, таймауты сессий, тесты

---

## Архитектура

```
Client:  SOCKS5(:1081) → QUIC(UDP) → Obfuscation → Protocol → UDP
Server:  UDP ← Protocol ← Obfuscation ← QUIC ← TCP Proxy → Target
```

**Ключевые модули:**
- `src/crypto/gost_cipher.c` — ГОСТ Р 34.12-2015 (Кузнечик), RFC 7801 ✅
- `src/core/session.c` — pack/unpack, CTR, MAC, padding, CPS ✅
- `src/core/obfuscation.c` — обфускация payload ✅
- `src/network/quic_layer.c` — UDP-слой ✅
- `src/network/socks5.c` — SOCKS5-прокси ✅
- `src/core/server.c` — сервер: UDP listener → TCP прокси ✅

---

## Реализовано (v1.0.0)

- ✅ Сборка Makefile (gost-server, gost-client)
- ✅ Криптографическое ядро — Кузнечик, все 5 тестов RFC 7801 прошли
- ✅ QUIC-транспорт поверх UDP (handshake, keepalive, мультиплексирование conn_id)
- ✅ Auth-tag (encrypt-then-MAC) для проверки целостности
- ✅ CTR-режим для потоковых данных
- ✅ conn_id — параллельные соединения изолированы
- ✅ Демультиплексор — все потоки читают из одного UDP сокота
- ✅ Переиспользование сессий (free list + тайм-аут)
- ✅ Хеш сессий с цепочками (без коллизий)
- ✅ CPS handshake — challenge/response с фиксированным ключом
- ✅ Обфускация payload (Salamander XOR)
- ✅ DNS на сервере (клиент шлёт ATYP 0x03 домен)
- ✅ Логирование с fallback на /tmp/gost-proxy.log
- ✅ systemd-юниты (gost-proxy-server, gost-proxy-client)
- ✅ Сборка RPM/DEB пакетов
- ✅ Ключ из JSON/env (64 hex-символа)
- ✅ Nonce из /dev/urandom

---

## Этап 1. Стабильность (P0)

### 1.1. Валидация входных данных (1 день)
Проблема: Пакеты от 10 байт, читает как полную структуру (1433 Б).
Решение: Требовать sizeof(gost_packet_t), проверять n >= 5+dlen+2.
Файлы: server.c, socks5.c, session.c

### 1.2. Keepalive от сервера к клиенту (2-3 часа)
Проблема: Клиент отправляет KEEPALIVE, сервер не отвечает.
Решение: Сервер шлёт PKT_KEEPALIVE обратно каждые 30 сек.
Файлы: server.c

### 1.3. Таймауты сессий (2-3 часа)
Проблема: session_timeout из конфига не используется.
Решение: Проверка в main loop, очистка просроченных сессий.
Файлы: server.c

---

## Этап 2. Архитектура (P1)

### 2.1. DNS-кэш (1 день)
Проблема: getaddrinfo() на каждом CONNECT.
Решение: Лёгкий кэш с TTL, LRU-вытеснение.
Файлы: server.c, socks5.c

### 2.2. IPv6 (2-3 дня)
Презаема: IPv4-only, gethostbyname().
Решение: getaddrinfo() с поддержкой A+AAAA, dual-stack sockets.
Файлы: socks5.c, server.c, quic_layer.c

### 2.3. epoll вместо poll (3-4 дня)
Проблема: poll 100мс → 100% CPU.
Решение: epoll event loop.
Файлы: socks5.c, quic_layer.c

---

## Этап 3. Безопасность (P2)

### 3.1. Аутентификация handshake (2-3 дня)
Проблема: auth_tag не проверяется, сервер принимает от всех.
Решение: CMAC(PSK, client_nonce || server_nonce).
Файлы: session.c, quic_layer.c

### 3.2. MAC с привязкой к длине (1-2 дня)
Проблема: compute_mac инвариантен к перестановке блоков.
Решение: CMAC на отдельном ключе, привязка к длине.
Файлы: session.c

### 3.3. Retry handshake с backoff (2-3 часа)
Проблема: Клиент падает при недоступном сервере.
Решение: Экспоненциальный backoff вместо выхода.
Файлы: client.c

---

## Этап 4. Эксплуатация (P3)

### 4.1. Rate limiting (1-2 дня)
Проблема: rate_limit в конфиге есть, но не используется.
Решение: Token bucket per IP, configurable.
Файлы: server.c

### 4.2. Graceful shutdown (2-3 часа)
Проблема: SIGINT убивает процессы без очистки.
Решение: Обработка SIGINT, отправка DISCONNECT.
Файлы: server.c, client.c

---

## Этап 5. Тесты (параллельно)

### 5.1. Юнит-тесты протокола
- pack → unpack на всех длинах
- Повреждённый MAC, повтор счётчика
- Обрезанные пакеты

### 5.2. Интеграционный тест
- Сервер + клиент → curl через прокси
- Сверить контрольную сумму
- Проверить CPS handshake

### 5.3. Санитайзеры
- fsanitize=address,undefined
- -Werror в CI

---

## Сводка

| Этап | Что | Оценка |
|------|-----|--------|
| 1 | Стабильность (P0) | 1.5-2 дня |
| 2 | Архитектура (P1) | 5-7 дней |
| 3 | Безопасность (P2) | 4-6 дней |
| 4 | Эксплуатация (P3) | 1-2 дня |
| 5 | Тесты (параллельно) | 3-4 дня |

**Суммарно:** ~4-6 недель на одного разработчика.
