# План развития gost-proxy v2.0

## Текущее состояние проекта

✅ **Работает:** Сборка, SOCKS5 end-to-end, QUIC handshake, обфускация, CPS handshake, session переиспользование, DNS на сервере
✅ **Работает:** Двусторонняя CMAC-аутентификация (client/server nonce, CMAC(PSK, client_nonce || server_nonce))
✅ **Работает:** Retry handshake с экспоненциальным backoff (config: handshake_timeout_ms, handshake_max_retries)
✅ **Работает:** Санитайзеры ASan/UBSan (make asan, make asan MODE=ubsan), -Werror ✅
✅ **Работает:** 13/13 тестов test_pack_roundtrip (pack→unpack, MAC corruption, replay counter)

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

### 1.1. Валидация входных данных (1 день) ✅ **ВЫПОЛНЕНО**
Проблема: Пакеты от 10 байт, читает как полную структуру (1433 Б).
Решение: Требовать sizeof(gost_packet_t), проверять n >= 5+dlen+2.
Файлы: server.c, socks5.c, session.c

### 1.2. Keepalive от сервера к клиенту (2-3 часа) ✅ **ВЫПОЛНЕНО**
Проблема: Клиент отправляет KEEPALIVE, сервер не отвечает.
Решение: Сервер шлёт PKT_KEEPALIVE обратно каждые 30 сек.
Функция: `send_keepalive_to_sessions()` server.c:537, вызов из main loop:580.
Файлы: server.c

### 1.3. Таймауты сессий (2-3 часа) ✅ **ВЫПОЛНЕНО**
Проблема: session_timeout из конфига не использовался для очистки.
Решение: `expire_sessions()` очищает сессии и proxy_conns (TCP fd close).
Функция: `session_remove(idx)` теперь закрывает tcp_fd и сбрасывает proxy_conns.
Тест: `expire_sessions()` вызывается в main loop (lines 454, 457, 488, 492, 599).
Файлы: server.c

### 1.4. Обфускация: mismatch длины obf/deobf (1 час) ✅ **ВЫПОЛНЕНО**
Проблема: клиент obfuscate(8+tl), сервер deobfuscate(8+MAX_PAYLOAD-4) — stream рассинхрон.
Решение: клиент обфусцирует 8+MAX_PAYLOAD-4 целиком.
Тест: test_obf_simple.c → 730 errors → 0.
Файлы: session.c → protocol_pack_data()

---

## Этап 2. Архитектура (P1)

### 2.1. DNS-кэш (1 день) ✅ **ВЫПОЛНЕНО**
Проблема: getaddrinfo() на каждом CONNECT.
Решение: Лёгкий кэш с TTL, LRU-вытеснение.
Файлы: dns_cache.h, dns_cache.c, server.c, socks5.c

### 2.2. IPv6 (2-3 дня) ✅ **ВЫПОЛНЕНО**
Проблема: клиент SOCKS5 слушал только IPv4.
Решение:
- ✅ SOCKS5 listener: AF_INET6 + IPV6_V6ONLY=0 (dual-stack) + fallback на AF_INET
- ✅ DNS-кэш: поддержка IPv6 через AF_UNSPEC (getaddrinfo)
- ✅ SOCKS5 CONNECT: поддержка IPv6 target (case 0x04), sockaddr_storage в accept
- ✅ Серверный connect_to_target: IPv6 поддержка
Файлы: socks5.c, dns_cache.h, dns_cache.c, server.c

### 2.3. epoll вместо poll (3-4 дня) ✅ **ВЫПОЛНЕНО**
Проблема: poll 100мс → 100% CPU.
Решение: epoll event loop.
Файлы: server.c, quic_layer.c

---

## Этап 3. Безопасность (P2)

### 3.1. Аутентификация handshake (2-3 дня) ✅ **ВЫПОЛНЕНО**
Проблема: auth_tag не проверяется, сервер принимает от всех.
Решение: CMAC(PSK, client_nonce || server_nonce) — двусторонняя аутентификация.
- Клиент отправляет `client_nonce` и `auth_tag = CMAC(PSK, client_nonce)`
- Сервер возвращает `server_nonce` и `auth_tag = CMAC(PSK, client_nonce || server_nonce)`
- При неверном ключе — соединение отклоняется с `CMAC mismatch`
Файлы: session.c, quic_layer.c, server.c

### 3.2. MAC с привязкой к длине (1-2 дня) ✅ **ВЫПОЛНЕНО**
Проблема: compute_mac инвариантен к перестановке блоков (MAC(A||B) == MAC(B||A)).
Решение: CBC-MAC — шифрование каждого блока перед XOR'ом со следующим + включение длины.
- `compute_mac`: CBC-MAC с 16-битным XOR-аккумулятором и финальным шифрованием с длиной
- Тест 6: `MAC(A||B) != MAC(B||A)` — доказательство order-sensitivity
Файлы: session.c, test_crypto.c

### 3.3. Retry handshake с backoff (2-3 часа) ✅ **ВЫПОЛНЕНО**
Проблема: Клиент падает при недоступном сервере.
Решение: Экспоненциальный backoff (1s, 2s, 4s, 8s...) с ограничением 60с.
- `handshake_max_retries` (по умолч. 5): макс. попыток
- `handshake_timeout_ms` (по умолч. 1000): базовая задержка
- Retry-цикл в `client.c`: `quic_client_connect` → проверка → backoff → повтор
- `quic_client_close()` вызывается перед каждой повторной попыткой
Файлы: client.c, config.h, config.c

---

## Этап 4. Эксплуатация (P3)

### 4.1. Rate limiting (1-2 дня) ✅ **ВЫПОЛНЕНО**
Проблема: rate_limit в конфиге есть, но не использовался для данных.
Решение: Token bucket per IP с параметрами `rate_limit` (токенов/сек) и `rate_burst` (max burst).
- `check_rate_limit()`: токеновый бакет с `clock_gettime(CLOCK_MONOTONIC)`
- Применяется к HANDSHAKE + DATA пакетам
- Фикс CMAC-бага: `server_nonce = {0}` при проверке auth клиента (до генерации реального nonce)
Файлы: server.c, config.h, config.c

### 4.2. Graceful shutdown (2-3 часа) ✅ **ВЫПОЛНЕНО**
Проблема: SIGINT убивает процессы без очистки.
Статус: Сервер и клиент обрабатывают SIGINT/SIGTERM, закрывают сокеты.
Сервер: signal handler закрывает socket, ставит `qs_obj.active=0` (server.c:234,608-612).
Клиент: signal handler (client.c:38,71-75), graceful close в quic_client_close().
✅ Отправка DISCONNECT сессиям перед завершением (server.c:716-728).
Файлы: server.c, client.c

---

## Этап 5. Тесты (параллельно)

### 5.1. Юнит-тесты протокола ✅ **ВЫПОЛНЕНО**
Статус: Все тесты проходят, в т.ч. с ASan/UBSan.
- ✅ test_pack_roundtrip.c — 13 тестов: pack→unpack на всех длинах (1,10,64,256,512), MAC corruption detection, MAC order-sensitivity, replay counter detection, auth-tag checks
- ✅ test_protocol.c — 8 тестов: unpack0, unpack1, pack_unpack, pack->unpack max, MAC fails with wrong key, MAC detects tampered, counter replay rejected, null params rejected
- ✅ gost_test — 5 крипто-тестов: расширение ключа, шифрование, расшифрование, CTR roundtrip, полный roundtrip
Файлы: test_pack_roundtrip.c, src/core/test_protocol.c, src/crypto/gost_test.c

### 5.2. Интеграционный тест ⚠️ **ЧАСТИЧНО**
Статус: `tests/test-https.sh` — HTTP/HTTPS через SOCKS5-прокси с curl.
Осталось:
- Сверить контрольную сумму (upload + download)
- Проверка CPS handshake в CI
Файлы: tests/

### 5.3. Санитайзеры ✅ **ВЫПОЛНЕНО**
- ✅ `make asan` — ASan сборка и тесты (гост-тест + test_protocol)
- ✅ `make asan MODE=ubsan` — UBSan сборка и тесты
- ✅ `make sanitize-werror` — `-Wall -Wextra -Werror` на все .c файлы
- ✅ -Werror ✅, ASan ✅, UBSan ✅
Файлы: Makefile, scripts/sanitize.sh

---

## Сводка

| Этап | Что | Статус | Оценка |
|------|-----|--------|--------|
| 1 | Стабильность (P0) | 4/4 выполнено | ✅ |
| 2 | Архитектура (P1) | 3/3 выполнено | ✅ |
| 3 | Безопасность (P2) | 3/3 выполнено | ✅ |
| 4 | Эксплуатация (P3) | 2/2 выполнено | ✅ |
| 5.1 | Юнит-тесты протокола | 3/3 выполнено | ✅ |
| 5.2 | Интеграционный тест | 0/1 выполнено | ~1-2 дн. |
| 5.3 | Санитайзеры | 3/3 выполнено | ✅ |

**Суммарно:** ~3-4 дн. до готовности (vs ~4-6 нед. изначально).

## Следующие шаги

1. Интеграционный тест: сверить контрольную сумму upload/download через тест-сервер
2. CI (.github/workflows): добавить make sanitize-werror, make asan
3. Документация: обновить README с примерами запуска и настройки
4. Код-ревью: проверить security-угрозы (auth-tag bypass, padding oracle, overflow)
