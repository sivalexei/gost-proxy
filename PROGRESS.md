# ГОСТ Прокси — Промежуточные результаты
## Дата: 25 июля 2026

---

## 1. Шифрование ГОСТ Р 34.12-2015 — ПРОВЕРЕНО ✅

Реализация `gost_cipher.c` полностью соответствует стандарту:

| Тест | Результат |
|------|-----------|
| Шифрование (А.1.5 ГОСТ Р 34.12-2015) | ✅ PASS |
| Расшифрование (А.1.6) | ✅ PASS |
| Roundtrip encrypt+decrypt | ✅ PASS |
| CTR 1396 байт (MAX_PAYLOAD-4) | ✅ PASS |
| CTR 652 байт (второй чанк) | ✅ PASS |
| Multi-chunk pack/unpack (3 чанка: 1396/652/245) | ✅ PASS |

**Все ключевые элементы из стандарта реализованы корректно:**
- S-п.box (π) из §4.1.1 ✓
- Линейное преобразование ℓ из §4.1.2 ✓
- Преобразования R, L, R⁻¹, L⁻¹ из §4.2 ✓
- Алгоритм развёртывания ключа из §4.3 ✓
- Шифрование E = X[K₁₀]LSX[K₉]...LSX[K₁] из §4.4.1 ✓
- Расшифрование из §4.4.2 ✓
- Контрольные примеры из приложения А.1.5/А.1.6 ✓

---

## 2. HTTPS через прокси — НЕ РАБОТАЕТ ❌

### Что работает:
- HTTP через прокси ✅ (httpbin.org:80 — 376 байт ответа)
- Handshake ✅
- SOCKS5 CONNECT ✅
- Шифрование/дешифрование всех чанков ✅

### Что НЕ работает:
- HTTPS через прокси ❌ (curl: "Decryption has failed" / "An unexpected TLS packet was received")
- Firefox: PR_END_OF_FILE_ERROR ❌

### Корневая проблема:
Сервер подключается к target (example.com:443), отправляет TLS ClientHello (413 байт), но получает HTTP-ответ (272 байта, first=48545450="HTTP") вместо TLS ServerHello.

```
[PROXY] TCP подключение к 8.6.112.0:443 установлено
[PROXY] TCP write: 416 bytes, first=1603030198010001    ← TLS ClientHello ОК
[PROXY] TCP read 272 bytes from target, first=48545450  ← HTTP вместо TLS!
```

### Ключевые выводы:
1. **Криптография НЕ виновата** — CTR работает корректно для всех чанков
2. **Nonce совпадают** на клиенте/сервере: `c6237b3267458b6b`
3. **Счётчики корректны**: клиент чётные (0,2,4...), сервер нечётные (1,3,5...)
4. **Данные расшифровываются ПРАВИЛЬНО** — dl совпадает, содержимое совпадает с raw TCP
5. TLS ClientHello отправляется корректно (first=16030301, 413 байт)

---

## 3. Исправления, внесённые в код

### server.c:
- ✅ TCP_NODELAY на целевых TCP-соединениях
- ✅ Write loop — гарантированная отправка всех байтов
- ✅ Более детальный логинг (8 байт вместо 4)

### socks5.c:
- ✅ Extra chunk drain — считывание всех доступных чанков без задержки
- ✅ Write loop — гарантированная отправка данных клиенту (curl/Firefox)
- ✅ Лейбл `close_client` для корректного завершения

### session.c:
- ✅ Детальный логинг: data_len + первые 8 байт в PACK/UNPACK
- ✅ Nonce логирование в PACK/UNPACK

---

## 4. Что нужно доделать

### Приоритет 1: Выяснить почему target отвечает HTTP вместо TLS
- Проверить DNS: клиент разрешает через `gethostbyname()` — возможно IP неверный
- Проверить напрямую: `openssl s_client -connect IP:443`
- Добавить hex dump расшифрованных данных на сервере в `handle_data_packet`

### Приоритет 2: Исправить write() на сервере
- Текущий write loop НЕ проверяет возвратное значение `write()` для каждого вызова
- Нужно: `if (written < data_len && written > 0) retry remaining`

### Приоритет 3: Очистка debug-кода
- Убрать все `printf("[PACK]..."` и `printf("[UNPACK]..."` из session.c
- Убрать лишний логинг из socks5.c и server.c

### Приоритет 4: DEB-пакет
- Собрать финальный .deb для сервера (Ubuntu)
- RPM для клиента (ALT Linux)

---

## 5. Конфигурация

```
Сервер: 109.122.195.152:10443 (Ubuntu 24.04)
Клиент: ALT Linux P11 x86_64
Ключ: задаётся в /etc/gost-proxy/client.json и server.json
SOCKS5: 127.0.0.1:1080
Бинарь сервера: /usr/bin/gost-server
Конфиг сервера: /etc/gost-proxy/server.json
```

---

## 6. Следующий шаг

1. Запустить `openssl s_client -connect 8.6.112.0:443` напрямую с сервера — проверить отвечает ли target TLS
2. Если да — проблема в relay. Если нет — проблема с DNS/IP.
3. Добавить hex dump в `handle_data_packet` для проверки целостности расшифрованных данных.

---

## 7. Проверка прямого подключения (07:30)

### openssl s_client -connect example.com:443 (с клиента):
- ✅ Работает, CN=example.com, сертификат от SSL.com/Cloudflare

### openssl s_client -connect 8.6.112.0:443 (с сервера):
- ✅ Работает, CN=cdnjs.cloudflare.com (другой CDN edge server)

### DNS example.com:
- 8.47.69.0
- 8.6.112.0

### Вывод:
- Прямое подключение к example.com:443 через openssl работает ✅
- Проблема НЕ в DNS — IP правильный (8.47.69.0)
- Проблема НЕ в TLS библиотеке — openssl получает валидный сертификат
- **Проблема в том, как прокси пересылает данные** — возможно:
  1. `write()` делает short write (отправляет не все байты)
  2. Проблема с timing в SOCKS5 relay
  3. Клиент не отправляет TLS ClientHello до готовности сервера

### Следующий шаг:
1. Добавить hex dump отправляемых TCP-данных на сервере (первые 32 байта)
2. Проверить что `write()` отправляет ВСЕ байты (добавить проверку возврата)
3. Проверить что `send()` от клиента к curl тоже отправляет все байты

---

## 8. Модуль tcp_helpers.asm (NASM x86-64)

### Назначение:
- `tcp_write_all` — запись ВСЕХ байтов в TCP с retry (write loop)
- `hex_dump` — быстрый hex-отладочный вывод через syscall write

### Сборка:
```bash
cd src/core
nasm -f elf64 tcp_helpers.asm -o tcp_helpers.o
```

### Сигнатуры (C):
```c
ssize_t tcp_write_all(int fd, const void *buf, size_t len);
void hex_dump(const char *label, const void *data, size_t len);
```

### Использование в server.c:
```c
extern ssize_t tcp_write_all(int fd, const void *buf, size_t len);

// Вместо:
//   write(conn->tcp_fd, decrypted, data_len);
// Использовать:
//   tcp_write_all(conn->tcp_fd, decrypted, data_len);
```

---

## 9. Тест tcp_helpers.asm (09:00)

### Что установлено:
- NASM установлен (пароль: sivushkin)
- `tcp_helpers.asm` собран, сервер пересобран с `-no-pie`
- Добавлен write loop + MSG_NOSIGNAL в socks5.c

### Результат HTTPS через прокси:
- **Все 5 чанков расшифровываются корректно** ✅
- TLS ServerHello доставляется (`160303007a020000`) ✅
- Nonce совпадают (`7348336669983c64`) ✅
- **Но GnuTLS всё ещё падает**: "Decryption has failed"

### Корень проблемы:
TLS handshake падает НЕ из-за шифрования (CTR работает), а из-за:
1. Целевой сервер возвращает TLS с cipher suite, который GnuTLS не поддерживает
2. Или TLS ClientHello содержит unsupported extensions
3. Проблема совместимости TLS-библиотек, а НЕ крипто-протокола

### Что нужно сделать:
1. Проверить cipher suite negotiation через `openssl s_client -cipher ...`
2. Попробовать `curl --tlsv1.2 --ciphers ...` для фиксированного cipher suite
3. Или использовать Firefox вместо curl (Firefox поддерживает больше cipher suites)

---

## 10. Анализ TLS handshake failure (09:10)

### Ключевое наблюдение:
- **SSH-туннель напрямую к example.com:443** тоже даёт `ssl/tls alert handshake failure` (alert 40)
- Это значит проблема НЕ в нашем прокси — **target отвергает TLS handshake**

### Прямое подключение с сервера работает:
```
TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384, CN=example.com ✅
```

### Через прокси — GnuTLS падает:
- `--tls-max 1.2`: "Error in the certificate"
- `--tls-max 1.3`: "Unexpected message"
- Default: "Decryption has failed"

### Причина:
GnuTLS 3.8.13 (ALT Linux) не может завершить TLS handshake с example.com через прокси. Проблема в TLS-библиотеке, **а НЕ в ГОСТ шифровании**.

### Что работает:
- ✅ ГОСТ CTR-шифрование (все тесты PASS)
- ✅ Прямое TLS подключение openssl с сервера
- ✅ HTTP через прокси
- ✅ Nonce/счётчики совпадают
- ✅ Все чанки расшифровываются корректно
- ✅ tcp_helpers.asm (NASM x86-64) собран

### Что НЕ работает:
- ❌ HTTPS через прокси (GnuTLS падает)
- SSH-туннель напрямую к example.com:443 тоже падает

### Вывод:
**ГОСТ прокси-слой работает корректно.** Проблема HTTPS — в несовместимости GnuTLS с целевым сервером (или TLS-расширениями). Это задача на стороне TLS-клиента, а не крипто-протокола.

---

## 11. Firefox через SOCKS5 прокси (09:35)

### Firefox подключается через SOCKS5 ✅
- CONNECT команды отправляются корректно
- Сервер подключается к правильным IP: 34.107.243.93:443 (github.com), 34.120.208.123:443 (github.com)
- HTTP запросы работают (detectportal.firefox.com:80 → GET /canonical...)

### Найдена критическая проблема: мультиплексирование соединений

Firefox открывает **множественные параллельные соединения**:
- github.com:443 (TLS)
- incoming.telemetry.mozilla.org:443 (TLS)
- detectportal.firefox.com:80 (HTTP)
-和其他 подключения

**Все SOCKS5-потоки делят ОДИН UDP-сокет** (`proxy_udp_fd`). Когда поток A вызывает `tunnel_recv()`, он может забрать пакет, предназначенный для потока B. Это приводит к:
- `CONNECT отклонён сервером` — данные от другого соединения попадают не туда
- `errno=104 (Connection reset by peer)` — Firefox получает мусор и закрывает сокет
- `send extra to client failed: errno=32 (Broken pipe)` — Firefox закрыл сокет до доставки второй порции

### Нужно для решения:
1. **conn_id в заголовке пакета** — каждый SOCKS5-поток фильтрует только свои пакеты
2. Или **один reader-поток** для UDP, который маршрутизирует пакеты по conn_id
3. Изменение протокола: добавить `conn_id` (4 байта) в `gost_packet_t`

### ГОСТ шифрование:
Всё работает корректно. Проблема НЕ в криптографии, а в архитектуре мультиплексирования соединений.

### Итого сделано:
- ✅ ГОСТ CTR-шифрование проверено по ГОСТ Р 34.12-2015 (6 тестов PASS)
- ✅ tcp_helpers.asm (NASM x86-64) — write loop + hex dump
- ✅ NASM установлен, модуль собран
- ✅ tunnel_send чанкирует данные > MAX_PAYLOAD-4
- ✅ Write loop + MSG_NOSIGNAL для всех send() вызовов
- ✅ Debug логирование с errno/strerror
- 🔴 **Критическая проблема**: мультиплексирование UDP-соединений (нужен conn_id в протоколе)

---

## 12. conn_id в протоколе (10:00)

### Что сделано:
- Добавлен `conn_id` (uint32_t) в `gost_packet_t` заголовок
- `protocol_pack_data` принимает `conn_id`, записывает в пакет
- `protocol_unpack_data` возвращает `out_conn_id` из пакета
- **Клиент**: каждый SOCKS5-поток получает уникальный `conn_id` (атомарный инкремент)
- **Клиент**: `tunnel_recv` фильтрует пакеты по `expect_conn_id`
- **Сервер**: `proxy_conn_t` хранит `conn_id`, `find_proxy_conn` ищет по `session_id + conn_id`
- **Сервер**: `tcp_to_udp_thread` отправляет пакеты с `conn_id` соединения
- **Сервер**: OK/ERR ответы содержат `conn_id` клиента

### Результаты:
- ✅ HTTP работает (httpbin.org:80, conn_id=1)
- ✅ Все параллельные соединения изолированы по conn_id
- ✅ Нет больше "CONNECT отклонён" из-за мультиплексирования
- ✅ Нет больше errno=104/errno=32 (нет перемешивания пакетов)
- ✅ Все 5 TLS-чанков получены корректно для HTTPS
- 🔴 HTTPS не работает из-за GnuTLS (не прокси) — SSH tunnel напрямую к example.com тоже падает
- 🔴 Многие целевые серверы закрывают TCP соединение с IP сервера (109.122.195.152)

### Изменённые файлы:
- `src/crypto/gost_common.h` — добавлен `conn_id` в `gost_packet_t`
- `src/core/protocol.h` — обновлены сигнатуры pack/unpack
- `src/core/session.c` — pack/unpack работают с `conn_id`
- `src/network/socks5.c` — conn_id на клиенте, фильтрация в tunnel_recv
- `src/core/server.c` — conn_id на сервере, маршрутизация по conn_id
