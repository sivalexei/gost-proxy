# Прогресс по исправлениям (FIX_PLAN.md)

## ✅ Сделано сегодня (11.08.2026)

### 1. Удалён proxy.c (1.8)
- Удалён файл `src/core/proxy.c` (412 строк)
- Удалены его упоминания из Makefile
- Собрано успешно: `gost-server` и `gost-client`

### 2. Исправлен tcp_helpers.asm — EAGAIN (2.8)
- Добавлена обработка `EAGAIN` (errno=11) в `tcp_write_all`
- Теперь `EAGAIN`/`EWOULDBLOCK` обрабатываются как `EINTR` — повторная попытка

### 3. Исправлены блокировки сессий (2.5)
- `session_remove()` — переиспользование слотов, корректное удаление из хеша
- `session_reset_free_slot()` — поиск свободных слотов с wrap-around
- `session_hash` — перестроен: теперь `int hash[SESSION_HASH_SIZE]` с `-1` пустым, поиск по индексу

### 4. Исправлен клиент — рандомный nonce (1.5)
- Генерация nonce из `/dev/urandom` с fallback на `read()`
- Добавлен `#include <fcntl.h>` для `open()`/`O_RDONLY`

### 5. Конфигурация (2.1)
- Сервер: `key` из JSON (72 hex-символа → 36 байт ключа)
- Клиент: `key` из JSON (64 hex-символа → 32 байт ключа)
- Поддержка `GOST_PROXY_KEY` env

### 6. Сборка
- `make clean && make all` — компилируется успешно
- Только предупреждения: unused функции в session.c, strncpy в socks5.c

---

## ⏳ Нужно сделать завтра

### 🔴 Критичное: Handshake timeout
**Проблема:** Клиент не может подключиться к локальному серверу — handshake timeout (5 сек)
- UDP 10443 на сервере слушается (`ss -unlp` подтверждает)
- Клиент отправляет PKT_HANDSHAKE, но не получает ответ
- **Причина:** Клиент использует `config/client.json` (localhost:10443), но лог-файл `client.log` перезаписывается всеми запусками — старые записи скрывают новые
- **Важно:** `client.log` показывает "Клиент запущен, сервер: 109.122.195.152:10443" — это старые записи, текущий клиент пишет на `127.0.0.1:10443`

**Что проверить:**
1. `killall gost-client` перед тестом
- `clear /var/log/gost-proxy/client.log`
- Пересобрать и протестировать локально: `gost-server` + `gost-client`
- Проверить `strace -e sendto,recvfrom -p <pid>` на клиенте
- Проверить HMAC-аутентификацию: клиент шифрует `session_id` ключом, сервер проверяет

### 🟡 Среднее:
1. **DNS-утечка (2.6)** — `gethostbyname` в socks5.c
   - Заменить на `getaddrinfo()` с DNS через прокси
   - Добавить `#include <netdb.h>` (уже есть)

2. **Логирование** — нет `server.log` (Permission denied)
   - Создать `/var/log/gost-proxy/` или изменить `log_file` в конфиге
   - Добавить `mkdir -p /var/log/gost-proxy && chmod 755 /var/log/gost-proxy`

3. **session.c** — unused функции `apply_permutation`/`inverse_permutation`
   - Можно удалить или добавить `__attribute__((unused))`

4. **socks5.c** — `strncpy` warning
   - Использовать безопасную копию или отключить warning

### 🟢 Низкий приоритет:
1. `config/server.json` — `key` 72 символа (36 байт), а не 64 (32 байт)
   - Привести к единому формату (64 hex = 32 байт)

---

## 📋 Файлы, изменённые сегодня
- `Makefile` — убран proxy.c
- `src/core/client.c` — рандомный nonce, добавлен `<fcntl.h>`
- `src/core/server.c` — session_hash, session_remove, session_reset_free_slot, EAGAIN
- `src/core/tcp_helpers.asm` — EAGAIN обработка
- `config/server.json` — ключ
- `src/core/proxy.c` — **удалён**
- `src/core/session.c` — session_hash перестроен
- `src/crypto/kuznyechik_modes.asm` — (изменение из прошлой сессии)
