# Прогресс разработки — ГОСТ Прокси

## Текущий статус: v2.0.0

Основные функции реализованы и протестированы. CPS handshake работает, туннель передаёт данные end-to-end.

---

## ✅ Выполненные задачи (v2.0.0)

### 1. Криптографическое ядро
- **Кузнечик** — C-реализация по RFC 7801, все 5 тестов прошли
- **CTR-режим** — потоковое шифрование
- **MAC** — encrypt-then-MAC для целостности
- **Nonce** — генерация из `/dev/urandom`

### 2. QUIC-транспорт
- **UDP-сокет** — серверный listener, клиентский connect
- **Протокол пакетов** — magic, type, conn_id, session_id, payload, auth_tag
- **Типы пакетов**: HANDSHAKE (0x01), DATA (0x02), KEEPALIVE (0x03), DISCONNECT (0x04)
- **Session management** — создание/удаление, переиспользование слотов
- **conn_id** — мультиплексирование, параллельные соединения изолированы
- **Демультиплексор** — один читатель, потоки читают из очереди

### 3. CPS (Chaffing/Pretense System)
- **Fake packets** — QUIC/DNS/TLS обфускация для маскировки
- **Challenge/Response** — верификация сессии через HMAC
- **Session key** — из KDF(PSK, client_nonce, server_nonce)

### 4. TCP-прокси (сервер)
- **DATA-пакеты** — извлечение payload, перенаправление через TCP
- **DISCONNECT** — корректное завершение
- **tcp_helpers.asm** — assembly write-loop для гарантии доставки

### 5. Клиент (SOCKS5 + UDP)
- **SOCKS5-прокси** — на 127.0.0.1:1081
- **CONNECT** — поддержка TCP через UDP-транспорт
- **DNS на сервере** — клиент шлёт ATYP 0x03 (домен), сервер резолвит

### 6. Обфускация
- **Salamander XOR** — рандомизация размера пакетов
- **Header seed** — перемешивание заголовка

### 7. Конфигурация
- **JSON-парсер** — поддержка строк и чисел
- **server.json** — bind, port, max_sessions, key, log_level, log_file
- **client.json** — server_ip, server_port, key, log_level, log_file
- **GOST_PROXY_KEY** env-переменная
- **Валидация** — 64 hex-символа = 32 байт ключа

### 8. Логирование
- **Структурированное** — timestamp, level, message
- **Уровни** — error, warn, info, debug
- **Два потока** — stderr + файл
- **Fallback** — /tmp/gost-proxy.log если /var/log недоступен

### 9. Пакетирование
- **RPM** — build_rpm.sh, ALT Linux
  - gost-proxy-server с systemd unit
  - gost-proxy-client с systemd unit
- **DEB** — build_deb.sh, Ubuntu/Debian
- **systemd** — автозапуск, рестарт, LimitNOFILE=65536

### 10. Безопасность
- **session_id** из /dev/urandom
- **conn_id** изолирует параллельные соединения
- **session_hash** с цепочками (без коллизий)
- **session_remove** — корректное удаление из хеша

---

## 🔄 Осталось реализовать (DEVELOPMENT_PLAN.md)

### Короткие задачи (P0)
- [x] Keepalive от сервера к клиенту (2-3 часа) ✅
- [ ] Таймауты сессий (2-3 часа)
- [ ] Валидация входных данных (1 день)

### Средние задачи (P1)
- [ ] DNS-кэш (1 день)
- [ ] IPv6 поддержка (2-3 дня)
- [ ] epoll вместо poll (3-4 дня)

### Безопасность (P2)
- [ ] Аутентификация handshake (2-3 дня)
- [ ] MAC с привязкой к длине (1-2 дня)
- [ ] Retry handshake с backoff (2-3 часа)

---

## 📦 Сборка и запуск

```bash
# Сборка
make              # gost-server и gost-client
make test         # крипто-тесты (все 5 прошли)
make clean        # очистка

# Запуск
./build/gost-server config/server.json
./build/gost-client config/client.json

# Проверка
curl --socks5-hostname 127.0.0.1:1081 https://example.com
```

### HTTPS через прокси
Прокси пересылает байты — TLS handshake в клиентском приложении.
Используйте curl с OpenSSL или Firefox (NSS).

---

## 📝 История версий

- **v2.0.0** (2026-08-28) — CPS handshake, обфускация, переиспользование сессий, DNS на сервере
- **v1.0.0** (2026-08-01) — начальный рабочий туннель, крипто-ядро, QUIC-транспорт
- **v0.1.0** (2026-07-xx) — прототип, сборка, базовый протокол
