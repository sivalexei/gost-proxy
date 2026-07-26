# Прогресс разработки — ГОСТ Прокси

## Текущий статус: v1.0.0 ✅

Все основные функции реализованы и протестированы.

---

## ✅ Выполненные задачи

### 1. Криптографическое ядро (Кузнечик)
- **Ключевое расширение** — реализация из RFC 7801 §5.4, все тесты прошли
- **Блочное шифрование** — ECB режим, тесты на соответствие RFC 7801 §5.5
- **CTR-режим** — потоковое шифрование с roundtrip тестами
- **MAC (аутентификация)** — encrypt-then-MAC для целостности данных
- Все тесты по RFC 7801 прошли ✅

### 2. UDP-транспорт (аналог Hysteria2)
- **Серверный UDP-сокет** — создание, настройка, обработка пакетов
- **Протокол пакетов** — magic, type, conn_id, session_id, payload, auth_tag
- **Типы пакетов**: HANDSHAKE (0x01), DATA (0x02), KEEPALIVE (0x03), DISCONNECT (0x04)
- **Session management** — создание/удаление сессий, session_id (8 байт)
- **conn_id** — мультиплексирование, параллельные соединения изолированы

### 3. TCP-прокси (сервер)
- **tcp_helpers.asm** — assembly write-loop для гарантированной доставки
- **Обработка DATA-пакетов** — извлечение payload, перенаправление через TCP
- **DISCONNECT** — корректное завершение TCP-соединений
- **KEEPALIVE** — отправка от клиента к серверу
- **Сохранение session_id** — для ретрансляции в ответах

### 4. Клиент (SOCKS5 + UDP)
- **SOCKS5-прокси** — запуск на 127.0.0.1:1080
- **SOCKS5 CONNECT** — поддержка TCP CONNECT через UDP-транспорт
- **UDP relay** — пересылка данных через UDP с шифрованием
- **tcp_write_all** — гарантированная доставка через TCP write-loop

### 5. Конфигурация
- **JSON-парсер** — простой парсер с поддержкой строк и чисел
- **server.json** — bind, port, max_sessions, key, log_level, log_file
- **client.json** — server_ip, server_port, key, log_level, log_file
- **config_defaults()** — значения по умолчанию

### 6. Логирование
- **Структурированное логирование** — timestamp, level, message
- **Уровни**: error, warn, info, debug
- **Два потока** — stderr + файл (настраивается)
- **Потокобезопасность** — pthread_mutex

### 7. Пакетирование и протокол
- **DEB-пакеты** — build_deb.sh
  - gost-proxy-server — сервер с systemd unit
  - gost-proxy-client — клиент с systemd unit
  - Включает постинсталляционные скрипты
- **RPM-пакеты** — build_rpm.sh (ALT Linux совместимость)
  - gost-proxy-server — сервер с systemd unit
  - gost-proxy-client — клиент с systemd unit
  - Man-страницы для server и client
  - systemd post/preun/postun скрипты
- **Системные сервисы**:
  - `gost-proxy-server.service` — автозапуск, рестарт, LimitNOFILE=65536
  - `gost-proxy-client.service` — автозапуск, рестарт, LimitNOFILE=65536
- **Синхронизация counter** — `protocol_unpack_data` теперь обновляет counter значением из пакета для корректной синхронизации CTR-счётчика
- **DEB-пакеты** — build_deb.sh
  - gost-proxy-server — сервер с systemd unit
  - gost-proxy-client — клиент с systemd unit
  - Включает постинсталляционные скрипты
- **RPM-пакеты** — build_rpm.sh (ALT Linux совместимость)
  - gost-proxy-server — сервер с systemd unit
  - gost-proxy-client — клиент с systemd unit
  - Man-страницы для server и client
  - systemd post/preun/postun скрипты
- **Системные сервисы**:
  - `gost-proxy-server.service` — автозапуск, рестарт, LimitNOFILE=65536
  - `gost-proxy-client.service` — автозапуск, рестарт, LimitNOFILE=65536

### 8. Тестирование
- **5 крипто-тестов** — все прошли ✅
  1. Расширение ключа (RFC 7801 §5.4)
  2. Шифрование (RFC 7801 §5.5)
  3. Расшифрование (RFC 7801 §5.6)
  4. CTR-режим (roundtrip)
  5. Полный roundtrip encrypt→decrypt

---

## 🔄 Текущие задачи

### 1. Keepalive от сервера к клиенту (низкий приоритет)
- Клиент отправляет KEEPALIVE на сервер — ✅
- Сервер должен отправлять KEEPALIVE обратно клиенту — 🔲
- Это нужно для поддержания NAT-сессий

### 2. Таймауты сессий на сервере (низкий приоритет)
- max_sessions и session_timeout читаются из конфига — ✅
- Фактическая очистка просроченных сессий — 🔲
- Нужно добавить background-timer или проверку в main loop

### 3. Тест hex_dump (низкий приоритет)
- hex_dump из tcp_helpers.asm не протестирован отдельно
- Можно проверить через gdb или добавить отдельный тест

---

## 📋 Следующие шаги

### Короткие улучшения
- [ ] Добавить keepalive от сервера к клиенту
- [ ] Добавить таймауты сессий
- [ ] Добавить IPv6 поддержку (опционально)
- [ ] Добавить поддержку нескольких серверов (failover)

### Среднесрочные задачи
- [ ] Добавить аутентификацию пользователя (SOCKS5 auth)
- [ ] Добавить rate limiting на клиенте
- [ ] Добавить статистику (пропускная способность, количество сессий)
- [ ] Добавить graceful shutdown

---

## 📦 Сборка пакетов

### DEB (Ubuntu/Debian)
```bash
./build_deb.sh
ls debs/
```

### RPM (ALT Linux)
```bash
./build_rpm.sh
ls rpmbuild/RPMS/x86_64/
```

### Установка
```bash
# DEB
sudo dpkg -i debs/gost-proxy-server_1.0.0_amd64.deb
sudo dpkg -i debs/gost-proxy-client_1.0.0_amd64.deb

# RPM
sudo rpm -i rpmbuild/RPMS/x86_64/gost-proxy-server-1.0.0-1.x86_64.rpm
sudo rpm -i rpmbuild/RPMS/x86_64/gost-proxy-client-1.0.0-1.x86_64.rpm
```

### Запуск
```bash
# Сервер
sudo systemctl start gost-proxy-server
sudo systemctl enable gost-proxy-server

# Клиент
gost-client /etc/gost-proxy/client.json
# Или через systemd:
sudo systemctl start gost-proxy-client
sudo systemctl enable gost-proxy-client
```
