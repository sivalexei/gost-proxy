# Рекомендации по доработке gost-proxy

> Сравнение с Hysteria 2 (v2.10.0) — клиент на локальном ПК, сервер на 109.122.195.152:220

## 1. Транспортный слой и протокол

### 1.1. Переход на QUIC вместо сырого UDP

**Hysteria:** Использует quic-go (QUIC на основе HTTP/3). QUIC обеспечивает:
- Встроенную мультиплексированность потоков
- Автоматическое управление congestion control
- 0-RTT handshakes
- Надёжность на уровне протокола (ACK, retransmit)

**gost-proxy:** Сырой UDP с самодельной логикой. Проблемы:
- Нет встроенной доставки — пакеты могут теряться
- Нет flow control / congestion control
- Нет мультиплексирования потоков — conn_id реализован на уровне приложения

**Рекомендация:** Переписать транспортный слой на QUIC (quic-go). Это решит проблемы с потерей пакетов, переподключением и мультиплексированием.

### 1.2. Улучшение handshake

**Hysteria:**
```yaml
auth: 8ae904688b6f9b082f5643c826b7cab3    # HMAC-SHA256
tls:
  sni: 109.122.195.152
  insecure: true
```

**gost-proxy:** Простейший handshake — отправляется пакет с type=HANDSHAKE, сервер генерирует session_id и отвечает. Нет аутентификации клиента, нет проверки ключа.

**Рекомендации:**
1. Добавить аутентификацию — аналог auth из Hysteria: HMAC-SHA256 от client_ip:port:auth_string
2. Поддержка TLS — обёртка QUIC поверх TLS для маскировки под HTTPS
3. Challenge-response — сервер отправляет nonce, клиент шифрует ответ ключом
4. Поддержка SNI — для TLS-обёртки

### 1.3. Обфускация трафика

**Hysteria:**
```yaml
obfs:
  type: salamander
  salamander:
    password: hysteria-obf-f30b5309cf025009
```

**gost-proxy:** Нет обфускации. Трафик имеет фиксированный размер (1436 байт), детектируемый pattern.

**Рекомендация:** Добавить обфускатор наподобие Hysteria's Salamander (XOR с хешем от заголовка), рандомизацию размера пакетов.

---

## 2. Шифрование и безопасность

### 2.1. Улучшение MAC (Auth-tag) — КРИТИЧНО

**gost-proxy:** Текущий compute_mac() — это XOR всех 16-байтных блоков payload + одно шифрование. Критически слабый, уязвим к length-extension.

**Hysteria:** HMAC-SHA256 (через TLS) + AEAD (TLS record layer).

**Рекомендация:** Заменить compute_mac() на HMAC-SHA256 или BLAKE3. Добавить AEAD (AES-GCM или XChaCha20-Poly1305) вместо Encrypt-then-MAC. Добавить replay protection.

### 2.2. Forward Secrecy (PFS)

**gost-proxy:** Статический ключ на весь lifetime сессии. Нет PFS.

**Hysteria:** Каждый new connection использует ephemeral DH key exchange.

**Рекомендация:** Добавить ECDHE (X25519) key exchange при handshake. Динамический session key = HMAC(long_term_key, ephemeral_shared_secret).

### 2.3. Управление ключами

**Рекомендации:**
- Поддержка GOST_KEY env variable
- Загрузка ключа из файла (не hex в JSON)
- Автоматическая ротация session key

---

## 3. Конфигурация

### 3.1. Формат

**gost-proxy:** Self-made JSON-парсер (string search в тексте). Нет валидации, нет nested объектов.

**Hysteria:** YAML с полной валидацией, defaults, документированными полями.

**Рекомендации:**
1. Заменить на cJSON или nlohmann/json
2. Поддержать YAML конфигурацию (libyaml)
3. Добавить validate режим
4. Добавить примеры конфигов с комментариями

### 3.2. Расширенная конфигурация

Рекомендуемые поля:
```json
{
    "server": {
        "listen": "0.0.0.0:10443",
        "key": "hex-key-here",
        "auth_token": "optional",
        "max_connections": 1024,
        "session_timeout": 300,
        "udp_timeout": 60
    },
    "tls": {
        "enabled": false,
        "cert": "/path/to/cert.pem",
        "key": "/path/to/key.pem",
        "sni": "proxy.example.com"
    },
    "obfuscation": {
        "enabled": true,
        "type": "salamander",
        "password": "obf-password"
    },
    "bandwidth": {
        "up": "100mbps",
        "down": "100mbps"
    },
    "logging": {
        "level": "info",
        "file": "/var/log/gost-proxy/server.log",
        "format": "json"
    },
    "fast_open": true
}
```

---

## 4. Архитектура и производительность

### 4.1. Модель обработки

**gost-proxy:** Один recvfrom loop, pthread для каждого TCP-соединения, MAX_PROXY_CONNS=256, хеш-таблица сессий с modulo (коллизии).

**Hysteria:** Event-loop на goroutines, adaptive congestion control, dynamic stream multiplexing.

**Рекомендации:**
1. Заменить pthread на epoll event loop
2. Увеличить лимит до 1024+
3. Заменить хеш-таблицу на concurrent hash map
4. Добавить connection pooling

### 4.2. Контроль пропускной способности

**gost-proxy:** Поле rate_limit в конфиге есть, но НЕ используется в коде.

**Hysteria:** bandwidth: up/down в конфиге реально применяется.

**Рекомендация:** Реализовать token bucket rate limiter. Поддержка формата: "100mbps", "1gbps". Per-session rate limiting.

### 4.3. Fast Open

**Рекомендация:** Включить TCP_FASTOPEN на SOCKS5 listener.

---

## 5. Прокси-функционал

### 5.1. Протоколы

**Hysteria:** SOCKS5, HTTP (forward proxy), TCP/UDP relay.
**gost-proxy:** Только SOCKS5 (CONNECT).

**Рекомендации:**
1. Добавить HTTP forward proxy
2. Добавить TCP/UDP relay режим
3. Добавить SOCKS5 UDP ASSOCIATE (DNS через прокси)
4. Поддержка SOCKS5 username/password

### 5.2. DNS

**gost-proxy:** gethostbyname() — блокирующий, нет IPv6, нет DoH/DoT.

**Hysteria:** Встроенный resolver с DoH, DoT, custom DNS servers.

**Рекомендация:**
- Custom DNS resolver в конфиге
- DNS-over-HTTPS (DoH), DNS-over-TLS (DoT)
- IPv6 поддержка (A+AAAA)
- DNS кэш с TTL

### 5.3. HTTP/HTTPS

**Рекомендация:** Добавить HTTP forward proxy для совместимости с приложениями без SOCKS5.

---

## 6. Мониторинг и логирование

### 6.1. Логирование

**gost-proxy:** Простое текстовое логирование. Нет rotation.

**Рекомендации:**
1. JSON формат логов
2. Log rotation (по размеру/времени)
3. Metrics endpoint (HTTP) — скорость, соединения, байты
4. Health check endpoint

### 6.2. Метрики

- Активные соединения (count)
- Пропускная способность (in/out, bytes/sec)
- Ошибки (MAC failure, timeout, connection refused)
- Uptime сессии
- DNS cache hit rate

---

## 7. Пакетирование и deployment

### 7.1. systemd unit

**gost-proxy:** Нет systemd unit.

**Hysteria:**
```ini
[Service]
Type=simple
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
```

**Рекомендация:** Добавить systemd unit для gost-server и gost-client.

### 7.2. RPM/DEB

**Рекомендации:**
1. Post-install скрипт — создание пользователя, директорий
2. systemd unit в пакетах
3. Logrotate конфиг
4. Man page
5. Config в /etc/gost-proxy/

---

## 8. Тестирование

**Рекомендации:**
1. Integration-тесты (server + client, проверка трафика)
2. Benchmark (throughput, MB/s)
3. Stress-тест (много одновременных соединений)
4. Тест на потерю пакетов (tc netem)
5. Тест обфускации (отличимость от случайного трафика)

---

## 9. Дополнительные возможности

### 9.1. Web Dashboard
- Активные соединения, throughput chart, список сессий, статус сервера, live log

### 9.2. Relay mode / Mesh
- Несколько серверов соединяются друг с другом

### 9.3. IPv6
- Dual-stack sockets, AAAA резолвинг, [ipv6]:port в конфиге

### 9.4. Статистика
- bytes in/out per session/connection, connection duration, last activity

---

## 10. Приоритезация доработок

| Приоритет | Доработка | Оценка |
|-----------|-----------|--------|
| 🔴 P0 | QUIC транспортный слой | Критически важно |
| 🔴 P0 | HMAC-SHA256 вместо self-made MAC | Безопасность |
| 🔴 P0 | Аутентификация клиента (auth token) | Безопасность |
| 🟠 P1 | Обфускация (Salamander/XOR) | Антидетект |
| 🟠 P1 | systemd unit + proper deployment | Production-ready |
| 🟠 P1 | rate limiter (bandwidth control) | Ресурсы |
| 🟡 P2 | Custom DNS resolver (DoH/DoT) | Функционал |
| 🟡 P2 | JSON-парсер (cJSON/nlohmann) | Надёжность |
| 🟡 P2 | HTTP forward proxy | Совместимость |
| 🟡 P2 | IPv6 поддержка | Современность |
| 🟢 P3 | Web dashboard | UX |
| 🟢 P3 | Forward Secrecy (ECDHE) | Безопасность |
| 🟢 P3 | Integration-тесты + benchmark | Качество |

---

## Сравнительная таблица

| Фича | gost-proxy | Hysteria 2 |
|------|------------|------------|
| Транспорт | Сырой UDP | QUIC (HTTP/3) |
| Шифрование | ГОСТ Р 34.12-2015 + self-made MAC | TLS 1.3 + AEAD |
| Аутентификация | Нет (hex key в конфиге) | HMAC-SHA256 auth token |
| Обфускация | Нет | Salamander XOR |
| Мультиплексирование | conn_id (ручное) | Stream multiplexing |
| Congestion control | Нет | Adaptive (QUIC) |
| Прокси | SOCKS5 | SOCKS5 + HTTP + TCP/UDP |
| DNS | gethostbyname() | Custom resolver (DoH/DoT) |
| TLS обёртка | Нет | Поддержка |
| Fast Open | Нет | TCP Fast Open |
| IPv6 | Нет | Да |
