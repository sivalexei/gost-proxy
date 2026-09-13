# CHANGELOG

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- [!] CRITICAL FIX: payload obfuscation sync fix — deobfuscation no longer zeroes counter/length bytes (#427)
- [!] CRITICAL FIX: padding length deterministic derivation via `getrandom()` (session_id hash)
- [!] CRITICAL FIX: packet reordering protection — sliding window + bitmap
- [!] CRITICAL FIX: eventfd вместо SIGUSR1 для сигналов, side-channel защита
- [!] CRITICAL FIX: ChaCha20/Кунечик-CTR obfuscation — каскадная защита трафика
- [!] CRITICAL FIX: RFC1929 auth для SOCKS5 — user/pass credentials stored и проверяются
- [!] DNS-кеширование на стороне сервера, LRU вытеснение, TTL
- [!] Rate limiting: token-bucket per-IP, burst window
- [!] Graceful shutdown с eventfd

### Security
- CMAC-128 для каждой транзакции (client/server nonce)
- Auth-tag encrypt-then-MAC на каждом пакетe
- Sliding window + counter + eventfd replay protection
- MITM protection на каждой транзакции
- Analysis-resistant padding + obfuscation (ChaCha20-CTR)
- getrandom() вместо PRNG для padding/nonce, eventfd вместо SIGUSR1
- В логах нет паролей/ключей

## [1.2.0] — 2024-09-13

### Fixed
- Обфускация payload синхронизирована между клиентом и сервером
- Деобфускация больше не обнуляет первые 8 байт
- CMAC challenge-response для CPS обфускации
- Auth-tag для DISCONNECT: HMAC(session_id, conn_id) с EK
- Sliding window bitmap для защиты от reordering
- Counter + eventfd replay protection

## [1.1.0] — 2024-09-13

### Added
- ChaCha20 obfuscation layer (кэширование, CTR mode)
- Кунечик-CTR cipher
- RFC1929 аутентификация для SOCKS5
- DNS-кеширование серверное
- Rate limiting (token-bucket per IP)
- Graceful shutdown

## [1.0.0] — 2024-09-13

### Added
- Изначальная версия: ГОСТ Кузнечик шифрование (10 раундов, 256 бит)
- CMAC-128 аутентификация
- Auth-tag encrypt-then-MAC
- QUIC transport: handshake, keepalive, multiplexing
- SOCKS5 proxy с RFC1929 auth
- Sliding window + bitmap protection
- Eventfd вместо SIGUSR1 для сигналов
- getrandom() для padding/nonce вместо PRNG
- Side-channel защита

## [0.1.0] — Pre-release

### Added
- Прототип структуры проекта
- Базовые криптографические функции (Кузнечик, ChaCha20)
- CMAC-128 implementation
- Прототин QUIC layer
