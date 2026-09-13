# CONTRIBUTING

Contributions are welcome! Please read the guidelines below before submitting pull requests.

## Как внести вклад

### 1. Fork и branch

```bash
git fork https://github.com/sivalexei/gost-proxy.git
cd gost-proxy
git checkout -b feature/название-feature
# или
git checkout -b fix/название-fix
```

### 2. Код

- **Форматирование**: используйте `clang-format` для C-файлов
- **Commit messages**: следуйте conventional commits:
  ```
  feat: добавить feature/фичу
  fix: исправить баг
  docs: обновить документацию
  style: форматирование, пробелы
  refactor: рефакторинг
  perf: улучшение производительности
  test: тесты
  ci: CI/CD
  chore: рутина
  ```
- **Подпись коммитов**: предпочтительна GPG-подпись

### 3. Тесты

- Все новые функции должны иметь юнит-тесты (`make test`)
- Все фиксы багов должны иметь regression-тесты
- Sanitizer тесты (`make asan`, `make asan MODE=ubsan`) должны проходить
- Werror проверка (`make sanitize-werror`) — без ошибок

### 4. Документация

- Обновите `README.md`, `README_RU.md` при изменении API
- Обновите `CHANGELOG.md` для значимых изменений
- Обновите `PROGRESS.md` и `DEVELOPMENT_PLAN.md`

### 5. Код-ревью

- Все PR должны пройти code-review минимум от 2 мейнтейнеров
- CI должен проходить: `make test`, `make asan`, `make sanitize-werror`
- Документация должна быть актуальной

## Архитектурные принципы

- **Слоистая архитектура**: crypto → protocol → QUIC → network → core
- **Безопасность прежде всего**: getrandom(), eventfd, no secrets in logs
- **Производительность**: 10 раундов Кузнечик, CMAC-128, sliding window
- **Безопасность от MITM**: CMAC на каждой транзакции, auth-tag encrypt-then-MAC
- **Replay protection**: sliding window + counter + eventfd
- **Анализ трафика защита**: padding + obfuscation (ChaCha20-CTR)
- **Rate limiting**: per-IP token-bucket
- **Session limit**: per-IP, max_sessions_per_ip

## Структура проекта

```
gost-proxy/
├── src/
│   ├── crypto/      # Кузнечик, ChaCha20, CMAC, SHA256, HMAC, AES
│   ├── core/        # server, client, session, config, log, dns_cache, obfuscation, key_derivation
│   └── network/     # QUIC, SOCKS5, SOCKS5-auth
├── tests/           # Integration tests
├── scripts/         # Sanitize scripts
├── debian/          # Packaging
├── deb-build/       # Build artifacts
├── config/          # JSON configs
├── etc/             # Server config
├── LICENSE
├── README.md
├── README_RU.md
├── CHANGELOG.md
├── CONTRIBUTING.md
├── PROGRESS.md
├── DEVELOPMENT_PLAN.md
├── CRITICAL_FIX_PLAN.md
├── Makefile
└── Dockerfile
```

## Вопросы и помощь

- **Issues**: https://github.com/sivalexei/gost-proxy/issues
- **Discussions**: https://github.com/sivalexei/gost-proxy/discussions
- **Email**: (при наличии)

## Лицензия

Проект лицензирован под MIT License.

---

*Спасибо за вклад в развитие Gost-Proxy!*
