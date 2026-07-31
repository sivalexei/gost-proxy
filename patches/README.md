# Патчи для gost-proxy

## Список патчей

| # | Файл | Приоритет | Описание |
|---|------|-----------|----------|
| 01 | `01-config-free.patch` | P0 | Добавить `config_free()` для освобождения памяти |
| 02 | `02-proxy-fixes.patch` | P0 | Исправление багов proxy.c: handshake, гонка данных, `_Atomic` counter |
| 03 | `03-session-hashtable.patch` | P1 | Хеш-таблица сессий вместо O(N) линейного поиска |
| 04 | `04-socks5-poll-replace-usleep.patch` | P1 | Заменить `usleep` loop на `poll()` в `tunnel_recv()` |
| 05 | `05-client-keepalive.patch` | P2 | Keepalive от клиента к серверу (каждые 30 сек) |
| 06 | `06-socks5-dns-cache.patch` | P2 | DNS-кэш с TTL 5 минут для сокращения резолвов |
| 07 | `07-tcp-writev-coalesce.patch` | P3 | Coalesced TCP write через `tcp_writev_coalesce()` |

## Применение

```bash
# Все патчи сразу
./apply-all.sh

# Или по одному
cd /home/sivakun/mimo/gost-proxy
patch -p1 < patches/01-config-free.patch
patch -p1 < patches/02-proxy-fixes.patch
# ...
```

## Откат

```bash
# Все .bak файлы содержат оригинальные версии
cp src/core/config.h.bak src/core/config.h
cp src/core/server.c.bak src/core/server.c
# ...
```

## Проверка сборки

```bash
make clean && make
ls -la build/gost-server build/gost-client build/gost-proxy
```
