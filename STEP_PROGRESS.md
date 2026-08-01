# Прогресс по шагам — AVX2 / io_uring / Huge Pages

> Файл создан для сохранения прогресса после очистки контекста.
> Прочитать перед продолжением работы.

---

## Текущий статус

### Шаг 1: AVX2 оптимизация kuznyechik.asm — 🔄 В ПРОЦЕССЕ

**Что сделано:**
- Изучена текущая структура проекта
- `kuznyechik.asm` переписан с SSE2 на AVX2 (256-битные ymm регистры)
- Добавлены 256-битные S-box таблицы (`table_sbox_avx2_256`, `table_inv_sbox_avx2_256`)
- Реализована `kuznyechik_S_256` — подстановка S-box через `pshufb` с 256-битной таблицей
- Реализована `kuznyechik_L_256` — линейное преобразование через `pmulld`/`pshufb`
- Реализована `kuznyechik_set_key_avx2` — расширение ключа
- Реализована `kuznyechik_encrypt_block_256` — шифрование блока с AVX2
- Реализована `kuznyechik_decrypt_block_256` — расшифрование блока с AVX2
- Реализована `kuznyechik_encrypt_ctr_256` — CTR-режим с AVX2
- Добавлены функции параллельной обработки 2 блоков: `kuznyechik_encrypt_block_parallel_avx2`, `kuznyechik_set_key_parallel_avx2`
- Добавлены функции `kuznyechik_precompute_tables_256` для precompute S-box таблиц

**Что осталось:**
- ⚠️ Нужно проверить, что Makefile собирает `kuznyechik.asm` (сейчас он в Makefile **НЕ добавлен**)
- ⚠️ Нужно убедиться, что C-код (`gost_cipher.c`) вызывает ассемблерные функции, а не свои внутренние
- ⚠️ Нужно протестировать сборку и крипто-тесты
- ⚠️ Возможно, нужно убрать дублирующую C-реализацию из `gost_cipher.c`

**Файлы изменены:**
- `src/crypto/kuznyechik.asm` — полностью переписан

---

### Шаг 2: io_uring — ❌ НЕ НАЧАТ

**План:**
1. Создать `src/network/io_uring_layer.c` и `src/network/io_uring_layer.h`
2. Заменить `poll()` + `recvfrom()`/`sendto()` на `io_uring_prep_recv()`/`io_uring_prep_sendto()`
3. Серверный цикл: один поток, `io_uring_wait_cq()` для обработки событий
4. Клиент: async send/recv через io_uring
5. Обновить Makefile для линковки с `-liburing`
6. Обновить `quic_layer.h` / `quic_layer.c` или заменить их

**Зависимости:**
- Нужно проверить наличие `liburing` в системе: `apt list --installed | grep liburing`
- Если нет — добавить в build-зависимости

**Текущее состояние I/O:**
- `quic_layer.c` использует `poll()` с таймаутом + `recvfrom()`/`sendto()` на UDP сокетах
- Сервер: `quic_server_recv()` в основном цикле, `pthread` для каждого TCP-соединения
- Клиент: `quic_client_recv()` с `poll()` таймаутом
- TCP-помощники: `tcp_to_udp_thread()` в `server.c` использует `poll()`

---

### Шаг 3: Huge Pages — ❌ НЕ НАЧАТ

**План:**
1. Создать `src/core/huge_pages.h` / `src/core/huge_pages.c`
2. Функции:
   - `hp_alloc(size)` — `mmap` с `MAP_HUGETLB | MAP_ANONYMOUS`
   - `hp_free(ptr)` — `munmap`
   - `hp_init()` — проверка доступности huge pages
3. Заменить `BUFFER_SIZE 2048` буферы в `server.c`, `client.c`, `quic_layer.c`
4. Добавить поддержку в Makefile: `./configure --enable-hugepages` или флаг
5. Обновить systemd unit: `LimitMEMLOCK=infinity` (нужно для MAP_HUGETLB)

**Зависимости:**
- Нужны права: `sudo sysctl -w vm.nr_hugepages=...`
- systemd: `LimitMEMLOCK=infinity` в unit-файлах

**Текущее состояние:**
- Буферы в `server.c`: `uint8_t buf[BUFFER_SIZE]` (стек), `malloc` для sessions
- Буферы в `quic_layer.c`: `recvfrom` буферы на стеке
- TCP-поток: `uint8_t buf[BUFFER_SIZE]` на стеке
- Нет никакой поддержки huge pages

---

## Команды для продолжения

```bash
# Проверить что изменилось
cd /home/sivakun/mimo/gost-proxy
git diff --stat
git diff src/crypto/kuznyechik.asm

# Попробовать собрать
make clean && make

# Если сборка не прошла — проверить Makefile
cat Makefile | grep -A2 "kuznyechik"

# Проверить наличие liburing
apt list --installed 2>/dev/null | grep liburing
ldconfig -p | grep liburing

# Запустить крипто-тесты
cd build && ./gost-test
```

---

## Важные замечания

1. **AVX2 код уже написан**, но **НЕ добавлен в Makefile** — нужно исправить Makefile
2. **C-код всё ещё использует свою C-реализацию** из `gost_cipher.c` — ассемблерные функции могут не вызываться
3. **io_uring** требует установки `liburing-dev` если нет в системе
4. **Huge Pages** требуют root-прав для настройки `vm.nr_hugepages`

---

## Приоритет продолжения

1. ✅ **Шаг 1**: Исправить Makefile, проверить сборку, запустить тесты
2. ⬜ **Шаг 2**: Создать io_uring слой (если liburing есть)
3. ⬜ **Шаг 3**: Реализовать huge pages аллокатор
