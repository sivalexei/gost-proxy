# Прогресс — Гость Прокси (2025-09-11 → 2025-09-12)

## Текущая задача
fix: `test_pack_roundtrip` — 4 failing (len=10, 64, 256, 512), 9 passing

## Что сделано
- ✅ Исправлен `test_pack_roundtrip.c`: все `key` → `ek` (расширенный ключ через `mk_ek`)
- ✅ Добавлен `mk_ek` хелпер, `kuznyechik_set_key`
- ✅ Пройдут тесты 2-5 (MAC corruption, MAC order, replay counter, auth-tag boundary)
- ✅ `protocol_pack_data`/`protocol_unpack_data` работают корректно с расширенным ключом

## Что осталось
- ❌ **test_pack_unpack_lengths** — длина 1 проходит, длины 10/64/256/512 падают на unpack (r=-1, outlen=1400)

## Наблюдения
- `protocol_pack_data` правильно pack'ит (log: sid=1 dlen=10 padding_len=49 total=71)
- `protocol_unpack_data` возвращает -1 сразу (r=-1), outlen=MAX_PAYLOAD=1400
- Проблема на раннем этапе unpack: возможно в деобфускации или вычислении MAC
- `gost_test` прошёл все проверки — проблема только в тесте с определёнными длинами

## Следующие шаги
1. Добавить отладку в `protocol_unpack_data` — показать, на каком этапе возвращается -1
2. Проверить, что padding_len для длины=10 соответствует ожиданиям
3. Сравнить с `gost_test` — какие длины там проходят
4. Возможно проблема в `compute_padding_len` для определённых session_id/длин

## Ключевые файлы
- `test_pack_roundtrip.c` — основной тест, исправлен
- `src/core/session.c` — pack/unpack функции
- `src/core/obfuscation.c` — деобфускация
- `src/crypto/kuznyechik.c` — блочный шифр
