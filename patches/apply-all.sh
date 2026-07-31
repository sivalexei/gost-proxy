#!/bin/bash
# apply-all.sh — Применение всех патчей для gost-proxy
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "=== GOST-Proxy: Применяем патчи ==="
echo ""

# Проверяем, что мы в правильном репозитории
if [ ! -f "Makefile" ]; then
    echo "❌ Ошибка: Makefile не найден. Запустите скрипт из корня проекта gost-proxy."
    exit 1
fi

# Патчи по приоритету
PATCHES=(
    "01-config-free.patch:P0:Исправление config_free()"
    "02-proxy-fixes.patch:P0:Исправление proxy.c (баги handshake, гонка)"
    "03-session-hashtable.patch:P1:Хеш-таблица сессий"
    "04-socks5-poll-replace-usleep.patch:P1:poll() вместо usleep()"
    "05-client-keepalive.patch:P2:Keepalive от клиента"
    "06-socks5-dns-cache.patch:P2:DNS-кэш"
    "07-tcp-writev-coalesce.patch:P3:Coalesced TCP write"
)

APPLIED=0
FAILED=0
SKIPPED=0

for patch_info in "${PATCHES[@]}"; do
    IFS=':' read -r patch_file priority desc <<< "$patch_info"
    patch_path="$SCRIPT_DIR/$patch_file"

    if [ ! -f "$patch_path" ]; then
        echo "⚠️  Пропуск: $patch_file (файл не найден)"
        SKIPPED=$((SKIPPED + 1))
        continue
    fi

    echo -n "[$priority] $desc... "

    # Создаём бэкап оригинального файла
    orig_file=$(echo "$patch_path" | sed 's/\.patch$//')
    if [ ! -f "${orig_file}.bak" ]; then
        cp "$orig_file" "${orig_file}.bak"
    fi

    if patch -p1 --dry-run < "$patch_path" > /dev/null 2>&1; then
        if patch -p1 < "$patch_path" --silent; then
            echo "✅ Применён"
            APPLIED=$((APPLIED + 1))
        else
            echo "❌ Ошибка применения (контекст не совпадает)"
            cp "${orig_file}.bak" "$orig_file"
            FAILED=$((FAILED + 1))
        fi
    else
        echo "⚠️  Контекст не совпадает (проверьте оригинальные файлы)"
        SKIPPED=$((SKIPPED + 1))
    fi
done

echo ""
echo "=== Итог ==="
echo "✅ Применено: $APPLIED"
echo "❌ Ошибки: $FAILED"
echo "⚠️  Пропущено: $SKIPPED"
echo ""

if [ $FAILED -eq 0 ]; then
    echo "🎉 Все патчи применены успешно!"
    echo ""
    echo "Сборка:"
    echo "  cd $PROJECT_DIR && make clean && make"
else
    echo "⚠️  Некоторые патчи не применились. Проверьте вывод выше."
    echo "Бэкапы оригинальных файлов: *.bak"
fi
