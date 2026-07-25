#!/bin/bash
set -e

APP_NAME="gost-proxy"
VERSION="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOP_DIR="${SCRIPT_DIR}/rpmbuild"

echo "=== Сборка RPM пакетов для $APP_NAME ==="

# Проверяем зависимости
echo "[1/6] Проверка зависимостей..."

export PATH="/tmp/nasm_extract/usr/bin:$PATH"
if ! command -v nasm &> /dev/null; then
    echo "  NASM не найден. Скачивание..."
    cd /tmp
    curl -sL https://www.nasm.us/pub/nasm/releasebuilds/2.16.01/linux/nasm-2.16.01-0.fc36.x86_64.rpm -o nasm.rpm
    mkdir -p nasm_extract && cd nasm_extract && rpm2cpio ../nasm.rpm | cpio -idm 2>/dev/null
    export PATH="/tmp/nasm_extract/usr/bin:$PATH"
fi

if ! command -v gcc &> /dev/null; then
    echo "  ОШИБКА: GCC не установлен!"
    exit 1
fi

# Создаём исходный tarball
echo "[2/6] Создание исходного tarball..."
TARBALL_DIR="/tmp/${APP_NAME}-${VERSION}"
rm -rf "$TARBALL_DIR"
mkdir -p "$TARBALL_DIR"

# Копируем исходники
cp -r src/ "$TARBALL_DIR/"
cp -r config/ "$TARBALL_DIR/"
cp Makefile "$TARBALL_DIR/"
cp README.md "$TARBALL_DIR/"

# Создаём tarball
cd /tmp
tar czf "${TOP_DIR}/SOURCES/${APP_NAME}-${VERSION}.tar.gz" "${APP_NAME}-${VERSION}"
rm -rf "$TARBALL_DIR"

echo "  Tarball: ${TOP_DIR}/SOURCES/${APP_NAME}-${VERSION}.tar.gz"

# Сборка бинарников
echo "[3/6] Сборка бинарников..."
cd "$SCRIPT_DIR"
make clean 2>/dev/null || true
make

if [ ! -f build/gost-server ] || [ ! -f build/gost-client ]; then
    echo "  ОШИБКА: Бинарники не собраны!"
    exit 1
fi

echo "  Бинарники собраны успешно"

# Сборка RPM
echo "[4/6] Сборка RPM пакетов..."
rpmbuild -bb --nodeps \
    --define "_topdir $TOP_DIR" \
    --define "version $VERSION" \
    rpmbuild/SPECS/gost-proxy.spec

echo "[5/6] Готово!"
echo ""
echo "=== RPM Пакеты ==="
ls -lh "$TOP_DIR"/RPMS/x86_64/*.rpm
echo ""
echo "=== Установка ==="
echo "  sudo rpm -i $TOP_DIR/RPMS/x86_64/gost-proxy-server-${VERSION}-*.rpm"
echo "  sudo rpm -i $TOP_DIR/RPMS/x86_64/gost-proxy-client-${VERSION}-*.rpm"
echo ""
echo "=== Запуск ==="
echo "  Сервер: sudo systemctl start gost-proxy-server"
echo "  Клиент: gost-client 127.0.0.1 8443"

echo "[6/6] Сборка RPM завершена!"
