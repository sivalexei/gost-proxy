#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_NAME="gost-proxy"
VERSION="1.0.0"

export PATH="/tmp/nasm_extract/usr/bin:$PATH"

echo "=== Сборка DEB пакетов для $APP_NAME ==="

# Проверяем зависимости
echo "[1/4] Проверка зависимостей..."

if ! command -v nasm &> /dev/null; then
    echo "  NASM не найден. Скачивание..."
    cd /tmp
    curl -sL https://www.nasm.us/pub/nasm/releasebuilds/2.16.01/linux/nasm-2.16.01-0.fc36.x86_64.rpm -o nasm.rpm
    mkdir -p nasm_extract && cd nasm_extract && rpm2cpio ../nasm.rpm | cpio -idm 2>/dev/null
    export PATH="/tmp/nasm_extract/usr/bin:$PATH"
fi

if ! command -v gcc &> /dev/null; then
    echo "  ОШИБКА: GCC не установлен! (sudo apt install build-essential)"
    exit 1
fi

if ! command -v dpkg-deb &> /dev/null; then
    echo "  dpkg-deb не найден. Установка..."
    sudo apt-get install -y -qq dpkg-dev
fi

# Сборка бинарников
echo "[2/4] Сборка бинарников..."
cd "$SCRIPT_DIR"
make clean 2>/dev/null || true
make

if [ ! -f build/gost-server ] || [ ! -f build/gost-client ]; then
    echo "  ОШИБКА: Бинарники не собраны!"
    exit 1
fi

echo "  Бинарники собраны"

# Формируем структуру пакетов
echo "[3/4] Формирование пакетов..."

# --- Server ---
SERVER_DIR="/tmp/${APP_NAME}-server_${VERSION}"
rm -rf "$SERVER_DIR"
mkdir -p "$SERVER_DIR/usr/bin"
mkdir -p "$SERVER_DIR/etc/gost-proxy"
mkdir -p "$SERVER_DIR/usr/lib/systemd/system"
mkdir -p "$SERVER_DIR/DEBIAN"

install -m 0755 build/gost-server "$SERVER_DIR/usr/bin/gost-server"
install -m 0644 config/server.json "$SERVER_DIR/etc/gost-proxy/server.json"

cat > "$SERVER_DIR/usr/lib/systemd/system/gost-proxy-server.service" << 'EOF'
[Unit]
Description=ГОСТ Прокси-Сервер
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/gost-server /etc/gost-proxy/server.json
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

cat > "$SERVER_DIR/DEBIAN/control" << EOF
Package: gost-proxy-server
Version: ${VERSION}
Section: net
Priority: optional
Architecture: amd64
Maintainer: Developer <dev@example.com>
Description: ГОСТ Прокси-Сервер
 Прокси-сервер с шифрованием ГОСТ Р 34.12-2015 "Кузнечик".
 Ядро шифрования: C-реализация (RFC 7801).
 Транспорт — UDP, SOCKS5-прокси для клиента.
EOF

cat > "$SERVER_DIR/DEBIAN/postinst" << 'EOF'
#!/bin/bash
systemctl daemon-reload
echo "gost-proxy-server установлен. Запуск: systemctl start gost-proxy-server"
EOF
chmod 755 "$SERVER_DIR/DEBIAN/postinst"

# --- Client ---
CLIENT_DIR="/tmp/${APP_NAME}-client_${VERSION}"
rm -rf "$CLIENT_DIR"
mkdir -p "$CLIENT_DIR/usr/bin"
mkdir -p "$CLIENT_DIR/etc/gost-proxy"
mkdir -p "$CLIENT_DIR/DEBIAN"

install -m 0755 build/gost-client "$CLIENT_DIR/usr/bin/gost-client"
install -m 0644 config/client.json "$CLIENT_DIR/etc/gost-proxy/client.json"

cat > "$CLIENT_DIR/DEBIAN/control" << EOF
Package: gost-proxy-client
Version: ${VERSION}
Section: net
Priority: optional
Architecture: amd64
Maintainer: Developer <dev@example.com>
Description: Клиент ГОСТ Прокси-Сервера
 Клиент для подключения к ГОСТ Прокси-Серверу.
 Шифрование: ГОСТ Р 34.12-2015 (RFC 7801).
 Включает SOCKS5-прокси на 127.0.0.1:1080.
EOF

# Сборка .deb
echo "[4/4] Сборка .deb файлов..."

mkdir -p "$SCRIPT_DIR/debs"
dpkg-deb --build "$SERVER_DIR" "$SCRIPT_DIR/debs/gost-proxy-server_${VERSION}_amd64.deb"
dpkg-deb --build "$CLIENT_DIR" "$SCRIPT_DIR/debs/gost-proxy-client_${VERSION}_amd64.deb"

# Очистка
rm -rf "$SERVER_DIR" "$CLIENT_DIR"

echo ""
echo "=== DEB Пакеты ==="
ls -lh "$SCRIPT_DIR/debs/"
echo ""
echo "=== Установка ==="
echo "  sudo dpkg -i debs/gost-proxy-server_${VERSION}_amd64.deb"
echo "  sudo dpkg -i debs/gost-proxy-client_${VERSION}_amd64.deb"
echo ""
echo "=== Запуск ==="
echo "  Сервер: sudo systemctl start gost-proxy-server"
echo "  Клиент: gost-client 127.0.0.1 8443"
