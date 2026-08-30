#!/bin/bash
# sanitize-werror.sh — проверка компиляции с -Werror
set -euo pipefail

CC="${CC:-gcc}"
BUILDDIR="build/werror"

CFLAGS="-Wall -Wextra -Werror -O2 -I src/crypto -I src/core -I src/network"

rm -rf "$BUILDDIR"
mkdir -p "$BUILDDIR"

echo "=== Build with -Werror ==="
echo "CFLAGS: ${CFLAGS}"
echo ""

FILES=(
    "src/core/server.c"
    "src/core/client.c"
    "src/core/session.c"
    "src/core/config.c"
    "src/core/log.c"
    "src/core/obfuscation.c"
    "src/core/dns_cache.c"
    "src/network/socks5.c"
    "src/network/quic_layer.c"
    "src/crypto/gost_cipher.c"
    "src/crypto/gost_test.c"
    "src/core/test_protocol.c"
)

for f in "${FILES[@]}"; do
    echo "  cc ${f}"
    $CC ${CFLAGS} -c "$f" -o "${BUILDDIR}/$(basename ${f%.*}).o"
done

# Ассемблерные файлы
echo "  nasm src/core/tcp_helpers.asm"
nasm -f elf64 src/core/tcp_helpers.asm -o "${BUILDDIR}/tcp_helpers.o"

echo ""
echo "✅ All files compile with -Werror"
echo ""
echo "Compiled objects:"
ls -la "$BUILDDIR/"
