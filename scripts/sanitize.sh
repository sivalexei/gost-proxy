#!/bin/bash
# sanitize.sh — сборка и запуск с санитайзерами
set -euo pipefail

MODE="${1:-asan}"
CC="${CC:-gcc}"
INCLUDES="-I src/crypto -I src/core -I src/network"

CFLAGS=""
LDFLAGS=""
if [ "$MODE" = "asan" ]; then
    CFLAGS="-fsanitize=address -fno-omit-frame-pointer -g"
    LDFLAGS="-fsanitize=address -lgcc_s -lpthread"
elif [ "$MODE" = "ubsan" ]; then
    CFLAGS="-fsanitize=undefined -fno-omit-frame-pointer -g"
    LDFLAGS="-fsanitize=undefined -lgcc_s -lpthread"
else
    CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g"
    LDFLAGS="-fsanitize=address,undefined -lgcc_s -lpthread"
fi

BUILDDIR="build/${MODE}"

# Только серверные файлы (без client.c и test_protocol.c — там свой main)
FILES=(
    "src/core/server.c"
    "src/core/session.c"
    "src/core/config.c"
    "src/core/log.c"
    "src/core/obfuscation.c"
    "src/core/dns_cache.c"
    "src/network/socks5.c"
    "src/network/socks5_server.c"
    "src/network/quic_layer.c"
    "src/crypto/gost_cipher.c"
    "src/crypto/cmac_impl.c"
    "src/core/key_derivation.c"
    "src/crypto/chacha20.c"
    "src/crypto/aes.c"
    "src/crypto/ecc.c"
    "src/crypto/sha256.c"
    "src/crypto/hmac_sha256.c"
    "src/network/socks5_auth.c"
)

echo "=== Build with ${MODE} ==="
echo "CFLAGS: ${CFLAGS}"
echo "INCLUDES: ${INCLUDES}"

rm -rf "$BUILDDIR"
mkdir -p "$BUILDDIR"

for f in "${FILES[@]}"; do
    echo "  cc ${f}"
    $CC ${CFLAGS} ${INCLUDES} -c "$f" -o "${BUILDDIR}/$(basename ${f%.*}).o"
done

# Ассемблерные файлы
echo "  nasm src/core/tcp_helpers.asm"
nasm -f elf64 src/core/tcp_helpers.asm -o "${BUILDDIR}/tcp_helpers.o"

# Собираем исполняемый
echo "  linking server"
$CC ${BUILDDIR}/*.o -o "${BUILDDIR}/server" ${LDFLAGS}

echo ""
echo "✅ ${MODE} build OK"
echo ""
echo "Compiled objects:"
ls -la "$BUILDDIR/"
echo ""
echo "Binary:"
ls -la "${BUILDDIR}/server"
