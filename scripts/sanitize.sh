#!/bin/bash
# sanitize.sh — сборка и запуск с AddressSanitizer / UndefinedBehaviorSanitizer
set -euo pipefail

CC="${CC:-gcc}"
NASM="${NASM:-nasm}"
BUILDDIR="build"
SHADERDIR="${BUILDDIR}/sanitize"
CFLAGS="-Wall -Wextra -Werror -O1 -fno-omit-frame-pointer -I src/crypto -I src/core -I src/network"
LDFLAGS="-lpthread"

# Определить тип санитайзера по первому аргументу
MODE="${1:-asan}"
if [[ "$MODE" == "asan" ]]; then
    CFLAGS+=" -fsanitize=address"
    LDFLAGS+=" -fsanitize=address"
    echo "=== AddressSanitizer ==="
elif [[ "$MODE" == "ubsan" ]]; then
    CFLAGS+=" -fsanitize=undefined"
    LDFLAGS+=" -fsanitize=undefined"
    echo "=== UndefinedBehaviorSanitizer ==="
else
    echo "Usage: $0 [asan|ubsan]"
    exit 1
fi

echo "CFLAGS: ${CFLAGS}"
echo "LDFLAGS: ${LDFLAGS}"
echo ""

rm -rf "$SHADERDIR"
mkdir -p "$SHADERDIR"

# Объектные файлы
OBJS=()
add_obj() {
    local src="$1" out="$2"
    if [[ -f "$src" ]]; then
        echo "  cc ${src} -> ${out}"
        $CC ${CFLAGS} -c "$src" -o "$out"
        OBJS+=("$out")
    else
        echo "  SKIP ${src} (not found)"
    fi
}

add_obj "src/crypto/gost_cipher.c"      "$SHADERDIR/gost_cipher.o"
add_obj "src/core/server.c"              "$SHADERDIR/server.o"
add_obj "src/core/client.c"              "$SHADERDIR/client.o"
add_obj "src/core/session.c"             "$SHADERDIR/session.o"
add_obj "src/core/config.c"              "$SHADERDIR/config.o"
add_obj "src/core/log.c"                 "$SHADERDIR/log.o"
add_obj "src/core/obfuscation.c"         "$SHADERDIR/obfuscation.o"
add_obj "src/core/dns_cache.c"           "$SHADERDIR/dns_cache.o"
add_obj "src/network/socks5.c"           "$SHADERDIR/socks5.o"
add_obj "src/network/quic_layer.c"       "$SHADERDIR/quic_layer.o"
add_obj "src/crypto/gost_test.c"         "$SHADERDIR/gost_test.o"
add_obj "src/core/test_protocol.c"       "$SHADERDIR/test_protocol.o"

# Ассемблерные объекты (не компилируются через CC)
echo "  nasm src/core/tcp_helpers.asm"
$NASM -f elf64 src/core/tcp_helpers.asm -o "${SHADERDIR}/tcp_helpers.o"

echo ""
echo "=== Linking ==="

# Линкуем бинарники: LDFLAGS только один раз (санитайзер + pthread)
# gost-server: сервер + общие модули
$CC "${SHADERDIR}/gost_cipher.o" \
    "${SHADERDIR}/server.o" "${SHADERDIR}/session.o" "${SHADERDIR}/config.o" \
    "${SHADERDIR}/log.o" "${SHADERDIR}/socks5.o" "${SHADERDIR}/quic_layer.o" \
    "${SHADERDIR}/obfuscation.o" "${SHADERDIR}/dns_cache.o" \
    "${SHADERDIR}/tcp_helpers.o" \
    -o "$SHADERDIR/gost-server" $LDFLAGS

# gost-client: клиент + общие модули
$CC "${SHADERDIR}/gost_cipher.o" \
    "${SHADERDIR}/client.o" "${SHADERDIR}/session.o" "${SHADERDIR}/config.o" \
    "${SHADERDIR}/log.o" "${SHADERDIR}/socks5.o" "${SHADERDIR}/quic_layer.o" \
    "${SHADERDIR}/obfuscation.o" "${SHADERDIR}/dns_cache.o" \
    -o "$SHADERDIR/gost-client" $LDFLAGS

# gost-test: только крипто + тест
# gost-test: только крипто + тест
$CC "${SHADERDIR}/gost_cipher.o" \
    "${SHADERDIR}/gost_test.o" \
    -o "$SHADERDIR/gost-test" $LDFLAGS

# test-protocol: протокол + общие модули (без main из server/client)
$CC "${SHADERDIR}/gost_cipher.o" \
    "${SHADERDIR}/test_protocol.o" \
    "${SHADERDIR}/session.o" "${SHADERDIR}/obfuscation.o" "${SHADERDIR}/log.o" \
    -o "$SHADERDIR/test-protocol" $LDFLAGS

echo ""
echo "=== Running tests ==="
echo "--- gost-test ---"
"$SHADERDIR/gost-test"
echo "--- test-protocol ---"
"$SHADERDIR/test-protocol"
echo ""
echo "✅ Sanitizers passed (${MODE})"
