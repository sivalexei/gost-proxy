CC = gcc
NASM = nasm
CFLAGS = -Wall -Wextra -O2 -I src/crypto -I src/core -I src/network
LDFLAGS = -lpthread
NASMFLAGS = -f elf64

SRC_DIR = src
BUILD_DIR = build

CRYPTO_SRC = $(SRC_DIR)/crypto/gost_cipher.c
# Шифрование обеспечивается C-реализацией в gost_cipher.c (RFC 7801)
# Ассемблерные реализации kuznyechik.asm исключены из репозитория.
CORE_SRC = $(SRC_DIR)/core/server.c $(SRC_DIR)/core/client.c $(SRC_DIR)/core/session.c $(SRC_DIR)/core/obfuscation.c

CRYPTO_OBJ = $(BUILD_DIR)/gost_cipher.o
CONFIG_OBJ = $(BUILD_DIR)/config.o
LOG_OBJ = $(BUILD_DIR)/log.o
SOCKS5_OBJ = $(BUILD_DIR)/socks5.o
QUIC_LAYER_OBJ = $(BUILD_DIR)/quic_layer.o
OBFUSCATION_OBJ = $(BUILD_DIR)/obfuscation.o
TCP_HELPERS_OBJ = $(BUILD_DIR)/tcp_helpers.o
SERVER_OBJ = $(BUILD_DIR)/server.o $(BUILD_DIR)/session.o $(CONFIG_OBJ) $(LOG_OBJ) $(TCP_HELPERS_OBJ) $(QUIC_LAYER_OBJ) $(OBFUSCATION_OBJ)
CLIENT_OBJ = $(BUILD_DIR)/client.o $(BUILD_DIR)/session.o $(CONFIG_OBJ) $(LOG_OBJ) $(SOCKS5_OBJ) $(QUIC_LAYER_OBJ) $(OBFUSCATION_OBJ)
PROXY_OBJ = $(BUILD_DIR)/proxy.o $(BUILD_DIR)/session.o $(CONFIG_OBJ) $(LOG_OBJ) $(TCP_HELPERS_OBJ)

.PHONY: all clean setup test test-https build-curl-openssl

all: $(BUILD_DIR)/gost-server $(BUILD_DIR)/gost-client

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/gost_cipher.o: $(CRYPTO_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/server.o: $(SRC_DIR)/core/server.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/client.o: $(SRC_DIR)/core/client.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/session.o: $(SRC_DIR)/core/session.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/config.o: $(SRC_DIR)/core/config.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/log.o: $(SRC_DIR)/core/log.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/socks5.o: $(SRC_DIR)/network/socks5.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/obfuscation.o: $(SRC_DIR)/core/obfuscation.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/quic_layer.o: $(SRC_DIR)/network/quic_layer.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/tcp_helpers.o: $(SRC_DIR)/core/tcp_helpers.asm | $(BUILD_DIR)
	$(NASM) $(NASMFLAGS) $< -o $@

$(BUILD_DIR)/gost-server: $(CRYPTO_OBJ) $(SERVER_OBJ)
	$(CC) $^ -o $@ $(LDFLAGS)

$(BUILD_DIR)/gost-client: $(CRYPTO_OBJ) $(CLIENT_OBJ)
	$(CC) $^ -o $@ $(LDFLAGS)

test: $(BUILD_DIR)/gost-test
	./$(BUILD_DIR)/gost-test

$(BUILD_DIR)/gost-test: $(CRYPTO_OBJ) $(BUILD_DIR)/gost_test.o | $(BUILD_DIR)
	$(CC) $^ -o $@ $(LDFLAGS)

$(BUILD_DIR)/gost_test.o: $(SRC_DIR)/crypto/gost_test.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

test-https:
	@bash tests/test-https.sh

build-curl-openssl:
	@bash tests/build-curl-openssl.sh

clean:
	rm -rf $(BUILD_DIR)

setup:
	sudo apt-get update && sudo apt-get install -y nasm build-essential
