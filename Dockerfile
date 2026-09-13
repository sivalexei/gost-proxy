FROM debian:bullseye-slim AS build

# Установите зависимости для сборки
RUN apt-get update && \
    apt-get install -y build-essential nasm libpthread-stubs0-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Скопируйте исходники
COPY . .

# Соберите проект
RUN make clean && \
    make && \
    make test && \
    make asan && \
    make sanitize-werror

# Создаём финальный образ
FROM debian:bullseye-slim

RUN apt-get update && \
    apt-get install -y libpthread-stubs0-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Скопируйте собранное бинарное ядро и конфиги
COPY --from=build /app/build/gost-server /usr/local/bin/gost-server
COPY --from=build /app/build/gost-client /usr/local/bin/gost-client
COPY --from=build /app/etc/server.json /etc/gost-proxy/server.json

# Создаём конфиги
RUN mkdir -p /etc/gost-proxy

EXPOSE 10443

# Команда по умолчанию
CMD ["gost-server", "/etc/gost-proxy/server.json"]

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD ["/usr/local/bin/gost-server", "--healthcheck"]
