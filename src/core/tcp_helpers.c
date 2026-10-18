/* tcp_helpers.c — TCP helper functions for gost-proxy */
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

ssize_t tcp_write_all(int fd, const void *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t s = send(fd, (const uint8_t *)buf + off, len - off, MSG_NOSIGNAL);
        if (s < 0) return -1;
        off += (size_t)s;
    }
    return (ssize_t)len;
}
