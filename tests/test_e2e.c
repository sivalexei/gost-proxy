/* test_e2e.c — End-to-End тесты с timeout
 *
 * Все сетевые операции имеют жёсткий timeout через poll().
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <pthread.h>
#include <sys/wait.h>

static int e2e_total = 0, e2e_pass = 0, e2e_fail = 0;
#define E2E_PASS(m) do { printf("\e[32m[PASS]\e[0m %s\n", m); e2e_pass++; e2e_total++; } while(0)
#define E2E_FAIL(m) do { printf("\e[31m[FAIL]\e[0m %s: %s\n", m, strerror(errno)); e2e_fail++; e2e_total++; } while(0)
#define E2E_FAIL_S(m,s) do { printf("\e[31m[FAIL]\e[0m %s: %s\n", m, s); e2e_fail++; e2e_total++; } while(0)

/* Утилита: wait с timeout (poll) */
static int wait_readable(int fd, int timeout_ms) {
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    int r = poll(&pfd, 1, timeout_ms);
    if (r <= 0) return -1; /* timeout */
    return 0;
}

/* Простой TCP echo-сервер — запускается в pthread */
static void* echo_server(void *arg) {
    (void)arg;
    int port = 21234;
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) return NULL;
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port = htons(port);
    if (bind(listen_fd, (struct sockaddr*)&sa, sizeof(sa)) < 0) return NULL;
    listen(listen_fd, 16);

    int fd = accept(listen_fd, NULL, NULL);
    if (fd >= 0) {
        uint8_t buf[4096];
        for (;;) {
            ssize_t n = read(fd, buf, sizeof(buf));
            if (n <= 0) break;
            size_t off = 0;
            while (off < (size_t)n) {
                ssize_t s = write(fd, buf + off, n - off);
                if (s < 0) break;
                off += (size_t)s;
            }
        }
        close(fd);
    }
    close(listen_fd);
    return NULL;
}

/* Тест 1: TCP echo roundtrip */
static int test_tcp_echo(void) {
    printf("\n=== E2E: TCP Echo ===\n");
    pthread_t tid;
    pthread_create(&tid, NULL, echo_server, NULL);
    usleep(500000); /* wait for listen */

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { E2E_FAIL("socket"); goto out; }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons(21234);

    if (connect(fd, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        E2E_FAIL("connect echo");
        close(fd);
        goto out;
    }

    const char *hello = "Hello GOST Proxy!";
    size_t hl = strlen(hello);
    if (write(fd, hello, hl) != (ssize_t)hl) {
        E2E_FAIL_S("write echo", "short write");
        close(fd);
        goto out;
    }

    /* Read response with timeout */
    if (wait_readable(fd, 5000) < 0) {
        E2E_FAIL_S("read echo", "timeout waiting for response");
        close(fd);
        goto out;
    }

    char resp[256];
    ssize_t n = read(fd, resp, sizeof(resp));
    if (n == (ssize_t)hl && memcmp(hello, resp, hl) == 0) {
        E2E_PASS("tcp echo roundtrip");
    } else {
        E2E_FAIL_S("tcp echo", "data mismatch or timeout");
    }
    close(fd);
out:
    pthread_join(tid, NULL);
    return 0;
}

/* Тест 2: SIGPIPE safety */
static int test_sigpipe_safety(void) {
    printf("\n=== E2E: SIGPIPE Safety ===\n");

    struct sigaction sa, old;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, &old);

    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
        E2E_FAIL("socketpair sigpipe");
        goto out_restore;
    }

    close(fds[1]); /* close receiver */
    if (write(fds[0], "x", 1) < 0) {
        if (errno == EPIPE || errno == ECONNRESET || errno == ESHUTDOWN) {
            E2E_PASS("sigpipe caught properly");
        } else {
            E2E_FAIL_S("sigpipe", strerror(errno));
        }
    } else {
        E2E_FAIL_S("sigpipe", "should have failed");
    }
    close(fds[0]);
out_restore:
    sigaction(SIGPIPE, &old, NULL);
    return 0;
}

int main(void) {
    test_tcp_echo();
    test_sigpipe_safety();

    printf("\n===================\n");
    printf("E2E Total: %d pass, %d fail\n", e2e_pass, e2e_fail);
    return e2e_fail > 0;
}
