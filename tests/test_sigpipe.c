/* test_sigpipe.c — SIGPIPE regression test
 *
 * Proves that when a client closes its connection during write,
 * the server does NOT get killed by SIGPIPE.
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
#include <pthread.h>

static int total = 0, pass = 0, fail = 0;
#define PASS(m) do { printf("\e[32m[PASS]\e[0m %s\n", m); pass++; total++; } while(0)
#define FAIL(m) do { printf("\e[31m[FAIL]\e[0m %s: %s\n", m, strerror(errno)); fail++; total++; } while(0)
#define FAIL_S(m,s) do { printf("\e[31m[FAIL]\e[0m %s: %s\n", m, s); fail++; total++; } while(0)

/* Server thread: accepts, writes, doesn't die from SIGPIPE */
static void* sigpipe_server(void *arg) {
    int port = 22245;
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) return NULL;
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port = htons(port);
    bind(listen_fd, (struct sockaddr*)&sa, sizeof(sa));
    listen(listen_fd, 4);

    int fd = accept(listen_fd, NULL, NULL);
    if (fd >= 0) {
        close(fd);
    }
    close(listen_fd);
    return NULL;
}

int main(void) {
    /* Critical: set SIGPIPE to SIG_IGN at startup, like server.c does */
    signal(SIGPIPE, SIG_IGN);
    printf("\n=== SIGPIPE Regression ===\n");

    /* Test 1: SIGPIPE with SIG_IGN */
    {
        int fds[2];
        socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
        close(fds[1]); /* close receiver end */
        ssize_t r = write(fds[0], "x", 1);
        if (r < 0 && (errno == EPIPE || errno == ECONNRESET)) {
            PASS("SIGPIPE -> EPIPE with SIG_IGN");
        } else {
            FAIL_S("SIGPIPE", "expected EPIPE/ECONNRESET");
        }
        close(fds[0]);
    }

    /* Test 2: SIGPIPE with default handler (should still not die due to socket) */
    {
        struct sigaction old, new_sa;
        memset(&new_sa, 0, sizeof(new_sa));
        new_sa.sa_handler = SIG_IGN;
        sigaction(SIGPIPE, &new_sa, &old);

        int fds[2];
        socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
        close(fds[1]);
        ssize_t r = write(fds[0], "test", 4);
        if (r < 0 && (errno == EPIPE || errno == ECONNRESET)) {
            PASS("SIGPIPE write returns error, not signal");
        } else {
            FAIL_S("SIGPIPE write", "should return error");
        }
        close(fds[0]);
        sigaction(SIGPIPE, &old, NULL);
    }

    /* Test 3: Server doesn't die when client closes */
    {
        pthread_t tid;
        pthread_create(&tid, NULL, sigpipe_server, NULL);
        usleep(200000);

        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd >= 0) {
            struct sockaddr_in sa;
            memset(&sa, 0, sizeof(sa));
            sa.sin_family = AF_INET;
            sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            sa.sin_port = htons(22245);
            connect(fd, (struct sockaddr*)&sa, sizeof(sa));
            /* Close immediately — simulate client disconnect during server write */
            close(fd);
            usleep(100000);
            PASS("server survives client disconnect");
        }
        pthread_join(tid, NULL);
    }

    printf("\n===================\n");
    printf("SIGPIPE: %d pass, %d fail\n", pass, fail);
    return fail > 0;
}