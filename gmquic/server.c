/*
 * gmquic-server.c — 国密 QUIC 测试服务端
 * 基于 Tongsuo 8.5 QUIC API(OpenSSL 3.2 风格)
 * 用法: gmquic-server -p <port> -cert <sm2-cert.pem> -key <sm2-key.pem>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/quic.h>
#include <openssl/err.h>

static int verbose = 1;

static int alpn_select_cb(SSL *ssl, const unsigned char **out,
                          unsigned char *outlen, const unsigned char *in,
                          unsigned int inlen, void *arg) {
    /* 选择 "mqtt"(或客户端提供的第一个) */
    *out = in + 1;
    *outlen = in[0];
    return SSL_TLSEXT_ERR_OK;
}

static void die(const char *msg) {
    fprintf(stderr, "FATAL: %s: %s\n", msg, strerror(errno));
    exit(1);
}

static void print_ssl_err(const char *what, SSL *ssl, int ret) {
    int err = SSL_get_error(ssl, ret);
    fprintf(stderr, "%s: ret=%d err=%d (%s)\n", what, ret, err,
            err == SSL_ERROR_WANT_READ ? "WANT_READ" :
            err == SSL_ERROR_WANT_WRITE ? "WANT_WRITE" :
            err == SSL_ERROR_SYSCALL ? "SYSCALL" :
            err == SSL_ERROR_SSL ? "SSL" : "OTHER");
    ERR_print_errors_fp(stderr);
}

const char *upstream_host = NULL;
int upstream_port = 1883;

/* 连接上游 TCP(MQTT broker) */
static int connect_upstream(void) {
    int ufd = socket(AF_INET, SOCK_STREAM, 0);
    if (ufd < 0) return -1;
    struct sockaddr_in ua;
    memset(&ua, 0, sizeof(ua));
    ua.sin_family = AF_INET;
    ua.sin_port = htons(upstream_port);
    if (inet_pton(AF_INET, upstream_host, &ua.sin_addr) != 1) {
        fprintf(stderr, "upstream %s 解析失败\n", upstream_host); close(ufd); return -1;
    }
    if (connect(ufd, (struct sockaddr *)&ua, sizeof(ua)) < 0) {
        fprintf(stderr, "upstream %s:%d connect 失败: %s\n", upstream_host, upstream_port, strerror(errno));
        close(ufd); return -1;
    }
    return ufd;
}

int main(int argc, char **argv) {
    int port = 4433;
    const char *cert = "server-sign.crt";
    const char *key = "server-sign.key";
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-p")) port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-cert")) cert = argv[++i];
        else if (!strcmp(argv[i], "-key")) key = argv[++i];
        else if (!strcmp(argv[i], "-upstream")) upstream_host = argv[++i];
        else if (!strcmp(argv[i], "-upstream-port")) upstream_port = atoi(argv[++i]);
    }

    /* UDP socket */
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) die("socket");
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) die("bind");

    /* SSL_CTX: QUIC server method */
    SSL_CTX *ctx = SSL_CTX_new(OSSL_QUIC_server_method());
    if (!ctx) die("SSL_CTX_new");
    SSL_CTX_enable_sm_tls13_strict(ctx); /* 启用 TLS1.3 国密套件(RFC 8998) */
    if (SSL_CTX_set_ciphersuites(ctx, "TLS_SM4_GCM_SM3") != 1) {
        fprintf(stderr, "set_ciphersuites TLS_SM4_GCM_SM3 failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    SSL_CTX_set_alpn_select_cb(ctx, alpn_select_cb, NULL);
    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "load cert/key failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    /* listener */
    SSL *listener = SSL_new_listener(ctx, SSL_LISTENER_FLAG_NO_VALIDATE);
    if (!listener) die("SSL_new_listener");
    BIO *bio = BIO_new_dgram(fd, BIO_NOCLOSE);
    if (!bio) die("BIO_new_dgram");
    SSL_set_bio(listener, bio, bio);

    printf("gmquic-server listening on udp://0.0.0.0:%d (cipher TLS_SM4_GCM_SM3)\n", port);
    fflush(stdout);

    /* 多连接事件循环 */
#define MAX_CONNS 16
    struct {
        SSL *conn;
        int upfd;
    } conns[MAX_CONNS];
    int nconns = 0;
    char buf[8192], buf2[8192];

    for (;;) {
        SSL_handle_events(listener);
        /* accept 新连接 */
        SSL *conn;
        while ((conn = SSL_accept_connection(listener, SSL_ACCEPT_CONNECTION_NO_BLOCK)) != NULL) {
            if (nconns < MAX_CONNS) {
                SSL_set_blocking_mode(conn, 0); /* QUIC 非阻塞,事件循环驱动 */
                conns[nconns].conn = conn;
                conns[nconns].upfd = (upstream_host != NULL) ? connect_upstream() : -1;
                printf(">>> accepted QUIC connection (total %d)\n", nconns + 1);
                fflush(stdout);
                nconns++;
            } else {
                SSL_free(conn);
            }
        }
        /* 轮询所有连接 */
        for (int i = 0; i < nconns; ) {
            SSL *c = conns[i].conn;
            int upfd = conns[i].upfd;
            int dead = 0;

            SSL_handle_events(c);
            /* QUIC -> TCP */
            int n = SSL_read(c, buf, sizeof(buf));
            if (verbose && n <= 0) {
                int rerr = SSL_get_error(c, n);
                printf("    ssl_read n=%d err=%d (want_r=%d want_w=%d zero=%d)\n", n, rerr,
                       rerr == SSL_ERROR_WANT_READ, rerr == SSL_ERROR_WANT_WRITE, rerr == SSL_ERROR_ZERO_RETURN);
                fflush(stdout);
            }
            if (n > 0) {
                if (verbose) printf(">>> quic->tcp %d bytes\n", n);
                fflush(stdout);
                if (upfd >= 0) {
                    int w = write(upfd, buf, n);
                    if (verbose) printf("    write(upfd)=%d\n", w);
                    fflush(stdout);
                    if (w < 0) dead = 1;
                }
            } else {
                /* QUIC 非阻塞:无数据时 SSL_read 返回 0 + WANT_READ,不是 EOF */
                int rerr = SSL_get_error(c, n);
                if (rerr == SSL_ERROR_WANT_READ || rerr == SSL_ERROR_WANT_WRITE) {
                    /* 无数据,继续轮询 */
                } else if (rerr == SSL_ERROR_ZERO_RETURN || n == 0) {
                    if (n == 0 && rerr == SSL_ERROR_WANT_READ) { /* 无数据 */ }
                    else dead = 1;
                } else {
                    dead = 1;
                }
            }
            /* TCP -> QUIC (非阻塞轮询) */
            if (!dead && upfd >= 0) {
                int r = recv(upfd, buf2, sizeof(buf2), MSG_DONTWAIT);
                if (verbose && r > 0) printf("<<< tcp->quic %d bytes: %02x %02x %02x %02x\n", r, (unsigned char)buf2[0], (unsigned char)buf2[1], (unsigned char)buf2[2], (unsigned char)buf2[3]);
                if (verbose && r == 0) printf("    recv EOF\n");
                if (verbose && r < 0) printf("    recv errno=%d %s\n", errno, strerror(errno));
                fflush(stdout);
                if (r > 0) {
                    if (verbose) printf("<<< tcp->quic %d bytes\n", r);
                    fflush(stdout);
                    int off = 0;
                    while (off < r) {
                        int w = SSL_write(c, buf2 + off, r - off);
                        if (verbose) printf("    ssl_write(quic)=%d\n", w);
                        fflush(stdout);
                        if (w > 0) { off += w; continue; }
                        int werr = SSL_get_error(c, w);
                        if (werr == SSL_ERROR_WANT_READ || werr == SSL_ERROR_WANT_WRITE) {
                            SSL_handle_events(c);
                            usleep(1000);
                            continue;
                        }
                        dead = 1;
                        break;
                    }
                } else if (r == 0) {
                    dead = 1;
                }
            }
            if (dead) {
                if (verbose) printf("    DEAD (errno=%d %s)\n", errno, strerror(errno));
                fflush(stdout);
                if (upfd >= 0) close(upfd);
                SSL_free(c);
                conns[i] = conns[nconns - 1];
                nconns--;
                printf(">>> connection closed (remaining %d)\n", nconns);
                fflush(stdout);
            } else {
                i++;
            }
        }
        usleep(1000);
    }
}