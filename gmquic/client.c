/*
 * gmquic-client.c — 国密 QUIC 测试客户端
 * 基于 Tongsuo 8.5 QUIC API(OpenSSL 3.2 风格)
 * 用法: gmquic-client -h <host> -p <port> [-cafile <sm2-ca.pem>] [-msg <text>]
 * 握手成功后向服务端发消息并回显
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/quic.h>
#include <openssl/err.h>

static void die(const char *msg) {
    fprintf(stderr, "FATAL: %s: %s\n", msg, strerror(errno));
    exit(1);
}

int main(int argc, char **argv) {
    const char *host = "127.0.0.1";
    int port = 4433;
    const char *cafile = NULL;
    const char *cert = NULL, *key = NULL;
    const char *msg = "hello 国密QUIC from gmquic-client\n";
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-h")) host = argv[++i];
        else if (!strcmp(argv[i], "-p")) port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-cafile")) cafile = argv[++i];
        else if (!strcmp(argv[i], "-cert")) cert = argv[++i];
        else if (!strcmp(argv[i], "-key")) key = argv[++i];
        else if (!strcmp(argv[i], "-msg")) msg = argv[++i];
    }

    /* resolve + UDP socket */
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%d", port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0) die("getaddrinfo");

    int fd = socket(res->ai_family, res->ai_socktype, 0);
    if (fd < 0) die("socket");
    if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) die("connect");

    /* SSL_CTX: QUIC client method + 国密套件 */
    SSL_CTX *ctx = SSL_CTX_new(OSSL_QUIC_client_method());
    if (!ctx) die("SSL_CTX_new");
    SSL_CTX_enable_sm_tls13_strict(ctx); /* 启用 TLS1.3 国密套件(RFC 8998) */
    if (SSL_CTX_set_ciphersuites(ctx, "TLS_SM4_GCM_SM3") != 1) {
        fprintf(stderr, "set_ciphersuites TLS_SM4_GCM_SM3 failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    if (cafile) {
        if (SSL_CTX_load_verify_locations(ctx, cafile, NULL) != 1) {
            fprintf(stderr, "load CA failed\n");
            ERR_print_errors_fp(stderr);
            return 1;
        }
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }
    /* TLS1.3 国密套件需要 SM2 证书(客户端侧) */
    if (cert && key) {
        if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1) {
            fprintf(stderr, "load client SM2 cert/key failed\n");
            ERR_print_errors_fp(stderr);
            return 1;
        }
    }

    /* SSL */
    SSL *ssl = SSL_new(ctx);
    if (!ssl) die("SSL_new");
    SSL_set_connect_state(ssl);
    SSL_set_tlsext_host_name(ssl, host);
    /* QUIC 强制要求 ALPN */
    static const unsigned char alpn[] = {4, 'm', 'q', 't', 't'}; /* "mqtt" */
    if (SSL_set_alpn_protos(ssl, alpn, sizeof(alpn)) != 0) {
        fprintf(stderr, "set alpn failed\n");
        return 1;
    }

    BIO *bio = BIO_new_dgram(fd, BIO_NOCLOSE);
    if (!bio) die("BIO_new_dgram");
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, res->ai_addr);
    SSL_set_bio(ssl, bio, bio);

    printf("connecting quic://%s:%d ...\n", host, port);
    fflush(stdout);

    /* handshake loop */
    int ret;
    for (;;) {
        ret = SSL_connect(ssl);
        if (ret == 1) break;
        int err = SSL_get_error(ssl, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            SSL_handle_events(ssl);
            usleep(1000);
            continue;
        }
        fprintf(stderr, "handshake failed: ret=%d err=%d\n", ret, err);
        ERR_print_errors_fp(stderr);
        return 1;
    }

    printf(">>> HANDSHAKE OK\n");
    printf("    negotiated cipher: %s\n", SSL_get_cipher_name(ssl));
    printf("    negotiated version: %s\n", SSL_get_version(ssl));
    fflush(stdout);

    /* send message */
    int len = strlen(msg);
    if (SSL_write(ssl, msg, len) <= 0) {
        fprintf(stderr, "SSL_write failed\n");
        return 1;
    }
    printf(">>> sent %d bytes\n", len);
    fflush(stdout);

    /* read echo */
    char buf[4096];
    for (int i = 0; i < 100; i++) {
        SSL_handle_events(ssl);
        int n = SSL_read(ssl, buf, sizeof(buf));
        if (n > 0) {
            buf[n] = 0;
            printf("<<< echo %d bytes: %s\n", n, buf);
            fflush(stdout);
            break;
        }
        int err = SSL_get_error(ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            usleep(20000);
            continue;
        }
        break;
    }

    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);
    printf("done\n");
    return 0;
}
