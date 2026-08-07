package main

/*
#cgo LDFLAGS: /opt/tongsuo85/lib/libssl.a /opt/tongsuo85/lib/libcrypto.a -ldl -lpthread
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/quic.h>
#include <openssl/err.h>

typedef struct {
	int fd;
	SSL *ssl;
} gmquic_conn;

// gmquic_connect 建立国密 QUIC 连接(TLS_SM4_GCM_SM3 over QUICv1)
static void *gmquic_connect(const char *host, int port,
                            const char *cafile, const char *cert, const char *key) {
	struct addrinfo hints, *res = NULL;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	char portstr[16];
	snprintf(portstr, sizeof(portstr), "%d", port);
	if (getaddrinfo(host, portstr, &hints, &res) != 0) {
		fprintf(stderr, "[gmquic] getaddrinfo fail\n");
		return NULL;
	}

	int fd = socket(res->ai_family, res->ai_socktype, 0);
	if (fd < 0) { fprintf(stderr, "[gmquic] socket fail\n"); freeaddrinfo(res); return NULL; }
	if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) { fprintf(stderr, "[gmquic] connect fail\n"); freeaddrinfo(res); close(fd); return NULL; }

	SSL_CTX *ctx = SSL_CTX_new(OSSL_QUIC_client_method());
	if (!ctx) { freeaddrinfo(res); close(fd); return NULL; }
	SSL_CTX_enable_sm_tls13_strict(ctx); // 启用 TLS1.3 国密套件
	if (SSL_CTX_set_ciphersuites(ctx, "TLS_SM4_GCM_SM3") != 1) {
		fprintf(stderr, "[gmquic] ciphersuites fail\n");
		SSL_CTX_free(ctx); freeaddrinfo(res); close(fd); return NULL;
	}
	if (cafile != NULL && strlen(cafile) > 0) {
		if (SSL_CTX_load_verify_locations(ctx, cafile, NULL) != 1) {
			fprintf(stderr, "[gmquic] load CA fail\n");
			SSL_CTX_free(ctx); freeaddrinfo(res); close(fd); return NULL;
		}
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	} else {
		SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	}
	// 客户端 SM2 证书(TLS1.3 国密套件需要)
	if (cert != NULL && key != NULL && strlen(cert) > 0 && strlen(key) > 0) {
		if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) != 1 ||
		    SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1) {
			fprintf(stderr, "[gmquic] load cert/key fail\n");
			SSL_CTX_free(ctx); freeaddrinfo(res); close(fd); return NULL;
		}
	}

	SSL *ssl = SSL_new(ctx);
	SSL_CTX_free(ctx);
	if (!ssl) { freeaddrinfo(res); close(fd); return NULL; }
	SSL_set_connect_state(ssl);
	SSL_set_blocking_mode(ssl, 0); // QUIC 非阻塞
	SSL_set_tlsext_host_name(ssl, host);
	static const unsigned char alpn[] = {4, 'm', 'q', 't', 't'};
	if (SSL_set_alpn_protos(ssl, alpn, sizeof(alpn)) != 0) {
		SSL_free(ssl); freeaddrinfo(res); close(fd); return NULL;
	}

	BIO *bio = BIO_new_dgram(fd, BIO_NOCLOSE);
	if (!bio) { SSL_free(ssl); freeaddrinfo(res); close(fd); return NULL; }
	BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, res->ai_addr);
	SSL_set_bio(ssl, bio, bio);
	freeaddrinfo(res);

	// 握手循环
	for (;;) {
		int r = SSL_connect(ssl);
		if (r == 1) break;
		int err = SSL_get_error(ssl, r);
		if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
			SSL_handle_events(ssl);
			usleep(1000);
			continue;
		}
		fprintf(stderr, "[gmquic] handshake fail ret=%d err=%d\n", r, SSL_get_error(ssl, r));
		ERR_print_errors_fp(stderr);
		SSL_free(ssl);
		close(fd);
		return NULL;
	}

	gmquic_conn *c = (gmquic_conn *)malloc(sizeof(gmquic_conn));
	c->fd = fd;
	c->ssl = ssl;
	return (void *)c;
}

static int gmquic_write(void *h, const void *data, int len) {
	gmquic_conn *c = (gmquic_conn *)h;
	int total = 0;
	while (total < len) {
		int r = SSL_write(c->ssl, (const char *)data + total, len - total);
		if (r > 0) { total += r; continue; }
		int err = SSL_get_error(c->ssl, r);
		if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
			SSL_handle_events(c->ssl);
			usleep(1000);
			continue;
		}
		return -1;
	}
	return total;
}

static int gmquic_read(void *h, void *buf, int len) {
	gmquic_conn *c = (gmquic_conn *)h;
	int tries = 0;
	for (;;) {
		int r = SSL_read(c->ssl, buf, len);
		if (r > 0) return r;
		int err = SSL_get_error(c->ssl, r);
		// QUIC 非阻塞:无数据时 SSL_read 返回 0 + WANT_READ,不是 EOF
		if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
			SSL_handle_events(c->ssl);
			usleep(1000);
			if (++tries > 5000) return -2; // ~5s 超时
			continue;
		}
		if (r == 0) return 0; // 真 EOF
		return -1;
	}
}

static const char *gmquic_cipher(void *h) {
	gmquic_conn *c = (gmquic_conn *)h;
	return SSL_get_cipher_name(c->ssl);
}

static void gmquic_close(void *h) {
	gmquic_conn *c = (gmquic_conn *)h;
	if (c) {
		if (c->ssl) SSL_free(c->ssl);
		if (c->fd >= 0) close(c->fd);
		free(c);
	}
}
*/
import "C"

import (
	"fmt"
	"io"
	"strconv"
	"unsafe"
)

// quicGMDial 建立国密 QUIC 连接(TLS_SM4_GCM_SM3 over QUICv1)
func quicGMDial(o *options) (io.ReadWriteCloser, error) {
	host := C.CString(o.host)
	defer C.free(unsafe.Pointer(host))
	cafile := C.CString(o.caFile)
	defer C.free(unsafe.Pointer(cafile))
	cert := C.CString(o.signCert)
	defer C.free(unsafe.Pointer(cert))
	key := C.CString(o.signKey)
	defer C.free(unsafe.Pointer(key))

	if o.verbose {
		fmt.Printf("[gmqtt] quic-gm dial %s:%s (TLS_SM4_GCM_SM3)\n", o.host, o.port)
	}

	p, _ := strconv.Atoi(o.port)
	h := C.gmquic_connect(host, C.int(p), cafile, cert, key)
	if h == nil {
		return nil, fmt.Errorf("quic-gm dial %s:%s failed (SM2 证书: cafile=%s cert=%s)",
			o.host, o.port, o.caFile, o.signCert)
	}

	if o.verbose {
		fmt.Printf("[gmqtt] quic-gm handshake OK, cipher=%s\n", C.GoString(C.gmquic_cipher(h)))
	}

	return &quicGMConn{h: h}, nil
}

// quicGMConn 实现 io.ReadWriteCloser(cgo 桥接 Tongsuo QUIC API)
type quicGMConn struct {
	h unsafe.Pointer
}

func (c *quicGMConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n := C.gmquic_read(c.h, unsafe.Pointer(&p[0]), C.int(len(p)))
	if n == -2 {
		return 0, fmt.Errorf("quic-gm read timeout")
	}
	if n < 0 {
		return 0, fmt.Errorf("quic-gm read error")
	}
	if n == 0 {
		return 0, io.EOF
	}
	return int(n), nil
}

func (c *quicGMConn) Write(p []byte) (int, error) {
	n := C.gmquic_write(c.h, unsafe.Pointer(&p[0]), C.int(len(p)))
	if n < 0 {
		return 0, fmt.Errorf("quic-gm write error")
	}
	return int(n), nil
}

func (c *quicGMConn) Close() error {
	C.gmquic_close(c.h)
	return nil
}
