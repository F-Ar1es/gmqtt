package main

/*
#cgo CFLAGS: -I/opt/tongsuo/include
#cgo LDFLAGS: /opt/tongsuo/lib/libssl.a /opt/tongsuo/lib/libcrypto.a -ldl -lpthread

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

static void set_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
}

// 服务端:NTLS 方法 + 双证书加载 + ctx 级启用 NTLS(可同时接受 TLS 与 TLCP)
static SSL_CTX *gm_server_ctx_new(void) {
    return SSL_CTX_new(NTLS_server_method());
}

static int gm_server_load(SSL_CTX *ctx,
        const char *cert, const char *key,
        const char *sc, const char *sk,
        const char *ec, const char *ek) {
    if (cert && SSL_CTX_use_certificate_chain_file(ctx, cert) != 1) return -1;
    if (key && SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1) return -2;
    if (sc && SSL_CTX_use_sign_certificate_file(ctx, sc, SSL_FILETYPE_PEM) != 1) return -3;
    if (sk && SSL_CTX_use_sign_PrivateKey_file(ctx, sk, SSL_FILETYPE_PEM) != 1) return -4;
    if (ec && SSL_CTX_use_enc_certificate_file(ctx, ec, SSL_FILETYPE_PEM) != 1) return -5;
    if (ek && SSL_CTX_use_enc_PrivateKey_file(ctx, ek, SSL_FILETYPE_PEM) != 1) return -6;
    return 0;
}

static int gm_accept(SSL *ssl) {
    return SSL_accept(ssl);
}
*/
import "C"

import (
	"fmt"
	"io"
	"net"
	"time"
	"unsafe"
)

// ServerConfig 服务端证书配置
type ServerConfig struct {
	Cert     string // 标准 TLS 证书(可选)
	Key      string
	SignCert string // SM2 签名证书
	SignKey  string
	EncCert  string // SM2 加密证书
	EncKey   string
}

// TLCPListener 接受 TLCP 连接的 net.Listener 包装
type TLCPListener struct {
	raw net.Listener
	ctx *C.SSL_CTX
}

// NewTLCPListener 创建监听器(raw 应为已监听端口的 TCP listener)
func NewTLCPListener(raw net.Listener, cfg *ServerConfig) (*TLCPListener, error) {
	ctx := C.gm_server_ctx_new()
	if ctx == nil {
		return nil, fmt.Errorf("server SSL_CTX_new(NTLS_server_method) failed")
	}
	var cert, key, sc, sk, ec, ek *C.char
	if cfg.Cert != "" {
		cert = C.CString(cfg.Cert)
	}
	if cfg.Key != "" {
		key = C.CString(cfg.Key)
	}
	if cfg.SignCert != "" {
		sc = C.CString(cfg.SignCert)
	}
	if cfg.SignKey != "" {
		sk = C.CString(cfg.SignKey)
	}
	if cfg.EncCert != "" {
		ec = C.CString(cfg.EncCert)
	}
	if cfg.EncKey != "" {
		ek = C.CString(cfg.EncKey)
	}
	r := C.gm_server_load(ctx, cert, key, sc, sk, ec, ek)
	freeAll := func() {
		if cert != nil {
			C.free(unsafe.Pointer(cert))
		}
		if key != nil {
			C.free(unsafe.Pointer(key))
		}
		if sc != nil {
			C.free(unsafe.Pointer(sc))
		}
		if sk != nil {
			C.free(unsafe.Pointer(sk))
		}
		if ec != nil {
			C.free(unsafe.Pointer(ec))
		}
		if ek != nil {
			C.free(unsafe.Pointer(ek))
		}
	}
	freeAll()
	if r != 0 {
		C.SSL_CTX_free(ctx)
		return nil, fmt.Errorf("server cert load failed (code %d)", int(r))
	}
	C.SSL_CTX_enable_ntls(ctx) // 服务端同时接受 TLS 与 TLCP
	return &TLCPListener{raw: raw, ctx: ctx}, nil
}

func (l *TLCPListener) Accept() (net.Conn, error) {
	raw, err := l.raw.Accept()
	if err != nil {
		return nil, err
	}
	tc, ok := raw.(*net.TCPConn)
	if !ok {
		raw.Close()
		return nil, fmt.Errorf("not TCP")
	}
	sc2, err := tc.SyscallConn()
	if err != nil {
		raw.Close()
		return nil, err
	}
	var fd C.int
	ctrlErr := sc2.Control(func(f uintptr) {
		fd = C.int(f)
		C.set_blocking(fd)
	})
	if ctrlErr != nil {
		raw.Close()
		return nil, ctrlErr
	}
	ssl := C.SSL_new(l.ctx)
	if ssl == nil {
		raw.Close()
		return nil, fmt.Errorf("SSL_new failed")
	}
	if C.SSL_set_fd(ssl, fd) != 1 {
		C.SSL_free(ssl)
		raw.Close()
		return nil, fmt.Errorf("SSL_set_fd failed")
	}
	if C.gm_accept(ssl) != 1 {
		C.SSL_free(ssl)
		raw.Close()
		return nil, fmt.Errorf("TLCP accept (SSL_accept) failed")
	}
	return &ServerConn{ssl: ssl, raw: raw}, nil
}

func (l *TLCPListener) Close() error   { return l.raw.Close() }
func (l *TLCPListener) Addr() net.Addr { return l.raw.Addr() }

// ServerConn 服务端 TLCP 连接
type ServerConn struct {
	ssl *C.SSL
	raw net.Conn
}

func (c *ServerConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n := C.SSL_read(c.ssl, unsafe.Pointer(&p[0]), C.int(len(p)))
	if n > 0 {
		return int(n), nil
	}
	e := C.SSL_get_error(c.ssl, n)
	if e == C.SSL_ERROR_ZERO_RETURN {
		return 0, io.EOF
	}
	return 0, fmt.Errorf("SSL_read error %d", int(e))
}

func (c *ServerConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n := C.SSL_write(c.ssl, unsafe.Pointer(&p[0]), C.int(len(p)))
	if n > 0 {
		return int(n), nil
	}
	return 0, fmt.Errorf("SSL_write error %d", int(C.SSL_get_error(c.ssl, n)))
}

func (c *ServerConn) Close() error {
	C.SSL_shutdown(c.ssl)
	C.SSL_free(c.ssl)
	return c.raw.Close()
}

func (c *ServerConn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *ServerConn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *ServerConn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *ServerConn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *ServerConn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }
