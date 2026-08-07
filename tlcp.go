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

static SSL_CTX *gm_ctx_new(void) {
    return SSL_CTX_new(NTLS_client_method());
}

static int gm_load_ca(SSL_CTX *ctx, const char *f) {
    return SSL_CTX_load_verify_locations(ctx, f, NULL);
}

static void gm_errstr(char *buf, int len) {
    unsigned long e = ERR_get_error();
    if (e == 0) {
        snprintf(buf, len, "no error");
        return;
    }
    ERR_error_string_n(e, buf, len);
}

static int gm_load_certs(SSL_CTX *ctx,
        const char *sc, const char *sk,
        const char *ec, const char *ek) {
    if (sc && SSL_CTX_use_sign_certificate_file(ctx, sc, SSL_FILETYPE_PEM) != 1) return -1;
    if (sk && SSL_CTX_use_sign_PrivateKey_file(ctx, sk, SSL_FILETYPE_PEM) != 1) return -2;
    if (ec && SSL_CTX_use_enc_certificate_file(ctx, ec, SSL_FILETYPE_PEM) != 1) return -3;
    if (ek && SSL_CTX_use_enc_PrivateKey_file(ctx, ek, SSL_FILETYPE_PEM) != 1) return -4;
    return 0;
}
*/
import "C"

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"
	"unsafe"
)

// TLCPConfig 国密 TLCP 连接配置
type TLCPConfig struct {
	CAFile   string // SM2 根 CA,验证服务器证书链
	SignCert string // 双向认证:签名证书
	SignKey  string // 双向认证:签名私钥
	EncCert  string // 双向认证:加密证书
	EncKey   string // 双向认证:加密私钥
}

// TLCPConn 基于 Tongsuo NTLS 的 net.Conn 实现
type TLCPConn struct {
	ssl *C.SSL
	ctx *C.SSL_CTX
	raw net.Conn
}

// TLCPDial 建立到 addr 的 TLCP 加密连接(发 NTLS ClientHello)
func TLCPDial(addr string, cfg *TLCPConfig, timeout time.Duration) (*TLCPConn, error) {
	raw, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("tcp dial: %w", err)
	}

	ctx := C.gm_ctx_new()
	if ctx == nil {
		raw.Close()
		return nil, errors.New("SSL_CTX_new(NTLS_client_method) failed")
	}

	if cfg.CAFile != "" {
		cf := C.CString(cfg.CAFile)
		r := C.gm_load_ca(ctx, cf)
		C.free(unsafe.Pointer(cf))
		if r != 1 {
			raw.Close()
			C.SSL_CTX_free(ctx)
			return nil, errors.New("load CA file failed")
		}
	}

	var sc, sk, ec, ek *C.char
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
	r := C.gm_load_certs(ctx, sc, sk, ec, ek)
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
	if r != 0 {
		raw.Close()
		C.SSL_CTX_free(ctx)
		return nil, fmt.Errorf("load sign/enc certificates failed (code %d)", int(r))
	}

	ssl := C.SSL_new(ctx)
	if ssl == nil {
		raw.Close()
		C.SSL_CTX_free(ctx)
		return nil, errors.New("SSL_new failed")
	}
	C.SSL_enable_ntls(ssl)

	tc, ok := raw.(*net.TCPConn)
	if !ok {
		raw.Close()
		C.SSL_free(ssl)
		C.SSL_CTX_free(ctx)
		return nil, errors.New("underlying conn is not TCP")
	}
	sc2, err := tc.SyscallConn()
	if err != nil {
		raw.Close()
		C.SSL_free(ssl)
		C.SSL_CTX_free(ctx)
		return nil, fmt.Errorf("SyscallConn: %w", err)
	}
	var fd C.int
	ctrlErr := sc2.Control(func(f uintptr) {
		fd = C.int(f)
		C.set_blocking(fd)
	})
	if ctrlErr != nil {
		raw.Close()
		C.SSL_free(ssl)
		C.SSL_CTX_free(ctx)
		return nil, fmt.Errorf("get fd: %w", ctrlErr)
	}
	if C.SSL_set_fd(ssl, fd) != 1 {
		raw.Close()
		C.SSL_free(ssl)
		C.SSL_CTX_free(ctx)
		return nil, errors.New("SSL_set_fd failed")
	}

	if C.SSL_connect(ssl) != 1 {
		gerr := C.SSL_get_error(ssl, -1)
		var ebuf [256]C.char
		C.gm_errstr(&ebuf[0], 256)
		msg := fmt.Sprintf("TLCP handshake failed (SSL_connect): ssl_error=%d, err=%s", int(gerr), C.GoString(&ebuf[0]))
		raw.Close()
		C.SSL_free(ssl)
		C.SSL_CTX_free(ctx)
		return nil, errors.New(msg)
	}

	return &TLCPConn{ssl: ssl, ctx: ctx, raw: raw}, nil
}

func (c *TLCPConn) Read(p []byte) (int, error) {
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

func (c *TLCPConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n := C.SSL_write(c.ssl, unsafe.Pointer(&p[0]), C.int(len(p)))
	if n > 0 {
		return int(n), nil
	}
	return 0, fmt.Errorf("SSL_write error %d", int(C.SSL_get_error(c.ssl, n)))
}

func (c *TLCPConn) Close() error {
	C.SSL_shutdown(c.ssl)
	C.SSL_free(c.ssl)
	C.SSL_CTX_free(c.ctx)
	return c.raw.Close()
}

func (c *TLCPConn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *TLCPConn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *TLCPConn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *TLCPConn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *TLCPConn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }
