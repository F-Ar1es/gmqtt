package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// quicDial 建立 MQTT over QUIC 连接
// 写:用一条双向流承载 MQTT 请求报文(CONNECT/PUBLISH/SUBSCRIBE)
// 读:合并初始流 + 服务器推送的新流(双向/单向)数据
func quicDial(o *options) (io.ReadWriteCloser, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	tlsConf := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"mqtt"}}
	if o.caFile != "" {
		tc, err := tlsConfig(o)
		if err != nil {
			return nil, err
		}
		tc.NextProtos = []string{"mqtt"}
		tlsConf = tc
	}

	if o.verbose {
		fmt.Printf("[gmqtt] quic dial %s\n", net.JoinHostPort(o.host, o.port))
	}

	conn, err := quic.DialAddr(ctx, net.JoinHostPort(o.host, o.port), tlsConf, &quic.Config{
		MaxIdleTimeout: 2 * time.Minute,
	})
	if err != nil {
		return nil, fmt.Errorf("quic dial: %w", err)
	}

	writeStream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		_ = conn.CloseWithError(0, "open stream failed")
		return nil, fmt.Errorf("quic open stream: %w", err)
	}

	// 读侧:合并所有流
	reader := newMergedReader()
	ctx2 := context.Background()

	// pump 单个流到 mergedReader
	pump := func(s io.Reader) {
		buf := make([]byte, 8192)
		for {
			n, err := s.Read(buf)
			if n > 0 {
				reader.add(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}
	go pump(writeStream) // 初始双向流(请求/响应)

	// accept 服务器推送的新流
	go func() {
		for {
			s, err := conn.AcceptStream(ctx2)
			if err != nil {
				return
			}
			go pump(s)
			us, err := conn.AcceptUniStream(ctx2)
			if err != nil {
				return
			}
			go pump(us)
		}
	}()

	return &quicConn{conn: conn, writeStream: writeStream, reader: reader}, nil
}

// quicConn 实现 io.ReadWriteCloser(写=初始双向流,读=合并流)
type quicConn struct {
	conn        *quic.Conn
	writeStream *quic.Stream
	reader      *mergedReader
	writeMu     sync.Mutex
}

func (c *quicConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func (c *quicConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	n, err := c.writeStream.Write(p)
	return n, err
}

func (c *quicConn) Close() error {
	_ = c.writeStream.Close()
	_ = c.conn.CloseWithError(0, "bye")
	return nil
}

// mergedReader 多流数据合并为单读流
type mergedReader struct {
	mu   sync.Mutex
	cond *sync.Cond
	bufs [][]byte
	idx  int
	done bool
}

func newMergedReader() *mergedReader {
	m := &mergedReader{}
	m.cond = sync.NewCond(&m.mu)
	return m
}

func (m *mergedReader) add(b []byte) {
	m.mu.Lock()
	cp := make([]byte, len(b))
	copy(cp, b)
	m.bufs = append(m.bufs, cp)
	m.cond.Signal()
	m.mu.Unlock()
}

func (m *mergedReader) Read(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for {
		if len(m.bufs) > 0 {
			b := m.bufs[0]
			if m.idx >= len(b) {
				m.bufs = m.bufs[1:]
				m.idx = 0
				continue
			}
			n := copy(p, b[m.idx:])
			m.idx += n
			if m.idx >= len(b) {
				m.bufs = m.bufs[1:]
				m.idx = 0
			}
			return n, nil
		}
		if m.done {
			return 0, io.EOF
		}
		m.cond.Wait()
	}
}
