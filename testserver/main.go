package main

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

// 国密 wss 测试网关(手工 ws 握手 + 帧解析,兼容阻塞 TLCP 连接):
// gmwss 客户端 --TLCP--> 本服务器(ws 解帧) --> 明文 MQTT TCP --> 上游 broker
// 用法:
//   testserver -listen :18884 -sign-cert ... -sign-key ... -enc-cert ... -enc-key ... -upstream 127.0.0.1:1883

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func main() {
	listen := flag.String("listen", ":18884", "TLCP+ws 监听地址")
	upstream := flag.String("upstream", "127.0.0.1:1883", "上游明文 MQTT broker")
	cert := flag.String("cert", "", "标准 TLS 证书(可选)")
	key := flag.String("key", "", "标准 TLS 私钥")
	signCert := flag.String("sign-cert", "", "SM2 签名证书")
	signKey := flag.String("sign-key", "", "SM2 签名私钥")
	encCert := flag.String("enc-cert", "", "SM2 加密证书")
	encKey := flag.String("enc-key", "", "SM2 加密私钥")
	flag.Parse()

	raw, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		os.Exit(1)
	}
	ln, err := NewTLCPListener(raw, &ServerConfig{
		Cert:     *cert,
		Key:      *key,
		SignCert: *signCert,
		SignKey:  *signKey,
		EncCert:  *encCert,
		EncKey:   *encKey,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "TLCP listener: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[testserver] 监听 %s (TLCP+ws), 上游 %s\n", *listen, *upstream)

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "accept: %v\n", err)
			continue
		}
		go handle(conn, *upstream)
	}
}

func handle(conn net.Conn, upstream string) {
	defer conn.Close()

	// 1. ws 握手(在 TLCP 连接上读 HTTP 请求,回 101)
	if err := wsHandshake(conn); err != nil {
		fmt.Fprintf(os.Stderr, "ws handshake: %v\n", err)
		return
	}

	// 2. 连上游明文 MQTT
	up, err := net.DialTimeout("tcp", upstream, 10*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "upstream dial: %v\n", err)
		return
	}
	defer up.Close()

	// 3. 双向泵:客户端 ws 帧 payload <-> 上游 TCP 流
	done := make(chan struct{})
	go func() {
		for {
			payload, err := readFrame(conn)
			if err != nil {
				close(done)
				return
			}
			if _, err := up.Write(payload); err != nil {
				close(done)
				return
			}
		}
	}()
	buf := make([]byte, 4096)
	for {
		n, err := up.Read(buf)
		if n > 0 {
			writeFrame(conn, 0x2, buf[:n]) // binary frame
		}
		if err != nil {
			break
		}
	}
	<-done
}

// wsHandshake 手工完成 WebSocket 握手
func wsHandshake(rw io.ReadWriter) error {
	// 读请求头(直到空行)
	var reqBuf []byte
	tmp := make([]byte, 1)
	for {
		if _, err := io.ReadFull(rw, tmp); err != nil {
			return err
		}
		reqBuf = append(reqBuf, tmp[0])
		if len(reqBuf) >= 4 && string(reqBuf[len(reqBuf)-4:]) == "\r\n\r\n" {
			break
		}
		if len(reqBuf) > 65536 {
			return fmt.Errorf("request header too large")
		}
	}
	req := string(reqBuf)
	if !strings.Contains(req, "Upgrade: websocket") && !strings.Contains(req, "upgrade: websocket") {
		return fmt.Errorf("not a websocket upgrade request")
	}
	// 提取 Sec-WebSocket-Key
	var key string
	for _, line := range strings.Split(req, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "sec-websocket-key:") {
			key = strings.TrimSpace(line[18:])
			break
		}
	}
	if key == "" {
		return fmt.Errorf("no Sec-WebSocket-Key")
	}
	h := sha1.Sum([]byte(key + wsGUID))
	accept := base64.StdEncoding.EncodeToString(h[:])
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n" +
		"Sec-WebSocket-Protocol: mqtt\r\n\r\n"
	_, err := io.WriteString(rw, resp)
	return err
}

// readFrame 读一个 ws 帧并解掩码,返回 payload
func readFrame(r io.Reader) ([]byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	masked := h[1]&0x80 != 0
	length := uint64(h[1] & 0x7f)
	if length == 126 {
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	} else if length == 127 {
		var ext [8]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return nil, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(r, mask[:]); err != nil {
			return nil, err
		}
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return payload, nil
}

// writeFrame 写一个 ws 帧(服务端不掩码)
func writeFrame(w io.Writer, opcode byte, payload []byte) error {
	var h []byte
	h = append(h, 0x80|opcode)
	l := len(payload)
	switch {
	case l < 126:
		h = append(h, byte(l))
	case l < 65536:
		h = append(h, 126, byte(l>>8), byte(l))
	default:
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(l))
		h = append(h, 127)
		h = append(h, ext[:]...)
	}
	if _, err := w.Write(h); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}
