package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/gorilla/websocket"
)

const usageText = `gmqtt — 国密 MQTT 命令行测试客户端(支持 mqtt/mqtts/tlcp/ws/wss/gmwss)

用法:
  gmqtt pub -s <scheme> -h <host> -p <port> -t <topic> -m <message> [选项]
  gmqtt sub -s <scheme> -h <host> -p <port> -t <topic> [选项]
  gmqtt conn -s <scheme> -h <host> -p <port> [选项]        # 仅连接+CONNECT

连接方式(-s):
  mqtt    明文 MQTT(TCP)
  mqtts   标准 TLS MQTT
  tlcp    国密 TLCP MQTT
  ws      MQTT over WebSocket(明文)
  wss     MQTT over WebSocket + 标准 TLS
  gmwss   MQTT over WebSocket + 国密 TLCP

证书选项:
  -cafile <file>       CA 证书(验证服务器;mqtts 用 RSA CA,tlcp/gmwss 用 SM2 CA)
  -sign-cert/-sign-key  双向认证:SM2 签名证书/私钥(可选)
  -enc-cert/-enc-key    双向认证:SM2 加密证书/私钥(可选)
  -servername <name>   TLS SNI/主机名校验(可选)
  -ws-path <path>      WebSocket 路径(默认 /mqtt)
  -id <client-id>      客户端 ID(默认 gmqtt-test)
  -mqtt-version <n>    MQTT 协议版本: 3(3.1) / 4(3.1.1) / 5(5.0)(默认 4)
  -v                   显示连接细节
`

type options struct {
	scheme     string
	host       string
	port       string
	topic      string
	message    string
	clientID   string
	wsPath     string
	serverName string
	version    int
	verbose    bool

	caFile   string
	signCert string
	signKey  string
	encCert  string
	encKey   string
}

func parseOpts(args []string) (*options, error) {
	fs := flag.NewFlagSet("gmqtt", flag.ExitOnError)
	o := &options{}
	fs.StringVar(&o.scheme, "s", "mqtt", "连接方式")
	fs.StringVar(&o.host, "h", "127.0.0.1", "主机")
	fs.StringVar(&o.port, "p", "1883", "端口")
	fs.StringVar(&o.topic, "t", "", "主题")
	fs.StringVar(&o.message, "m", "", "消息(pub)")
	fs.StringVar(&o.clientID, "id", "gmqtt-test", "客户端 ID")
	fs.StringVar(&o.wsPath, "ws-path", "/mqtt", "WebSocket 路径")
	fs.StringVar(&o.serverName, "servername", "", "TLS SNI")
	fs.IntVar(&o.version, "mqtt-version", 4, "MQTT 协议版本 3/4/5")
	fs.BoolVar(&o.verbose, "v", false, "详细输出")
	fs.StringVar(&o.caFile, "cafile", "", "CA 证书")
	fs.StringVar(&o.signCert, "sign-cert", "", "SM2 签名证书")
	fs.StringVar(&o.signKey, "sign-key", "", "SM2 签名私钥")
	fs.StringVar(&o.encCert, "enc-cert", "", "SM2 加密证书")
	fs.StringVar(&o.encKey, "enc-key", "", "SM2 加密私钥")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return o, nil
}

func dial(o *options) (io.ReadWriteCloser, error) {
	addr := net.JoinHostPort(o.host, o.port)
	tlcpCfg := &TLCPConfig{
		CAFile:   o.caFile,
		SignCert: o.signCert,
		SignKey:  o.signKey,
		EncCert:  o.encCert,
		EncKey:   o.encKey,
	}
	if o.verbose {
		fmt.Printf("[gmqtt] dial %s://%s\n", o.scheme, addr)
	}
	switch o.scheme {
	case "mqtt":
		return net.DialTimeout("tcp", addr, 10*time.Second)
	case "mqtts":
		return tlsDial(addr, o)
	case "tlcp":
		return TLCPDial(addr, tlcpCfg, 10*time.Second)
	case "ws", "wss", "gmwss":
		return wsDial(o)
	case "quic":
		return quicDial(o)
	default:
		return nil, fmt.Errorf("unknown scheme %q", o.scheme)
	}
}

func tlsConfig(o *options) (*tls.Config, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if o.caFile != "" {
		pem, err := os.ReadFile(o.caFile)
		if err != nil {
			return nil, err
		}
		pool.AppendCertsFromPEM(pem)
	}
	serverName := o.serverName
	if serverName == "" {
		serverName = o.host
	}
	return &tls.Config{RootCAs: pool, ServerName: serverName}, nil
}

func tlsDial(addr string, o *options) (net.Conn, error) {
	tc, err := tlsConfig(o)
	if err != nil {
		return nil, err
	}
	return tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr, tc)
}

// wsConn 把 gorilla websocket.Conn 包装成 io.ReadWriteCloser
// (gorilla 的 Conn 没有公开 Read/Write,需要按帧读写)
type wsConn struct {
	c *websocket.Conn
	r io.Reader
}

func (w *wsConn) Read(p []byte) (int, error) {
	for {
		if w.r == nil {
			_, r, err := w.c.NextReader()
			if err != nil {
				return 0, err
			}
			w.r = r
		}
		n, err := w.r.Read(p)
		if err == io.EOF {
			w.r = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

func (w *wsConn) Write(p []byte) (int, error) {
	wc, err := w.c.NextWriter(websocket.BinaryMessage)
	if err != nil {
		return 0, err
	}
	n, err := wc.Write(p)
	if err == nil {
		err = wc.Close()
	}
	return n, err
}

func (w *wsConn) Close() error                       { return w.c.Close() }
func (w *wsConn) LocalAddr() net.Addr                { return w.c.LocalAddr() }
func (w *wsConn) RemoteAddr() net.Addr               { return w.c.RemoteAddr() }
func (w *wsConn) SetDeadline(t time.Time) error {
	if err := w.c.SetReadDeadline(t); err != nil {
		return err
	}
	return w.c.SetWriteDeadline(t)
}
func (w *wsConn) SetReadDeadline(t time.Time) error  { return w.c.SetReadDeadline(t) }
func (w *wsConn) SetWriteDeadline(t time.Time) error { return w.c.SetWriteDeadline(t) }

func wsDial(o *options) (net.Conn, error) {
	d := websocket.Dialer{HandshakeTimeout: 10 * time.Second, Subprotocols: []string{"mqtt"}}
	if o.scheme == "wss" {
		tc, err := tlsConfig(o)
		if err != nil {
			return nil, err
		}
		d.TLSClientConfig = tc
	}
	if o.scheme == "gmwss" {
		tlcpCfg := &TLCPConfig{
			CAFile:   o.caFile,
			SignCert: o.signCert,
			SignKey:  o.signKey,
			EncCert:  o.encCert,
			EncKey:   o.encKey,
		}
		d.NetDial = func(network, addr string) (net.Conn, error) {
			return TLCPDial(addr, tlcpCfg, 10*time.Second)
		}
	}
	u := "ws://" + net.JoinHostPort(o.host, o.port) + o.wsPath
	if o.scheme == "wss" {
		u = "wss://" + net.JoinHostPort(o.host, o.port) + o.wsPath
	}
	if o.verbose {
		fmt.Printf("[gmqtt] ws dial %s\n", u)
	}
	c, resp, err := d.Dial(u, nil)
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("ws dial: %v (HTTP %s)", err, resp.Status)
		}
		return nil, fmt.Errorf("ws dial: %v", err)
	}
	return &wsConn{c: c}, nil
}

func runConn(args []string) error {
	o, err := parseOpts(args)
	if err != nil {
		return err
	}
	conn, err := dial(o)
	if err != nil {
		return err
	}
	defer conn.Close()
	mc := &MQTTClient{conn: conn, id: o.clientID, version: o.version}
	if err := mc.Connect(); err != nil {
		return err
	}
	fmt.Println("CONNECT OK")
	return nil
}

func runPub(args []string) error {
	o, err := parseOpts(args)
	if err != nil {
		return err
	}
	if o.topic == "" {
		return fmt.Errorf("pub 需要 -t topic")
	}
	if o.message == "" && len(args) == 0 {
		return fmt.Errorf("pub 需要 -m message")
	}
	conn, err := dial(o)
	if err != nil {
		return err
	}
	defer conn.Close()
	mc := &MQTTClient{conn: conn, id: o.clientID, version: o.version}
	if err := mc.Connect(); err != nil {
		return err
	}
	if err := mc.Publish(o.topic, o.message); err != nil {
		return err
	}
	fmt.Printf("PUBLISH OK -> %s\n", o.topic)
	return nil
}

func runSub(args []string) error {
	o, err := parseOpts(args)
	if err != nil {
		return err
	}
	if o.topic == "" {
		return fmt.Errorf("sub 需要 -t topic")
	}
	conn, err := dial(o)
	if err != nil {
		return err
	}
	defer conn.Close()
	mc := &MQTTClient{conn: conn, id: o.clientID, version: o.version}
	if err := mc.Connect(); err != nil {
		return err
	}
	if err := mc.Subscribe(o.topic); err != nil {
		return err
	}
	fmt.Printf("SUBSCRIBED %s (等待消息, Ctrl-C 退出)\n", o.topic)
	return mc.ReadLoop()
}

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usageText)
		os.Exit(1)
	}
	cmd := os.Args[1]
	args := os.Args[2:]
	var err error
	switch cmd {
	case "pub":
		err = runPub(args)
	case "sub":
		err = runSub(args)
	case "conn":
		err = runConn(args)
	default:
		fmt.Print(usageText)
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		os.Exit(1)
	}
}
