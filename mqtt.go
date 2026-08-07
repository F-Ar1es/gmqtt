package main

import (
	"errors"
	"fmt"
	"io"
)

// MQTTClient MQTT 客户端(测试用途:CONNECT/PUBLISH/SUBSCRIBE)
// 支持协议版本:3(MQTT 3.1)、4(MQTT 3.1.1)、5(MQTT 5.0)
type MQTTClient struct {
	conn    io.ReadWriteCloser
	id      string
	version int // 3 | 4 | 5
}

func encodeRemainingLength(n int) []byte {
	var out []byte
	for {
		b := byte(n % 128)
		n /= 128
		if n > 0 {
			b |= 0x80
		}
		out = append(out, b)
		if n == 0 {
			break
		}
	}
	return out
}

func readRemainingLength(r io.Reader) (int, error) {
	mult, val := 1, 0
	for i := 0; i < 4; i++ {
		var b [1]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, err
		}
		val += int(b[0]&0x7F) * mult
		if b[0]&0x80 == 0 {
			return val, nil
		}
		mult *= 128
	}
	return 0, errors.New("remaining length too long")
}

func readFull(r io.Reader, n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func (m *MQTTClient) writePacket(header byte, payload []byte) error {
	buf := []byte{header}
	buf = append(buf, encodeRemainingLength(len(payload))...)
	buf = append(buf, payload...)
	_, err := m.conn.Write(buf)
	return err
}

// Connect 发送 CONNECT 并等待 CONNACK
func (m *MQTTClient) Connect() error {
	var pl []byte
	switch m.version {
	case 3: // MQTT 3.1: 协议名 "MQIsdp", level 3
		pl = append(pl, 0x00, 0x06, 'M', 'Q', 'I', 's', 'd', 'p')
		pl = append(pl, 0x03)
	case 4: // MQTT 3.1.1
		pl = append(pl, 0x00, 0x04, 'M', 'Q', 'T', 'T')
		pl = append(pl, 0x04)
	case 5: // MQTT 5.0
		pl = append(pl, 0x00, 0x04, 'M', 'Q', 'T', 'T')
		pl = append(pl, 0x05)
	default:
		return fmt.Errorf("unsupported MQTT version %d", m.version)
	}
	pl = append(pl, 0x02)             // connect flags: clean session
	pl = append(pl, 0x00, 0x3C)       // keep alive 60s
	if m.version == 5 {
		pl = append(pl, 0x00) // properties length = 0
	}
	id := m.id
	pl = append(pl, byte(len(id)>>8), byte(len(id)))
	pl = append(pl, id...)

	if err := m.writePacket(0x10, pl); err != nil {
		return err
	}
	return m.readConnack()
}

func (m *MQTTClient) readConnack() error {
	var hdr [1]byte
	if _, err := io.ReadFull(m.conn, hdr[:]); err != nil {
		return err
	}
	if hdr[0] != 0x20 {
		return fmt.Errorf("unexpected packet 0x%02X, want CONNACK", hdr[0])
	}
	n, err := readRemainingLength(m.conn)
	if err != nil {
		return err
	}
	body, err := readFull(m.conn, n)
	if err != nil {
		return err
	}
	// body: ack flags(1) + reason/return code(1) [+ properties (v5)]
	reasonIdx := 1
	if m.version == 5 && len(body) > 2 {
		// v5: body[0]=ack flags, body[1]=reason code, body[2..]=properties(变长)
		// 只需 reason code,跳过 properties
	}
	_ = reasonIdx
	if len(body) < 2 {
		return errors.New("CONNACK too short")
	}
	rc := body[1]
	if rc != 0 {
		return fmt.Errorf("CONNACK failed, return code %d", rc)
	}
	return nil
}

// Publish 发送 QoS0 发布
func (m *MQTTClient) Publish(topic, payload string) error {
	var pl []byte
	pl = append(pl, byte(len(topic)>>8), byte(len(topic)))
	pl = append(pl, topic...)
	if m.version == 5 {
		pl = append(pl, 0x00) // properties length = 0
	}
	pl = append(pl, payload...)
	return m.writePacket(0x30, pl)
}

// Subscribe 发送 QoS0 订阅
func (m *MQTTClient) Subscribe(topic string) error {
	var pl []byte
	pl = append(pl, 0x00, 0x01) // packet id 1
	if m.version == 5 {
		pl = append(pl, 0x00) // properties length = 0
	}
	pl = append(pl, byte(len(topic)>>8), byte(len(topic)))
	pl = append(pl, topic...)
	pl = append(pl, 0x00) // requested QoS 0
	return m.writePacket(0x82, pl)
}

// ReadLoop 循环读取服务端消息并打印(SUBACK / PUBLISH / 其他)
func (m *MQTTClient) ReadLoop() error {
	for {
		var hdr [1]byte
		if _, err := io.ReadFull(m.conn, hdr[:]); err != nil {
			return err
		}
		n, err := readRemainingLength(m.conn)
		if err != nil {
			return err
		}
		body, err := readFull(m.conn, n)
		if err != nil {
			return err
		}
		switch hdr[0] >> 4 {
		case 3: // PUBLISH
			m.printPublish(body)
		case 9: // SUBACK
			fmt.Println("SUBACK ok")
		case 13: // PINGRESP
			// ignore
		default:
			// 其他报文忽略
		}
	}
}

// printPublish 解析并打印 PUBLISH(处理 v5 的 properties)
func (m *MQTTClient) printPublish(body []byte) {
	if len(body) < 4 {
		return
	}
	offset := 0
	tl := int(body[0])<<8 | int(body[1])
	offset += 2
	if len(body) < offset+tl {
		return
	}
	topic := string(body[offset : offset+tl])
	offset += tl
	if m.version == 5 {
		// 跳过 properties: 变长字节整数长度 + 内容
		pl, err := readRemainingLengthBytes(body[offset:])
		if err != nil {
			return
		}
		offset += pl
	}
	if offset > len(body) {
		return
	}
	payload := string(body[offset:])
	fmt.Printf("%s %s\n", topic, payload)
}

// readRemainingLengthBytes 从字节切片头部读变长整数,返回其总字节数(含长度字节)
func readRemainingLengthBytes(b []byte) (int, error) {
	mult, val, consumed := 1, 0, 0
	for i := 0; i < 4 && i < len(b); i++ {
		consumed++
		val += int(b[i]&0x7F) * mult
		if b[i]&0x80 == 0 {
			_ = val
			return consumed, nil
		}
		mult *= 128
	}
	return 0, errors.New("bad remaining length")
}
