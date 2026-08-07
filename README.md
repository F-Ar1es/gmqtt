# gmqtt v0.3.0 — 国密 MQTT 全连接方式测试套件

支持 **标准 TLS / 国密 TLCP / QUIC / 国密 QUIC** 的 MQTT 命令行测试工具。

## 本版本新增

- **`-s quic-gm`(国密 QUIC)**:QUICv1 传输 + TLS 1.3 国密套件 `TLS_SM4_GCM_SM3`(SM2 证书 + SM4-GCM 加密 + SM3 哈希)
- **`gmquic-server`**:国密 QUIC → 明文 MQTT 代理(模拟真实部署:QUIC 国密边缘 → 后端 broker)
- **`gmquic-client`**:国密 QUIC 命令行客户端
- **Tongsuo 8.5.0-pre2 国密 QUIC patch**(`patches/`):放开 QUIC 套件白名单 + record layer SM4 支持(5 处修改)

## 连接方式矩阵(9 种)

| `-s` | 传输 | 端口 | 需要 |
|---|---|---|---|
| `mqtt` | 明文 TCP | 1883 | — |
| `mqtts` | 标准 TLS | 8883 | `--cafile` |
| `tlcp` | 国密 TLCP | 8884 | `--cafile`(SM2 CA) |
| `ws` | 明文 WebSocket | 8083 | `-ws-path /mqtt` |
| `wss` | TLS+WS | 8084 | `--cafile` |
| `gmwss` | 国密 TLCP+WS | 自定义 | `--cafile`(SM2 CA) |
| `quic` | MQTT over QUIC | 14567 | `--cafile`(可选) |
| **`quic-gm`** | **国密 QUIC** | 4433 | `--cafile` + `--sign-cert/--sign-key`(SM2) |

## 国密 QUIC 快速开始

```bash
# 1. 启动国密 QUIC → MQTT 代理(终止国密 QUIC,后端明文连 broker)
./gmquic-server -p 4433 -cert certs/server-sign.crt -key certs/server-sign.key \
  -upstream 192.168.1.148 -upstream-port 1883

# 2. 客户端(国密 QUIC)
./gmqtt conn -s quic-gm -h <host> -p 4433 \
  --cafile certs/sm2-root-ca.crt \
  --sign-cert certs/server-sign.crt --sign-key certs/server-sign.key

# 3. pub / sub
./gmqtt pub -s quic-gm -h <host> -p 4433 --cafile certs/sm2-root-ca.crt \
  --sign-cert certs/server-sign.crt --sign-key certs/server-sign.key \
  -t "test/topic" -m "hello"
./gmqtt sub -s quic-gm -h <host> -p 4433 --cafile certs/sm2-root-ca.crt \
  --sign-cert certs/server-sign.crt --sign-key certs/server-sign.key -t "test/topic"
```

## 部署模型

```
[MQTT 客户端] --国密 QUIC(UDP, TLS_SM4_GCM_SM3)--> [gmquic-server] --TCP 明文--> [EMQX/RS]
     gmqtt -s quic-gm                              (SM2 证书终止)          (broker 集群)
```

国密 QUIC 边缘节点负责加解密,后端保持标准 MQTT,broker 无需改造。

## 国密 QUIC 说明

- 基于 Tongsuo 8.5.0-pre2(QUIC + TLS1.3 国密套件),patch 见 `patches/tongsuo-8.5-gmquic/`
- 客户端/服务端需使用**打了 patch 的 Tongsuo 8.5**(8.4 无 QUIC)
- 证书为实验样例,生产请用自有 CA
- 性能:QUIC 0-RTT/1-RTT、多路复用、抗丢包(QUIC 原生特性)

## 其他连接方式

```bash
./gmqtt pub -s tlcp -h host -p 8884 --cafile certs/sm2-root-ca.crt -t t -m m
./gmqtt pub -s mqtts -h host -p 8883 --cafile certs/rsa-root-ca.crt -t t -m m
./gmqtt pub -s quic -h host -p 14567 -t t -m m
```

## 构建

gmqtt:cgo 链接 Tongsuo 8.5(头文件/静态库),`CGO_ENABLED=1 go build`
gmquic:`gcc server.c client.c -lssl -lcrypto -ldl -lpthread`

## 许可

- gmqtt 源码 Apache-2.0;Tongsuo Apache-2.0(含国密算法);gorilla/websocket BSD-3
