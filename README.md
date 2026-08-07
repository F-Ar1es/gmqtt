# gmqtt — 国密 MQTT 命令行测试客户端

支持 **标准 TLS / 国密 TLCP** 的 MQTT 命令行测试工具,单静态二进制覆盖 6 种连接方式、3 种 MQTT 协议版本。

## 特性

- **7 种连接方式**:`mqtt`(明文)、`mqtts`(标准 TLS)、`tlcp`(国密 TLCP)、`ws`(WebSocket)、`wss`(TLS+WS)、`gmwss`(国密 TLCP+WS)、`quic`(QUIC, UDP)
- **3 种协议版本**:MQTT 3.1 / 3.1.1 / 5.0
- **国密支持**:基于 Tongsuo 8.4.0(静态链接),SM2 双证书 + NTLS
- **跨架构**:amd64 / arm64 静态二进制,无运行时依赖
- 附带 `testserver`:国密 wss 测试网关(供本地验证 gmwss)

## 快速开始

```bash
# 发布(标准 TLS)
./bin/amd64/gmqtt pub -s mqtts -h broker.example.com -p 8883 \
  --cafile certs/rsa-root-ca.crt -t "test/topic" -m "hello"

# 订阅(国密 TLCP)
./bin/amd64/gmqtt sub -s tlcp -h 192.168.1.162 -p 8884 \
  --cafile certs/sm2-root-ca.crt -t "test/topic"

# WebSocket + 国密
./bin/amd64/gmqtt conn -s gmwss -h 127.0.0.1 -p 18884 \
  --cafile certs/sm2-root-ca.crt
```

## 连接方式矩阵

| `-s` | 传输 | 典型端口 | 需要 |
|---|---|---|---|
| `mqtt` | 明文 TCP | 1883 | — |
| `mqtts` | 标准 TLS | 8883 | `--cafile`(RSA CA) |
| `tlcp` | 国密 TLCP | 8884 | `--cafile`(SM2 CA) |
| `ws` | 明文 WebSocket | 8083 | `-ws-path /mqtt` |
| `wss` | TLS + WebSocket | 8084 | `--cafile` + `-ws-path /mqtt` |
| `gmwss` | 国密 TLCP + WebSocket | 自定义 | `--cafile`(SM2 CA) |
| `quic` | MQTT over QUIC(UDP) | 14567 | `--cafile`(可选) |

## 全部参数

```
gmqtt pub|sub|conn -s <scheme> -h <host> -p <port> [选项]

  -s <scheme>        连接方式 mqtt|mqtts|tlcp|ws|wss|gmwss|quic(默认 mqtt)
  -h <host>          主机(默认 127.0.0.1)
  -p <port>          端口(默认 1883)
  -t <topic>         主题(pub/sub 必需)
  -m <message>       消息(pub)
  -id <client-id>    客户端 ID(默认 gmqtt-test)
  -mqtt-version <n>  MQTT 版本 3|4|5(默认 4)
  -cafile <file>     CA 证书(mqtts 用 RSA CA;tlcp/gmwss 用 SM2 CA)
  -sign-cert/-sign-key   双向认证:SM2 签名证书/私钥(可选)
  -enc-cert/-enc-key     双向认证:SM2 加密证书/私钥(可选)
  -servername <name> TLS SNI / 主机名校验(默认取 -h)
  -ws-path <path>    WebSocket 路径(默认 /mqtt)
  -v                 详细输出
```

## 双向认证示例(客户端证书)

```bash
./gmqtt pub -s tlcp -h host -p 8884 \
  --cafile sm2-root-ca.crt \
  --sign-cert client-sign.crt --sign-key client-sign.key \
  --enc-cert client-enc.crt --enc-key client-enc.key \
  -t "topic" -m "msg"
```

## 国密 wss 本地测试(testserver)

```bash
# 启动国密 wss 测试网关(TLCP+ws → 明文 MQTT broker)
./testserver -listen :18884 -upstream 127.0.0.1:1883 \
  -sign-cert server-sign.crt -sign-key server-sign.key \
  -enc-cert server-enc.crt -enc-key server-enc.key

# 用 gmqtt 连接
./gmqtt conn -s gmwss -h 127.0.0.1 -p 18884 --cafile sm2-root-ca.crt
```

## MQTT over QUIC

标准 MQTT over QUIC(EMQX 5.8+ 原生 quic listener,默认 14567):

```bash
# 服务器:EMQX 启用 quic listener
#   listeners.quic.default { bind = "0.0.0.0:14567" }

# 客户端
./gmqtt conn -s quic -h broker-host -p 14567
./gmqtt pub -s quic -h broker-host -p 14567 -t "topic" -m "msg"
./gmqtt sub -s quic -h broker-host -p 14567 -t "topic"
```

说明:QUIC 传输基于 quic-go,服务器推送经新流接收(已实现多流合并);国密 QUIC 需 Tongsuo 支持(8.4.0 暂无 QUIC),列为远期方向。

## 从源码构建

需要:Go 1.21+,Tongsuo 8.4.0 静态库(含 NTLS 头文件),gcc(CGO)。

```bash
# 在装有 Tongsuo 的环境(头文件在 /opt/tongsuo/include,/opt/tongsuo/lib)
CGO_ENABLED=1 go build -o gmqtt .
CGO_ENABLED=1 go build -o testserver ./testserver
```

## 证书说明

- `certs/` 下的证书为**实验环境样例**(仅测试用),生产请使用自己的 CA 与证书
- 私钥文件不随发布包分发,请自行保管

## 许可

- gmqtt 源码:Apache-2.0
- 静态链接 Tongsuo(Apache-2.0):国密算法与 NTLS 支持
- 依赖:gorilla/websocket(BSD-3)
