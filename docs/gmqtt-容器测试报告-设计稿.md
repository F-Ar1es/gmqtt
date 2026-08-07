# gmqtt 九种连接方式容器复现 — 测试报告(设计稿)

> 状态:**待确认**。确认后按本报告在容器环境执行复现,采集验证日志。

---

## 1. 测试目的

在**本地容器环境**中,复现 gmqtt 客户端支持的**全部连接方式**,验证:

- 每种连接方式的**握手/协商结果**(协议版本、套件)
- MQTT 业务语义(**CONNECT / SUBSCRIBE / PUBLISH**)是否端到端打通
- 国密链路(TLCP / 国密 QUIC / 国密 wss)的**加密套件正确性**

> 说明:gmqtt 客户端实际支持 **8 种连接方式**(见 §4 矩阵)。第 9 种若指
> `gmquic-client`(独立国密 QUIC 工具)或 testserver 服务端,可一并覆盖;
> 若你有具体的第 9 种定义,请指出,报告按 9 种调整。

## 2. 测试环境拓扑(容器)

```
┌─────────────────────────── 本机 (Apple Silicon / arm64) ───────────────────────────┐
│                                                                                     │
│  ┌─ emqx-test 容器 (192.168.64.13) ─────────────────────────────┐                  │
│  │  EMQX 5.8.9                                                   │                  │
│  │  ├─ tcp:default  :1883  (明文 MQTT)                           │                  │
│  │  ├─ ssl:default  :8883  (标准 TLS, RSA 证书)                  │                  │
│  │  ├─ ws:default   :8083  (WebSocket)                           │                  │
│  │  ├─ wss:default  :8084  (TLS + WebSocket)                     │                  │
│  │  └─ quic:default :14567 (MQTT over QUIC)                      │                  │
│  └────────────────────────────────────────────────────────────────┘                  │
│                        ▲ ▲ ▲                                                       │
│          TCP 明文 转发  │ │ │(代理终止国密,后端明文连 EMQX)                        │
│                        │ │ │                                                       │
│  ┌─ gmqtt-tools 容器 ──┴─┴─┴────────────────────────────────────┐                 │
│  │  gmquic-server :4433  国密 QUIC → TCP(quic-gm)               │                 │
│  │  tlcp-server   :8884  TLCP(NTLS)→ TCP(tlcp)                  │                 │
│  │  testserver    :18884 TLCP+WebSocket → TCP(gmwss)            │                 │
│  │  客户端:gmqtt(arm64)+ 证书(/opt/certs)                        │                 │
│  └────────────────────────────────────────────────────────────────┘                 │
│                                                                                     │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

**部署模型**:国密通道在边缘(代理)终止并转发为明文 MQTT 到 broker,broker 零改造——
与生产旁挂方案一致。

## 3. 测试前置

| 项 | 值 |
|---|---|
| broker | EMQX 5.8.9 容器 `emqx-test` @ 192.168.64.13 |
| 工具容器 | `gmqtt-tools`(debian:13,挂载 /opt/bin + /opt/certs)|
| 证书 | RSA:`server-rsa.crt/key` + `rsa-root-ca.crt`(mqtts/wss)|
| | SM2:`server-sign/enc.crt/key` + `sm2-root-ca.crt`(tlcp/gmwss/quic-gm)|
| 客户端 | `gmqtt-arm64`(8 种连接方式,含 quic-gm cgo)|
| 服务端工具 | `gmquic-server-arm64` / `tlcp-server-arm64` / `testserver-arm64` |

## 4. 连接方式矩阵与测试方法

| # | 方式 `-s` | 目标端点 | 服务端链路 | 命令要点 | 预期握手结果 |
|---|---|---|---|---|---|
| 1 | mqtt | 127.0.0.1:1883 → EMQX 1883 | 直连 | `-s mqtt` | 明文 TCP,无加密 |
| 2 | mqtts | 127.0.0.1:8883 → EMQX 8883 | 直连(RSA TLS) | `-s mqtts -cafile rsa-root-ca.crt` | TLSv1.3, AES-GCM |
| 3 | tlcp | 127.0.0.1:8884 → tlcp-server → EMQX | NTLS 双证书 | `-s tlcp -cafile sm2-root-ca.crt` | **NTLSv1.1, ECC-SM2-SM4-GCM-SM3** |
| 4 | ws | 127.0.0.1:8083 → EMQX 8083 | 直连(WS) | `-s ws -ws-path /mqtt` | WebSocket 明文 |
| 5 | wss | 127.0.0.1:8084 → EMQX 8084 | 直连(TLS+WS) | `-s wss -cafile rsa-root-ca.crt -ws-path /mqtt` | TLSv1.3 + WebSocket |
| 6 | gmwss | 127.0.0.1:18884 → testserver → EMQX | TLCP+WS | `-s gmwss -cafile sm2-root-ca.crt` | **NTLS + WebSocket** |
| 7 | quic | 127.0.0.1:14567 → EMQX 14567 | 直连(QUIC) | `-s quic` | **QUICv1, TLS1.3** |
| 8 | quic-gm | 127.0.0.1:4433 → gmquic-server → EMQX | 国密 QUIC | `-s quic-gm -cafile sm2-root-ca.crt -sign-cert/-sign-key` | **QUICv1, TLS_SM4_GCM_SM3** |

## 5. 每种方式的验证步骤(以 tlcp 为例)

```
① 订阅端:gmqtt sub  -s tlcp -h 127.0.0.1 -p 8884 -cafile sm2-root-ca.crt \
         -t <case>/test -id sub-<case>       → 预期:SUBACK ok
② 发布端:gmqtt pub  -s tlcp -h 127.0.0.1 -p 8884 -cafile sm2-root-ca.crt \
         -t <case>/test -m "hello-<case>"    → 预期:PUBLISH OK
③ 订阅端收到:<case>/test hello-<case>        → 业务打通
④ 连接检查:gmqtt conn -s tlcp ... -v          → 输出套件/版本(采证)
```

## 6. 验证日志采集

| 来源 | 内容 | 用途 |
|---|---|---|
| gmqtt `-v` 输出 | 连接方式/端点/握手套件/CONNECT 结果 | 客户端侧证据 |
| sub/pub 输出 | SUBACK/PUBLISH OK/消息回显 | 业务语义证据 |
| 代理日志 | gmquic-server/tlcp-server/testserver 的握手与转发记录 | 国密链路证据 |
| EMQX 日志 | `emqx ctl listeners` + 连接/订阅事件 | broker 侧证据 |

判定标准:**①③④ 全通过** = 该方式复现成功;任何一步失败记录错误并复测。

## 7. 执行计划(确认后)

1. 逐方式执行 §5 步骤(sub + pub + conn),记录全部输出
2. 汇总为「复现结果表」:每方式 通过/失败 + 握手证据 + 业务证据
3. 输出最终测试报告(本报告 + 复现结果 + 日志附件)

---
**请确认**:1) 范围是否按 8 种连接方式 + 说明执行;2) 第 9 种的具体定义;
3) 其他需要调整的项(如加双向认证、MQTT 5.0 版本、断线重连等)。
