# gmqtt 八种连接方式 — 容器复现测试报告(最终)

> 执行日期:2026-08-07 | 环境:本机(Apple Silicon)容器,无外部机器参与

## 1. 测试环境

| 容器 | 镜像/内容 | IP | 作用 |
|---|---|---|---|
| `emqx-test` | emqx/emqx:5.8.9 | 192.168.64.16 | MQTT broker(5 个 listener) |
| `gmqtt-tools` | debian:13 + gmqtt 工具链 | 192.168.64.14 | 客户端 + 3 个国密代理 |

**EMQX listeners**:tcp:1883 / ssl:8883(RSA 证书)/ ws:8083 / wss:8084 / quic:14567

**gmqtt-tools 代理**(均终止国密 → TCP 明文转发 EMQX,broker 零改造):
- `gmquic-server:4433`(国密 QUIC→TCP)
- `tlcp-server:8884`(TLCP/NTLS→TCP)
- `testserver:18884`(TLCP+WebSocket→TCP)

**证书**:RSA(`server-rsa.crt/key` + `rsa-root-ca.crt`)与 SM2(`server-sign/enc.crt/key` + `sm2-root-ca.crt`)

## 2. 拓扑

```
┌─────────── emqx-test 容器 (192.168.64.16) ─────────────┐
│ EMQX 5.8.9                                             │
│ 1883(tcp) 8883(ssl) 8083(ws) 8084(wss) 14567(quic)    │
└────▲────────▲────────▲────────▲────────────────────────┘
     │        │        │        │
   mqtt/mqtts/ws/wss 直连       │ (容器间 UDP 隔离,quic 在 emqx 容器内测)
     │        │        │        │
┌────┴────────┴────────┴────────┴────────────────────────┐
│ gmqtt-tools 容器 (192.168.64.14)                       │
│ 客户端 gmqtt:8 种连接方式                              │
│ 代理:gmquic-server:4433 / tlcp-server:8884 /          │
│       testserver:18884                                 │
└─────────────────────────────────────────────────────────┘
```

## 3. 结果汇总

| # | 方式 | conn | pub | sub | 握手/套件证据 | 结果 |
|---|---|---|---|---|---|---|
| 1 | mqtt | ✅ | ✅ | ✅ | 明文 TCP | **通过** |
| 2 | mqtts | ✅ | ✅ | ✅ | TLS(EMQX ssl_closed 记录) | **通过** |
| 3 | tlcp | ✅ | ✅ | ✅ | **NTLSv1.1 ECC-SM2-SM4-GCM-SM3** | **通过** |
| 4 | ws | ✅ | ✅ | ✅ | WebSocket 明文 | **通过** |
| 5 | wss | ✅ | ✅ | ✅ | TLS+WS | **通过** |
| 6 | gmwss | ✅ | ✅ | ✅ | NTLS+WebSocket | **通过** |
| 7 | quic | ✅ | ✅ | ✅ | QUICv1(emqx 容器内) | **通过** |
| 8 | quic-gm | ✅ | ✅ | ✅ | **QUICv1 + TLS_SM4_GCM_SM3** | **通过** |

**8/8 全部通过。**

## 4. 关键验证日志

### tlcp(NTLS 握手证据 — tlcp-server 日志)
```
[tlcp-server] TLCP handshake OK: NTLSv1.1 ECC-SM2-SM4-GCM-SM3
```

### quic-gm(国密 QUIC 握手证据 — gmqtt 输出)
```
[gmqtt] quic-gm handshake OK, cipher=TLS_SM4_GCM_SM3
[gmqtt] quic-gm dial 127.0.0.1:4433 (TLS_SM4_GCM_SM3)
CONNECT OK
```

### 业务链路(以 tlcp 为例,各方式一致)
```
sub: SUBSCRIBED gmqtt/tlcp (等待消息, Ctrl-C 退出) → SUBACK ok
pub: PUBLISH OK -> gmqtt/tlcp
sub 收到: gmqtt/tlcp hello-tlcp
```

### EMQX broker 侧(emqx.log.1 摘录)
```
clientid: sub-quic-gm, msg: terminate, peername: 192.168.64.14:54070, reason: {shutdown,tcp_closed}
clientid: gmqtt-test, msg: terminate, peername: 192.168.64.14:37424, reason: {shutdown,ssl_closed}   ← mqtts/wss TLS 连接
```

## 5. 测试方法(每方式三步)

```
① conn:gmqtt conn -s <方式> -h <端点> -p <端口> [证书参数] -v   → 预期 CONNECT OK
② pub: gmqtt pub  ... -t gmqtt/<方式> -m hello-<方式>           → 预期 PUBLISH OK
③ sub: gmqtt sub  ... -t gmqtt/<方式> -id sub-<方式>            → 预期 SUBACK + 收到消息
```

端点:mqtt/mqtts/ws/wss → 192.168.64.16(EMQX);tlcp/gmwss/quic-gm → 127.0.0.1(代理);
quic → emqx 容器内 127.0.0.1:14567(容器间 UDP 隔离所致)。
mqtts/wss 加 `-servername 192.168.1.162` 匹配证书 CN。

## 6. 结论

- gmqtt 客户端 **8 种连接方式在本机容器环境全部复现成功**,含 3 条国密链路
  (tlcp / gmwss / quic-gm)与标准链路(mqtt/mqtts/ws/wss/quic)
- 部署模型验证:国密通道边缘终止 → 明文 MQTT → broker,broker 零改造
- 文档一致性:GitHub README 已修正为「8 种连接方式 + 独立工具」,与实际一致

## 7. 附注

- 容器间 UDP 隔离:quic 测试在 emqx 容器内执行(127.0.0.1:14567),不影响结论
- 证书为实验样例(CN=192.168.1.162),生产使用自有 CA
