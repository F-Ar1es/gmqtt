# 交接提示词 — 给下一个 AI 助手

> 用途:协助用户**换一台机器**复现/继续 gmqtt 国密 MQTT 测试。
> 请先读:`README.md`、`docs/gmqtt-容器测试报告-最终.md`、`gmquic/patches/tongsuo-8.5-gmquic/README.md`。

## 你的任务

协助我在新机器上用 **gmqtt 工具链**复现 8 种 MQTT 连接方式的测试,或继续国密 QUIC 相关开发。
当前所有成果已在本仓库:客户端、服务端代理、Tongsuo patch、测试报告与日志。

## 背景速览

**gmqtt** = 国密 MQTT 命令行测试客户端(Go + cgo 链接 Tongsuo),支持:

| `-s` | 连接方式 | 端口 | 说明 |
|---|---|---|---|
| mqtt | 明文 TCP | 1883 | |
| mqtts | 标准 TLS | 8883 | RSA 证书 |
| tlcp | 国密 TLCP(NTLS) | 8884 | SM2 双证书 |
| ws | WebSocket | 8083 | 需 `-ws-path /mqtt` |
| wss | TLS+WS | 8084 | RSA 证书 |
| gmwss | 国密 TLCP+WS | 18884 | SM2 |
| quic | MQTT over QUIC | 14567 | quic-go |
| quic-gm | 国密 QUIC | 4433 | Tongsuo 8.5 + TLS_SM4_GCM_SM3 |

## 新机器复现步骤

### 1. 取二进制
- GitHub Release v0.3.0:按新机器架构选
  `gmqtt-v0.3.0-linux-amd64.tar.gz`(x86_64)或 `-arm64`(ARM64)
- 包内含:`bin/<arch>/gmqtt`、`gmquic-server`、`gmquic-client`、`certs/`、`patches/`

### 2. 起容器(2 个,推荐)
```bash
# broker 容器(EMQX 5.8.9,5 listener)
docker run -d --name emqx-test \
  -v $PWD/emqx.conf:/opt/emqx/etc/emqx.conf \
  -v $PWD/certs:/opt/emqx/certs emqx/emqx:5.8.9

# 工具容器(客户端 + 3 个国密代理)
docker run -d --name gmqtt-tools \
  -v $PWD/bin:/opt/bin -v $PWD/certs:/opt/certs debian:13 sleep infinity
```
`emqx.conf` 见 `docs/测试日志/` 或按报告 §1 配置 5 个 listener
(tcp/ssl/ws/wss/quic);`ssl/wss` 用 RSA 证书(server-rsa.crt/key)。

### 3. 启动国密代理(在 gmqtt-tools 内,上游指向 EMQX 容器 IP)
```bash
gmquic-server -p 4433  -cert server-sign.crt -key server-sign.key -upstream <EMQX_IP> -upstream-port 1883
tlcp-server   -p 8884  -sign-cert server-sign.crt -sign-key server-sign.key \
               -enc-cert server-enc.crt -enc-key server-enc.key -upstream <EMQX_IP> -upstream-port 1883
testserver    -listen :18884 -upstream <EMQX_IP>:1883 \
               -sign-cert server-sign.crt -sign-key server-sign.key \
               -enc-cert server-enc.crt -enc-key server-enc.key
```

### 4. 逐方式测试(conn/sub/pub 三步)
```bash
gmqtt conn -s <scheme> -h <endpoint> -p <port> [证书参数] -v   # 预期 CONNECT OK
gmqtt pub  -s <scheme> ... -t gmqtt/<name> -m hello-<name>      # 预期 PUBLISH OK
gmqtt sub  -s <scheme> ... -t gmqtt/<name> -id sub-<name>       # 预期 SUBACK + 收到消息
```

## 已知问题与坑(务必先看)

1. **容器间 UDP 可能不通**(TCP 通):quic 测试可在 EMQX 容器内对 `127.0.0.1:14567` 执行;
   或给 EMQX 加端口映射 `-p 14567:14567/udp` 后经宿主 IP 测。
2. **容器重启 IP 会漂移**:重启后用 `docker inspect` / `hostname -I` 查新 IP,
   重新配置 3 个代理的 `-upstream`。**改了 IP 一定要同步更新测试脚本**。
3. **mqtts/wss 证书 CN 不匹配**:实验证书 CN=192.168.1.162,连其他 IP 需加
   `-servername 192.168.1.162`。
4. **pkill 在 debian slim 容器不可用**:用 `/proc` 遍历杀进程:
   `for pid in $(ls /proc|grep -E '^[0-9]+$'); do grep -qa "<名字>" /proc/$pid/cmdline && kill -9 $pid; done`
   (注意:grep 模式别匹配到自己的命令行)。
5. **cgo 编译需 Tongsuo 8.5 + patch**:tlcp/quic-gm 都链接 Tongsuo 8.5.0-pre2
   (patch 在 `gmquic/patches/`);Tongsuo 8.4 无 QUIC。编译环境见下。
6. **gmwss 客户端连 testserver 默认 ws 路径即可**;连 EMQX wss 需 `-ws-path /mqtt`。

## 如需从源码构建(换机器自建)

- gmqtt:cgo 链接 Tongsuo 8.5(`CGO_ENABLED=1 go build`),Go 1.21+
- gmquic-server/client:`gcc server.c/client.c/tlcp-server.c -lssl -lcrypto -ldl -lpthread`
- Tongsuo 8.5 patch 版:按 `gmquic/patches/tongsuo-8.5-gmquic/README.md` 打补丁编译
  (`./config no-shared enable-ntls && make build_sw && make install_sw`;amd64 装 lib64 需
  `ln -s /opt/tongsuo85/lib64 /opt/tongsuo85/lib`)

## 交付物索引

- `README.md` — 使用说明(8 种连接方式)
- `docs/gmqtt-容器测试报告-最终.md` — 容器复现结果(8/8 通过)
- `docs/gmqtt-容器测试报告-设计稿.md` — 测试设计
- `docs/测试日志/` — sub 业务日志 + 代理握手日志
- `gmquic/` — 国密 QUIC/代理源码 + Tongsuo 8.5 patch
- 源码:gmqtt(Go)含 `quic_gm.go`(国密 QUIC cgo)

## 当前遗留/可继续的方向

1. 新机器上完整复现 8 种连接方式(若新机器是 amd64,用 amd64 包)
2. 真实环境(192.168.1.x 实验网)端到端:gmquic-server/tlcp-server 部署在网关节点
3. MQTT 5.0 × 各连接方式交叉验证
4. 国密 QUIC 的 GMQUIC 0-RTT 与性能压测
5. 如遇 README 与实现不一致,以代码为准并修正文档
