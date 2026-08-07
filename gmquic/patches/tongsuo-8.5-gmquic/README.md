# Tongsuo 8.5.0-pre2 国密 QUIC 支持 patch

让 Tongsuo 的 QUIC 实现支持 TLS 1.3 国密套件 `TLS_SM4_GCM_SM3` / `TLS_SM4_CCM_SM3`
(QUIC 传输 + SM2 证书 + SM4-GCM 加密 + SM3 哈希)。

## 背景

Tongsuo 8.5.0-pre2 自带 QUIC(OpenSSL 3.2 风格 API)和 TLS 1.3 国密套件
(`TLS1_3_CK_SM4_GCM_SM3 0x030000C6`),但两处硬编码把国密套件排除在 QUIC 之外:

1. `ssl/t1_lib.c` `ssl_cipher_disabled()`:QUIC 模式只允许 3 个标准 TLS 1.3 套件
   (AES-128/256-GCM、CHACHA20-POLY1305),SM4 套件一律拒绝。
2. QUIC record layer(密钥派生/AEAD/header protection)只识别上述 3 种 suite。

## 修改文件(5 处)

| 文件 | 修改 |
|---|---|
| `include/internal/quic_record_util.h` | 新增 `# define QRL_SUITE_SM4GCM 4 /* SM3 */` |
| `include/internal/quic_wire_pkt.h` | 新增 `# define QUIC_HDR_PROT_CIPHER_SM4 4` |
| `ssl/quic/quic_record_util.c` | 新增 `suite_sm4gcmsm3` suite 表项(SM4-GCM/SM3, 16B key, SM4-ECB 做 header protection);`get_suite()` 加 case |
| `ssl/quic/quic_tls.c` | `quic_new_record_layer()` 加 `EVP_CIPHER_is_a(ciph, "SM4-GCM")` → `QRL_SUITE_SM4GCM` 映射 |
| `ssl/quic/quic_wire_pkt.c` | `ossl_quic_hdr_protector_init()` 加 `QUIC_HDR_PROT_CIPHER_SM4 → "SM4-ECB"`;mask 计算分支加入 SM4 |

## 应用方式(手工)

```bash
cd <Tongsuo-8.5.0-pre2-src>
# 按上表逐处修改,或对照 diff 应用
./config no-shared enable-ntls --prefix=/opt/tongsuo85 --openssldir=/opt/tongsuo85/ssl
make -j4 && make install_sw
```

## 验证

gmquic-client/server(本目录)在容器内验证通过:

```
>>> HANDSHAKE OK
    negotiated cipher: TLS_SM4_GCM_SM3
    negotiated version: QUICv1
>>> sent 25 bytes
<<< echo 25 bytes: hello 国密QUIC 你好
```

## 注意

- 基于 Tongsuo `8.5.0-pre2`(pre 版);正式版(8.5.x)发布后需核对代码位置
- SM4 套件的 QUIC 使用上限参照 RFC 9001(类比 AES-128-GCM/ChaCha20)
- 仅放开套件白名单,不涉及协议栈其他部分
