# opple-hilink（Rust）

欧普读写台灯（HiLink，prodId `134D`）**全部交互协议**的 Rust 实现，与真机逐字节对齐。

三条链路 + 两个辅助：

| 模块 | 协议 | 传输 | 加密 |
|---|---|---|---|
| `control` | 本地控制（开关/亮度/色温/模式…） | CoAP · UDP/5686 | AES-128-CBC + HMAC-SHA256 |
| `session` | 会话建立 `/.sys/sessMngr` | CoAP · UDP/5686 | 明文 JSON |
| `provision` | 配网（下发 WiFi） | 私有帧 · UDP/5683 | AES-128-CBC（IV=0）+ 白盒封装密钥 |
| `ota` | 固件升级 | MQTT（云端）/ 本地 `update` 服务 | TLS / 同上控制加密 |
| `discovery` | 设备发现 `/.well-known/core?st=cloudSetup` | CoAP GET | 明文 |
| `coap` / `crypto` | CoAP 编解码、PBKDF2/HMAC/AES/crc8/UUIDv4 | — | — |

## 文档

`docs/` 存放这两份协议分析报告，是全部实现的依据（反编译结论 + 真机实测记录）：

| 文档 | 内容 |
|---|---|
| [`docs/OPPLE台灯协议分析.md`](docs/OPPLE台灯协议分析.md) | 本地控制链路：CoAP/UDP-5686、`/.sys/sessMngr` 会话、PSK/HMAC 派生、控制帧逐字节解析、prodId `134D` 服务字典 |
| [`docs/OPPLE台灯-配网与固件升级协议.md`](docs/OPPLE台灯-配网与固件升级协议.md) | 配网（白盒帧为主、SPEKE 仅记录）与固件升级（云端 MQTT / 本地 `update`），含实测边界、未决项与后续实验记录 |

> 文档内的相对路径（`src_full/`、`tools/…`、`opple_lamp.mjs`、`prov_frame_*.hex`、`log*.txt` 等）都相对**分析工作区根目录**，即本仓库之上三层（`../../../`）；本仓库只包含 Rust 实现与这两份文档。
>
> 两份报告是**公开版**：设备标识、账号、`authCode`、云端 `code/psk`、家庭 WiFi 的 SSID/密码、白盒块及其封装密钥均替换为 `<PLACEHOLDER>` 占位符，协议结构、字节布局与结论未改动。

## 构建与测试

```bash
cargo build --release
cargo test            # 19 个测试（14 单测 + 5 集成）；配网帧用合成夹具回归，真机帧回归见 docs/
```

交叉编译到手机（已装 cargo-ndk）：

```bash
cargo ndk -t arm64-v8a -o ./jniLibs build --release
```

## 快速开始

用环境变量传连接参数：

```bash
export OPPLE_IP=192.168.78.101
export OPPLE_DEVICE_ID=<DEVICE_ID>
export OPPLE_ACCOUNT_ID=<ACCOUNT_ID>
export OPPLE_USER_ID=<USER_ID>
export OPPLE_AUTH_CODE=<AUTH_CODE>

opple session                # 建会话，打印 sessId/sn1/sn2/psk/hmacKey
opple on
opple brightness 120         # 26-255，26≈10%
opple cct 4000               # 2000-6500
opple mode 2                 # 2阅读 3读写 4电脑 6自定义
opple side on                # 侧边灯
opple raw netInfo '{}'       # 任意服务
opple discover               # 配网态才有响应
```

配网帧：

```bash
# 解析 + 解密（密钥来自 hook，见下）
opple prov-decode frame.hex --key <WHITEBOX_KEY_B64>

# 组帧（白盒块未知时用 --wb 或省略=全 0 占位；AES-CBC+全 0 IV 是确定性的）
opple prov-build --ssid "<HOME_SSID>" --password <WIFI_PASSWORD> \
  --register '{"appName":"smarthome",...}' \
  --key <WHITEBOX_KEY_B64> --ap-ssid "Hi- OPPLE-READINGLAMP-0134DC" \
  --wb <WHITEBOX_BLOCK> --out frame.hex

# 把帧发给配网态设备（默认 192.168.5.1:5683），等明文 HI-ACK
opple prov-send frame.hex --timeout 2000 --retries 5
```

### 配网能力边界

| 能力 | 支持 | 说明 |
|---|---|---|
| 帧解析 / 校验 / 解密 | ✅ | 真机帧回归通过（校验字节、SSID、明文全对上）；仓库内测试改用合成夹具 |
| 帧组装 | ✅ | 按解析结果重建**逐字节一致**（测试断言）；真机帧亦曾逐字节对齐 |
| 发送 + 等 `HI-ACK` | ✅ | `prov-send`，带超时/重试；回环测试覆盖成功与超时两条路径 |
| 从零发起完整配网 | ❌ | 缺两块外部输入：16B 白盒块（`libsecurityi.so` 生成）、云端按会话下发的 `code/psk` |
| SPEKE 分支（有 PIN 机型） | ❌ | 本机型不走该路径，无真机帧可对齐，仅文档记录 |

结论：Rust 端是**完整的协议实现 + 可用的发送器**；"凭据"仍得由 App/云端提供——因为白盒块与
`code/psk` 本质上是华为云端与 App 之间的凭据，不是可以离线算出来的东西。

OTA：

```bash
opple ota check mqtt --token "$AT" --user-id $UID --device-id $DEVID   # 打印 MQTT 命令
opple ota start local                                                  # 直接发 /update（本机型不响应）
```

## 协议要点

### 1. 本地控制（UDP/5686）

```
选项: 11=<serviceId> 12=50 2048=<sessId> 2050=<uuid> 2051=<deviceId>
      2052=AES-CBC(userId)‖IV16  2053=<seq 大端>  2056=<accountId>
payload: AES-CBC(JSON) ‖ IV16 ‖ HMAC-SHA256(整条报文，含 2056)
```

- `salt = sn1(8B) ‖ sn2(8B)`；`PSK = PBKDF2-HMAC-SHA256(authCode, salt, 1)[0..16]`；`HMACKey = PBKDF2(PSK, salt, 1)`
- **MAC 覆盖整条报文（包含选项 2056）**——反编译里 `getCoapBytes()` 少写了 2056，照抄会一直被设备静默丢包
- `seq` 用会话返回的 `seq+1`；设备同一时刻只保留一个本地会话（新会话会让 App 的旧会话失效，App 会自动重建）
- 服务：`switch` `brightness` `cct` `lightMode` `nightSwitch` `backlight`（`update`/`timer`/`delay`/`netInfo` 被 App 列入禁止本地控制）

### 2. 配网（UDP/5683，本机型**没有 SPEKE/securityData**）

App 有两条配网实现，按设备是否有 PIN 二选一；本台灯 `mPinType=0`，走 `cafebabe.tqe` 的白盒帧：

```
[0]      crc8(keyId)        keyId = AP SSID 第4段去首字符取5位（…-0134DC → 134DC）
[1]      crc8(frame[2..iA)) 计算时 byte1 置 0；iA = 未补齐长度
[2]      (1|2|3)<<4         设备类别 100→0x10
[3..19]  16B 白盒块
[19]     (ssidLen-1) | (((pwdCipherLen>>4)-1)<<5)
[20..]   SSID 明文
...      密码密文     AES-128-CBC/PKCS7，IV = 16×0x00
...      1B          注册包密文长度 >> 4
...      注册包密文   （扁平 JSON，无 {"data"} 外壳）
末尾     总长奇数补 0x00
```

实测解出的注册包：

```json
{"appName":"smarthome","cloudPrimaryUrl":"wisedevice-hilink-drcn.things.dbankcloud.cn",
 "cloudPrimaryUrlKey":"hilinkDevicePrimaryCloudUrl",
 "cloudStandbyUrl":"wisedevice-hilink-drcn.things.dbankcloud.cn",
 "cloudStandbyUrlKey":"hilinkDeviceStandbyCloudUrl","cloudUrl":"iomplatform.hicloud.com",
 "code":"<PROV_CODE>","countryCode":"CN","devId":"<DEVICE_ID>",
 "psk":"<PROV_PSK>","serviceName":"com.huawei.cloud.wisedevice"}
```

设备回 `HI-ACK`（明文）。密钥每帧随机，被华为白盒（`libsecurityi.so`，TypeEnum 100）封装进帧头，
**离线无法反解**；实践里在 App 运行时 hook：

- `CommonLibUtil.whiteBoxEncrypt(int, byte[], String)`：第 3 参即 Base64(AES 密钥)
- `cafebabe.dnd.a(byte[], String, byte[])`：直接拿到明文（密码 / 注册包）

`provision::build` 因此把白盒块作为**入参**（`--wb`），不知道时留全 0 占位。

### 3. 固件升级

App 把 `update` 列入本地控制黑名单（`cafebabe/mwd.java`），命令固定走云端 MQTT：

```
topic: /smartHome/signaltrans/v2/categories/command   (QoS1)
{"header":{"method":"POST","accessToken":"…","mode":"ACK","requestId":"…",
           "from":"/users/<uid>","to":"/devices/<devId>/services/update",
           "timestamp":"20261027T080557Z"},
 "body":{"action":0}}     // 0=检查 1=升级
```

设备侧服务 `update` 的 `{"action":0|1}` 本地实测无响应（固件 6.3.6 不提供），状态上报字段为
`version/introduction/progress/bootTime/autoUpdateOn`。

## 局域网控制到底依赖什么（实测）

一次对照实验（同一台灯、同一会话）：

| 发送的 `accountId` / `userId` | 结果 |
|---|---|
| 正确值 | ✅ 控制成功 |
| `accountId` 换成 `0000000000000000` | ✅ 仍然成功 |
| `userId` 换成 `1234567890` | ✅ 仍然成功 |

结论：设备**不校验账号身份**，`accountId`(2056) / `userId`(2052) 只是随包携带；
真正决定能不能控制的是 **`authCode`**（派生 PSK/HMAC 的 16 字节设备密钥）。

所以：

- **不需要绑定账号、不需要云端**，只要拿到过 `authCode`，就能长期在局域网内控制；
- `deviceId` 用来标识设备（设备回包里的 `devId` 也会回显它）；
- 唯一的硬约束：**设备恢复出厂会换 authCode**，换的那一次必须由 App（或云端
  `POST /home-manager/v1/homes/devices/authcode`）提供新值；拿到之后又可以无限期离线使用。

凭据可以存起来，之后免参数：

```bash
opple use --ip 192.168.78.101 --device-id <DEVICE_ID> \
          --account-id <ACCOUNT_ID> --user-id <USER_ID> \
          --auth-code <AUTH_CODE>
opple config          # 查看（authCode 打码）
opple on              # 直接可用，不读任何环境变量
```

配置文件默认 `~/.opple.json`，可用 `OPPLE_CONFIG` 指定。

## 密钥（authCode）从哪来

- 每台设备独有，16 字节；数据库里是 AES-GCM + Android Keystore 包裹，**拷库离线读不出**。
- 两条路：Frida 运行时读（`xsd.b().m(deviceId).getAuthCode()` / 控制请求里的 authCode），或云端
  `POST /home-manager/v1/homes/devices/authcode`。
- 设备恢复出厂后会**换 ID 和 authCode**（实测：每次重置后 deviceId 与 authCode 都变）。

## 测试

`cargo test` 覆盖：

| 测试 | 说明 |
|---|---|
| `crypto::crc8_matches_firmware` | crc8 与固件一致（`"134DC"` → 0xa5） |
| `coap::*` | 选项编码/大选项号（2048/2051）往返 |
| `control::frame_has_mac_and_parses` | 控制帧 MAC 自校验、选项齐全（2052=48B） |
| `ota::*` | MQTT 信封、状态解析、时间戳格式 |
| `provision_frame::parses_synthetic_frame` | 合成帧校验字节、SSID / 长度字段、白盒块回读 |
| `provision_frame::padding_branches` | 奇 / 偶两种帧尾补齐分支 |
| `provision_frame::decrypts_roundtrip` | AES-CBC(IV=0) 解出密码与注册包 JSON |
| `provision_frame::rebuild_is_byte_identical` | **按解析结果重建，与原帧逐字节相同** |
| `provision_frame::rejects_bad_checksums` | 两段校验字节分别失效 |

## 目录

```
src/coap.rs        CoAP 编解码（含 2048/2050/2051/2052/2053/2056 私有选项）
src/crypto.rs      PBKDF2/HMAC/AES-CBC/crc8/UUIDv4/Base64
src/session.rs     会话建立 + UDP 收发（超时/重试）
src/control.rs     控制帧构造/解析/发送
src/provision.rs   白盒配网帧解析/组帧/解密
src/ota.rs         MQTT 升级命令 + 本地 update 服务
src/discovery.rs   /.well-known/core?st=cloudSetup
src/error.rs       统一错误类型
src/main.rs        CLI
tests/             配网帧回归测试（合成夹具，不含真机数据）
docs/              协议分析报告（逆向依据与真机实测记录）
```
