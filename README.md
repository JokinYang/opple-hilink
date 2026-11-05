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
cargo test            # 25 个测试（14 单测 + 6 C ABI + 5 配网帧集成）
```

产物（`[lib] crate-type = ["cdylib", "staticlib", "rlib"]`）：

| 产物 | 用途 |
|---|---|
| `opple` / `opple.exe` | CLI |
| `opple_hilink.dll` / `libopple_hilink.so` / `libopple_hilink.dylib` | 动态库：JNI、`ctypes`、Unity、C/C++ |
| `opple_hilink.lib` / `libopple_hilink.a` | 静态库 |
| `libopple_hilink.rlib` | 供其他 Rust crate 引用 |

交叉编译到手机（已装 cargo-ndk）：

```bash
cargo ndk -t arm64-v8a -o ./jniLibs build --release
# → jniLibs/arm64-v8a/libopple_hilink.so
```

## 作为库使用（C ABI）

导出层在 `src/ffi.rs`，只有一个「JSON 进、JSON 出」的入口，避免为每种语言写一套结构体映射：

```c
#include <stdio.h>

extern char *opple_version(void);
extern char *opple_call(const char *op, const char *args_json);
extern void  opple_free(char *p);

int main(void) {
    char *r = opple_call("derive",
        "{\"auth_code\":\"00112233445566778899aabbccddeeff\","
        "\"sn1_hex\":\"0102030405060708\",\"sn2_hex\":\"1112131415161718\"}");
    puts(r);          // {"ok":true,"data":{"psk":"…","hmac_key":"…"}}
    opple_free(r);
    return 0;
}
```

约定：返回值永远是非 NULL 的堆分配 UTF-8 字符串，**必须** `opple_free`；失败时也给合法 JSON：

```json
{"ok":true,"data":{…}}
{"ok":false,"error":{"kind":"Timeout","message":"设备响应 超时（设备无响应）"}}
```

`error.kind` ∈ `Io | Timeout | Coap | Crypto | Json | Frame | Arg | Device`，便于调用方分类处理。
入参 NULL、非法 UTF-8、非法 JSON、内部 panic 都会转成错误体，**不会跨 FFI 边界崩溃**。

支持的操作：

| `op` | 说明 | 主要参数 |
|---|---|---|
| `version` / `profile` | 版本探针 / 服务字典 | — |
| `derive` / `crc8` | 纯计算：PSK+HMACKey 派生 / keyId 校验字节 | `auth_code` `sn1_hex` `sn2_hex`；`key_id` |
| `session` | 建本地会话 | `host` `account_id` `auth_code` |
| `control` | 建会话并下发一条服务 | `service` `data`/`data_json` + 设备四要素 |
| `prov_parse` / `prov_decrypt` | 配网帧解析 / 解密 | `frame_hex` `ap_ssid` `key_hex`\|`key_b64` |
| `prov_build` / `prov_send` | 组帧 / 发送并等 `HI-ACK` | `ssid` `password` `register_json` … |
| `discover` | `/.well-known/core?st=cloudSetup` | `host` `port` |
| `ota_mqtt` / `ota_status` | 云升级命令 / 升级状态解析 | `access_token` `user_id` `device_id` `action` |

Python 侧同样直连，无需编译绑定：

```python
import ctypes, json
lib = ctypes.CDLL("./libopple_hilink.so")          # Windows 用 "opple_hilink.dll"
lib.opple_call.restype = ctypes.c_void_p
lib.opple_free.argtypes = [ctypes.c_void_p]
p = lib.opple_call(b"crc8", b'{"key_id":"TEST1"}')
print(json.loads(ctypes.string_at(p).decode()))
lib.opple_free(p)
```

## 作为 Python 库使用

`python/` 是 maturin 混合项目：一个 wheel 里同时包含纯 Python 包与 PyO3 扩展，装完即用。

| 后端 | 来源 | 说明 |
|---|---|---|
| `native` | wheel 内的 `opple_hilink/_native`（PyO3，`abi3` ≥3.8） | 默认，无 ctypes 开销 |
| `ctypes` | 外部 `opple_hilink.dll` / `libopple_hilink.so` | 无需编译扩展时可回退；用 `OPPLE_HILINK_LIB` 指路径 |

```bash
pip install -e python                  # 开发安装（maturin 自动编译扩展）
pip install ./python                   # 构建 wheel 并安装
cd python && maturin build --release -o dist   # 只产 wheel：dist/opple_hilink-0.1.0-cp38-abi3-*.whl
```

```bash
python -c "import opple_hilink as o; print(o.backend(), o.crc8('134DC'))"
# → native 165   （没有扩展时自动回退 ctypes）
```

```python
import json
import opple_hilink as opple

# 设备控制
lamp = opple.Client(host="192.168.1.100", device_id="<DEVICE_ID>",
                    account_id="<ACCOUNT_ID>", user_id="<USER_ID>",
                    auth_code="<AUTH_CODE>")
lamp.on(); lamp.brightness(120); lamp.cct(4000); lamp.mode(2); lamp.side(True)

# 纯计算：不需要设备、不触网
opple.derive(auth_code, sn1, sn2)          # {"psk": …, "hmac_key": …}
opple.crc8("134DC")                        # 165

# 配网帧
frame = opple.prov_build(ap_ssid="Hi- OPPLE-READINGLAMP-0TEST1",
                         ssid="home-2.4G", password="…",
                         register_json=json.dumps({"code": "…"}),
                         key=bytes(16))
opple.prov_parse(frame, "Hi- OPPLE-READINGLAMP-0TEST1")
```

参数较宽松：`auth_code` / `key` / `frame` 都接受 `bytes` 或 hex 字符串（`key` 也接受 base64）。
失败统一抛 `OppleError`，`.kind` ∈ `Io | Timeout | Coap | Crypto | Json | Frame | Arg | Device`。

## CI：各平台产物

`.github/workflows/build.yml` 在 push / PR / 打 tag 时构建，产物以 artifact 形式保留；
推 `v*` tag 时会自动创建 Release 并附上全部文件。

| Job | 产物 |
|---|---|
| `test` | Ubuntu / Windows / macOS 上跑 `cargo test`（25 项）与 Python 测试（12 项，含双后端对比） |
| `binaries` | Linux x86_64 / aarch64、Windows x86_64、macOS x86_64 / arm64：`opple`、`libopple_hilink.so/.dylib/.a`、`opple_hilink.dll/.lib` |
| `android` | `jniLibs/{arm64-v8a,armeabi-v7a,x86_64,x86}/libopple_hilink.so` |
| `wheel-linux` | `cp38-abi3` manylinux2014（x86_64、aarch64） |
| `wheel-desktop` | `cp38-abi3` Windows x86_64、macOS universal2 |
| `sdist` | `opple_hilink-0.1.0.tar.gz` |

> wheel 用 `abi3-py38`，一个文件覆盖 CPython 3.8+，不必按 Python 版本铺矩阵。


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
| `ffi::version_probe` | `opple_version` 探针、C 字符串往返与释放 |
| `ffi::derive_matches_rust_api` | 同一组输入下 C ABI 与 Rust API 结果一致 |
| `ffi::provision_roundtrip_via_ffi` | 经 C ABI 组帧→解析→解密闭环 |
| `ffi::error_paths_do_not_panic` | 未知操作 / 非法 JSON / NULL 指针均返回错误体 |

## 目录

```
src/coap.rs        CoAP 编解码（含 2048/2050/2051/2052/2053/2056 私有选项）
src/crypto.rs      PBKDF2/HMAC/AES-CBC/crc8/UUIDv4/Base64
src/session.rs     会话建立 + UDP 收发（超时/重试）
src/control.rs     控制帧构造/解析/发送
src/provision.rs   白盒配网帧解析/组帧/解密
src/ota.rs         MQTT 升级命令 + 本地 update 服务
src/discovery.rs   /.well-known/core?st=cloudSetup
src/ffi.rs         C ABI 导出层（JSON 进出的统一入口，cdylib/staticlib 用）
src/error.rs       统一错误类型
src/main.rs        CLI
tests/             配网帧回归测试（合成夹具）+ C ABI 边界测试
python/            maturin 混合项目：Python 包 + PyO3 扩展（同一 wheel）
.github/workflows/ CI：各平台二进制库、Android .so、Python wheel、sdist、Release
docs/              协议分析报告（逆向依据与真机实测记录）
```
