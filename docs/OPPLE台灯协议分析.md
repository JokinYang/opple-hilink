# 欧普（OPPLE）读写台灯 —— 控制协议分析报告

> 目标设备：欧普读写台灯（华为 HiLink 生态，prodId `134D`）
> 分析日期：2026-10-27
> 分析方式：APK 静态逆向 + 真机（MI 8 / Android 9 / Magisk root）动态抓包 + 协议复现验证
> 结论：**本地控制为 CoAP over UDP（端口 5686），业务数据用「authCode 派生 PSK」做 AES-128-CBC 加密 + HMAC-SHA256 完整性保护；已完整复现并实测可控（开关 / 亮度 / 色温 / 模式 / 侧边灯）。**
>
> **阅读提示**：本文为公开版，设备标识、账号、`authCode`、云端 `code/psk`、家庭 WiFi 的 SSID/密码、白盒块与其封装密钥等均已替换为 `<PLACEHOLDER>` 形式；协议结构与字节语义保持原样。

---

## 0. 结论摘要

| 项目 | 结论 |
|---|---|
| 控制 App | `com.huawei.smarthome`（华为「智慧生活 / AI Life」）15.1.3.310 |
| 桌面「台灯」快捷方式 | 固定快捷方式 → `ShortCutExecActivity` → `DeviceH5ReadingLampActivity`（WebView 加载 `134D/h5_001/index.html`）→ JS Bridge → 原生控制 |
| 本地控制通道 | `DeviceControlImpl` 选择 `channel = 2`（local control），由 `LocalControl-CoapCommandTask` 发出 |
| 传输层 | **CoAP over UDP，端口 5686**（不是标准 5683） |
| 会话接口 | `POST coap://<lamp>:5686/.sys/sessMngr`（明文 JSON） |
| 控制接口 | `POST coap://<lamp>:5686/<serviceId>`（如 `/switch`、`/brightness`） |
| 加密 | AES-128-CBC/PKCS5，`密文 ‖ 随机IV(16B)` |
| 完整性 | HMAC-SHA256(32B) 附在 payload 末尾，**覆盖整条 CoAP 报文（含选项 2056）去掉 MAC 后的字节** |
| 密钥 | `PSK = PBKDF2-HMAC-SHA256(authCode, sn1‖sn2, 1, 32)[0..16]`；`HMACKey = PBKDF2-HMAC-SHA256(PSK, sn1‖sn2, 1, 32)` |
| 设备固件 | 6.3.6（App 埋点上报值），`e2eCtrl=0`、`hichainVersion=-1` → 走 authCode 分支（非 SPEKE/HiChain） |
| 云端回退 | 同一套命令经 MQTT/HTTPS 上云；本次分析的是局域网直连通道 |

---

## 1. 目标与环境

### 1.1 硬件 / 系统

| 项 | 值 |
|---|---|
| 手机 | Xiaomi MI 8（dipper），Android 9，已 root（Magisk，`u:r:magisk:s0`） |
| 局域网 | `192.168.78.0/24`，手机 `192.168.78.106`，分析 PC `192.168.78.105` |
| 台灯 | `192.168.78.101`，CoAP UDP/5686 |
| App 版本 | `15.1.3.310`（versionCode 2021513310，targetSdk 30） |

### 1.2 设备身份（来自 App 数据库 `SmartHome.db` / `HomeBase.db`）

| 字段 | 值 |
|---|---|
| HiLink deviceId | `<DEVICE_ID_OLD>` |
| 产品 ID (prodId) | `134D` |
| 设备名 / 型号 | 欧普读写台灯 / `Domestic Reading lamp` |
| 设备类型 | `046`（智能台灯） |
| 厂商 | `013` 欧普照明 |
| profile | `134D/134D.json`（版本 202） |
| 配网 SSID | `Hi- OPPLE-READINGLAMP-0134DX`（SoftAP 配网） |
| 能力标记 | `e2eCtrl=0`（不做端到端加密）、`isSupportSoftAP=1`、`hichainVersion=-1` |

### 1.3 App 内部调用链（日志实证）

```
input tap(电源键)
 └─ JavaBridge  DeviceControlManager.modifyDeviceProperty
     └─ DeviceControlImpl.sendDeviceControlCommand  topoType:-1
         └─ getChannel → "local control" → "control channel is 2"
             └─ LocalControl-LocalDeviceControlManager.begin control device
                 └─ LocalControl-CoapControlHiLinkBuilder  (digest len:32)
                     └─ LocalControl-CoapCommandTask  send to: 192.*.*.101
                         └─ LocalControl-CoapMessageSender  command random port:xxxxx
                             └─ CoAP POST /switch
```

关键源码（jadx 反编译，见 `src_full/`）：

- `com/huawei/iotplatform/appcommon/localcontrol/model/control/CoapControlHiLinkBuilder.java` —— 报文封装、密钥派生、HMAC
- `com/huawei/iotplatform/appcommon/localcontrol/model/session/CoapSessionBuilder.java` —— `/.sys/sessMngr` 会话请求
- `cafebabe/s3e.java` —— 会话建立任务（sn1、seq、sn2、sessId 落库）
- `cafebabe/z4d.java` —— 控制任务（seq 递增、错误码语义）
- `cafebabe/x4d.java` —— CoAP 发送（`coap://ip:5686` + `useCONs()`）
- `cafebabe/t4d.java` —— 业务参数 → payloadMap（`deviceId/serviceId/uuid/data`）

---

## 2. 协议总览

```
┌──────────┐   CoAP/UDP 5686    ┌──────────────┐
│ App/脚本 │ ─────────────────► │  台灯(134D)  │
│          │ ◄───────────────── │              │
└──────────┘   ACK 2.05 + JSON  └──────────────┘

阶段 1  会话： POST /.sys/sessMngr     明文 JSON（sn1/seq → sn2/sessId/seq）
阶段 2  控制： POST /<serviceId>       AES-128-CBC + HMAC-SHA256
阶段 3  回报： ACK 2.05                同结构加密，明文为设备状态
```

### 2.1 CoAP 报文骨架

| 字段 | 值 |
|---|---|
| Version / Type | 1 / `CON`（请求），`ACK`（响应） |
| TKL | 3（随机 3 字节 token） |
| Code | 请求 `0x02`（POST）；响应 `0x45`（2.05 Content） |
| Message ID | 随机 16 位 |
| Options | 见下表 |

### 2.2 选项表（业务请求）

| 选项号 | 名称 | 编码内容 | 长度示例 |
|---|---|---|---|
| 11 | Uri-Path | `serviceId`（如 `switch`、`brightness`） | 6 |
| 12 | Content-Format | `50`（application/json） | 1 |
| 2048 | Session-Id | 会话 ID（15 字符，`sessId`） | 15 |
| 2050 | Request-Id | 每次控制随机 UUID（36 字符） | 36 |
| 2051 | Device-Id | `<DEVICE_ID_OLD>` | 36 |
| 2052 | User-Id | `AES-128-CBC(华为账号ID) ‖ IV16` | 48 |
| 2053 | Seq | 大端整数（按字节数动态长度） | 2 |
| 2056 | Account-Id | App 的 uuid，如 `<ACCOUNT_ID>` | 16 |

> 选项必须按编号升序排列；2048 相对 12、2056 相对 2053 的增量分别用 CoAP 的 13/14 扩展编码。

### 2.3 payload 结构

```
payload = AES-128-CBC( JSON ) ‖ IV(16B) ‖ HMAC-SHA256(32B)
```

---

## 3. 阶段一：会话建立（明文）

**请求**：`POST coap://192.168.78.101:5686/.sys/sessMngr`

- Uri-Path 两段：`.sys`、`sessMngr`
- Content-Format：50
- 选项 2056：`<ACCOUNT_ID>`
- payload（明文 JSON，无加密）：

```json
{"type":1,"modeSupport":3,"sn1":"<SN1>","seq":8587}
```

| 字段 | 含义 |
|---|---|
| `type` | 固定 `1` |
| `modeSupport` | 支持的鉴权模式位图，固定 `3`（authCode 模式） |
| `sn1` | 客户端随机 8 字节（16 个十六进制字符，**大写**） |
| `seq` | 客户端随机初始序号（0–32767） |

**响应**（ACK 2.05，明文 JSON）：

```json
{"errcode":0,"modeResp":1,"sessId":"4r7Qpe6N2IHEE6W","seq":60710,"sn2":"797166676e506e61"}
```

| 字段 | 含义 |
|---|---|
| `errcode` | 0 成功 |
| `modeResp` | 设备选定的鉴权模式（1） |
| `sessId` | 会话 ID，后续控制必须携带 |
| `seq` | 设备给出的**应用侧序号基准**，控制时从 `seq+1` 开始 |
| `sn2` | 设备随机 8 字节（16 个十六进制字符，**小写**） |

**密钥盐**：`salt = hexToBytes(sn1) ‖ hexToBytes(sn2)`（共 16 字节）。

实测原始报文（App 发出）：

```
4302a46bbf9618b4 2e737973 08 736573734d6e6772 11 32 ed06ef 03 <ACCOUNT_ID_HEX>
ff <SESSION_JSON_HEX_HEAD>
<SESSION_JSON_HEX_TAIL>
```

解析：`43 02` = ver1/CON/TKL3，MID=`a46b`，Token=`bf9618`，Uri-Path=`.sys`+`sessMngr`，Content-Format=50，Option 2056=`<ACCOUNT_ID>`，随后 0xFF + 明文 JSON。

---

## 4. 阶段二：业务控制（加密）

**请求**：`POST coap://192.168.78.101:5686/<serviceId>`

### 4.1 密钥派生（与设备端一致）

```
authCode  : 16 字节（32 个十六进制字符），按 hex 解码后作为 PBKDF2 口令
salt      : sn1(8B) ‖ sn2(8B)
PSK       : PBKDF2-HMAC-SHA256(authCode, salt, 1, 32)[0..16]     // 取前 16 字节 → AES-128
HMACKey   : PBKDF2-HMAC-SHA256(PSK,       salt, 1, 32)           // 32 字节
```

> 迭代次数为 **1**（代码里 `p1f.d(..., 1, 32)`，即 PBKDF2 单轮），这是 HiLink 该版本的实际参数。

### 4.2 封装步骤

1. 业务 JSON 先 `trim()`，UTF-8 编码；
2. 随机 16 字节 IV，`AES/CBC/PKCS5Padding` 加密 → `C`；
3. `body = C ‖ IV`；
4. 组 CoAP 报文 `M`：头 + MID + Token + 全部选项 + `0xFF` + `body`；
5. `MAC = HMAC-SHA256(HMACKey, M)`；
6. 最终 payload = `body ‖ MAC`，以 `M` 的选项骨架重新发送（唯一区别是 payload 尾巴多了 32B MAC）。

> ⚠️ 关键实测结论：**HMAC 覆盖的是「包含选项 2056 的整条报文」**。反编译代码里的 `getCoapBytes()` 少写了 2056，容易误判；用真实报文验证时，只有「含 2056」的版本能通过校验，设备对 MAC 错误**静默丢弃**（无任何响应），排障时先核对这一点。

### 4.3 业务 JSON（payloadMap）

```json
{"on":1}                     // switch / nightSwitch / backlight
{"brightness":200}           // brightness
{"colorTemperature":4000}    // cct
{"mode":2}                   // lightMode
```

**实测原始报文**（App 发出，247 字节）：

```
4302 b41b b6a9b8
b6 737769746368                              // option 11 "switch"
11 32                                        // option 12 = 50
ed 06e7 02 <SESS_ID_HEX>                     // option 2048 "<SESS_ID>"
2d 17 <REQUEST_ID>                           // option 2050 requestId
1d 17 <DEVICE_ID_OLD>                        // option 2051 deviceId
1d 23 <USER_ID_CIPHER>                       // option 2052 AES(userId)‖IV (48B)
12 7243                                      // option 2053 seq = 0x7243 = 29251
3d 03 <ACCOUNT_ID_HEX>                       // option 2056 accountId
ff <PAYLOAD_HEX>                             // payload = 密文16 ‖ IV16 ‖ HMAC32
```

解析结果（`tools/decode_coap.mjs`）：

```
option 11   "switch"
option 12   "2"(=50)
option 2048 "<SESS_ID>"
option 2050 "<REQUEST_ID>"
option 2051 "<DEVICE_ID_OLD>"
option 2052 <USER_ID_CIPHER> (48B)
option 2053 0x7243
option 2056 "<ACCOUNT_ID>"
HMAC 校验: 通过
明文: {"on":1}
```

### 4.4 序号（Seq）规则

- 会话响应里的 `seq` 为基准，首条控制用 `seq+1`，之后每条 `+1`；
- 设备有窗口校验（代码里窗口 30），乱序/回退会被判为非法；
- 实测 `seq` 与 `seq+1` 都能被接受，但**建议严格 +1**，避免长时间运行后偏移。

---

## 5. 阶段三：设备回报

响应 `ACK 2.05`（code `0x45`），选项：`2048 / 2050 / 2051 / 2053`（无 2052、2056、11、12），payload 结构与请求相同（密文 ‖ IV ‖ HMAC），用同一 PSK 解密：

```json
{
  "devId": "<DEVICE_ID_OLD>",
  "services": [
    {"sid": "switch", "reportId": "9303205900201", "data": {"on": 1}}
  ],
  "devicedelay": 9
}
```

| 字段 | 含义 |
|---|---|
| `sid` | 服务 ID（与 Uri-Path 对应） |
| `reportId` | 设备侧状态上报流水号，单调递增，可用于去重 |
| `data` | 该服务的当前值（即执行结果） |
| `devicedelay` | 设备内部处理耗时（ms），App 用于体验统计 |

实测响应解码：

```
6345 515c 832f4c
ed 06f3 02 <SESS_ID_HEX>
2d 17 <REQUEST_ID_2>
1d 17 <DEVICE_ID_OLD>
12 0fa7
ff b69bc853...b972c76d
→ HMAC 校验: 通过
→ 明文: {"devId":"<DEVICE_ID_OLD>","services":[{"sid":"switch","reportId":"9303205900201","data":{"on":1}}],"devicedelay":9}
```

---

## 6. 服务与属性字典（prodId 134D）

来源：`HomeBase.db → DeviceConfigTable(134D)` 的 profile JSON。

| serviceId | 属性 | 类型 | 取值范围 / 枚举 | 说明 |
|---|---|---|---|---|
| `switch` | `on` | bool | 0/1 | 主灯开关 |
| `nightSwitch` | `on` | bool | 0/1 | 侧边灯（小夜灯） |
| `backlight` | `on` | bool | 0/1 | 底座背光/指示 |
| `brightness` | `brightness` | int | **26–255** | 亮度，26≈10%（UI 百分比） |
| `cct` | `colorTemperature` | int | **2000–6500** | 色温（K） |
| `lightMode` | `mode` | enum | **2**=阅读 `3`=读写 `4`=电脑 `6`=自定义（最爱） | 场景模式 |
| `timer` | — | — | — | 定时（番茄钟等） |
| `delay` | — | — | — | 倒计时 |
| `update` | — | — | — | OTA |
| `netInfo` | — | — | — | 网络信息 |

---

## 7. 复现工具与用法

### 7.1 控制脚本 `opple_lamp.mjs`（Node ≥ 18，无第三方依赖）

```bash
# 单条
node opple_lamp.mjs on
node opple_lamp.mjs off
node opple_lamp.mjs brightness=200      # 26~255
node opple_lamp.mjs cct=4000            # 2000~6500
node opple_lamp.mjs mode=2              # 2阅读 3读写 4电脑 6自定义
node opple_lamp.mjs side=on             # 侧边灯
node opple_lamp.mjs backlight=off

# 同一会话内连续多条（推荐，避免重复建会话）
node opple_lamp.mjs on brightness=120 mode=2
```

可用环境变量覆盖设备参数（换设备时用）：

```bash
LAMP_IP=192.168.78.101 \
DEVICE_ID=<DEVICE_ID_OLD> \
ACCOUNT_ID=<ACCOUNT_ID> \
USER_ID=<USER_ID> \
AUTH_CODE=<AUTH_CODE_OLD> \
node opple_lamp.mjs on
```

输出示例：

```
[i] 本地端口 62615 -> 192.168.78.101:5686
[i] 会话 <SESS_ID_2> sn1=<SN1_2> sn2=<SN2_2> seq=26922
[√] switch {"on":1} -> {"devId":"<DEVICE_ID_OLD>","services":[{"sid":"switch","reportId":"9303230900284","data":{"on":1}}],"devicedelay":9}
[√] brightness {"brightness":120} -> {... "data":{"brightness":120} ...}
[√] lightMode {"mode":2} -> {... "data":{"mode":2} ...}
```

### 7.2 报文解析 / 校验 `tools/decode_coap.mjs`

```bash
node tools/decode_coap.mjs <报文hex> <authCode> <sn1> <sn2>
```

输出选项表、HMAC 校验结果、解密明文。用于验证抓包或排查「设备无响应」。

---

## 8. 换一台设备怎么取密钥

本协议的控制权限完全由每台设备独有的 `authCode` 决定（另需账号侧 `userId`、`accountId`、设备 `deviceId`）。

### 8.1 需要收集的 4 个值

| 名称 | 来源 | 示例 |
|---|---|---|
| `deviceId` | App 设备列表 / `SmartHome.db.DeviceInfoTable.deviceid` | `<DEVICE_ID_OLD>` |
| `accountId` | App 的 uuid（`xsd.b().n()`），也出现在 CoAP 选项 2056 | `<ACCOUNT_ID>` |
| `userId` | 华为账号 ID（`j9d.G()`） | `<USER_ID>` |
| `authCode` | 云端下发、App 落库（加密存储） | `<AUTH_CODE_OLD>` |

### 8.2 方法 A：Frida 直接读（推荐，已实测）

设备端跑 `frida-server 17.24.3 (android-arm64)`，PC 端 `frida` + `frida-compile` + `frida-java-bridge`（Frida 17 起 Java 桥需自行打包）：

```bash
adb push frida-server /data/local/tmp/ && adb shell su -c 'chmod 755 /data/local/tmp/frida-server'
adb shell su -c 'nohup /data/local/tmp/frida-server -l 127.0.0.1:27042 &'
adb forward tcp:27042 tcp:27042

cd frida
npx frida-compile agent.js -o agent.bundle.js
node run.js        # 脚本内 attach com.huawei.smarthome 并调用：
```

`agent.js` 核心（见 `frida/agent.js`）：

```js
const Java = require('frida-java-bridge').default;
Java.perform(() => {
  const inst = Java.use('cafebabe.xsd').b();          // 单例 DBManager
  const t = inst.m('<DEVICE_ID_OLD>');                     // DeviceLocalControlTable
  send({
    authCode: String(t.getAuthCode()),
    sn1: String(t.getSn1()), sn2: String(t.getSn2()),
    sessionId: String(t.getSessionId()),
    uuid: String(inst.n()),                           // accountId
    userId: String(Java.use('cafebabe.j9d').G()),     // 华为账号
  });
});
```

> 混淆类名随 App 版本变化：用 jadx 搜索字符串 `LocalControl-CoapControlHiLinkBuilder` / `DeviceLocalControlDbManager` 即可定位新的 `xsd`、`j9d` 等类。

### 8.3 方法 B：云端接口

App 通过 `POST /home-manager/v1/homes/devices/authcode` 拉取 authCode（字符串见 `classes19.dex`），携带华为账号的 access token 即可拿到同一份密钥。

### 8.4 不能直接读数据库

`HomeBase.db.DeviceLocalControl` 里的 `authCode`、`sessionInfo` 由 `cafebabe.upe` 使用 **AES-GCM** 加密，工作密钥再用 `Android Keystore`（别名 `com.huawei.smarthomeAppCommonAesGcmKeyStore`）包裹后存 SharedPreferences，离线拷贝 DB 无法还原明文 —— 必须运行时读取（方法 A）或走云端（方法 B）。

---

## 9. 注意事项 / 限制

1. **仅局域网可用**：设备只监听 UDP 5686，跨网段/公网不可达（云端通道是另一套 MQTT+HTTPS）。
2. **会话互斥**：设备同一时刻只保留一个本地会话；脚本新建会话会让 App 的旧会话失效，App 下次控制会报 `9206` 并自动重建会话（实测 1 次点击即可恢复）。脚本与 App 混用时属正常现象。
3. **MAC 错误无回包**：设备对 HMAC 不通过的报文静默丢弃，表现为「完全没响应」；排查顺序应为：MAC 覆盖范围 → 会话 ID 是否最新 → seq 是否在窗口内。
4. **seq 递增**：每条控制 +1；跨会话重新从响应 `seq+1` 起算。
5. **请求 ID / MID / Token 随机**即可，但 MAC 必须与最终报文一致（先算 MAC 再补进 payload）。
6. **亮度值是 26–255 的线性标度**，不是百分比；UI 的 10% 对应 26。
7. **reportId 单调递增**，可作为状态去重/幂等依据。
8. 设备对高频请求有限流（App 侧点按过快会出现 `under control`），批量控制建议 ≥100ms 间隔。

---

## 10. 附录：证据清单

| 文件 | 内容 |
|---|---|
| `apk/huawei_smarthome_base.apk` | 原始 APK（161 MB，25 个 dex） |
| `src_full/sources/…` | jadx 全量反编译（关键类见 §1.3） |
| `appdata/sm/SmartHome.db`、`HomeBase.db` | 设备列表、prodId、profile、本地控制表 |
| `proxy_dev.log` | 手机侧代理抓到的 **App 真实请求**（去重后 4 条唯一报文：2 条会话 + 2 条控制） |
| `sniff2.log` | AF_PACKET 抓到的 **设备回报**（ACK 2.05） |
| `sniff.log`、`udp_capture.txt` | 早期抓包样本 |
| `evidence_session.txt` | 进程内存中的会话三元组 `sn1\|sn2\|sessId` 与 sn1 明文证据 |
| `frida/agent.js`、`frida/run.js` | 运行时读取 authCode/userId/accountId 的脚本 |
| `tools/decode_coap.mjs` | 报文解析 + HMAC 校验 + 解密 |
| `opple_lamp.mjs` | 协议客户端（实测可控） |

### 未决/未展开

- `timer` / `delay` / `update` / `netInfo` 服务的字段结构未逐个抓包（推测同样走 `/<serviceId>` + `data` 对象）。
- 配网/发现阶段（CoAP 组播 `238.238.x.x?st=cloudSetup`、SoftAP `Hi- OPPLE-READINGLAMP-0134DX`）未深入。
- App 的云端 MQTT 通道（`AiLifeCoreMqttReceiver`）未分析，本文只覆盖本地直连。
