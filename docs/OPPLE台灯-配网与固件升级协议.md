# 欧普（OPPLE）读写台灯 —— 配网（下发 WiFi）与固件升级协议

> 续《OPPLE台灯协议分析.md》。本文聚焦两条链路：
> **① 初始化配网：App 如何把 SSID/密码下发给台灯；② 固件升级（OTA）：走哪条通道、报文长什么样。**
>
> 方法：APK 反编译静态还原（`src_full/`）+ 真机动态验证（台灯 `192.168.78.101`、App `com.huawei.smarthome 15.1.3.310`、Frida 调用 App 内部接口）。
>
> **一句话结论：**
> - 配网 = **设备 SoftAP + CoAP 明文 SPEKE 协商 + AES-256-GCM 加密的 `/CloudSetup/v2` 注册包**（`ssid/password` 就在这个包里）。
> - 固件升级 = **App 侧把 `update` 服务列入「禁止本地控制」黑名单，命令固定走云端 MQTT**（`{"action":0|1}`，topic `/smartHome/signaltrans/v2/categories/command`）；因此本地 CoAP `/update` 实测无响应。
>
> **阅读提示**：本文为公开版，设备标识、账号、`authCode`、云端 `code/psk`、家庭 WiFi 的 SSID/密码、白盒块与其封装密钥等均已替换为 `<PLACEHOLDER>` 形式；协议结构与字节语义保持原样。

---

## 0. 结论速查

| 链路 | 通道 | 关键端点 | 加密 | 验证状态 |
|---|---|---|---|---|
| 配网（下发 WiFi） | 设备 SoftAP 下 **UDP/5683 私有「白盒帧」**（**本机型不走 SPEKE**） | 单包：帧头(20B)+SSID明文+密码密文+注册包密文；设备回明文 `HI-ACK` | AES-128-CBC/PKCS7，**IV=16×0x00**，每帧随机密钥用**白盒**封装在帧头 | **真机实测 + 逐字节验证**（见 §1.9） |
| 配网前发现 | CoAP 5685（AP）/5686（STA） | `/.well-known/core?st=cloudSetup` | 明文 JSON | 代码 + 抓包 |
| 固件升级 | **云端 MQTT**（QoS1） | topic `/smartHome/signaltrans/v2/categories/command`，`to=/devices/<id>/services/update`，body `{"action":0\|1}` | TLS（MQTT over TLS） | **真机实测**：`channel=1`、errcode 0 |
| 固件升级（本地 CoAP） | — | `POST /update` | — | **App 主动禁用**（黑名单），设备也不响应 |
| 升级信息服务 | 设备上报 | `services[sid=update].data` = `{version,introduction,progress,bootTime,autoUpdateOn}` | — | 真机读取到实体 JSON |

---

## 1. 配网（给台灯下发 WiFi）

### 1.1 拓扑与前置条件

- 台灯 profile：`isSupportSoftAP=1`，配网 SSID `Hi- OPPLE-READINGLAMP-0134DX`（`SmartHome.db → DeviceList.deviceSsid`）。
- 设备处于配网态时开 SoftAP；手机连上后由设备做 DHCP，设备自身是网关（HiLink 常见 `192.168.43.1`，实际以 DHCP 下发为准，代码里从网关地址取 IP，没有硬编码）。
- App 侧主流程：`cafebabe.vfd` → `DeviceSpekeConfigNetworkTask`（`cafebabe.ju2`）→ `cafebabe.h71`（CoAP 发送器）。

```
[手机] --连接--> [台灯 SoftAP: Hi- OPPLE-READINGLAMP-0134DX]
        │
        ├─(1) GET  /.well-known/core?st=cloudSetup     取设备自述（devId/prodId/sn/...）
        ├─(2) POST /SPEKE            （多轮）          用设备 PIN 做 SPEKE 协商
        ├─(3) POST /CloudSetup/v2                       Base64(AES-GCM({"data":{ssid,password,...}}))
        └─(4) 设备连上路由器 → 云端绑定 → POST /localSetup/setupResult
```

### 1.2 端点 / 端口 / Content-Format

| 步骤 | URI | 端口 | Content-Format | Payload |
|---|---|---|---|---|
| 设备信息 | `/.well-known/core?st=cloudSetup` | 5685 | — | 空（GET） |
| SPEKE 协商 | `/SPEKE`（新版 `/SPEKE/v2`） | **5683**（`portType==2` → **5685**） | 50 | JSON 信封 |
| 注册（下发 WiFi） | `/CloudSetup/v2` | 同上 | 50 | Base64 字符串 |
| 配网结果 | `/localSetup/setupResult` | 同上 | **42** | `{"devId":…,"setupResult":0}` |

端口选择的原始代码（`cafebabe/h71.java`）：

```java
r71.B(new CoapRegisterBuilder(str2), i == 2 ? 5685 : CoAP.DEFAULT_COAP_PORT, cb);   // 注册
r71.A(new CoapSpekeBuilder(str2),   i == 2 ? 5685 : CoAP.DEFAULT_COAP_PORT, cb);   // SPEKE
```

### 1.3 第 1 步：设备自述

`CoapDeviceInfoBuilder` 返回字段（常量名）：

```
devId, devType, prodId, manu, model, sn, mac, hwv, swv, fwv, hiv,
devName, protType, services[{sid,st}], devWanIp, baseUrl, centralCapability, hcv, isCloudDeviceId
```

SoftAP 直连路径可以跳过（设备在注册响应里仍会带 `devId`）。

### 1.4 第 2 步：SPEKE 协商（PIN 鉴权）

- 需要**设备 PIN**（8 位，设备标签/引导页），App 字段 `RegisterEntity.devicePin`。
- 算法：华为 PIN/SPEKE SDK（`com.huawei.iotplatform.security.pin`）：
  - 3072-bit MODP 群（`PakeUtils.MOD_POW`），私钥 32 字节；
  - `computeSharedBase = g² mod p`，`computePublicParameter = base^x mod p`；
  - 共享秘密经 HKDF-SHA256 派生 32 字节会话密钥。
- 报文：每轮把 SDK 产出的 JSON **原样** POST 到 `/SPEKE`，把设备返回 JSON 回喂 SDK。信封结构（`cafebabe.dtd`）：

```json
{
  "sessionId": "<协商会话 ID>",
  "puuid": "<手机 uuid>",
  "cmd": "nego",
  "securityData": {
    "payload": { "operationCode": <int>, "...": "..." },
    "...": "..."
  }
}
```

协商成功 → 得到 `zia`（内部 32B key），供后续加解密。

### 1.5 第 3 步：注册包（真正下发 SSID / 密码）

#### ① 明文 JSON

```json
{"data": { ...RegisterEntity... }}
```

字段（`RegisterEntity` + `DeviceSpekeConfigNetworkTask.RegisterEntity`）：

| JSON 字段 | 含义 | 备注 |
|---|---|---|
| `ssid` | 目标路由器 SSID | App 读当前 WiFi |
| `password` | 目标 WiFi 密码 | **明文在 GCM 密文内** |
| `cloudUrl` | 设备应连的云地址 | 云端下发 |
| `devId` | 设备 ID | |
| `code` | 配网校验码 | 云端生成，用于账号-设备绑定 |
| `psk` | 配网预共享密钥 | 云端生成 |
| `appName` | App 标识 | |
| `authCode` / `authCodeId` | 本地控制密钥（可选下发） | 下发后即可局域网直连 |
| `cloudPrimaryUrl` / `devicePrimaryUrl` / `cloudStandbyUrl` / `deviceStandbyUrl` | 主备云地址与键名 | |
| `countryCode` | 国家码 | |
| `serviceName` | 服务名 | |
| `secret` | 附加密钥 | 部分机型 |
| `timeZoneId` / `timeZoneDisplay` | 时区 | |
| `uidHash` | 账号 uid 哈希 | |
| `wifiBgnSwitch` | 2.4G/5G 选择 | 值为 -1 时被过滤器剔除 |

序列化过滤器 `cafebabe.zh0`：`ssid` 为空则丢弃该字段；`wifiBgnSwitch == -1` 丢弃。

#### ② 加密 / 编码（可精确复现）

```java
// cafebabe/ju2.java → z()
String json = JSON.toJSONString({"data": registerEntity}, new zh0());
byte[] enc  = en3.e(session, json.getBytes("UTF-8"));           // → Cipher.aesEncrypt
this.l.i(ip, Base64.encodeToString(enc, 0), portType, cb);      // CoAP POST /CloudSetup/v2
```

`com.huawei.iotplatform.security.common.crypto.Cipher` 的实现：

```java
// AES/GCM/NoPadding，128-bit tag，12B IV
iv = random(12);
cipher.init(ENCRYPT, new SecretKeySpec(key,"AES"), new GCMParameterSpec(128, iv));
out = concat( 0x00, iv, cipher.doFinal(plain) );                // 0x00 = 版本号
```

即：

```
payload_bytes = 0x00 ‖ IV(12B) ‖ AES-GCM(明文JSON) ‖ TAG(16B)      # 密钥=SPEKE 会话密钥（32B，AES-256）
CoAP payload  = Base64(payload_bytes)     // 标准 Base64，NO_WRAP
```

设备回包同样结构：`Base64(0x00‖IV‖CT‖TAG)` → 解密得：

```json
{"errcode":0, "lastStep":<int>, "lastError":<int>}
```

`lastStep/lastError` 是设备配网状态机的位置/错误码，App 用于失败引导。

#### ③ 设备侧动作

解密 → 用 `ssid/password` 连路由器 → 用 `cloudUrl + devId + code/psk` 向云端注册绑定 → App 轮询绑定状态（`/c/service/getBindStatus` 等）。

### 1.6 第 4 步：配网结果回报

```json
POST /localSetup/setupResult          // Content-Format 42
{"devId":"<DEVICE_ID_OLD>","setupResult":0}
```

`CoapReportSetupResultBuilder`：超时 10s；若会话安全类型为 GCM/CBC，body 会再套一层 `SecuritySessionManager` 加密（CBC：AES-CBC/PKCS5 + 16B IV；GCM：`00‖IV12‖CT‖TAG`）。

### 1.7 复现伪代码

```python
ip = dhcp_gateway()                                      # 例 192.168.43.1
dev_id = coap_get(f"coap://{ip}:5685/.well-known/core?st=cloudSetup")["devId"]

sess = speke_new(pin="12345678", device_id=dev_id)       # 华为 PIN SDK
while not sess.done:
    sess.feed(coap_post(f"coap://{ip}:5683/SPEKE", sess.next_frame_json()))

reg = {"data": {"ssid":"MyWiFi","password":"12345678","devId":dev_id,
                "cloudUrl":"https://…","code":"…","psk":"…",
                "appName":"com.huawei.smarthome","countryCode":"CN"}}
enc = b"\x00" + iv12 + aes_gcm_encrypt(json.dumps(reg,separators=(",",":")), sess.key)
coap_post(f"coap://{ip}:5683/CloudSetup/v2", base64.b64encode(enc), content_format=50)
coap_post(f"coap://{ip}:5683/localSetup/setupResult",
          json.dumps({"devId":dev_id,"setupResult":0}), content_format=42)
```

### 1.8 实测边界

台灯当前处于 **STA 模式（已绑定、在线）**，配网端点不开放，且非法报文被静默丢弃：

```
POST /CloudSetup/v2 "AAAA"            → 无响应
POST /SPEKE "{}"                      → 无响应
POST /localSetup/setupResult "{}"     → 无响应
POST /.sys/sessMngr "{}"              → 无响应（合法会话请求才有回包）
```

要有逐帧字节，需让台灯进入配网模式（长按灯体/上电操作），手机连其 SoftAP 后抓包。该操作会把台灯从当前 WiFi 解绑，属破坏性操作，本次未执行。

### 1.9 真机实测（2026-10-27 20:30）：本机型**不走 SPEKE**，`securityData` 不存在

#### ① 路径判定

App 有两条配网实现，按 `mPinType`（= `v7f.c().E(设备SSID)` 的版本，只有 `"1"/"2"` 才算有 PIN）二选一（`cafebabe/vfd.x0()`）：

```java
if (u1()) { L0(regMsg); new DeviceSpekeConfigNetworkTask(...) }   // 有 PIN → /SPEKE + /CloudSetup/v2
else      {            new tqe(...) }                             // 无 PIN → 白盒帧
```

本台灯重置后广播 `Hi- OPPLE-READINGLAMP-0134DC`，版本参数为 0 → 走 **`cafebabe.tqe`**。
实测抓到的唯一配网报文是 516B 的私有帧（不是 CoAP，也**没有任何 `/SPEKE` 帧**），因此**这台灯没有 `securityData`**——`securityData` 是 SPEKE 路径专有的。

#### ② 抓包方法（可复现）

坑：`iptables DNAT` 若不限定 UID，会把代理自己的转发包再次 DNAT 回去，形成自环（上一轮就是这样把日志写成 477MB、把真实帧冲掉的）。正确做法：

```sh
# 只重定向 App(uid 10143) 发往设备 AP 网关的包，代理以 root 身份转发不受影响
iptables -t nat -A OUTPUT -p udp -d 192.168.5.1 --dport 5683 -m owner --uid-owner 10143 -j DNAT --to-destination 127.0.0.1:5683
nohup /data/local/tmp/udpproxy 5683 192.168.5.1 5683 > /data/local/tmp/prov5683.log 2>&1 &
```

脚本：`tools/prov_start.sh` / `prov_stop.sh`（已推送至手机 `/data/local/tmp/`）。

#### ③ 帧格式（已用本帧逐字段验证）

```
偏移      内容
[0]       校验1 = crc8( keyId )            keyId = AP SSID 第4段去掉首字符取5位 → "134DC"
[1]       校验2 = crc8( frame[2..iA) )     计算时 byte1 先置 0；iA = 未补齐长度
[2]       类型  = (1|2|3)<<4               0x10 = b7e.q()==100（设备类别）
[3..18]   16B 白盒块 = WhiteBox(mode=类型, key=AES密钥, data=密码密文前16B)
[19]      长度  = (ssidLen-1) | (((pwdCipherLen>>4)-1)<<5)
[20..]    SSID 明文（UTF-8）
...       密码密文   = AES-128-CBC/PKCS7(密码, 每帧随机密钥, IV=16×0x00)
...       1B        = 注册包密文长度 >> 4
...       注册包密文 = AES-128-CBC/PKCS7( 注册 JSON, 同一密钥, 同一 IV)   ← 本机型是**扁平对象**，无 `{"data":…}` 外壳（见 ⑨）
末尾      总长为奇数时补 1 字节 0x00
```

`crc8`：`init=0xFF，poly=0xB8，LSB-first`（`h8f.a()` / `tqe.l()` 的 `Opcodes.INVOKESTATIC` = 184）。

#### ④ 实抓报文（`prov_frame_1.hex`，手机 192.168.5.100 → 台灯 192.168.5.1:5683）

```
a57810de <WHITEBOX_BLOCK_3_HEAD> 0d
<HOME_SSID_HEX>                       ← "<HOME_SSID>"（14B 明文）
<PWD_CIPHER_2>                   ← 密码密文 16B
1d
<REG_CIPHER_HEAD>…（464B）                     ← 注册包密文
00
```

解码结果（`tools/decode_prov_frame.mjs`）：

```
总长度 516（未补齐 515）
byte0 0xa5  = crc8("134DC") ✓
byte1 0x78  = crc8(frame[2..515)) ✓
byte2 0x10  → 设备类别 100
白盒块  <WHITEBOX_BLOCK_3>
SSID    "<HOME_SSID>"（明文）
密码    AES-CBC 密文 16B
注册包  464B 密文（明文为 {"data":{ssid,password,cloudUrl,devId,code,psk,authCode,…}}）
```

#### ⑤ 为什么不能离线解开注册包

- 每帧用 `rre.d()` 生成一把**随机 AES-128 密钥**；
- 密钥被 `CommonLibUtil.whiteBoxEncrypt(mode, key16, base64(AESkey))` 用华为**白盒**（`libsecurityi.so`，`WhiteBox` 原生实现）封装进帧头；
- 白盒解密需要设备/固件内嵌的白盒表，App 侧只有加密方向可用；
- 结论：**离线只有密文**；要拿明文只能在 App 运行时取（见下）。

#### ⑥ 想要注册包明文 / 密钥，两条现成路线

1. **hook 密钥**（最省事）：hook `com.huawei.iotplatform.appcommon.base.openapi.utils.CommonLibUtil.whiteBoxEncrypt(int, byte[], String)`，第 3 参就是 Base64(AES密钥)，拿到后用 `aes-128-cbc + IV=0` 解 `prov_frame_1.hex` 的两段密文即可。
2. **hook 明文**：hook `cafebabe.tqe` 的构造/`a.run()`，直接读 `tqe.b`（`mRegMessage`，就是 `{"data":{…}}` 原文）。

两者都需要台灯**再次进入配网模式**（SoftAP）时执行一次。

#### ⑦ 第三次复现（22:2x）：又抓到一帧，但密钥没拿到

- 重新按上面流程配网，再次成功；抓到 4 条重传的同一帧（`prov_frame_2.hex`），解码校验同样全过：
  `byte0=0xa5 ✓`、`byte1=0xaf ✓`、白盒块 `<WHITEBOX_BLOCK_2>`、SSID `<HOME_SSID>`、密码密文 `ad38f08e…`、注册包密文 464B。
- **失败原因**：配网过程中 App 进程被系统重启（pid 变了），先前 attach 的 Frida hook 随旧进程失效，`dnd.a` / `whiteBoxEncrypt` 一次都没触发 → 没有该帧的 AES 密钥。
- **对策**：已写守护式 hook `frida/watch_prov.js`（每 700ms 轮询 App pid，进程一变就自动重新 attach 并加载 hook），已本地验证可跨重启重连。
- 该轮新设备 ID：`<DEVICE_ID_2>`，authCode：`<AUTH_CODE_2>`；本地控制复测通过（brightness/off）。


#### ⑧ 本轮配网结果

| 项 | 结果 |
|---|---|
| 台灯是否加入家庭 WiFi | ✅ **三次**实测均成功，回到 `192.168.78.101`（MAC `<DEVICE_MAC>`） |
| App 是否完成绑定 | ✅ 已完成，最终 deviceId = 注册包里的 `<DEVICE_ID>`（**与注册包 `devId` 完全一致**） |
| 新本地控制密钥 | `authCode = <AUTH_CODE>`，`authCodeId = <AUTH_CODE_ID>`，`authCodeFlag=2` |
| 本地控制复测 | ✅ `on brightness=80` / `off` 均返回正常（`devId=<DEVICE_ID>`） |
| 设备 ACK | 明文 `HI-ACK`（`tqe.b.c()` 判定；本帧因设备随即切走 SoftAP 未抓到） |
| 旧密钥 | 重置前的 `deviceId=<DEVICE_ID_OLD>` / `authCode=<AUTH_CODE_OLD>` 已失效 |



---

## 2. 固件升级（OTA）

### 2.1 设备侧的升级服务模型（真机读取）

用 Frida 调 `DataBaseApiBase.getSingleDevice(devId).getDeviceInfo()` 拿到的设备实体：

```json
"devInfo": {
  "devType":"046","deviceName":"台灯","model":"READINGLAMP","prodId":"134D","manu":"013",
  "fwv":"6.3.6","swv":"9.0.10.323","hwv":"1.0.0","hiv":"1.0","protType":"1",
  "sn":"<DEVICE_SN>","udid":"<DEVICE_SN>","mac":"<DEVICE_MAC>"
}
```

`services[]` 中的升级服务（注意 `sid` 与 `st` 不同）：

```json
{"sid":"update","st":"devOta",
 "data":"{\"bootTime\":0,\"action\":0,\"progress\":0,\"version\":\"\",
          \"introduction\":\"\",\"autoUpdateOn\":0}"}
```

| 属性 | 类型 | 方向 | 说明 |
|---|---|---|---|
| `action` | enum | W | `0`=检查新版本，`1`=启动升级 |
| `version` | string | R | 版本号（当前为空 = 无新版本） |
| `introduction` | string | R | 版本说明 |
| `progress` | int 0–100 | R | 升级进度 |
| `bootTime` | int | R | 升级后启动耗时 |
| `autoUpdateOn` | int | RW | 自动升级开关 |

其它服务（实测）：`switch{on:0}`、`brightness{brightness:26,on:0}`、`backlight{on:0}`、`cct{colorTemperature:4000}`、`lightMode{mode:2}`、`nightSwitch{on:1}`、`faultDetection`、`netInfo`、`timer`、`delay`、`diagnose`。

### 2.2 关键机制：App 把 `update` 列入「禁止本地控制」黑名单

`cafebabe/mwd.java`（本地 CoAP 通道的 `isAvailable`）里有一组硬编码黑名单：

```java
this.c.add("update");
this.c.add("timer");
this.c.add("delay");
this.c.add("diagnose");
this.c.add("netInfo");
this.c.add("remoteCode");
this.c.add("enableState");
this.c.add("keyOperate");
this.c.add("e2eCtrlState");
this.c.add("sts"); this.c.add("stsSession"); this.c.add("control"); this.c.add("speke");
```

命中黑名单 → 本地通道 `isAvailable` 直接 false → 落到 MQTT 通道。

**这解释了两件事：**
1. 我们手工向 `/update`、`/devOta` 发 `{"action":0}` 一直无响应——设备本来就不在本地实现该服务，App 也从不会这么发。
2. `timer` / `delay` / `netInfo` 同样只能走云（这也印证了 profile 里它们虽然声明 `RW`，但本地 CoAP 不提供）。

### 2.3 实测：App 的升级检查命令（云端 MQTT）

用 Frida 直接调用 App 自己的控制入口，模拟一次「检查新版本」：

```js
// frida/agent_ota.js
const map = HashMap.$new(); map.put('action', Integer.valueOf(0));
DeviceControlManager.getInstance().modifyDeviceProperty(devId, 'update', null, map, callback);
```

结果（logcat + 回调）：

```
DeviceControlImpl: getChannel getTopoType:-1
DeviceControlImpl: getChannel mqtt
DeviceControlImpl: getChannel type:1
DeviceControlImpl: control channel is 1
CommonControlCallback: controlInfo{ characteristics=[action], channel=1, errorCode=0,
                                    serviceId=upda**, deviceId=<DEVICE_ID_OLD>}
回调: {"errcode":0,"devicectltype":0,"devicedelay":2}

埋点: service_datamap_list=[{"update":{"action":0}}]  device_product_id=134D  device_swv=9.0.10.323
```

命令报文（`cafebabe/bbe.java` = `MqttControlChannel`）：

```
topic : /smartHome/signaltrans/v2/categories/command      (QoS 1)
payload:
{
  "header": {
    "method": "POST",
    "accessToken": "<华为账号 AT>",
    "mode": "ACK",
    "requestId": "<uuid>",
    "from": "/users/<uid>",
    "to": "/devices/<DEVICE_ID_OLD>/services/update",
    "timestamp": "20261027T080557Z"
  },
  "body": { "action": 0 }
}
```

- `method`：`GET`（无参数）或 `POST`（带 characteristics）。
- 启动升级就是把 `body` 换成 `{"action":1}`。
- 云端把命令透传给设备；设备回 ACK（`mode:"ACK"`，带 `requestId` 关联）。

### 2.4 升级进度 / 结果

设备通过服务数据上报（App 的 `DeviceUpgradeActivity` 解析）：

```json
{"sid":"update","data":{"progress":42,"version":"6.3.7","introduction":"…","bootTime":0}}
```

判定逻辑（`com.huawei.smarthome.about.DeviceUpgradeActivity`）：

- `progress > 0` → 显示升级进度条；
- `progress == 0` 且 `version` 非空 → 提示有新版本；
- 升级结束 `progress == 100` 且 `bootTime` 变化 → 判定成功。

### 2.5 云端 OTA 接口（App 内置的另一条路径）

`a/a/a/f/j.java` 常量表：

| 常量 | 路径 | 用途 |
|---|---|---|
| `X` | `/c/service/devmanager/v1/getProductOtaInfos` | 按产品查可用固件（版本/大小/md5/下载地址/灰度） |
| `V` | `/c/service/triggerOtaUpdate` | 触发设备升级（指定目标版本） |
| `W` | `/c/service/getOtaProgress` | 轮询升级进度 |
| `U` | `/c/service/frimUpdate` | 固件信息登记/更新 |

本机型实际走的是 **MQTT 控制命令**（2.3），上述 HTTP 接口主要服务于没有该控制通道的设备类型（路由/摄像头/音箱等）。

### 2.6 能否自己复刻升级？

| 目标 | 做法 | 说明 |
|---|---|---|
| 查询是否有新固件 | 复刻 2.3 的 MQTT 命令（需 accessToken）或读设备 `update.version` | `version` 为空即无新版本（当前实测为空） |
| 触发升级 | MQTT `body={"action":1}` | 需账号 token；升级中断有变砖风险 |
| 走本地 CoAP | 不可行 | 设备不实现、App 也禁用 |
| 自建固件 | 不可行 | 固件需华为云签名，设备侧有校验 |

---

## 3. 代码位置索引

| 主题 | 文件 |
|---|---|
| 配网主流程 | `cafebabe/vfd.java`（`assembleRegisterInfoVerOne` / `startDeviceApConnection`） |
| 配网任务、SPEKE、注册 | `cafebabe/ju2.java`（`A()` 起 SPEKE，`z()` 发注册包） |
| CoAP 发送器（5683/5685） | `cafebabe/h71.java`（`i()` 注册，`j()` SPEKE） |
| 注册实体字段 | `com/huawei/iotplatform/appcommon/deviceadd/entity/RegisterEntity.java`、`.../logic/DeviceSpekeConfigNetworkTask.java` |
| 序列化过滤 | `cafebabe/zh0.java` |
| GCM 封装 | `com/huawei/iotplatform/security/common/crypto/Cipher.java` |
| SPEKE 参数 / 信封 | `com/huawei/iotplatform/security/common/util/PakeUtils.java`、`cafebabe/dtd.java` |
| setupResult | `.../coap/builder/CoapReportSetupResultBuilder.java`、`.../coap/model/b.java` |
| 本地通道黑名单 | `cafebabe/mwd.java`（`isAvailable`） |
| 现成工具 | `opple_lamp.mjs`（含 `svc:<id>:<json>` 通用命令）、`tools/send_raw.mjs`、`frida/agent_ota.js` |
| 配网抓包 | `tools/prov_start.sh` / `prov_stop.sh`（UID 限定 DNAT + udpproxy）、`prov5683.log`、`prov_frame_1.hex` |
| 帧解析 | `tools/decode_prov_frame.mjs`（校验、SSID、密文分段全部实测通过） |
| 通道选择 | `cafebabe/f2d.java`（`n()`） |
| MQTT 命令封装 | `cafebabe/bbe.java`（`g()`/`h()`） |
| 升级业务 | `com/huawei/smarthome/homeservice/manager/selfupgrade/device/HilinkUpgrade.java`、`.../about/DeviceUpgradeActivity.java` |
| OTA 云接口 | `a/a/a/f/j.java` |
| 设备实体（真机） | Frida：`DataBaseApiBase.getSingleDevice(id).getDeviceInfo()` |

---

## 4. 未决项

1. **本机型无 SPEKE/`securityData`**（已实测确认，走 `tqe` 白盒帧）。只有 `mPinType∈{1,2}` 的机型才会走 `/SPEKE`；那类机型的 `securityData` 内层字段本机无法验证。
2. **注册包明文**（`cloudUrl/code/psk/authCode` + WiFi 密码）：离线只有 AES 密文（密钥被白盒封装）。下次台灯进配网模式时，hook `CommonLibUtil.whiteBoxEncrypt` 取密钥、或 hook `cafebabe.tqe.b` 取明文即可补齐。
3. **MQTT 下行 `body` 是否会附加字段**（如 `cookie`、`subDev`）：代码里 body 就是 characteristics map，未见额外字段；如遇多子设备机型可能带 `subDev`。

#### ⑨ 完整解密结果（22:3x，实时 hook + 抓包同一帧，已 100% 对上）

**密钥**：`<WHITEBOX_KEY_B64>`（Base64，末尾带 `\n`，Android `Base64.DEFAULT` 特性）→ 16 字节 `<AES_KEY_HEX>`

**WiFi 密码**（16B 密文 `<PWD_CIPHER>` 解出）：
```
<WIFI_PASSWORD>
```

**注册包明文**（464B 密文解出，459 字节，扁平 JSON，**没有 `{"data":…}` 外壳**）：
```json
{"appName":"smarthome",
 "cloudPrimaryUrl":"wisedevice-hilink-drcn.things.dbankcloud.cn",
 "cloudPrimaryUrlKey":"hilinkDevicePrimaryCloudUrl",
 "cloudStandbyUrl":"wisedevice-hilink-drcn.things.dbankcloud.cn",
 "cloudStandbyUrlKey":"hilinkDeviceStandbyCloudUrl",
 "cloudUrl":"iomplatform.hicloud.com",
 "code":"<PROV_CODE>",
 "countryCode":"CN",
 "devId":"<DEVICE_ID>",
 "psk":"<PROV_PSK>",
 "serviceName":"com.huawei.cloud.wisedevice"}
```

交叉验证（三处一致）：

| 来源 | 值 |
|---|---|
| hook `dnd.a`（密码） | `<WIFI_PASSWORD>` / key `<WHITEBOX_KEY_B64>` |
| hook `whiteBoxEncrypt` | mode=100, data=`<PWD_CIPHER>`, out=`<WHITEBOX_BLOCK>` |
| 抓包帧 byte3..18 | `<WHITEBOX_BLOCK>` ✓ 与 hook 输出逐字节相同 |
| 抓包帧密码密文 | `<PWD_CIPHER>` ✓ 与 hook 的 data 相同 |

字段含义：

| 字段 | 说明 |
|---|---|
| `ssid` / 密码 | 不在 JSON 里，而是帧内的明文 SSID + 上面这段密文密码 |
| `devId` | 云端为本次配网分配的**新设备 ID**（`<DEVICE_ID>`）；它和 App 最终入库的 deviceId 不同，说明设备侧会再换一次 |
| `code` | 8 位绑定校验码（云端生成，一次一密） |
| `psk` | 32 hex 预共享密钥（设备向云端注册用） |
| `cloudUrl` | `iomplatform.hicloud.com`（GCM/业务接入点） |
| `cloudPrimaryUrl` / `cloudStandbyUrl` | `wisedevice-hilink-drcn.things.dbankcloud.cn`（HiLink 设备云主/备） |
| `serviceName` | `com.huawei.cloud.wisedevice` |
| `appName` / `countryCode` | `smarthome` / `CN` |

一次性脚本：`tools/collect_prov.mjs`（拉日志→取帧→用 hook 的密钥解密）；本次实测输出即上表。
#### ⑩ PC 侧实验（23:0x）：不绑账号能不能局域网控制？

环境：台灯恢复出厂进入配网态；PC 加了一块 USB 无线网卡（`WLAN 2`，Realtek RTL8187）连台灯热点，
同时保留 `WLAN` 上家庭网络的默认路由。

为避免"连上热点后电脑没网"：

```powershell
Set-NetIPInterface -InterfaceIndex 146 -InterfaceMetric 9000      # WLAN 2 跃点拉高
Remove-NetRoute -InterfaceIndex 146 -DestinationPrefix 0.0.0.0/0 -Confirm:$false
```

结果：`WLAN 2` 拿到 `192.168.5.100 / gw 192.168.5.1`，默认路由仍走 `WLAN`（metric 45），
访问外网正常（baidu 200），同时能 ping 通台灯网关（38-43 ms）。

台灯热点 SSID 有 **4 个尾空格**（32 字节），Windows 需用 profile 的 `<hex>` 精确匹配才能连上：

```
SSID(hex) = 48692d204f50504c452d52454144494e474c414d502d30313334444320202020
```

**探测结果**：配网态下设备**不提供**任何标准 CoAP/HTTP 服务——
UDP 5683 / 5685 / 5686 对 `/.well-known/core`、`/config`、`/device/info` 全部无响应；
TCP 80 / 443 / 8080 / 22 / 23 全部 filtered。也就是说 AP 模式只认那一个私有帧。

**重放抓包帧**（`prov_frame_3.hex`，516B，用 Rust `opple prov-send` 发到 `192.168.5.1:5683`）：

| 观察 | 结果 |
|---|---|
| 是否收到明文 `HI-ACK` | ✗ 超时（设备切 AP 太快，来不及回） |
| 台灯热点 | ✅ 立刻消失（`WLAN 2` 断开） |
| 台灯是否入网 | ✅ 约 20 秒后出现在家庭网络：`192.168.78.101`，MAC `<DEVICE_MAC>` |

→ **配网本身可以完全由 PC 完成**，不需要 App、不需要云端。

**紧接着测本地控制**（旧 authCode `<AUTH_CODE>` + 旧 deviceId `<DEVICE_ID>`）：

| 步骤 | 结果 |
|---|---|
| `opple session` | ✗ 超时 |
| `opple on` | ✗ 超时 |
| 端口状态 | 5686 不再返回 ICMP 不可达（端口像是开着的），但应用层不回应 |

**原因（代码证实）**：
`RegisterEntity` 只有 `cloudUrl / devId / code / psk / wifiBgnSwitch / password / ssid / pin`，
**没有任何 authCode 字段**；`RegisterInfoResponseEntity` 也只有 `errcode / lastStep / lastErr`。
即：设备在配网过程中既收不到、也不回传本地控制密钥，authCode **只可能来自云端绑定**。

**结论**：局域网控制可行（绑一次之后永久离线可控），但"完全跳过账号绑定"在这套固件上不成立——
恢复出厂后设备没有 authCode，本地控制端口不提供服务，必须先经 App/云端绑定一次。
---

## 5. 固件获取可行性（2026-10-27 23:2x 实测）

目标：拿到台灯固件做静态分析。逐条排除后，网络侧**没有**可取路径。

| 尝试 | 结果 |
|---|---|
| App 是否下载固件 | ❌ 不下载。App 只通过 MQTT 发 `{"action":0/1}`，固件由**设备自己**去 OTA 服务器拉 |
| 手机里是否有缓存固件 | ❌ 扫了 `/sdcard/Android/data/com.huawei.smarthome`、`/data/data/com.huawei.smarthome`，无 `.bin/.ota/.zip` 固件（只有日志与 db） |
| 设备是否开放端口 | ❌ TCP 1-12000 无真实开放端口（25/110/143 的"open"是 PC 侧 Mihomo TUN 代理假连接，同一组端口在路由器上也"open"，属误报） |
| 设备是否开放 CoAP | ❌ 未绑定状态下 5683/5685/5686 全无响应 |
| 公网是否有该型号固件 | ❌ 检索无果（OPPLE/HiLink 的固件不对外发布） |

结论：**固件只能从"设备下载 OTA 的那一刻"抓，或者拆机读 Flash。**

### 5.1 关键能力已验证：可给任意 SSID 组出合法配网帧

白盒块只与 **AES 密钥 + 密码前 16 字节密文** 绑定，SSID 在帧里是**明文**。所以只要密码不变，
就能复用同一白盒块给**任意 SSID** 组帧：

```
opple prov-build --ssid "OPPLE-TEST" --password <WIFI_PASSWORD> \
  --register @reg.json --key <WHITEBOX_KEY_B64> \
  --wb <WHITEBOX_BLOCK> --ap-ssid "Hi- OPPLE-READINGLAMP-0134DC"
```

实测（`prov_frame_test.hex`）：新帧 512 字节，SSID 变为 `OPPLE-TEST`，
而**白盒块 `<WHITEBOX_BLOCK>` 与密码密文 `<PWD_CIPHER>` 与原始帧完全一致**，两个校验字节复算通过。
→ 可以把台灯挪到我们自己的热点上，不需要 App、不需要重新抓白盒块。

### 5.2 推荐方案：手机热点 + tcpdump 抓设备 OTA

设备 `/vendor/bin/tcpdump` 已存在（已 root），手机做热点时 `ap0` 能看到客户端（台灯）全部流量：

1. 手机开热点：SSID `OPPLE-TEST`，密码 `<WIFI_PASSWORD>`（这样自定义帧也能用），开移动数据；
2. `su -c "/vendor/bin/tcpdump -i any -s0 -w /sdcard/lamp.pcap"`；
3. 台灯复位进配网态 → 用 App 添加（或直接发我们组的帧）把灯接入热点；
4. 绑定完成后触发升级（App 里"检查更新"或我们自己发 MQTT `update`）；
5. 在 pcap 里找 OTA 域名与下载 URL → PC 侧下载 → 分析。

### 5.3 备选：拆机读 Flash

台灯这类 HiLink 灯具通常是 WiFi 模组 + 外置 SPI Flash（或模组内置 Flash）。
拆开看丝印：若有 8 脚 SPI Flash（如 GD25Q32/W25Q64），用 CH341A 直接读；
若是模组内置 Flash（Hi3861/BK7231 等），走 UART 下载模式读。得到完整固件后再做 binwalk/strings。
### 5.4 热点抓包方案的实测阻塞（23:3x）

按 5.2 准备时发现两条硬阻塞：

| 检查项 | 结果 |
|---|---|
| SIM 状态 | `gsm.sim.state = ABSENT`（无卡） |
| 移动数据 | `mobile_data=0`，`airplane_mode_on=1`，`mVoiceRegState=POWER_OFF` |
| 热点开关 | MIUI 在无数据时把"便携式 WLAN 热点"开关置灰，点了不生效（`wlan1` 一直 DOWN） |
| 手机自带抓包 | ✅ `/vendor/bin/tcpdump` 存在，已部署 `/data/local/tmp/lamp_capture.sh` |

结论：**没有 SIM 就没有上行链路，热点开不起来，5.2 的"手机热点 + tcpdump"暂时走不通。**

可行的替代：

1. **换一张有流量的卡**（或临时插卡）→ 直接走 5.2；
2. **用能抓包的路由器/软路由**（OpenWrt 的 tcpdump / 端口镜像）承载台灯，同样能拿到 OTA 域名与 URL；
3. **拆机读 Flash**（5.3），不依赖网络。

注：本机（PC）侧已有 Mihomo TUN，TCP 端口扫描会把 25/110/143 等报成 open（假连接），判断设备端口时必须排除这一干扰。
---

## 6. 台灯入网抓包与本地 API 新发现（2026-10-29 23:5x）

### 6.1 抓法与结果

树莓派（`pi@pi.local`，`192.168.78.107`）：

```bash
# USB 网卡 RTL8187 不支持 AP，但支持 monitor
sudo ip link set wlan1 down
sudo iw dev wlan1 set type monitor
sudo ip link set wlan1 up
sudo iw dev wlan1 set channel 1          # 家里 2.4G BSSID <HOME_AP_BSSID> 在 2412MHz
sudo tcpdump -i wlan1 -s 0 -w /tmp/lamp.pcap -U -n
```

用手机（连台灯热点）`udpsend 192.168.5.1 5683 prov_frame.hex` 把抓到的配网帧重放一次，
台灯立刻切走 AP 并连上家里 WiFi —— 抓到了完整入网过程：

```
Total number of WPA data packets       959
Number of decrypted WPA  packets        46      # airdecap-ng -e "<HOME_SSID>" -p <WIFI_PASSWORD>
```

解密后的关键信息：

| 项 | 值 |
|---|---|
| 台灯 IP（DHCP 拿到） | **192.168.78.104**（不是之前的 .101） |
| DNS 查询 | `iomplatform.hicloud.com` |
| TCP 连接 | `121.36.118.212:5685`、`118.194.33.124:8089` |
| UDP 多播 | `238.238.238.238:5683`（HiLink 发现） |

### 6.2 重大发现：未绑定状态下本地 CoAP 在 **UDP/5683**，不是 5686

之前的理解有误——5686 是**绑定之后**才开放的端口。未绑定的设备只有 5683：

```bash
opple discover --ip 192.168.78.104 --port 5683     # 成功，返回完整设备 JSON
opple session  --ip 192.168.78.104 --port 5683     # 成功，sessId/sn2/psk/hmacKey 全部派生
opple on       --ip 192.168.78.104 --port 5683     # 超时（未绑定 = 没有 authCode）
```

`discover` 返回：

```json
{"CR":"52229a98…","devId":"","devInfo":{"devType":"046","fwv":"6.3.6","hiv":"1.0",
 "hwv":"1.0.0","manu":"013","model":"READINGLAMP","prodId":"134D","protType":1,
 "sn":"**04040119BBC81C","swv":"9.0.10.323"},"errcode":0,
 "services":[{"sid":"switch"},{"sid":"brightness"},{"sid":"backlight"},{"sid":"cct"},
             {"sid":"lightMode"},{"sid":"nightSwitch"},{"sid":"cloudSetup"}]}
```

注意 `cloudSetup` 是设备自述的服务之一，但直接 `GET/POST /cloudSetup`（5683）暂无响应，
后续可继续试不同的 options / 子路径来本地完成绑定，从而绕开 App 与云端。
---

## 7. 打通本地 `/cloudSetup`（2026-10-29 23:5x，无需 App、无需 authCode）

### 7.1 协议还原（来自 `CoapIdentifyCodeBuilder`）

```
POST coap://<dev>:5683/cloudSetup      (CON, TKL=3, Content-Format=50)
选项: 2048=sessionId(≤16B)  2053=seq(会话 seq+1, 大端最少字节)
payload: AES-128-CBC(JSON, pskKey, iv) ‖ HMAC-SHA256(hmacKey, 整条报文含 payload)
响应:    {"errcode":0}   ← 同样加密+MAC
```

密钥推导（**只用会话的 sn1/sn2，不含 authCode**）：

```
salt   = hex(sn1) ‖ hex(sn2)            # 16B
k32    = ae1.f(salt, 1, 32)             # App 内部 KDF（password 由 t80.b() 派生）
pskKey = k32[0..16]
iv     = k32[16..32]                    # 注意：IV 固定来自 KDF，不是随机
hmacKey= PBKDF2-HMAC-SHA256(pskKey, salt, 1, 32)
```

`t80.b()` 的种子由 `ae1.B()` + `gia.getSecondPske()` + `dj.a()` 混合后 AES 得出（App 侧密钥库参与），
离线无法复刻——**但可以直接在运行时用 App 自己的函数算**：hook 进程里调用
`ae1.f(salt,1,32)` 与 `ch8.a(pskKey,salt,1,32)` 即可拿到同一组密钥（已实现，见 `frida/agent_kdf.js`）。

### 7.2 实测

```bash
# 1) 建会话拿 sn1/sn2/sessId/seq
opple session --ip 192.168.78.104 --port 5683

# 2) 用 App 实现算密钥（Frida）
node … agent_kdf.js  →  pskKey / iv / hmacKey

# 3) 发 /cloudSetup
node tools/cloudsetup_send.mjs 192.168.78.104 5683 <sessId> <seq+1> <pskKey> <iv> <hmacKey> \
  '{"code":"…","devId":"…","psk":"…","cloudUrl":"iomplatform.hicloud.com"}'
```

设备响应：

```
← 78B
  opt 2048: "<sessId>"
  opt 2053: 1104
  MAC: 通过 ✓
  明文: {"errcode":0}
```

即：**设备接受了我们伪造的注册数据**（用的是上一轮的旧 code/psk，注册到云端会失败，但通道已打通）。

### 7.3 剩下的一步

本地绑定只差**新鲜的云端凭据** `code / psk / devId`。它们由 App 在"添加设备"时向云端申请
（`/home-manager` 或 `/service` 系列接口，需 accessToken）。拿到后即可：

1. 会话 → 算密钥 → `/cloudSetup` 下发 → 设备连云端注册成功 → 绑定完成；
2. 绑定后设备开放 5686 本地控制并下发 authCode；
3. 之后 OTA 可触发，且用树莓派 monitor+PSK 解密即可看到固件下载域名。
---

## 8. 假冒云端（TCP/5685）实验 —— 朝"不经过云端配网"迈出的关键一步

把 `/cloudSetup` 的 `cloudUrl` 改成树莓派 IP（`192.168.78.107`）后，台灯**立刻改连我们的服务器**：

```bash
# /cloudSetup 下发
{"code":"<PROV_CODE>","devId":"<DEVICE_ID_3>…","psk":"<PROV_PSK>","cloudUrl":"192.168.78.107"}
```

树莓派 `5685` 上收到（**明文**，非 TLS）：

```
CONN ('192.168.78.104', 58409)
RX 145  code=0x02  /.sys/psk
   {"devId":"<DEVICE_ID_3>",
    "sn1":"<SN1_2>","seq":62856,
    "encryptMode":["AES-128-GCM","AES-128-CBC"]}
```

帧格式（实测）：

```
[uint16 BE 长度][1B: ver(2)|type(2)|tkl(4)][1B code][token][options][0xFF][payload]
例: 008f 52 02 fba0  b4 ".sys"  03 "psk"  ff <json>
```

即云端会话握手也是 CoAP-over-TCP，`/.sys/psk` 明文交换 devId/sn1/seq/encryptMode，
之后应该用 `psk`（就是我们在 `/cloudSetup` 里下发的那串）派生会话密钥加密后续报文。

### 当前进度

| 阶段 | 状态 |
|---|---|
| 设备改连我们指定的 cloudUrl | ✅ 立即生效 |
| 收到 `/.sys/psk` 握手 | ✅ 明文可见 |
| 回复握手 | ⚠️ 我们回明文 `{"errcode":0,"modeResp":1,"sessId":…,"seq":…,"sn2":…}`，设备收到后**立刻断开重连**，说明响应格式/加密方式不对 |

下一步候选：响应改为**加密**（AES-CBC，key 由 psk+sn1+sn2 派生，与本地 `/cloudSetup` 同一套）、
或换 code（2.04）、或补选项 2048 的长度/字段。设备会不停重试，正好方便迭代。

### 关于固件

抓包里台灯只访问 `iomplatform.hicloud.com`（5685）与 `118.194.33.124:8089`，
**没有任何 OTA 域名**——因为设备从未真正注册成功，云端不会下发升级命令。
所以固件只能：①先让它"绑定成功"（真云端或假云端）再抓 OTA；②或拆机读 Flash。
### 8.1 迭代结果（00:0x）

用多变量脚本逐个试响应格式，设备反应明显分两类：

| 响应头 type | 响应体 | 设备反应 |
|---|---|---|
| `0x52`（type=1） | 明文/加密 | **立即 EOF**（拒绝） |
| `0x62`（type=2） | 明文或加密，含/不含 sessId | **保持连接 15 秒**后才断开 |

结论：**响应头 type 必须为 2（0x62）**，帧结构与响应被接受；但 15 秒是设备自己的空闲超时，
期间它不再发任何报文——说明它在等云端发起下一步（注册确认/绑定命令），或我们的响应内容仍不对。

仍未达成：`discover` 里 `devId` 依然为空，`5686` 仍未开放 → **设备不认为自己已绑定**。

下一步要试：
1. 响应体加 `devId` / `psk` / `authCode` 字段（云端绑定结果可能随握手一起下发）；
2. 握手成功后由**服务端主动发**一条 CoAP 请求（如 `/.sys/reg`、`/.sys/bind`）触发设备上报；
3. 抓一次**真实云端**的响应做对照——需要一次有效的 code/psk（即账号侧申请），这是唯一能 100% 对齐格式的办法。
### 8.2 三轮迭代结果（00:0x）

**① 握手响应加字段**（三种组合：`devId+psk` / `authCode+authCodeId` / `encryptMode`）
→ 设备行为完全不变：保持 15 秒后断开，期间不发任何报文。说明这些字段不是它等待的东西。

**② 握手后服务端主动下发探测请求**（`/.sys/reg`、`/.sys/bind`、`/.sys/heartbeat`，hdr type=1）
→ 设备**一条都不回**。它似乎只在"自己发起请求"时才说话，不接受服务端主动 push（或我们的请求帧格式不对）。

**③ 抓真云响应（ARP MITM）**
树莓派上 `arpspoof` 双向毒化 `192.168.78.104 ↔ 192.168.78.1` + `ip_forward` + MASQUERADE + `tcpdump tcp port 5685`，
把 `cloudUrl` 改回 `iomplatform.hicloud.com`。结果：**设备不再拨号**（此前连续失败后进入退避），
20 秒实时抓包零 TCP 报文。

→ 需要给台灯**断电重启**，让它上电时重新拨云；那时 MITM 就能抓到真云对 `/.sys/psk` 的原始响应，
照抄即可完成本地假云绑定。

关键前提：设备↔云走的是 **明文 CoAP-over-TCP（5685，无 TLS）**，所以 MITM 能直接看到完整应答字节。