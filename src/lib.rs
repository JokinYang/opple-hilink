//! OPPLE / HiLink 台灯交互协议实现。
//!
//! 三条链路：
//! - [`control`]：局域网控制，CoAP over UDP/5686，AES-128-CBC + HMAC-SHA256（选项 2052/2053/2056）
//! - [`provision`]：配网白盒帧，UDP/5683，帧内 SSID 明文 + 密码/注册包 AES-CBC（密钥每帧随机，白盒封装）
//! - [`ota`]：固件升级，App 侧走 MQTT `/smartHome/signaltrans/v2/categories/command`；
//!   设备侧服务 `update` 的 `{"action":0|1}`（本机型本地通道被 App 屏蔽）
//!
//! 另外提供 [`discovery`]（`/.well-known/core?st=cloudSetup`）与 [`coap`]（通用 CoAP 编解码）。

pub mod coap;
pub mod control;
pub mod crypto;
pub mod discovery;
pub mod error;
pub mod ota;
pub mod provision;
pub mod session;

pub use control::DeviceConfig;
pub use error::{Error, Result};

/// 欧普读写台灯（prodId 134D）常用服务与取值范围，供 CLI 与服务字典复用。
pub mod profile {
    /// 服务 ID → 说明
    pub const SERVICES: &[(&str, &str)] = &[
        ("switch", "主灯开关 {\"on\":0|1}"),
        ("brightness", "亮度 {\"brightness\":26-255}（26≈10%）"),
        ("cct", "色温 {\"colorTemperature\":2000-6500}"),
        ("lightMode", "模式 {\"mode\":2|3|4|6} 阅读/读写/电脑/自定义"),
        ("nightSwitch", "侧边灯 {\"on\":0|1}"),
        ("backlight", "背光 {\"on\":0|1}"),
        ("update", "固件升级 {\"action\":0|1}（本机型本地不响应）"),
        ("netInfo", "网络信息（R）"),
        ("faultDetection", "故障检测（R）"),
        ("timer", "定时器（云端通道）"),
        ("delay", "延时任务（云端通道）"),
        ("diagnose", "诊断（云端通道）"),
    ];
}
