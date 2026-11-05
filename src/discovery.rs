//! 配网前/局域网内的设备发现：`GET /.well-known/core?st=cloudSetup`。
//!
//! 返回设备自述 JSON（字段名见 README）：`devId / devType / prodId / manu / model / sn / mac /
//! hwv / swv / fwv / hiv / devName / protType / services[{sid,st}] / baseUrl / centralCapability`。
//! 注意：设备处于 STA 模式时通常**不响应**该端点（只有配网态/AP 模式开放），实测如此。

use serde_json::Value;

use crate::coap::{self, Message};
use crate::crypto::random_bytes;
use crate::error::{Error, Result};
use crate::session::udp_roundtrip;

#[derive(Debug, Clone)]
pub struct Discovered {
    pub raw: Vec<u8>,
    pub text: String,
    pub json: Option<Value>,
}

/// 发送发现请求（GET，明文）
pub fn query(host: &str, port: u16, timeout_ms: u64, retries: u32) -> Result<Discovered> {
    let mut msg = Message::new(coap::TYPE_CON, coap::CODE_GET, rand_mid(), random_bytes(3));
    msg.set_path("/.well-known/core");
    msg.add_query("st=cloudSetup");
    let wire = msg.encode();
    let resp = udp_roundtrip(host, port, &wire, timeout_ms, retries)?;
    let parsed = Message::decode(&resp)?;
    let text = String::from_utf8_lossy(&parsed.payload).to_string();
    let json = serde_json::from_str(&text).ok();
    if text.is_empty() {
        return Err(Error::Device("发现响应为空".into()));
    }
    Ok(Discovered { raw: parsed.payload, text, json })
}

fn rand_mid() -> u16 {
    let b = random_bytes(2);
    let v = u16::from_be_bytes([b[0], b[1]]);
    if v == 0 { 1 } else { v }
}
