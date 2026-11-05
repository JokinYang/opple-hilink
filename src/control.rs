//! 控制通道：`POST /<serviceId>`，AES-128-CBC（IV 随机）+ HMAC-SHA256。
//!
//! 报文结构（实测）：
//! ```text
//! 选项: 11=<serviceId> 12=50 2048=<sessId> 2050=<uuid> 2051=<deviceId>
//!       2052=AES-CBC(userId)‖IV16  2053=<seq 大端> 2056=<accountId>
//! payload: AES-CBC(JSON) ‖ IV16 ‖ HMAC-SHA256(整条报文, 含 2056 选项)
//! ```
//! 关键坑：MAC 覆盖**整条 CoAP 报文（含选项 2056）**；MAC 错设备静默丢弃、不回包。

use serde_json::Value;

use crate::coap::{self, Message};
use crate::crypto::{aes128_cbc_decrypt, aes128_cbc_encrypt, hmac_sha256, hmac_sha256_verify, random_bytes, uuid_v4};
use crate::error::{Error, Result};
use crate::session::{udp_roundtrip, Session};

#[derive(Debug, Clone)]
pub struct DeviceConfig {
    pub host: String,
    pub port: u16,
    pub device_id: String,
    pub account_id: String,
    pub user_id: String,
    pub auth_code: Vec<u8>,
    pub timeout_ms: u64,
    pub retries: u32,
}

impl Default for DeviceConfig {
    fn default() -> Self {
        Self {
            host: "192.168.1.100".into(),
            port: 5686,
            device_id: String::new(),
            account_id: String::new(),
            user_id: String::new(),
            auth_code: Vec::new(),
            timeout_ms: 3500,
            retries: 2,
        }
    }
}

impl DeviceConfig {
    pub fn session_config(&self) -> crate::session::SessionConfig {
        crate::session::SessionConfig {
            host: self.host.clone(),
            port: self.port,
            account_id: self.account_id.clone(),
            auth_code: self.auth_code.clone(),
            timeout_ms: self.timeout_ms,
            retries: self.retries,
        }
    }
}

/// 组装一帧控制报文（含 HMAC），返回 (最终字节, requestId)
pub fn build_control_frame(
    cfg: &DeviceConfig,
    sess: &Session,
    service: &str,
    data: &Value,
    seq: u32,
) -> Result<(Vec<u8>, String)> {
    if cfg.device_id.is_empty() || cfg.account_id.is_empty() || cfg.user_id.is_empty() {
        return Err(Error::Arg("device_id / account_id / user_id 不能为空".into()));
    }
    let plain = serde_json::to_vec(data)?;
    let iv = random_bytes(16);
    let cipher = aes128_cbc_encrypt(&sess.psk, &iv, &plain)?;

    let user_iv = random_bytes(16);
    let mut user_opt = aes128_cbc_encrypt(&sess.psk, &user_iv, cfg.user_id.as_bytes())?;
    user_opt.extend_from_slice(&user_iv);

    let request_id = uuid_v4();
    let mut msg = Message::new(coap::TYPE_CON, coap::CODE_POST, rand_mid(), random_bytes(3));
    msg.set_path(&format!("/{service}"));
    msg.add_option(coap::OPT_CONTENT_FORMAT, vec![50u8]);
    msg.add_option(coap::OPT_SESSION_ID, sess.sess_id.as_bytes().to_vec());
    msg.add_option(coap::OPT_REQUEST_ID, request_id.as_bytes().to_vec());
    msg.add_option(coap::OPT_DEVICE_ID, cfg.device_id.as_bytes().to_vec());
    msg.add_option(coap::OPT_USER_ID, user_opt);
    msg.add_option(coap::OPT_SEQ, encode_seq(seq));
    msg.add_option(coap::OPT_ACCOUNT_ID, cfg.account_id.as_bytes().to_vec());

    let mut payload = cipher;
    payload.extend_from_slice(&iv);
    msg.payload = payload;

    let encoded = msg.encode();
    let mac = hmac_sha256(&sess.hmac_key, &encoded);
    let mut wire = encoded;
    wire.extend_from_slice(&mac);
    Ok((wire, request_id))
}

/// 发送一条服务控制并解析响应
pub fn send(cfg: &DeviceConfig, sess: &mut Session, service: &str, data: &Value) -> Result<Value> {
    let seq = sess.next_seq();
    let (wire, request_id) = build_control_frame(cfg, sess, service, data, seq)?;
    let raw = udp_roundtrip(&cfg.host, cfg.port, &wire, cfg.timeout_ms, cfg.retries)?;
    let _ = request_id;
    decode_response(sess, &raw)
}

/// 解析设备响应（校验 MAC 后解密）
pub fn decode_response(sess: &Session, raw: &[u8]) -> Result<Value> {
    let msg = Message::decode(raw)?;
    if msg.code != coap::CODE_205 && msg.code != coap::CODE_204 {
        return Err(Error::Device(format!("响应码 0x{:02x}", msg.code)));
    }
    let p = &msg.payload;
    if p.len() < 48 {
        return Err(Error::Crypto(format!("响应负载太短: {} 字节", p.len())));
    }
    let body_len = p.len() - 32;
    let (body, mac) = p.split_at(body_len);
    // MAC 覆盖“整条报文去掉尾部 32 字节”
    if !hmac_sha256_verify(&sess.hmac_key, &raw[..raw.len() - 32], mac) {
        return Err(Error::Crypto("响应 MAC 校验失败".into()));
    }
    if body.len() < 16 {
        return Err(Error::Crypto("响应密文太短".into()));
    }
    let (ct, iv) = body.split_at(body.len() - 16);
    let plain = aes128_cbc_decrypt(&sess.psk, iv, ct)?;
    Ok(serde_json::from_slice(&plain)?)
}

fn encode_seq(seq: u32) -> Vec<u8> {
    let b = seq.to_be_bytes();
    let first = b.iter().position(|x| *x != 0).unwrap_or(3);
    b[first..].to_vec()
}

fn rand_mid() -> u16 {
    let b = random_bytes(2);
    let v = u16::from_be_bytes([b[0], b[1]]);
    if v == 0 { 1 } else { v }
}

/// 常用命令构造
pub fn cmd_switch(on: bool) -> Value {
    serde_json::json!({ "on": if on { 1 } else { 0 } })
}
pub fn cmd_brightness(v: u8) -> Value {
    serde_json::json!({ "brightness": v })
}
pub fn cmd_cct(v: u32) -> Value {
    serde_json::json!({ "colorTemperature": v })
}
pub fn cmd_mode(v: u8) -> Value {
    serde_json::json!({ "mode": v })
}
pub fn cmd_on(on: bool) -> Value {
    serde_json::json!({ "on": if on { 1 } else { 0 } })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> DeviceConfig {
        DeviceConfig {
            host: "127.0.0.1".into(),
            port: 5686,
            device_id: "00000000-0000-4000-8000-000000000000".into(),
            account_id: "0000000000000000".into(),
            user_id: "1000000000000000001".into(),
            auth_code: hex::decode("00112233445566778899aabbccddeeff").unwrap(),
            timeout_ms: 100,
            retries: 1,
        }
    }

    #[test]
    fn frame_has_mac_and_parses() {
        let c = cfg();
        let sn1 = [1u8; 8];
        let sn2 = [2u8; 8];
        let (psk, hmac_key) = Session::derive(&c.auth_code, &sn1, &sn2);
        let sess = Session {
            sess_id: "SessIdForTest01".into(),
            sn1,
            sn2,
            seq: 100,
            psk,
            hmac_key,
        };
        let (wire, _id) = build_control_frame(&c, &sess, "switch", &cmd_switch(true), 101).unwrap();
        // 尾部 32 字节是 MAC，且能自校验
        let body = &wire[..wire.len() - 32];
        let mac = &wire[wire.len() - 32..];
        assert!(hmac_sha256_verify(&sess.hmac_key, body, mac));
        // 报文本身可解析，选项齐全
        let msg = Message::decode(body).unwrap();
        assert_eq!(msg.path(), "/switch");
        assert!(msg.option(coap::OPT_SESSION_ID).is_some());
        assert!(msg.option(coap::OPT_ACCOUNT_ID).is_some());
        assert_eq!(msg.option(coap::OPT_USER_ID).unwrap().len(), 48);
        assert!(!msg.option(coap::OPT_SEQ).unwrap().is_empty());
    }
}
