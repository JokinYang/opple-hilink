//! HiLink 本地会话：`POST /.sys/sessMngr` 明文 JSON 换取 sessId / sn2，并派生控制密钥。
//!
//! 请求：`{"type":1,"modeSupport":3,"sn1":"<16hex 大写>","seq":N}` + 选项 2056(accountId)
//! 响应：`{"errcode":0,"modeResp":1,"sessId":"<15字符>","seq":N,"sn2":"<16hex 小写>"}`
//!
//! 密钥：`salt = sn1 ‖ sn2`；`PSK = PBKDF2-HMAC-SHA256(authCode, salt, 1)[0..16]`；
//! `HMACKey = PBKDF2-HMAC-SHA256(PSK, salt, 1)`

use std::net::UdpSocket;
use std::time::Duration;

use serde_json::Value;

use crate::coap::{self, Message};
use crate::crypto::{pbkdf2_sha256, random_bytes};
use crate::error::{Error, Result};

#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub host: String,
    pub port: u16,
    pub account_id: String,
    /// 16 字节 authCode（每台设备独有，见 README 的获取方式）
    pub auth_code: Vec<u8>,
    pub timeout_ms: u64,
    pub retries: u32,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub sess_id: String,
    pub sn1: [u8; 8],
    pub sn2: [u8; 8],
    /// 设备返回的 seq，发送时用 seq+1 起
    pub seq: u32,
    pub psk: [u8; 16],
    pub hmac_key: [u8; 32],
}

impl Session {
    /// 由 sn1/sn2/authCode 派生 PSK 与 HMACKey
    pub fn derive(auth_code: &[u8], sn1: &[u8; 8], sn2: &[u8; 8]) -> ([u8; 16], [u8; 32]) {
        let mut salt = Vec::with_capacity(16);
        salt.extend_from_slice(sn1);
        salt.extend_from_slice(sn2);
        let psk_full = pbkdf2_sha256(auth_code, &salt, 1, 32);
        let mut psk = [0u8; 16];
        psk.copy_from_slice(&psk_full[..16]);
        let hmac_full = pbkdf2_sha256(&psk, &salt, 1, 32);
        let mut hmac_key = [0u8; 32];
        hmac_key.copy_from_slice(&hmac_full);
        (psk, hmac_key)
    }

    /// 下一条报文使用的 seq（设备允许范围内的 +1）
    pub fn next_seq(&mut self) -> u32 {
        self.seq = self.seq.wrapping_add(1);
        self.seq
    }
}

/// 建立会话
pub fn create(cfg: &SessionConfig) -> Result<Session> {
    let sn1_bytes: [u8; 8] = random_bytes(8).try_into().unwrap();
    let sn1_hex = hex::encode_upper(sn1_bytes);
    let seq0: u32 = 1 + (u32::from(random_bytes(2)[0]) << 8 | u32::from(random_bytes(1)[0])) % 30000;

    let body = serde_json::json!({
        "type": 1,
        "modeSupport": 3,
        "sn1": sn1_hex,
        "seq": seq0,
    });

    let mut msg = Message::new(coap::TYPE_CON, coap::CODE_POST, rand_mid(), random_bytes(3));
    msg.set_path("/.sys/sessMngr");
    msg.add_option(coap::OPT_CONTENT_FORMAT, vec![50u8]);
    msg.add_option(coap::OPT_ACCOUNT_ID, cfg.account_id.as_bytes().to_vec());
    msg.payload = body.to_string().into_bytes();

    let resp = udp_roundtrip(&cfg.host, cfg.port, &msg.encode(), cfg.timeout_ms, cfg.retries)?;
    let parsed = Message::decode(&resp)?;
    if parsed.code != coap::CODE_205 && parsed.code != coap::CODE_204 {
        return Err(Error::Device(format!("会话响应码 0x{:02x}", parsed.code)));
    }
    let json: Value = serde_json::from_slice(&parsed.payload)?;
    let errcode = json.get("errcode").and_then(Value::as_i64).unwrap_or(-1);
    if errcode != 0 {
        return Err(Error::Device(format!("会话失败 errcode={errcode}")));
    }
    let sess_id = json
        .get("sessId")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Device("响应缺 sessId".into()))?
        .to_string();
    let sn2_hex = json
        .get("sn2")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Device("响应缺 sn2".into()))?;
    let seq = json.get("seq").and_then(Value::as_u64).unwrap_or(seq0 as u64) as u32;

    let sn2_vec = hex::decode(sn2_hex).map_err(|e| Error::Crypto(format!("sn2: {e}")))?;
    if sn2_vec.len() != 8 {
        return Err(Error::Crypto("sn2 不是 8 字节".into()));
    }
    let mut sn2 = [0u8; 8];
    sn2.copy_from_slice(&sn2_vec);

    let (psk, hmac_key) = Session::derive(&cfg.auth_code, &sn1_bytes, &sn2);
    Ok(Session { sess_id, sn1: sn1_bytes, sn2, seq, psk, hmac_key })
}

fn rand_mid() -> u16 {
    let b = random_bytes(2);
    let v = u16::from_be_bytes([b[0], b[1]]);
    if v == 0 { 1 } else { v }
}

/// 一次 UDP 收发：带超时与重试
pub fn udp_roundtrip(host: &str, port: u16, data: &[u8], timeout_ms: u64, retries: u32) -> Result<Vec<u8>> {
    let bind = if host.contains(':') { "[::]:0" } else { "0.0.0.0:0" };
    let sock = UdpSocket::bind(bind)?;
    sock.set_read_timeout(Some(Duration::from_millis(timeout_ms)))?;
    sock.connect((host, port))?;
    let attempts = retries.max(1);
    let mut last_err = None;
    for _ in 0..attempts {
        sock.send(data)?;
        let mut buf = [0u8; 4096];
        match sock.recv(&mut buf) {
            Ok(n) => return Ok(buf[..n].to_vec()),
            Err(e) => last_err = Some(e),
        }
    }
    Err(match last_err {
        Some(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
            Error::Timeout("设备响应")
        }
        Some(e) => Error::Io(e),
        None => Error::Timeout("设备响应"),
    })
}
