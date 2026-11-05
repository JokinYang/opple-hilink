//! CoAP（RFC 7252 子集）编解码：HiLink 用的是标准 CoAP 报文 + 私有选项号。
//!
//! 私有选项（本协议专用）：
//! - 2048 sessionId
//! - 2050 requestId（UUID）
//! - 2051 deviceId
//! - 2052 AES(userId) ‖ IV
//! - 2053 seq（大端最短字节）
//! - 2056 accountId

use crate::error::{Error, Result};

pub const TYPE_CON: u8 = 0;
pub const TYPE_NON: u8 = 1;
pub const TYPE_ACK: u8 = 2;
pub const TYPE_RST: u8 = 3;

pub const CODE_GET: u8 = 0x01;
pub const CODE_POST: u8 = 0x02;
pub const CODE_205: u8 = 0x45; // 2.05 Content
pub const CODE_204: u8 = 0x44; // 2.04 Changed

pub const OPT_URI_PATH: u16 = 11;
pub const OPT_CONTENT_FORMAT: u16 = 12;
pub const OPT_URI_QUERY: u16 = 15;

pub const OPT_SESSION_ID: u16 = 2048;
pub const OPT_REQUEST_ID: u16 = 2050;
pub const OPT_DEVICE_ID: u16 = 2051;
pub const OPT_USER_ID: u16 = 2052;
pub const OPT_SEQ: u16 = 2053;
pub const OPT_ACCOUNT_ID: u16 = 2056;

#[derive(Debug, Clone)]
pub struct Message {
    pub typ: u8,
    pub code: u8,
    pub mid: u16,
    pub token: Vec<u8>,
    /// 已按选项号升序保存
    pub options: Vec<(u16, Vec<u8>)>,
    pub payload: Vec<u8>,
}

impl Message {
    pub fn new(typ: u8, code: u8, mid: u16, token: Vec<u8>) -> Self {
        Self { typ, code, mid, token, options: Vec::new(), payload: Vec::new() }
    }

    pub fn add_option(&mut self, number: u16, value: impl Into<Vec<u8>>) {
        self.options.push((number, value.into()));
        self.options.sort_by_key(|(n, _)| *n);
    }

    /// 一次设置路径（`/a/b` → 选项 11 重复）
    pub fn set_path(&mut self, path: &str) {
        self.options.retain(|(n, _)| *n != OPT_URI_PATH);
        for seg in path.split('/').filter(|s| !s.is_empty()) {
            self.add_option(OPT_URI_PATH, seg.as_bytes().to_vec());
        }
    }

    pub fn add_query(&mut self, q: &str) {
        self.add_option(OPT_URI_QUERY, q.as_bytes().to_vec());
    }

    pub fn option(&self, number: u16) -> Option<&[u8]> {
        self.options.iter().find(|(n, _)| *n == number).map(|(_, v)| v.as_slice())
    }

    pub fn options_all(&self, number: u16) -> Vec<&[u8]> {
        self.options.iter().filter(|(n, _)| *n == number).map(|(_, v)| v.as_slice()).collect()
    }

    pub fn path(&self) -> String {
        let segs: Vec<String> = self
            .options_all(OPT_URI_PATH)
            .iter()
            .map(|v| String::from_utf8_lossy(v).to_string())
            .collect();
        format!("/{}", segs.join("/"))
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + self.payload.len());
        out.push(0x40 | (self.typ << 4) | (self.token.len() as u8 & 0x0F));
        out.push(self.code);
        out.extend_from_slice(&self.mid.to_be_bytes());
        out.extend_from_slice(&self.token);

        let mut last = 0u16;
        for (num, val) in &self.options {
            let delta = num - last;
            last = *num;
            encode_option(delta, val, &mut out);
        }
        if !self.payload.is_empty() {
            out.push(0xFF);
            out.extend_from_slice(&self.payload);
        }
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Message> {
        if buf.len() < 4 {
            return Err(Error::Coap("报文不足 4 字节".into()));
        }
        let ver = buf[0] >> 6;
        if ver != 1 {
            return Err(Error::Coap(format!("版本号 {ver} 不是 1")));
        }
        let typ = (buf[0] >> 4) & 0x03;
        let tkl = (buf[0] & 0x0F) as usize;
        let code = buf[1];
        let mid = u16::from_be_bytes([buf[2], buf[3]]);
        if buf.len() < 4 + tkl {
            return Err(Error::Coap("token 长度越界".into()));
        }
        let token = buf[4..4 + tkl].to_vec();
        let mut pos = 4 + tkl;
        let mut number: u16 = 0;
        let mut options = Vec::new();
        while pos < buf.len() {
            let b = buf[pos];
            if b == 0xFF {
                pos += 1;
                break;
            }
            pos += 1;
            let delta = decode_ext(b >> 4, buf, &mut pos)?;
            let len = decode_ext(b & 0x0F, buf, &mut pos)? as usize;
            number = number
                .checked_add(delta)
                .ok_or_else(|| Error::Coap("选项号溢出".into()))?;
            if pos + len > buf.len() {
                return Err(Error::Coap("选项值越界".into()));
            }
            options.push((number, buf[pos..pos + len].to_vec()));
            pos += len;
        }
        let payload = if pos <= buf.len() { buf[pos..].to_vec() } else { Vec::new() };
        Ok(Message { typ, code, mid, token, options, payload })
    }

    /// 便于打印：把选项转成可读形式
    pub fn describe_options(&self) -> Vec<String> {
        self.options
            .iter()
            .map(|(n, v)| {
                let printable = v.iter().all(|b| (0x20..0x7f).contains(b));
                if printable {
                    format!("{n}={:?}", String::from_utf8_lossy(v))
                } else {
                    format!("{n}={}", hex::encode(v))
                }
            })
            .collect()
    }
}


fn encode_option(delta: u16, value: &[u8], out: &mut Vec<u8>) {
    let (d_nib, d_ext) = split_ext(delta);
    let (l_nib, l_ext) = split_ext(value.len() as u16);
    out.push((d_nib << 4) | l_nib);
    out.extend_from_slice(&d_ext);
    out.extend_from_slice(&l_ext);
    out.extend_from_slice(value);
}

fn split_ext(v: u16) -> (u8, Vec<u8>) {
    if v < 13 {
        (v as u8, Vec::new())
    } else if v < 269 {
        (13, vec![(v - 13) as u8])
    } else {
        let x = v - 269;
        (14, vec![(x >> 8) as u8, (x & 0xFF) as u8])
    }
}

fn decode_ext(nibble: u8, buf: &[u8], pos: &mut usize) -> Result<u16> {
    match nibble {
        0..=12 => Ok(nibble as u16),
        13 => {
            if *pos >= buf.len() {
                return Err(Error::Coap("选项扩展越界".into()));
            }
            let v = 13 + buf[*pos] as u16;
            *pos += 1;
            Ok(v)
        }
        14 => {
            if *pos + 1 >= buf.len() {
                return Err(Error::Coap("选项扩展越界".into()));
            }
            let v = 269 + ((buf[*pos] as u16) << 8 | buf[*pos + 1] as u16);
            *pos += 2;
            Ok(v)
        }
        _ => Err(Error::Coap("选项长度 15 为保留值".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_request_option_layout() {
        // 会话请求的选项布局（取值用合成常量，长度按协议：accountId 16B、sessId 15B）
        let mut m = Message::new(TYPE_CON, CODE_POST, 0x1234, vec![1, 2, 3]);
        m.set_path("/.sys/sessMngr");
        m.add_option(OPT_CONTENT_FORMAT, vec![50u8]);
        m.add_option(OPT_ACCOUNT_ID, b"0000000000000000".to_vec());
        let bytes = m.encode();
        let back = Message::decode(&bytes).unwrap();
        assert_eq!(back.path(), "/.sys/sessMngr");
        assert_eq!(back.option(OPT_CONTENT_FORMAT), Some(&[50u8][..]));
        assert_eq!(back.option(OPT_ACCOUNT_ID), Some(&b"0000000000000000"[..]));
    }

    #[test]
    fn large_option_number_roundtrip() {
        let mut m = Message::new(TYPE_CON, CODE_POST, 1, vec![]);
        m.add_option(OPT_SESSION_ID, b"SessIdForTest01".to_vec());
        m.add_option(OPT_DEVICE_ID, b"00000000-0000-4000-8000-000000000000".to_vec());
        let bytes = m.encode();
        let back = Message::decode(&bytes).unwrap();
        assert_eq!(back.option(OPT_SESSION_ID), Some(&b"SessIdForTest01"[..]));
        assert_eq!(
            back.option(OPT_DEVICE_ID),
            Some(&b"00000000-0000-4000-8000-000000000000"[..])
        );
    }
}
