//! 配网白盒帧（App → 设备 UDP/5683），本机型（无 PIN）走的就是这条路径，**没有 SPEKE / securityData**。
//!
//! 帧结构（已用真机帧逐字节验证，结论见 `docs/OPPLE台灯-配网与固件升级协议.md`；
//! 仓库内测试用合成夹具，不含真机数据）：
//! ```text
//! [0]      crc8( keyId )            keyId = 设备 AP SSID 第 4 段去掉首字符取 5 位（"Hi- OPPLE-READINGLAMP-0134DC" → "134DC"）
//! [1]      crc8( frame[2..iA) )     计算时 byte1 置 0；iA = 未补齐长度
//! [2]      类型 = (1|2|3) << 4      设备类别 100→0x10 / 101→0x20 / 110→0x30
//! [3..19]  16B 白盒块 = WhiteBox(mode=类型, key=AES密钥, data=密码密文前 16B)
//! [19]     (ssidLen-1) | (((pwdCipherLen>>4)-1) << 5)
//! [20..]   SSID 明文（UTF-8）
//! ...      密码密文   = AES-128-CBC/PKCS7(密码, 每帧随机密钥, IV = 16×0x00)
//! ...      1B        = 注册包密文长度 >> 4
//! ...      注册包密文 = AES-128-CBC/PKCS7(注册 JSON, 同一密钥, 同一 IV)
//! 末尾      总长奇数时补 1 字节 0x00
//! ```
//! 说明：白盒块由华为 `libsecurityi.so`（`WhiteBox.whiteBoxEncrypt`，TypeEnum 100/101/110）生成，
//! 逆向白盒没有工程意义——实际取法是在 App 运行时 hook `CommonLibUtil.whiteBoxEncrypt`；
//! 因此本模块的 [`build`] 把白盒块作为**输入参数**（已拿到就用，未拿到就留空占位）。

use crate::crypto::{aes128_cbc_decrypt, aes128_cbc_encrypt, crc8};
use crate::error::{Error, Result};

pub const TYPE_100: u8 = 0x10;
pub const TYPE_101: u8 = 0x20;
pub const TYPE_110: u8 = 0x30;

/// 从设备 AP SSID 推导 5 位 keyId：`Hi- OPPLE-READINGLAMP-0134DC` → `134DC`
pub fn ap_key_id(ap_ssid: &str) -> Option<String> {
    let parts: Vec<&str> = ap_ssid.split('-').collect();
    if parts.len() < 4 {
        return None;
    }
    parts[3].chars().skip(1).take(5).collect::<String>().into()
}

/// 由设备类别码（100/101/110）得到帧类型字节
pub fn type_byte(code: u8) -> Result<u8> {
    match code {
        100 => Ok(TYPE_100),
        101 => Ok(TYPE_101),
        110 => Ok(TYPE_110),
        other => Err(Error::Frame(format!("未知设备类别 {other}"))),
    }
}

/// 帧类型字节反推类别码
pub fn type_code(byte: u8) -> Result<u8> {
    match byte & 0xF0 {
        TYPE_100 => Ok(100),
        TYPE_101 => Ok(101),
        TYPE_110 => Ok(110),
        other => Err(Error::Frame(format!("未知类型字节 0x{other:02x}"))),
    }
}

#[derive(Debug, Clone)]
pub struct FrameInfo {
    pub raw: Vec<u8>,
    pub checksum1_ok: bool,
    pub checksum2_ok: bool,
    pub type_byte: u8,
    pub kind: u8,
    pub whitebox_block: [u8; 16],
    pub ssid: String,
    pub password_cipher: Vec<u8>,
    pub register_cipher: Vec<u8>,
    /// 是否带 1 字节补齐
    pub padded: bool,
    /// 未补齐长度 iA
    pub unpadded_len: usize,
}

/// 解析一帧配网报文
pub fn parse(raw: &[u8], ap_ssid: &str) -> Result<FrameInfo> {
    if raw.len() < 21 {
        return Err(Error::Frame(format!("报文太短: {}", raw.len())));
    }
    let type_byte = raw[2];
    let kind = type_code(type_byte)?;

    let mut whitebox_block = [0u8; 16];
    whitebox_block.copy_from_slice(&raw[3..19]);

    let lenb = raw[19];
    let ssid_len = (lenb & 0x1F) as usize + 1;
    let pwd_chunks = ((lenb >> 5) & 0x07) as usize + 1;
    let ssid_start = 20;
    let ssid_end = ssid_start + ssid_len;
    let pwd_end = ssid_end + pwd_chunks * 16;
    if pwd_end + 1 > raw.len() {
        return Err(Error::Frame("长度字段超出报文".into()));
    }
    let ssid = String::from_utf8(raw[ssid_start..ssid_end].to_vec())
        .map_err(|e| Error::Frame(format!("SSID 不是 UTF-8: {e}")))?;
    let password_cipher = raw[ssid_end..pwd_end].to_vec();

    let reg_len = raw[pwd_end] as usize * 16;
    let reg_start = pwd_end + 1;
    let reg_end = reg_start + reg_len;
    if reg_end > raw.len() {
        return Err(Error::Frame("注册包长度超出报文".into()));
    }
    let register_cipher = raw[reg_start..reg_end].to_vec();

    let computed = reg_end;
    let padded = raw.len() == computed + 1 && raw[computed] == 0;
    if raw.len() != computed && !padded {
        return Err(Error::Frame(format!(
            "长度不一致: 报文 {} 字节，字段推算 {} 字节",
            raw.len(),
            computed
        )));
    }
    let unpadded_len = computed;

    let key_id = ap_key_id(ap_ssid).ok_or_else(|| Error::Frame("AP SSID 格式无法推导 keyId".into()))?;
    let checksum1_ok = raw[0] == crc8(key_id.as_bytes());

    let mut tmp = raw[..unpadded_len].to_vec();
    tmp[1] = 0;
    let checksum2_ok = raw[1] == crc8(&tmp[2..]);

    Ok(FrameInfo {
        raw: raw.to_vec(),
        checksum1_ok,
        checksum2_ok,
        type_byte,
        kind,
        whitebox_block,
        ssid,
        password_cipher,
        register_cipher,
        padded,
        unpadded_len,
    })
}

impl FrameInfo {
    /// 用每帧 AES 密钥解出 (WiFi 密码, 注册包 JSON)
    pub fn decrypt(&self, key: &[u8]) -> Result<(String, String)> {
        if key.len() != 16 {
            return Err(Error::Crypto(format!("AES 密钥应为 16 字节，实际 {}", key.len())));
        }
        let iv = [0u8; 16];
        let pwd = aes128_cbc_decrypt(key, &iv, &self.password_cipher)?;
        let reg = aes128_cbc_decrypt(key, &iv, &self.register_cipher)?;
        Ok((
            String::from_utf8(pwd).map_err(|e| Error::Crypto(format!("密码不是 UTF-8: {e}")))?,
            String::from_utf8(reg).map_err(|e| Error::Crypto(format!("注册包不是 UTF-8: {e}")))?,
        ))
    }
}

/// 组帧参数
pub struct BuildSpec<'a> {
    /// 设备 AP SSID（用于 byte0 的 keyId）
    pub ap_ssid: &'a str,
    /// 设备类别：100 / 101 / 110
    pub kind: u8,
    /// 16B 白盒块（hook `whiteBoxEncrypt` 得到；留空表示未知，全 0 占位）
    pub whitebox_block: [u8; 16],
    /// 目标路由器 SSID
    pub ssid: &'a str,
    /// 目标 WiFi 密码（明文，内部加密）
    pub password: &'a str,
    /// 注册包 JSON 明文（扁平对象，见 README）
    pub register_json: &'a str,
    /// 每帧随机 AES-128 密钥
    pub aes_key: &'a [u8],
}

/// 组装一帧配网报文（与固件算法逐字节一致；AES-CBC + 全 0 IV 是确定性的，可复现抓包帧）
pub fn build(spec: &BuildSpec<'_>) -> Result<Vec<u8>> {
    if spec.aes_key.len() != 16 {
        return Err(Error::Crypto(format!("AES 密钥应为 16 字节，实际 {}", spec.aes_key.len())));
    }
    let ssid_bytes = spec.ssid.as_bytes();
    if ssid_bytes.is_empty() || ssid_bytes.len() > 32 {
        return Err(Error::Frame(format!("SSID 长度非法: {}", ssid_bytes.len())));
    }
    let type_b = type_byte(spec.kind)?;
    let iv = [0u8; 16];
    let pwd_ct = aes128_cbc_encrypt(spec.aes_key, &iv, spec.password.as_bytes())?;
    let reg_ct = aes128_cbc_encrypt(spec.aes_key, &iv, spec.register_json.as_bytes())?;
    if pwd_ct.len() > 16 * 8 {
        return Err(Error::Frame("密码密文超过 8 个块，帧内长度字段放不下".into()));
    }
    if reg_ct.len() % 16 != 0 || reg_ct.len() / 16 > 255 {
        return Err(Error::Frame("注册包密文长度必须是 16 的倍数且 ≤ 4080 字节".into()));
    }

    let mut out = Vec::with_capacity(20 + ssid_bytes.len() + pwd_ct.len() + 1 + reg_ct.len() + 1);
    out.push(0); // [0] 校验1 占位
    out.push(0); // [1] 校验2 占位
    out.push(type_b);
    out.extend_from_slice(&spec.whitebox_block);
    let lenb = ((ssid_bytes.len() - 1) as u8 & 0x1F) | ((((pwd_ct.len() >> 4) - 1) as u8) << 5);
    out.push(lenb);
    out.extend_from_slice(ssid_bytes);
    out.extend_from_slice(&pwd_ct);
    out.push((reg_ct.len() >> 4) as u8);
    out.extend_from_slice(&reg_ct);
    let unpadded_len = out.len();
    if unpadded_len % 2 == 1 {
        out.push(0);
    }

    let key_id = ap_key_id(spec.ap_ssid).ok_or_else(|| Error::Frame("AP SSID 格式无法推导 keyId".into()))?;
    out[0] = crc8(key_id.as_bytes());
    out[1] = 0;
    out[1] = crc8(&out[2..unpadded_len]);
    Ok(out)
}

/// 把一帧配网报文发给设备（AP 模式下的网关，UDP/5683），等待明文 `HI-ACK`。
///
/// 说明：帧本身必须是**真实可用的**（含有效的白盒块与云端下发的 code/psk），
/// 本 crate 只能保证字节级正确、无法凭空生成这两项，见 README。
pub fn send_frame(
    host: &str,
    port: u16,
    frame: &[u8],
    timeout_ms: u64,
    retries: u32,
) -> Result<SendOutcome> {
    use std::net::UdpSocket;
    use std::time::{Duration, Instant};

    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.connect((host, port))?;
    sock.set_read_timeout(Some(Duration::from_millis(timeout_ms)))?;

    let start = Instant::now();
    let attempts = retries.max(1);
    for attempt in 0..attempts {
        sock.send(frame)?;
        let mut buf = [0u8; 512];
        match sock.recv(&mut buf) {
            Ok(n) => {
                let text = String::from_utf8_lossy(&buf[..n]).to_string();
                if text.contains("HI-ACK") {
                    return Ok(SendOutcome {
                        ack: text,
                        attempts: attempt + 1,
                        elapsed_ms: start.elapsed().as_millis(),
                    });
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => return Err(Error::Io(e)),
        }
    }
    Err(Error::Timeout("等待 HI-ACK"))
}

#[derive(Debug, Clone)]
pub struct SendOutcome {
    pub ack: String,
    pub attempts: u32,
    pub elapsed_ms: u128,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ap_key_id_works() {
        assert_eq!(ap_key_id("Hi- OPPLE-READINGLAMP-0134DC").unwrap(), "134DC");
        assert!(ap_key_id("no-dash-here").is_none());
    }

    #[test]
    fn type_bytes() {
        assert_eq!(type_byte(100).unwrap(), TYPE_100);
        assert_eq!(type_code(TYPE_110).unwrap(), 110);
        assert!(type_byte(7).is_err());
    }

    #[test]
    fn send_frame_waits_for_hi_ack() {
        use std::net::UdpSocket;
        let srv = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = srv.local_addr().unwrap().port();
        let t = std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            let (n, from) = srv.recv_from(&mut buf).unwrap();
            assert!(n > 0);
            srv.send_to(b"HI-ACK", from).unwrap();
        });
        let out = send_frame("127.0.0.1", port, b"frame", 1000, 2).expect("应收到 HI-ACK");
        assert!(out.ack.contains("HI-ACK"));
        assert_eq!(out.attempts, 1);
        t.join().unwrap();
    }

    #[test]
    fn send_frame_times_out_without_ack() {
        use std::net::UdpSocket;
        let srv = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = srv.local_addr().unwrap().port();
        let e = send_frame("127.0.0.1", port, b"frame", 50, 2).unwrap_err();
        assert!(matches!(e, Error::Timeout(_)), "应为超时错误");
    }
}