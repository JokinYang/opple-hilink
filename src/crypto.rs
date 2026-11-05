//! 密码学原语：PBKDF2-HMAC-SHA256、HMAC-SHA256、AES-128-CBC/PKCS7、crc8、随机数与 UUID v4。
//!
//! 与固件/App 完全一致的两处细节：
//! - 控制通道：`PSK = PBKDF2(authCode, salt, 1)[0..16]`，`HMACKey = PBKDF2(PSK, salt, 1)`，
//!   salt = `sn1(8B) ‖ sn2(8B)`，AES-128-CBC + PKCS5/7，IV 16B 随机，MAC 覆盖整条 CoAP 报文。
//! - 配网帧：AES-128-CBC/PKCS7，**IV = 16×0x00**，密钥每帧随机（白盒封装在帧头）。

use aes::Aes128;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

use crate::error::{Error, Result};

type HmacSha256 = Hmac<Sha256>;
type Enc = cbc::Encryptor<Aes128>;
type Dec = cbc::Decryptor<Aes128>;

/// HMAC-SHA256
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC 接受任意长度密钥");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// 校验 HMAC（常量时间比较）
pub fn hmac_sha256_verify(key: &[u8], data: &[u8], mac_bytes: &[u8]) -> bool {
    if mac_bytes.len() != 32 {
        return false;
    }
    let calc = hmac_sha256(key, data);
    // 常量时间比较
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= calc[i] ^ mac_bytes[i];
    }
    diff == 0
}

/// PBKDF2-HMAC-SHA256（RFC 8018），`iterations` 为 1 时就是 `HMAC(password, salt‖0x00000001)` 截断。
pub fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32, out_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(out_len);
    let mut block: u32 = 1;
    while out.len() < out_len {
        // U1 = HMAC(password, salt ‖ INT_32_BE(block))
        let mut msg = Vec::with_capacity(salt.len() + 4);
        msg.extend_from_slice(salt);
        msg.extend_from_slice(&block.to_be_bytes());
        let mut u = hmac_sha256(password, &msg);
        let mut t = u;
        for _ in 1..iterations {
            u = hmac_sha256(password, &u);
            for i in 0..32 {
                t[i] ^= u[i];
            }
        }
        out.extend_from_slice(&t);
        block += 1;
    }
    out.truncate(out_len);
    out
}

/// AES-128-CBC 加密，PKCS#7 填充
pub fn aes128_cbc_encrypt(key: &[u8], iv: &[u8], plain: &[u8]) -> Result<Vec<u8>> {
    let cipher = Enc::new_from_slices(key, iv).map_err(|e| Error::Crypto(format!("{e:?}")))?;
    Ok(cipher.encrypt_padded_vec_mut::<Pkcs7>(plain))
}

/// AES-128-CBC 解密，PKCS#7 去填充
pub fn aes128_cbc_decrypt(key: &[u8], iv: &[u8], cipher: &[u8]) -> Result<Vec<u8>> {
    let dec = Dec::new_from_slices(key, iv).map_err(|e| Error::Crypto(format!("{e:?}")))?;
    dec.decrypt_padded_vec_mut::<Pkcs7>(cipher)
        .map_err(|e| Error::Crypto(format!("{e:?}")))
}

/// 配网帧里的自定义 crc8：init=0xFF、poly=0xB8、LSB-first（对应 `h8f.a()` / `tqe.l()`）
pub fn crc8(bytes: &[u8]) -> u8 {
    let mut i: u8 = 0xFF;
    for b in bytes {
        i ^= *b;
        for _ in 0..8 {
            let lsb = i & 1;
            i >>= 1;
            if lsb != 0 {
                i ^= 0xB8;
            }
        }
    }
    i
}

/// 随机字节
pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

/// 随机 16 字节（AES 密钥）
pub fn random_key16() -> [u8; 16] {
    let mut k = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut k);
    k
}

/// 随机 8 字节，输出大写十六进制（会话 sn1）
pub fn random_hex_upper(n: usize) -> String {
    hex::encode_upper(random_bytes(n))
}

/// UUID v4（控制帧 requestId 需要）
pub fn uuid_v4() -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex::encode(b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// Base64（标准表，带填充）
pub fn b64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Base64 解码（容忍首尾空白，包括 Android `Base64.DEFAULT` 输出末尾的换行）
pub fn b64_decode(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|e| Error::Crypto(format!("Base64: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc8_matches_firmware() {
        // 实测帧 byte0 = 0xa5，输入是设备 AP SSID 第 4 段去掉首字符后的 5 位
        assert_eq!(crc8(b"134DC"), 0xa5);
    }

    #[test]
    fn aes_cbc_roundtrip() {
        let key = [0x11u8; 16];
        let iv = [0u8; 16];
        let ct = aes128_cbc_encrypt(&key, &iv, b"example-pass").unwrap();
        assert_eq!(ct.len(), 16);
        assert_eq!(aes128_cbc_decrypt(&key, &iv, &ct).unwrap(), b"example-pass");
    }

    #[test]
    fn pbkdf2_one_iteration_is_hmac_of_salt_and_counter() {
        let out = pbkdf2_sha256(b"pw", b"salt", 1, 32);
        let mut msg = b"salt".to_vec();
        msg.extend_from_slice(&1u32.to_be_bytes());
        assert_eq!(out, hmac_sha256(b"pw", &msg).to_vec());
    }

    #[test]
    fn uuid_shape() {
        let u = uuid_v4();
        assert_eq!(u.len(), 36);
        assert_eq!(u.as_bytes()[14], b'4');
    }
}
