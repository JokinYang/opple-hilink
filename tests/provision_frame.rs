//! 配网白盒帧的回归测试：解析、校验、解密、重建逐字节一致。
//!
//! 夹具是**合成数据**——由本实现的 `provision::build` 生成，不含任何真机凭据、家庭 SSID
//! 或设备标识。真机帧的原始回归（校验字节、真实白盒块、516B 帧）在 `docs/` 的分析报告里
//! 记录，其字节未纳入仓库。
//!
//! 覆盖点：keyId→crc8、两段校验、长度字段编解码、UTF-8 SSID（含中文）、
//! AES-128-CBC/PKCS7（IV=0）加解密、奇偶补齐分支、重建逐字节一致。

use opple_hilink::provision::{self, BuildSpec};

/// 设备 AP SSID：只用于推导 byte0 的 keyId（第 4 段去掉首字符取 5 位 → `TEST1`）
const AP_SSID: &str = "Hi- OPPLE-READINGLAMP-0TEST1";

/// 16B 白盒块：真实值由 `libsecurityi.so` 生成，这里用固定假值占位
const WHITEBOX_BLOCK: [u8; 16] = [
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
];

/// 每帧随机 AES-128 密钥（真实值随帧变化，这里固定以便复现）
const AES_KEY: [u8; 16] = [0x5A; 16];

const PASSWORD: &str = "example-pass";
const REGISTER: &str = concat!(
    r#"{"appName":"smarthome","countryCode":"CN","#,
    r#""devId":"00000000-0000-4000-8000-000000000000","#,
    r#""code":"DEMO0000","psk":"00000000000000000000000000000000","#,
    r#""cloudUrl":"iomplatform.hicloud.com"}"#
);

/// 16 字节 SSID（UTF-8 偶数长）→ 未补齐长度为奇数 → 帧尾补 1 字节 0x00
const SSID_EVEN: &str = "测试卧室-2.4";
/// 17 字节 SSID（UTF-8 奇数长）→ 未补齐长度为偶数 → 不补齐
const SSID_ODD: &str = "测试卧室-2.4G";

fn fixture(ssid: &str) -> Vec<u8> {
    provision::build(&BuildSpec {
        ap_ssid: AP_SSID,
        kind: 100,
        whitebox_block: WHITEBOX_BLOCK,
        ssid,
        password: PASSWORD,
        register_json: REGISTER,
        aes_key: &AES_KEY,
    })
    .expect("组帧失败")
}

#[test]
fn parses_synthetic_frame() {
    let raw = fixture(SSID_EVEN);
    let info = provision::parse(&raw, AP_SSID).expect("解析失败");

    assert!(info.checksum1_ok, "byte0 校验应通过");
    assert!(info.checksum2_ok, "byte1 校验应通过");
    assert_eq!(info.kind, 100);
    assert_eq!(info.type_byte, 0x10);
    assert_eq!(info.ssid, SSID_EVEN);
    assert_eq!(info.whitebox_block, WHITEBOX_BLOCK);

    // 密码 "example-pass" 12B → PKCS7 补到 16B；注册包按块对齐
    assert_eq!(info.password_cipher.len(), 16);
    assert_eq!(info.register_cipher.len() % 16, 0);
    assert!(info.register_cipher.len() >= 16);

    // 结构自洽：20B 帧头 + SSID + 密码密文 + 1B 长度 + 注册包密文
    let expect = 20 + SSID_EVEN.len() + info.password_cipher.len() + 1 + info.register_cipher.len();
    assert_eq!(info.unpadded_len, expect);
}

#[test]
fn padding_branches() {
    // 16B SSID → 未补齐长度奇数 → 补 1 字节
    let padded = fixture(SSID_EVEN);
    let pi = provision::parse(&padded, AP_SSID).unwrap();
    assert!(pi.padded, "奇数总长应补齐");
    assert_eq!(padded.len(), pi.unpadded_len + 1);
    assert_eq!(padded[pi.unpadded_len], 0x00);

    // 17B SSID → 未补齐长度偶数 → 不补
    let bare = fixture(SSID_ODD);
    let bi = provision::parse(&bare, AP_SSID).unwrap();
    assert!(!bi.padded, "偶数总长不应补齐");
    assert_eq!(bare.len(), bi.unpadded_len);
}

#[test]
fn decrypts_roundtrip() {
    let info = provision::parse(&fixture(SSID_EVEN), AP_SSID).expect("解析失败");
    let (pwd, reg) = info.decrypt(&AES_KEY).expect("解密失败");
    assert_eq!(pwd, PASSWORD);
    assert_eq!(reg, REGISTER);
}

#[test]
fn rebuild_is_byte_identical() {
    let raw = fixture(SSID_EVEN);
    let info = provision::parse(&raw, AP_SSID).expect("解析失败");
    let (pwd, reg) = info.decrypt(&AES_KEY).expect("解密失败");

    let rebuilt = provision::build(&BuildSpec {
        ap_ssid: AP_SSID,
        kind: info.kind,
        whitebox_block: info.whitebox_block,
        ssid: &info.ssid,
        password: &pwd,
        register_json: &reg,
        aes_key: &AES_KEY,
    })
    .expect("组帧失败");

    assert_eq!(hex::encode(&rebuilt), hex::encode(&raw), "重建帧应与输入逐字节一致");
}

#[test]
fn rejects_bad_checksums() {
    // byte0 = crc8(keyId)
    let mut raw = fixture(SSID_EVEN);
    raw[0] ^= 0xFF;
    assert!(!provision::parse(&raw, AP_SSID).unwrap().checksum1_ok);

    // byte1 = crc8(frame[2..iA])，改中段字节应使校验失效
    let mut raw2 = fixture(SSID_EVEN);
    raw2[25] ^= 0x01;
    assert!(!provision::parse(&raw2, AP_SSID).unwrap().checksum2_ok);

    // 未改动的帧两个校验都成立
    let ok = provision::parse(&fixture(SSID_EVEN), AP_SSID).unwrap();
    assert!(ok.checksum1_ok && ok.checksum2_ok);
}
