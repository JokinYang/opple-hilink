//! C ABI 导出层（供 `cdylib` / `staticlib` 使用）。
//!
//! 设计成**一个 JSON 进、一个 JSON 出**，因为核心 API 的类型比较丰富
//! （`String` / `&str` / `serde_json::Value` / `Result<T, Error>`），
//! 逐函数做 C 结构体映射会又脆又啰嗦；JSON 边界对 C、C++、JNI、Python `ctypes`、
//! Unity 都是一样的调用方式。
//!
//! 约定：
//! - 返回值永远是**堆分配的 UTF-8 JSON 字符串**，调用方用完必须调 [`opple_free`]；
//! - 返回体固定两态：`{"ok":true,"data":…}` / `{"ok":false,"error":{"kind":…,"message":…}}`；
//! - 入参指针为 NULL、非 UTF-8 或 JSON 非法时按错误返回，**不会 panic**（内部 `catch_unwind`）；
//! - 入参为空串时按 `{}` 处理。
//!
//! 典型 C 侧用法：
//! ```c
//! char *r = opple_call("derive", "{\"auth_code\":\"0011...\",\"sn1_hex\":\"...\",\"sn2_hex\":\"...\"}");
//! puts(r);
//! opple_free(r);
//! ```

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};

use serde_json::{json, Value};

use crate::control::{self, DeviceConfig};
use crate::crypto::{self, b64_decode};
use crate::error::{Error, Result};
use crate::provision::{self, BuildSpec};
use crate::{discovery, ota, session};

/// 包版本：`{"ok":true,"data":{"name":…,"version":…}}`
///
/// 单独给一个无参入口，方便加载方在真正调用业务接口前先做一次「库是否可用」探针。
#[no_mangle]
pub extern "C" fn opple_version() -> *mut c_char {
    to_c(json!({
        "ok": true,
        "data": {
            "name": env!("CARGO_PKG_NAME"),
            "version": env!("CARGO_PKG_VERSION"),
            "abi": 1,
        }
    }))
}

/// 统一入口：`op` 为操作名，`args_json` 为参数 JSON（可为 NULL，等价 `{}`）。
///
/// 返回堆分配字符串，**必须**用 [`opple_free`] 释放。
#[no_mangle]
pub extern "C" fn opple_call(op: *const c_char, args_json: *const c_char) -> *mut c_char {
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let op_name = match unsafe { read_str(op) } {
            Ok(s) => s,
            Err(e) => return err_value(&e),
        };
        let args = match unsafe { read_str(args_json) } {
            Ok(s) if s.trim().is_empty() => Value::Object(serde_json::Map::new()),
            Ok(s) => match serde_json::from_str::<Value>(&s) {
                Ok(v) if v.is_object() => v,
                Ok(_) => return err_value(&Error::Arg("args_json 必须是 JSON 对象".into())),
                Err(e) => return err_value(&Error::Json(e.to_string())),
            },
            Err(e) => return err_value(&e),
        };
        match dispatch(&op_name, &args) {
            Ok(data) => json!({ "ok": true, "data": data }),
            Err(e) => err_value(&e),
        }
    }));

    match outcome {
        Ok(v) => to_c(v),
        // panic 绝不跨 FFI 边界
        Err(_) => to_c(err_value(&Error::Arg("Rust 侧 panic 已被拦截".into()))),
    }
}

/// 释放 [`opple_call`] / [`opple_version`] 返回的字符串。传 NULL 是安全的。
///
/// # Safety
/// `p` 必须来自本库的返回，且只能释放一次。
#[no_mangle]
pub unsafe extern "C" fn opple_free(p: *mut c_char) {
    if !p.is_null() {
        drop(CString::from_raw(p));
    }
}

// ---------------------------------------------------------------- 分发

fn dispatch(op: &str, a: &Value) -> Result<Value> {
    match op {
        "version" => Ok(json!({
            "name": env!("CARGO_PKG_NAME"),
            "version": env!("CARGO_PKG_VERSION"),
            "abi": 1,
        })),
        "profile" => Ok(json!({
            "services": crate::profile::SERVICES
                .iter()
                .map(|(id, desc)| json!({"id": id, "desc": desc}))
                .collect::<Vec<_>>()
        })),

        // —— 纯计算：不触网，便于自检 ——
        "derive" => op_derive(a),
        "crc8" => {
            let key_id = str_arg(a, "key_id")?;
            Ok(json!({ "crc8": crypto::crc8(key_id.as_bytes()) }))
        }

        // —— 本地控制 ——
        "session" => op_session(a),
        "control" => op_control(a),

        // —— 配网帧 ——
        "prov_parse" => op_prov_parse(a),
        "prov_decrypt" => op_prov_decrypt(a),
        "prov_build" => op_prov_build(a),
        "prov_send" => op_prov_send(a),

        // —— 其他 ——
        "discover" => op_discover(a),
        "ota_mqtt" => op_ota_mqtt(a),
        "ota_status" => op_ota_status(a),

        other => Err(Error::Arg(format!("未知操作 {other}"))),
    }
}

fn op_derive(a: &Value) -> Result<Value> {
    let auth_code = hex_bytes(a, "auth_code", Some(16))?;
    let sn1 = hex_array8(a, "sn1_hex")?;
    let sn2 = hex_array8(a, "sn2_hex")?;
    let (psk, hmac_key) = session::Session::derive(&auth_code, &sn1, &sn2);
    Ok(json!({
        "psk": hex::encode(psk),
        "hmac_key": hex::encode(hmac_key),
    }))
}

fn op_session(a: &Value) -> Result<Value> {
    let cfg = session::SessionConfig {
        host: str_arg(a, "host")?,
        port: u16_arg(a, "port", 5686),
        account_id: str_arg(a, "account_id")?,
        auth_code: hex_bytes(a, "auth_code", Some(16))?,
        timeout_ms: u64_arg(a, "timeout_ms", 3500),
        retries: u64_arg(a, "retries", 2) as u32,
    };
    let s = session::create(&cfg)?;
    Ok(json!({
        "sess_id": s.sess_id,
        "sn1": hex::encode_upper(s.sn1),
        "sn2": hex::encode(s.sn2),
        "seq": s.seq,
        "psk": hex::encode(s.psk),
        "hmac_key": hex::encode(s.hmac_key),
    }))
}

/// 建会话 → 发一条服务 → 返回设备响应。`data` 可直接给对象，或用 `data_json` 给字符串。
fn op_control(a: &Value) -> Result<Value> {
    let cfg = DeviceConfig {
        host: str_arg(a, "host")?,
        port: u16_arg(a, "port", 5686),
        device_id: str_arg(a, "device_id")?,
        account_id: str_arg(a, "account_id")?,
        user_id: str_arg(a, "user_id")?,
        auth_code: hex_bytes(a, "auth_code", Some(16))?,
        timeout_ms: u64_arg(a, "timeout_ms", 3500),
        retries: u64_arg(a, "retries", 2) as u32,
    };
    let service = str_arg(a, "service")?;
    let data = match (a.get("data"), a.get("data_json")) {
        (Some(v), _) if v.is_object() => v.clone(),
        (_, Some(Value::String(s))) => serde_json::from_str::<Value>(s)?,
        _ => return Err(Error::Arg("需要 data（对象）或 data_json（JSON 字符串）".into())),
    };

    let mut sess = session::create(&cfg.session_config())?;
    let resp = control::send(&cfg, &mut sess, &service, &data)?;
    Ok(json!({
        "service": service,
        "response": resp,
        "session": { "sess_id": sess.sess_id, "seq": sess.seq },
    }))
}

fn op_prov_parse(a: &Value) -> Result<Value> {
    let frame = hex_bytes(a, "frame_hex", None)?;
    let ap_ssid = str_arg(a, "ap_ssid")?;
    let info = provision::parse(&frame, &ap_ssid)?;
    Ok(json!({
        "checksum1_ok": info.checksum1_ok,
        "checksum2_ok": info.checksum2_ok,
        "kind": info.kind,
        "type_byte": info.type_byte,
        "ssid": info.ssid,
        "whitebox_block": hex::encode(info.whitebox_block),
        "password_cipher": hex::encode(&info.password_cipher),
        "register_cipher": hex::encode(&info.register_cipher),
        "padded": info.padded,
        "unpadded_len": info.unpadded_len,
        "len": frame.len(),
    }))
}

fn op_prov_decrypt(a: &Value) -> Result<Value> {
    let frame = hex_bytes(a, "frame_hex", None)?;
    let ap_ssid = str_arg(a, "ap_ssid")?;
    let info = provision::parse(&frame, &ap_ssid)?;
    let key = aes_key_arg(a)?;
    let (password, register_json) = info.decrypt(&key)?;
    Ok(json!({ "password": password, "register_json": register_json }))
}

fn op_prov_build(a: &Value) -> Result<Value> {
    let key = aes_key_arg(a)?;
    let wb = match opt_str(a, "whitebox_hex") {
        Some(h) => {
            let v = hex::decode(&h).map_err(|e| Error::Arg(format!("whitebox_hex: {e}")))?;
            if v.len() != 16 {
                return Err(Error::Arg(format!("whitebox_hex 应为 16 字节，实际 {}", v.len())));
            }
            let mut b = [0u8; 16];
            b.copy_from_slice(&v);
            b
        }
        None => [0u8; 16],
    };
    let kind = a.get("kind").and_then(Value::as_u64).unwrap_or(100) as u8;
    let frame = provision::build(&BuildSpec {
        ap_ssid: &str_arg(a, "ap_ssid")?,
        kind,
        whitebox_block: wb,
        ssid: &str_arg(a, "ssid")?,
        password: &str_arg(a, "password")?,
        register_json: &str_arg(a, "register_json")?,
        aes_key: &key,
    })?;
    Ok(json!({ "frame_hex": hex::encode(&frame), "len": frame.len() }))
}

fn op_prov_send(a: &Value) -> Result<Value> {
    let frame = hex_bytes(a, "frame_hex", None)?;
    let out = provision::send_frame(
        &str_arg(a, "host")?,
        u16_arg(a, "port", 5683),
        &frame,
        u64_arg(a, "timeout_ms", 2000),
        u64_arg(a, "retries", 5) as u32,
    )?;
    Ok(json!({ "ack": out.ack, "attempts": out.attempts, "elapsed_ms": out.elapsed_ms }))
}

fn op_discover(a: &Value) -> Result<Value> {
    let d = discovery::query(
        &str_arg(a, "host")?,
        u16_arg(a, "port", 5686),
        u64_arg(a, "timeout_ms", 1500),
        u64_arg(a, "retries", 2) as u32,
    )?;
    Ok(json!({ "text": d.text, "json": d.json, "len": d.raw.len() }))
}

fn op_ota_mqtt(a: &Value) -> Result<Value> {
    let action = a.get("action").and_then(Value::as_u64).unwrap_or(0) as u8;
    if action > 1 {
        return Err(Error::Arg("action 只能是 0（检查）或 1（升级）".into()));
    }
    let ts = opt_str(a, "timestamp").unwrap_or_else(ota::utc_timestamp);
    let payload = ota::mqtt_command(
        &str_arg(a, "access_token")?,
        &str_arg(a, "user_id")?,
        &str_arg(a, "device_id")?,
        action,
        &ts,
    );
    Ok(json!({ "topic": ota::MQTT_TOPIC, "qos": 1, "payload": payload }))
}

fn op_ota_status(a: &Value) -> Result<Value> {
    let data = a.get("data").cloned().unwrap_or_else(|| json!({}));
    let s = ota::parse_status(&data);
    Ok(json!({
        "version": s.version,
        "introduction": s.introduction,
        "progress": s.progress,
        "boot_time": s.boot_time,
        "auto_update_on": s.auto_update_on,
    }))
}

// ---------------------------------------------------------------- 参数工具

fn str_arg(a: &Value, key: &str) -> Result<String> {
    a.get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| Error::Arg(format!("缺少字符串参数 {key}")))
}

fn opt_str(a: &Value, key: &str) -> Option<String> {
    a.get(key).and_then(Value::as_str).map(str::to_string)
}

fn u16_arg(a: &Value, key: &str, default: u16) -> u16 {
    a.get(key)
        .and_then(Value::as_u64)
        .map(|v| v as u16)
        .unwrap_or(default)
}

fn u64_arg(a: &Value, key: &str, default: u64) -> u64 {
    a.get(key).and_then(Value::as_u64).unwrap_or(default)
}

fn hex_bytes(a: &Value, key: &str, expect_len: Option<usize>) -> Result<Vec<u8>> {
    let s = str_arg(a, key)?;
    let v = hex::decode(s.trim()).map_err(|e| Error::Arg(format!("{key} 不是合法 hex: {e}")))?;
    if let Some(n) = expect_len {
        if v.len() != n {
            return Err(Error::Arg(format!("{key} 应为 {n} 字节，实际 {}", v.len())));
        }
    }
    Ok(v)
}

fn hex_array8(a: &Value, key: &str) -> Result<[u8; 8]> {
    let v = hex_bytes(a, key, Some(8))?;
    let mut out = [0u8; 8];
    out.copy_from_slice(&v);
    Ok(out)
}

/// 每帧 AES 密钥：`key_hex`（32 hex）或 `key_b64`，二选一。
fn aes_key_arg(a: &Value) -> Result<Vec<u8>> {
    let key = if a.get("key_hex").and_then(Value::as_str).is_some() {
        hex_bytes(a, "key_hex", Some(16))?
    } else if let Some(b64) = a.get("key_b64").and_then(Value::as_str) {
        b64_decode(b64)?
    } else {
        return Err(Error::Arg("需要 key_hex（32 hex）或 key_b64".into()));
    };
    if key.len() != 16 {
        return Err(Error::Arg(format!("AES 密钥应为 16 字节，实际 {}", key.len())));
    }
    Ok(key)
}

// ---------------------------------------------------------------- 边界工具

unsafe fn read_str(p: *const c_char) -> Result<String> {
    if p.is_null() {
        return Err(Error::Arg("指针为 NULL".into()));
    }
    CStr::from_ptr(p)
        .to_str()
        .map(str::to_string)
        .map_err(|e| Error::Arg(format!("不是合法 UTF-8: {e}")))
}

fn to_c(v: Value) -> *mut c_char {
    let s = v.to_string();
    match CString::new(s) {
        Ok(c) => c.into_raw(),
        // 输出里出现 NUL 属于异常；退化成最小错误体，保证不返回 NULL
        Err(_) => CString::new(r#"{"ok":false,"error":{"kind":"Ffi","message":"输出含 NUL"}}"#)
            .expect("静态串")
            .into_raw(),
    }
}

fn err_value(e: &Error) -> Value {
    json!({
        "ok": false,
        "error": { "kind": kind_name(e), "message": e.to_string() }
    })
}

fn kind_name(e: &Error) -> &'static str {
    match e {
        Error::Io(_) => "Io",
        Error::Timeout(_) => "Timeout",
        Error::Coap(_) => "Coap",
        Error::Crypto(_) => "Crypto",
        Error::Json(_) => "Json",
        Error::Frame(_) => "Frame",
        Error::Arg(_) => "Arg",
        Error::Device(_) => "Device",
    }
}
