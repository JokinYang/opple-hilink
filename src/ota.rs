//! 固件升级（OTA）两条通道。
//!
//! ## 1. 云端 MQTT（本机型实际使用）
//! App 把 `update` 服务列入「禁止本地控制」黑名单（`cafebabe/mwd.java` 的 `isAvailable()`），
//! 因此升级命令固定走云端：
//! ```text
//! topic : /smartHome/signaltrans/v2/categories/command    (QoS1)
//! payload:
//! {"header":{"method":"POST","accessToken":"<AT>","mode":"ACK","requestId":"<uuid>",
//!            "from":"/users/<uid>","to":"/devices/<devId>/services/update",
//!            "timestamp":"YYYYMMDDTHHMMSSZ"},
//!  "body":{"action":0|1}}
//! ```
//! `action=0` 检查新版本，`action=1` 启动升级。
//!
//! ## 2. 设备本地服务 `update`（同一套控制加密）
//! `POST /update` + `{"action":0|1}`；本机型固件 6.3.6 **不响应**（实测），仅供支持该服务的机型使用。
//! 升级进度通过服务数据上报：`{"version","introduction","progress","bootTime","autoUpdateOn"}`。

use serde_json::{json, Value};

use crate::crypto::uuid_v4;

pub const MQTT_TOPIC: &str = "/smartHome/signaltrans/v2/categories/command";

pub const ACTION_CHECK: u8 = 0;
pub const ACTION_START: u8 = 1;

/// 升级服务当前状态（设备上报的 data 结构）
pub fn parse_status(data: &Value) -> OtaStatus {
    OtaStatus {
        version: data.get("version").and_then(Value::as_str).unwrap_or("").to_string(),
        introduction: data.get("introduction").and_then(Value::as_str).unwrap_or("").to_string(),
        progress: data.get("progress").and_then(Value::as_i64).unwrap_or(-1),
        boot_time: data.get("bootTime").and_then(Value::as_i64).unwrap_or(-1),
        auto_update_on: data.get("autoUpdateOn").and_then(Value::as_i64).unwrap_or(-1),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtaStatus {
    pub version: String,
    pub introduction: String,
    pub progress: i64,
    pub boot_time: i64,
    pub auto_update_on: i64,
}

/// 生成 MQTT 升级命令（App → 云端）
pub fn mqtt_command(
    access_token: &str,
    user_id: &str,
    device_id: &str,
    action: u8,
    timestamp: &str,
) -> Value {
    json!({
        "header": {
            "method": "POST",
            "accessToken": access_token,
            "mode": "ACK",
            "requestId": uuid_v4(),
            "from": format!("/users/{user_id}"),
            "to": format!("/devices/{device_id}/services/update"),
            "timestamp": timestamp,
        },
        "body": { "action": action }
    })
}

/// 本地 `update` 服务的请求体
pub fn local_update_body(action: u8) -> Value {
    json!({ "action": action })
}

/// 生成 `yyyyMMdd'T'HHmmss'Z'` 时间戳（UTC）。
/// 不引入 chrono：用 Unix 时间手算。
pub fn utc_timestamp() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_utc(secs)
}

fn format_utc(secs: u64) -> String {
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, m, d) = civil_from_days(days as i64);
    format!("{y:04}{m:02}{d:02}T{h:02}{mi:02}{s:02}Z")
}

/// Howard Hinnant 的 days→(y,m,d) 算法
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_shape() {
        let t = format_utc(1_793_055_957); // 2026-10-27T08:25:57Z 附近
        assert_eq!(t.len(), 16);
        assert!(t.ends_with('Z'));
        assert_eq!(&t[8..9], "T");
    }

    #[test]
    fn mqtt_body_shape() {
        let v = mqtt_command("AT", "1000", "dev-1", ACTION_CHECK, "20261027T080557Z");
        assert_eq!(v["header"]["to"], "/devices/dev-1/services/update");
        assert_eq!(v["header"]["method"], "POST");
        assert_eq!(v["body"]["action"], 0);
        assert_eq!(v["header"]["from"], "/users/1000");
    }

    #[test]
    fn status_parse() {
        let d = json!({"bootTime":0,"action":0,"progress":42,"version":"6.3.7","introduction":"x","autoUpdateOn":0});
        let s = parse_status(&d);
        assert_eq!(s.progress, 42);
        assert_eq!(s.version, "6.3.7");
    }
}
