//! C ABI 边界测试：直接以 C 字符串指针调用 `opple_call` / `opple_version`，
//! 覆盖正常返回、错误返回、NULL 入参、以及返回值的释放路径。
//!
//! 这里只走**不触网**的操作（derive / crc8 / profile / prov_*），因此可以在 CI 里跑。

use std::ffi::{CStr, CString};

use opple_hilink::ffi::{opple_call, opple_free, opple_version};
use opple_hilink::session::Session;

/// 调用一次并取回 JSON 文本，随后释放指针
fn call(op: &str, args: &str) -> serde_json::Value {
    let op_c = CString::new(op).unwrap();
    let args_c = CString::new(args).unwrap();
    let p = opple_call(op_c.as_ptr(), args_c.as_ptr());
    assert!(!p.is_null(), "返回指针不应为 NULL");
    let text = unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_string();
    unsafe { opple_free(p) };
    serde_json::from_str(&text).expect("返回值应为合法 JSON")
}

#[test]
fn version_probe() {
    let p = opple_version();
    assert!(!p.is_null());
    let text = unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_string();
    unsafe { opple_free(p) };

    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["data"]["name"], "opple-hilink");
    assert_eq!(v["data"]["abi"], 1);
}

#[test]
fn derive_matches_rust_api() {
    let auth = "00112233445566778899aabbccddeeff";
    let sn1 = "0102030405060708";
    let sn2 = "1112131415161718";

    let v = call(
        "derive",
        &format!(r#"{{"auth_code":"{auth}","sn1_hex":"{sn1}","sn2_hex":"{sn2}"}}"#),
    );
    assert_eq!(v["ok"], true, "{v}");

    let (psk, mac) = Session::derive(
        &hex::decode(auth).unwrap(),
        &hex::decode(sn1).unwrap().try_into().unwrap(),
        &hex::decode(sn2).unwrap().try_into().unwrap(),
    );
    assert_eq!(v["data"]["psk"], hex::encode(psk));
    assert_eq!(v["data"]["hmac_key"], hex::encode(mac));
}

#[test]
fn crc8_and_profile() {
    let v = call("crc8", r#"{"key_id":"134DC"}"#);
    assert_eq!(v["ok"], true);
    assert_eq!(v["data"]["crc8"], 0xa5);

    let p = call("profile", "");
    assert_eq!(p["ok"], true);
    assert!(p["data"]["services"].as_array().unwrap().len() >= 6);
}

#[test]
fn provision_roundtrip_via_ffi() {
    let key = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
    let build_args = serde_json::json!({
        "ap_ssid": "Hi- OPPLE-READINGLAMP-0TEST1",
        "kind": 100,
        "ssid": "测试卧室-2.4",
        "password": "example-pass",
        "register_json": r#"{"appName":"smarthome","code":"DEMO0000"}"#,
        "key_hex": key,
        "whitebox_hex": "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
    });
    let built = call("prov_build", &build_args.to_string());
    assert_eq!(built["ok"], true, "{built}");
    let frame_hex = built["data"]["frame_hex"].as_str().unwrap().to_string();

    let parsed = call(
        "prov_parse",
        &serde_json::json!({
            "frame_hex": frame_hex,
            "ap_ssid": "Hi- OPPLE-READINGLAMP-0TEST1",
        })
        .to_string(),
    );
    assert_eq!(parsed["ok"], true, "{parsed}");
    assert_eq!(parsed["data"]["ssid"], "测试卧室-2.4");
    assert_eq!(parsed["data"]["kind"], 100);
    assert_eq!(parsed["data"]["checksum1_ok"], true);
    assert_eq!(parsed["data"]["checksum2_ok"], true);

    let plain = call(
        "prov_decrypt",
        &serde_json::json!({
            "frame_hex": frame_hex,
            "ap_ssid": "Hi- OPPLE-READINGLAMP-0TEST1",
            "key_hex": key,
        })
        .to_string(),
    );
    assert_eq!(plain["ok"], true, "{plain}");
    assert_eq!(plain["data"]["password"], "example-pass");
    assert!(plain["data"]["register_json"]
        .as_str()
        .unwrap()
        .contains("DEMO0000"));
}

#[test]
fn ota_helpers() {
    let v = call(
        "ota_mqtt",
        r#"{"access_token":"AT","user_id":"1000","device_id":"dev-1","action":1,"timestamp":"20261027T080557Z"}"#,
    );
    assert_eq!(v["ok"], true, "{v}");
    assert_eq!(v["data"]["topic"], "/smartHome/signaltrans/v2/categories/command");
    assert_eq!(v["data"]["payload"]["body"]["action"], 1);
    assert_eq!(
        v["data"]["payload"]["header"]["to"],
        "/devices/dev-1/services/update"
    );

    let s = call("ota_status", r#"{"data":{"version":"6.3.7","progress":42}}"#);
    assert_eq!(s["ok"], true);
    assert_eq!(s["data"]["progress"], 42);
}

#[test]
fn error_paths_do_not_panic() {
    // 未知操作
    let v = call("nope", "{}");
    assert_eq!(v["ok"], false);
    assert_eq!(v["error"]["kind"], "Arg");

    // 非法 JSON
    let v = call("derive", "{not json");
    assert_eq!(v["ok"], false);

    // 缺参数
    let v = call("derive", "{}");
    assert_eq!(v["ok"], false);
    assert_eq!(v["error"]["kind"], "Arg");

    // NULL 入参
    let op = CString::new("derive").unwrap();
    let p = opple_call(op.as_ptr(), std::ptr::null());
    assert!(!p.is_null());
    let text = unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_string();
    unsafe { opple_free(p) };
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["ok"], false);

    // 两个指针都为 NULL
    let p = opple_call(std::ptr::null(), std::ptr::null());
    assert!(!p.is_null());
    unsafe { opple_free(p) };

    // 释放 NULL 安全
    unsafe { opple_free(std::ptr::null_mut()) };
}
