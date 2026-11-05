//! `opple_hilink_native`：opple-hilink 的 Python 扩展模块。
//!
//! 只暴露一个转发入口 `opple_call(op, args_json)`，直接复用 C ABI 层
//! （`opple_hilink::ffi`），保证「native」与「ctypes」两条后端行为完全一致——
//! 两者最终走的都是同一份 Rust 实现，只是跨语言边界的方式不同。
//!
//! 返回值同样是 `{"ok":true,"data":…}` / `{"ok":false,"error":{…}}` 的 JSON 字符串，
//! 由 Python 侧的 `opple_hilink.call()` 统一解包与抛错。

use std::ffi::{CStr, CString};

use pyo3::prelude::*;

/// 转发到 C ABI 的 `opple_call`，并负责释放返回的字符串。
fn forward(op: &str, args_json: &str) -> String {
    let op_c = match CString::new(op) {
        Ok(v) => v,
        Err(_) => return r#"{"ok":false,"error":{"kind":"Arg","message":"操作名含 NUL"}}"#.to_string(),
    };
    let args_c = match CString::new(args_json) {
        Ok(v) => v,
        Err(_) => {
            return r#"{"ok":false,"error":{"kind":"Arg","message":"参数含 NUL"}}"#.to_string()
        }
    };

    let ptr = opple_hilink::ffi::opple_call(op_c.as_ptr(), args_c.as_ptr());
    if ptr.is_null() {
        return r#"{"ok":false,"error":{"kind":"Ffi","message":"返回 NULL"}}"#.to_string();
    }
    let text = unsafe { CStr::from_ptr(ptr) }.to_string_lossy().into_owned();
    unsafe { opple_hilink::ffi::opple_free(ptr) };
    text
}

/// `opple_call(op, args_json="")` → JSON 字符串
#[pyfunction]
#[pyo3(signature = (op, args_json = ""))]
fn opple_call(op: &str, args_json: &str) -> String {
    forward(op, args_json)
}

/// `opple_version()` → JSON 字符串
#[pyfunction]
fn opple_version() -> String {
    let ptr = opple_hilink::ffi::opple_version();
    if ptr.is_null() {
        return r#"{"ok":false,"error":{"kind":"Ffi","message":"返回 NULL"}}"#.to_string();
    }
    let text = unsafe { CStr::from_ptr(ptr) }.to_string_lossy().into_owned();
    unsafe { opple_hilink::ffi::opple_free(ptr) };
    text
}

/// 纯计算快路径：keyId 的 crc8
#[pyfunction]
fn crc8(key_id: &str) -> u8 {
    opple_hilink::crypto::crc8(key_id.as_bytes())
}

#[pymodule]
fn opple_hilink_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(opple_call, m)?)?;
    m.add_function(wrap_pyfunction!(opple_version, m)?)?;
    m.add_function(wrap_pyfunction!(crc8, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
