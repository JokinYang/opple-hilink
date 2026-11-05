//! 统一错误类型。

use std::fmt;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Timeout(&'static str),
    Coap(String),
    Crypto(String),
    Json(String),
    Frame(String),
    Arg(String),
    Device(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "IO 错误: {e}"),
            Error::Timeout(what) => write!(f, "{what} 超时（设备无响应）"),
            Error::Coap(m) => write!(f, "CoAP 解析失败: {m}"),
            Error::Crypto(m) => write!(f, "加解密失败: {m}"),
            Error::Json(m) => write!(f, "JSON 错误: {m}"),
            Error::Frame(m) => write!(f, "配网帧错误: {m}"),
            Error::Arg(m) => write!(f, "参数错误: {m}"),
            Error::Device(m) => write!(f, "设备返回错误: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Json(e.to_string())
    }
}
