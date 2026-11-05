"""opple-hilink 的 Python 绑定。

两套后端，自动选择：

1. **native** —— 编译出的 PyO3 扩展 `opple_hilink._native`（wheel 自带），最快；
2. **ctypes** —— 直接加载 Rust 产出的 `opple_hilink.dll` / `libopple_hilink.so`，无需编译 Python 扩展。

两者共用同一份 C ABI 约定（JSON 进、JSON 出），所以行为一致：

- 返回体 ``{"ok":true,"data":…}`` / ``{"ok":false,"error":{"kind":…,"message":…}}``
- 失败统一抛 :class:`OppleError`，``err.kind`` 可用于分类处理

快速上手::

    import opple_hilink as opple

    print(opple.version())
    print(opple.crc8("134DC"))                     # 165
    psk = opple.derive(auth_code, sn1, sn2)

    lamp = opple.Client("192.168.1.100", device_id, account_id, user_id, auth_code)
    lamp.on()
    lamp.brightness(120)
    lamp.cct(4000)

库文件查找顺序（ctypes 后端）：``OPPLE_HILINK_LIB`` → 包目录 → 仓库的
``target/{release,debug}`` → ``jniLibs/<abi>/`` → 系统搜索路径。
"""

from __future__ import annotations

import ctypes
import importlib
import json
import os
import sys
from typing import Any, Dict, List, Optional, Sequence

__all__ = [
    "OppleError",
    "Client",
    "backend",
    "library_path",
    "call",
    "version",
    "profile",
    "crc8",
    "derive",
    "session",
    "control",
    "prov_parse",
    "prov_decrypt",
    "prov_build",
    "prov_send",
    "discover",
    "ota_mqtt",
    "ota_status",
]

__version__ = "0.1.0"


class OppleError(Exception):
    """协议/参数/网络错误。``kind`` 与 Rust 侧 ``Error`` 枚举一一对应。"""

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(f"[{kind}] {message}")
        self.kind = kind
        self.message = message


# --------------------------------------------------------------------------- 后端

_lib: Optional[ctypes.CDLL] = None
_lib_path: Optional[str] = None
_native = None
_backend = "unset"


def _lib_names() -> Sequence[str]:
    sysname = sys.platform
    if sysname.startswith("win"):
        return ("opple_hilink.dll", "libopple_hilink.dll")
    if sysname == "darwin":
        return ("libopple_hilink.dylib", "opple_hilink.dylib")
    return ("libopple_hilink.so", "opple_hilink.so")


def _candidates() -> List[str]:
    out: List[str] = []
    env = os.environ.get("OPPLE_HILINK_LIB")
    if env:
        out.append(env)

    here = os.path.dirname(os.path.abspath(__file__))
    for d in (here, os.path.dirname(here)):
        for n in _lib_names():
            out.append(os.path.join(d, n))

    # 源码仓库布局：<repo>/target/{release,debug}、<repo>/jniLibs/<abi>
    repo = os.path.dirname(os.path.dirname(here))
    for profile in ("release", "debug"):
        for n in _lib_names():
            out.append(os.path.join(repo, "target", profile, n))
    for abi in ("arm64-v8a", "armeabi-v7a", "x86_64", "x86"):
        for n in _lib_names():
            out.append(os.path.join(repo, "jniLibs", abi, n))
    return out


def _load_ctypes() -> ctypes.CDLL:
    global _lib, _lib_path
    if _lib is not None:
        return _lib

    for p in _candidates():
        if p and os.path.isfile(p):
            try:
                lib = ctypes.CDLL(p)
            except OSError:
                continue
            lib.opple_call.restype = ctypes.c_void_p
            lib.opple_call.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
            lib.opple_version.restype = ctypes.c_void_p
            lib.opple_version.argtypes = []
            lib.opple_free.restype = None
            lib.opple_free.argtypes = [ctypes.c_void_p]
            _lib, _lib_path = lib, p
            return lib

    # 最后尝试系统搜索路径（例如已复制到 site-packages 或 PATH）
    last_err = None
    for n in _lib_names():
        try:
            lib = ctypes.CDLL(n)
        except OSError as e:  # pragma: no cover - 依赖环境
            last_err = e
            continue
        lib.opple_call.restype = ctypes.c_void_p
        lib.opple_call.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        lib.opple_version.restype = ctypes.c_void_p
        lib.opple_version.argtypes = []
        lib.opple_free.restype = None
        lib.opple_free.argtypes = [ctypes.c_void_p]
        _lib, _lib_path = lib, n
        return lib

    raise OppleError(
        "LibraryNotFound",
        "找不到 %s；请先 `cargo build --release`（或 `cargo ndk ... build --release`），"
        "或用环境变量 OPPLE_HILINK_LIB 指定库文件路径。最后错误: %s"
        % (" / ".join(_lib_names()), last_err),
    )


def _pick_backend() -> None:
    global _native, _backend
    if _backend != "unset":
        return
    forced = os.environ.get("OPPLE_HILINK_BACKEND", "").strip().lower()
    if forced == "ctypes":
        _backend = "ctypes"
        return

    # 优先包内子模块（wheel / maturin develop 产出的 `opple_hilink._native`），
    # 其次顶层模块（手工把 .pyd/.so 放在 python/ 下的开发场景）
    for name in (f"{__name__}._native", "opple_hilink_native"):
        try:
            _native = importlib.import_module(name)
            _backend = "native"
            return
        except Exception:
            continue

    if forced in ("native", "pyo3"):
        raise OppleError(
            "BackendUnavailable",
            "OPPLE_HILINK_BACKEND=native，但找不到扩展模块 `opple_hilink._native`；"
            "请用 wheel 安装（pip install dist/*.whl）或 `maturin develop`。",
        )
    _backend = "ctypes"


def backend() -> str:
    """当前后端：``"native"`` 或 ``"ctypes"``。"""
    _pick_backend()
    return _backend


def library_path() -> Optional[str]:
    """ctypes 后端实际加载的库路径；native 后端返回扩展模块路径。"""
    _pick_backend()
    if _backend == "native" and _native is not None:
        return getattr(_native, "__file__", None)
    if _lib is None:
        try:
            _load_ctypes()
        except OppleError:
            return None
    return _lib_path


# --------------------------------------------------------------------------- 调用层


def _decode(raw: Any) -> Dict[str, Any]:
    if not raw:
        raise OppleError("Ffi", "原生调用返回 NULL")
    try:
        text = ctypes.string_at(raw).decode("utf-8")
    finally:
        if _lib is not None:
            _lib.opple_free(raw)
    return json.loads(text)


def call(op: str, **kwargs: Any) -> Any:
    """直接调用底层操作；``kwargs`` 会序列化成 JSON 参数。

    返回 ``data`` 字段（已脱掉 ``{"ok":true}`` 外壳）；失败抛 :class:`OppleError`。
    """
    _pick_backend()
    args = {k: v for k, v in kwargs.items() if v is not None}

    if _backend == "native" and _native is not None:
        obj = json.loads(_native.opple_call(op, json.dumps(args, ensure_ascii=False)))
    else:
        lib = _load_ctypes()
        payload = json.dumps(args, ensure_ascii=False).encode("utf-8")
        obj = _decode(lib.opple_call(op.encode("utf-8"), payload))

    if not obj.get("ok"):
        err = obj.get("error") or {}
        raise OppleError(err.get("kind", "Unknown"), err.get("message", "未知错误"))
    return obj.get("data")


def version() -> Dict[str, Any]:
    return call("version")


def profile() -> List[Dict[str, str]]:
    return call("profile")["services"]


# --------------------------------------------------------------------------- 参数规整


def _hex_bytes(value: Any, field: str, length: Optional[int] = None) -> str:
    """接受 ``bytes`` 或 hex 字符串，统一返回小写 hex。"""
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        if length is not None and len(raw) != length:
            raise ValueError(f"{field} 应为 {length} 字节，实际 {len(raw)}")
        return raw.hex()
    if isinstance(value, str):
        s = value.strip().lower()
        try:
            raw = bytes.fromhex(s)
        except ValueError as e:
            raise ValueError(f"{field} 不是合法 hex: {e}") from e
        if length is not None and len(raw) != length:
            raise ValueError(f"{field} 应为 {length} 字节，实际 {len(raw)}")
        return s
    raise TypeError(f"{field} 需要 bytes 或 hex 字符串，收到 {type(value).__name__}")


def _aes_key_kwargs(key: Any) -> Dict[str, str]:
    """把 AES 密钥规整成 ``key_hex`` 或 ``key_b64``。"""
    if isinstance(key, (bytes, bytearray, memoryview)):
        raw = bytes(key)
        if len(raw) != 16:
            raise ValueError(f"密钥应为 16 字节，实际 {len(raw)}")
        return {"key_hex": raw.hex()}
    if isinstance(key, str):
        s = key.strip()
        if len(s) == 32 and all(c in "0123456789abcdefABCDEF" for c in s):
            return {"key_hex": s.lower()}
        return {"key_b64": s}
    raise TypeError("key 需要 bytes 或字符串")


def crc8(key_id: str) -> int:
    """keyId 的 crc8（配网帧 byte0）。"""
    return int(call("crc8", key_id=key_id)["crc8"])


def derive(auth_code: Any, sn1: Any, sn2: Any) -> Dict[str, str]:
    """由 authCode 与 sn1/sn2 派生 ``psk`` / ``hmac_key``（纯计算，不触网）。"""
    return call(
        "derive",
        auth_code=_hex_bytes(auth_code, "auth_code", 16),
        sn1_hex=_hex_bytes(sn1, "sn1", 8),
        sn2_hex=_hex_bytes(sn2, "sn2", 8),
    )


def session(host: str, account_id: str, auth_code: Any, port: int = 5686, timeout_ms: int = 3500, retries: int = 2) -> Dict[str, Any]:
    """建立本地会话，返回 ``sess_id/sn1/sn2/seq/psk/hmac_key``。"""
    return call(
        "session",
        host=host,
        port=port,
        account_id=account_id,
        auth_code=_hex_bytes(auth_code, "auth_code", 16),
        timeout_ms=timeout_ms,
        retries=retries,
    )


def control(
    host: str,
    device_id: str,
    account_id: str,
    user_id: str,
    auth_code: Any,
    service: str,
    data: Optional[Dict[str, Any]] = None,
    port: int = 5686,
    timeout_ms: int = 3500,
    retries: int = 2,
) -> Dict[str, Any]:
    """建会话并下发一条服务命令，返回设备响应。"""
    return call(
        "control",
        host=host,
        port=port,
        device_id=device_id,
        account_id=account_id,
        user_id=user_id,
        auth_code=_hex_bytes(auth_code, "auth_code", 16),
        service=service,
        data=data if data is not None else {},
        timeout_ms=timeout_ms,
        retries=retries,
    )


# --------------------------------------------------------------------------- 配网帧


def prov_parse(frame: Any, ap_ssid: str) -> Dict[str, Any]:
    return call("prov_parse", frame_hex=_hex_bytes(frame, "frame"), ap_ssid=ap_ssid)


def prov_decrypt(frame: Any, ap_ssid: str, key: Any) -> Dict[str, Any]:
    return call(
        "prov_decrypt",
        frame_hex=_hex_bytes(frame, "frame"),
        ap_ssid=ap_ssid,
        **_aes_key_kwargs(key),
    )


def prov_build(
    ap_ssid: str,
    ssid: str,
    password: str,
    register_json: str,
    key: Any,
    kind: int = 100,
    whitebox: Optional[Any] = None,
) -> bytes:
    """组一帧配网报文，返回原始字节。``whitebox`` 未知时可省略（全 0 占位）。"""
    data = call(
        "prov_build",
        ap_ssid=ap_ssid,
        kind=kind,
        ssid=ssid,
        password=password,
        register_json=register_json,
        whitebox_hex=_hex_bytes(whitebox, "whitebox", 16) if whitebox is not None else None,
        **_aes_key_kwargs(key),
    )
    return bytes.fromhex(data["frame_hex"])


def prov_send(frame: Any, host: str = "192.168.5.1", port: int = 5683, timeout_ms: int = 2000, retries: int = 5) -> Dict[str, Any]:
    return call(
        "prov_send",
        host=host,
        port=port,
        frame_hex=_hex_bytes(frame, "frame"),
        timeout_ms=timeout_ms,
        retries=retries,
    )


# --------------------------------------------------------------------------- 其他


def discover(host: str, port: int = 5686, timeout_ms: int = 1500, retries: int = 2) -> Dict[str, Any]:
    return call("discover", host=host, port=port, timeout_ms=timeout_ms, retries=retries)


def ota_mqtt(access_token: str, user_id: str, device_id: str, action: int = 0, timestamp: Optional[str] = None) -> Dict[str, Any]:
    return call(
        "ota_mqtt",
        access_token=access_token,
        user_id=user_id,
        device_id=device_id,
        action=action,
        timestamp=timestamp,
    )


def ota_status(data: Dict[str, Any]) -> Dict[str, Any]:
    return call("ota_status", data=data)


# --------------------------------------------------------------------------- 便捷客户端


class Client:
    """一台灯的便捷封装：``Client(host, device_id, account_id, user_id, auth_code)``。

    每次调用都会先建会话再下发命令（设备侧只保留一个本地会话，这符合它的行为）。
    """

    def __init__(
        self,
        host: str,
        device_id: str,
        account_id: str,
        user_id: str,
        auth_code: Any,
        port: int = 5686,
        timeout_ms: int = 3500,
        retries: int = 2,
    ) -> None:
        self.host = host
        self.device_id = device_id
        self.account_id = account_id
        self.user_id = user_id
        self.auth_code = auth_code
        self.port = port
        self.timeout_ms = timeout_ms
        self.retries = retries

    def __repr__(self) -> str:
        return f"Client(host={self.host!r}, device_id={self.device_id!r})"

    # 原始通道
    def send(self, service: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return control(
            self.host,
            self.device_id,
            self.account_id,
            self.user_id,
            self.auth_code,
            service,
            data,
            self.port,
            self.timeout_ms,
            self.retries,
        )

    def session(self) -> Dict[str, Any]:
        return session(
            self.host,
            self.account_id,
            self.auth_code,
            self.port,
            self.timeout_ms,
            self.retries,
        )

    # 常用服务
    def on(self) -> Dict[str, Any]:
        return self.send("switch", {"on": 1})

    def off(self) -> Dict[str, Any]:
        return self.send("switch", {"on": 0})

    def brightness(self, value: int) -> Dict[str, Any]:
        if not 26 <= value <= 255:
            raise ValueError("brightness 取值 26-255（26≈10%）")
        return self.send("brightness", {"brightness": int(value)})

    def cct(self, kelvin: int) -> Dict[str, Any]:
        if not 2000 <= kelvin <= 6500:
            raise ValueError("cct 取值 2000-6500")
        return self.send("cct", {"colorTemperature": int(kelvin)})

    def mode(self, mode: int) -> Dict[str, Any]:
        if mode not in (2, 3, 4, 6):
            raise ValueError("mode 取值 2|3|4|6（阅读/读写/电脑/自定义）")
        return self.send("lightMode", {"mode": int(mode)})

    def side(self, on: bool = True) -> Dict[str, Any]:
        return self.send("nightSwitch", {"on": 1 if on else 0})

    def backlight(self, on: bool = True) -> Dict[str, Any]:
        return self.send("backlight", {"on": 1 if on else 0})
