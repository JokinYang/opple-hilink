"""Python 绑定回归测试（不触网）。

运行：

    python -m unittest discover -s python/tests -v

只覆盖纯计算与配网帧编解码；涉及设备的 `session` / `control` / `prov_send` 需要真机，
不在自动化范围内。
"""

import json
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.dirname(HERE)

# 优先用已安装的包（wheel / `pip install -e`），否则退回归仓库里的源码目录
try:
    import opple_hilink as opple  # noqa: E402
except ImportError:  # pragma: no cover - 取决于运行方式
    sys.path.insert(0, SRC)
    import opple_hilink as opple  # noqa: E402

AUTH = "00112233445566778899aabbccddeeff"
SN1 = "0102030405060708"
SN2 = "1112131415161718"
KEY = bytes([0x5A] * 16)
WB = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
AP_SSID = "Hi- OPPLE-READINGLAMP-0TEST1"

# 与 Rust 侧 tests/ffi.rs 使用同一组合成输入，因此期望值是固定的
EXPECT_PSK = "fc53d0031ba55c576e6f96edb8dd3856"
EXPECT_HMAC = "eb95b78e3ea9f0b32de44a1085e0bf2b34dec62d570680d0e7425c7cfac0d053"


def build_frame():
    return opple.prov_build(
        ap_ssid=AP_SSID,
        ssid="测试卧室-2.4",
        password="example-pass",
        register_json=json.dumps({"code": "DEMO0000"}),
        key=KEY,
        whitebox=WB,
    )


class BindingTest(unittest.TestCase):
    def test_backend_known(self):
        self.assertIn(opple.backend(), ("native", "ctypes"))

    def test_version(self):
        v = opple.version()
        self.assertEqual(v["name"], "opple-hilink")
        self.assertEqual(v["abi"], 1)

    def test_crc8(self):
        self.assertEqual(opple.crc8("134DC"), 0xA5)
        self.assertEqual(opple.crc8("TEST1"), opple.crc8(b"TEST1".decode()))

    def test_derive_matches_rust(self):
        d = opple.derive(AUTH, SN1, SN2)
        self.assertEqual(d["psk"], EXPECT_PSK)
        self.assertEqual(d["hmac_key"], EXPECT_HMAC)

    def test_derive_accepts_bytes(self):
        a = opple.derive(bytes.fromhex(AUTH), bytes.fromhex(SN1), bytes.fromhex(SN2))
        b = opple.derive(AUTH, SN1, SN2)
        self.assertEqual(a, b)

    def test_derive_rejects_wrong_length(self):
        with self.assertRaises(ValueError):
            opple.derive("0011", SN1, SN2)

    def test_prov_roundtrip(self):
        frame = build_frame()
        self.assertIsInstance(frame, bytes)
        self.assertGreater(len(frame), 20)

        info = opple.prov_parse(frame, AP_SSID)
        self.assertTrue(info["checksum1_ok"])
        self.assertTrue(info["checksum2_ok"])
        self.assertEqual(info["ssid"], "测试卧室-2.4")
        self.assertEqual(info["kind"], 100)
        self.assertEqual(info["whitebox_block"], WB)

        plain = opple.prov_decrypt(frame, AP_SSID, KEY)
        self.assertEqual(plain["password"], "example-pass")
        self.assertIn("DEMO0000", plain["register_json"])

    def test_prov_parse_accepts_hex_str(self):
        frame = build_frame()
        a = opple.prov_parse(frame, AP_SSID)
        b = opple.prov_parse(frame.hex(), AP_SSID)
        self.assertEqual(a, b)

    def test_error_kind(self):
        with self.assertRaises(opple.OppleError) as ctx:
            opple.call("definitely-not-an-op")
        self.assertEqual(ctx.exception.kind, "Arg")

    def test_ota_helpers(self):
        v = opple.ota_mqtt(
            access_token="AT",
            user_id="1000",
            device_id="dev-1",
            action=1,
            timestamp="20261027T080557Z",
        )
        self.assertEqual(v["topic"], "/smartHome/signaltrans/v2/categories/command")
        self.assertEqual(v["qos"], 1)
        self.assertEqual(v["payload"]["body"]["action"], 1)
        self.assertEqual(v["payload"]["header"]["to"], "/devices/dev-1/services/update")

        s = opple.ota_status({"version": "6.3.7", "progress": 42})
        self.assertEqual(s["progress"], 42)

    def test_client_validation(self):
        c = opple.Client("127.0.0.1", "dev", "acc", "1000", AUTH)
        self.assertIn("127.0.0.1", repr(c))
        with self.assertRaises(ValueError):
            c.brightness(10)
        with self.assertRaises(ValueError):
            c.cct(1000)
        with self.assertRaises(ValueError):
            c.mode(5)

    def test_backend_parity(self):
        """native 与 ctypes 两个后端在同一输入下必须给出相同结果。

        两条后端无法在同一进程内共存（模块级单例），因此用子进程各跑一次再比对。
        """
        if not _native_available():
            self.skipTest("本机没有 PyO3 扩展，跳过双后端对比")

        outs = {}
        for be in ("native", "ctypes"):
            env = dict(os.environ, OPPLE_HILINK_BACKEND=be, PYTHONIOENCODING="utf-8")
            r = subprocess.run(
                [sys.executable, os.path.abspath(__file__), "--probe"],
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            outs[be] = json.loads(r.stdout.strip().splitlines()[-1])

        self.assertEqual(outs["native"]["backend"], "native")
        self.assertEqual(outs["ctypes"]["backend"], "ctypes")
        self.assertEqual(outs["native"]["parse"], outs["ctypes"]["parse"])
        self.assertEqual(outs["native"]["derive"], outs["ctypes"]["derive"])
        self.assertEqual(outs["native"]["frame"], outs["ctypes"]["frame"])


def _native_available():
    import importlib

    for name in ("opple_hilink._native", "opple_hilink_native"):
        try:
            importlib.import_module(name)
            return True
        except Exception:
            continue
    return False


def _probe():
    """供 --probe 使用：把一次完整往返的结果打成一行 JSON。"""
    frame = build_frame()
    print(
        json.dumps(
            {
                "backend": opple.backend(),
                "frame": frame.hex(),
                "parse": opple.prov_parse(frame, AP_SSID),
                "derive": opple.derive(AUTH, SN1, SN2),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    if "--probe" in sys.argv:
        _probe()
    else:
        unittest.main(verbosity=2)
