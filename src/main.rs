//! `opple` 命令行工具：本地控制 / 会话 / 发现 / 配网帧编解码 / OTA 命令生成。
//!
//! 环境变量（也可用同名小写参数覆盖）：
//! `OPPLE_IP` `OPPLE_PORT` `OPPLE_DEVICE_ID` `OPPLE_ACCOUNT_ID` `OPPLE_USER_ID` `OPPLE_AUTH_CODE`

use std::collections::HashMap;
use std::process::ExitCode;

use opple_hilink::control::{self, DeviceConfig};
use opple_hilink::crypto::{b64_decode, b64_encode};
use opple_hilink::error::{Error, Result};
use opple_hilink::provision::{self, BuildSpec};
use opple_hilink::{discovery, ota, profile, session};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("✗ {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let mut it = std::env::args().skip(1);
    let cmd = match it.next() {
        Some(c) => c,
        None => {
            usage();
            return Ok(());
        }
    };
    let rest: Vec<String> = it.collect();
    let args = Args::parse(&rest);

    match cmd.as_str() {
        "help" | "-h" | "--help" => {
            usage();
            Ok(())
        }
        "services" => {
            for (id, desc) in profile::SERVICES {
                println!("{id:<14} {desc}");
            }
            Ok(())
        }
        "use" => cmd_use(&args),
        "config" => cmd_config(&args),
        "discover" => cmd_discover(&args),
        "session" => cmd_session(&args),
        "on" => cmd_service(&args, "switch", control::cmd_switch(true)),
        "off" => cmd_service(&args, "switch", control::cmd_switch(false)),
        "brightness" => {
            let v = args.pos_num(0, "brightness")?;
            if !(26..=255).contains(&v) {
                return Err(Error::Arg("brightness 取值 26-255（26≈10%）".into()));
            }
            cmd_service(&args, "brightness", control::cmd_brightness(v as u8))
        }
        "cct" => {
            let v = args.pos_num(0, "colorTemperature")?;
            if !(2000..=6500).contains(&v) {
                return Err(Error::Arg("cct 取值 2000-6500".into()));
            }
            cmd_service(&args, "cct", control::cmd_cct(v as u32))
        }
        "mode" => {
            let v = args.pos_num(0, "mode")?;
            if ![2, 3, 4, 6].contains(&v) {
                return Err(Error::Arg("mode 取值 2|3|4|6（阅读/读写/电脑/自定义）".into()));
            }
            cmd_service(&args, "lightMode", control::cmd_mode(v as u8))
        }
        "side" => {
            let on = args.pos_bool(0, "on|off")?;
            cmd_service(&args, "nightSwitch", control::cmd_on(on))
        }
        "backlight" => {
            let on = args.pos_bool(0, "on|off")?;
            cmd_service(&args, "backlight", control::cmd_on(on))
        }
        "raw" => {
            let svc = args.pos.first().ok_or_else(|| Error::Arg("raw <serviceId> '<json>'".into()))?.clone();
            let js = args.pos.get(1).ok_or_else(|| Error::Arg("raw <serviceId> '<json>'".into()))?;
            let data = parse_json_arg(js)?;
            cmd_service(&args, &svc, data)
        }
        "ota" => cmd_ota(&args),
        "prov-decode" => cmd_prov_decode(&args),
        "prov-build" => cmd_prov_build(&args),
        "prov-send" => cmd_prov_send(&args),
        other => Err(Error::Arg(format!("未知命令 {other}（用 help 查看）"))),
    }
}

// ---------- 参数解析 ----------

struct Args {
    flags: HashMap<String, String>,
    pos: Vec<String>,
    cfg: serde_json::Map<String, serde_json::Value>,
}

impl Args {
    fn parse(argv: &[String]) -> Self {
        let mut flags = HashMap::new();
        let mut pos = Vec::new();
        let mut i = 0;
        while i < argv.len() {
            let a = &argv[i];
            if let Some(name) = a.strip_prefix("--") {
                if let Some((k, v)) = name.split_once('=') {
                    flags.insert(k.to_string(), v.to_string());
                } else if i + 1 < argv.len() && !argv[i + 1].starts_with("--") {
                    flags.insert(name.to_string(), argv[i + 1].clone());
                    i += 1;
                } else {
                    flags.insert(name.to_string(), "true".into());
                }
            } else {
                pos.push(a.clone());
            }
            i += 1;
        }
        Self { flags, pos, cfg: load_config() }
    }

    /// 取值优先级：命令行 `--flag` > 环境变量 `OPPLE_FLAG` > 配置文件 `~/.opple.json`
    fn flag(&self, name: &str) -> Option<String> {
        if let Some(v) = self.flags.get(name) {
            return Some(v.clone());
        }
        if let Ok(v) = std::env::var(format!("OPPLE_{}", name.to_uppercase().replace('-', "_"))) {
            return Some(v);
        }
        self.cfg
            .get(&name.replace('-', "_"))
            .and_then(|v| v.as_str().map(|s| s.to_string()))
    }

    fn pos_num(&self, idx: usize, what: &str) -> Result<i64> {
        let s = self.pos.get(idx).ok_or_else(|| Error::Arg(format!("缺少 {what}")))?;
        s.parse::<i64>().map_err(|_| Error::Arg(format!("{what} 不是数字: {s}")))
    }

    fn pos_bool(&self, idx: usize, what: &str) -> Result<bool> {
        match self.pos.get(idx).map(|s| s.as_str()) {
            Some("on") | Some("1") | Some("true") => Ok(true),
            Some("off") | Some("0") | Some("false") => Ok(false),
            _ => Err(Error::Arg(format!("{what} 需要 on/off"))),
        }
    }
}

fn device_config(args: &Args) -> Result<DeviceConfig> {
    let auth_hex = args
        .flag("auth-code")
        .ok_or_else(|| Error::Arg("缺少 authCode（--auth-code 或 OPPLE_AUTH_CODE）".into()))?;
    let auth_code = hex::decode(auth_hex.trim()).map_err(|e| Error::Arg(format!("authCode 需 32 位十六进制: {e}")))?;
    if auth_code.len() != 16 {
        return Err(Error::Arg(format!("authCode 应为 16 字节，实际 {}", auth_code.len())));
    }
    Ok(DeviceConfig {
        host: args.flag("ip").unwrap_or_else(|| "192.168.1.100".into()),
        port: args.flag("port").and_then(|p| p.parse().ok()).unwrap_or(5686),
        device_id: args.flag("device-id").unwrap_or_default(),
        account_id: args.flag("account-id").unwrap_or_default(),
        user_id: args.flag("user-id").unwrap_or_default(),
        auth_code,
        timeout_ms: args.flag("timeout").and_then(|v| v.parse().ok()).unwrap_or(3500),
        retries: args.flag("retries").and_then(|v| v.parse().ok()).unwrap_or(2),
    })
}

// ---------- 子命令 ----------

fn cmd_session(args: &Args) -> Result<()> {
    let cfg = device_config(args)?;
    if cfg.account_id.is_empty() {
        return Err(Error::Arg("缺少 accountId（--account-id）".into()));
    }
    let sess = session::create(&cfg.session_config())?;
    println!("sessId   : {}", sess.sess_id);
    println!("sn1      : {}", hex::encode_upper(sess.sn1));
    println!("sn2      : {}", hex::encode(sess.sn2));
    println!("seq      : {}", sess.seq);
    println!("psk      : {}", hex::encode(sess.psk));
    println!("hmacKey  : {}", hex::encode(sess.hmac_key));
    Ok(())
}

fn cmd_service(args: &Args, service: &str, data: serde_json::Value) -> Result<()> {
    let cfg = device_config(args)?;
    let mut sess = session::create(&cfg.session_config())?;
    let resp = control::send(&cfg, &mut sess, service, &data)?;
    println!("[√] {service} {data} -> {}", serde_json::to_string_pretty(&resp)?);
    Ok(())
}

fn cmd_discover(args: &Args) -> Result<()> {
    let ip = args.flag("ip").unwrap_or_else(|| "192.168.1.100".into());
    let port = args.flag("port").and_then(|p| p.parse().ok()).unwrap_or(5686);
    let timeout = args.flag("timeout").and_then(|v| v.parse().ok()).unwrap_or(3000);
    let d = discovery::query(&ip, port, timeout, 2)?;
    match d.json {
        Some(j) => println!("{}", serde_json::to_string_pretty(&j)?),
        None => println!("{}", d.text),
    }
    Ok(())
}

fn cmd_ota(args: &Args) -> Result<()> {
    let mode = args.pos.first().map(|s| s.as_str()).unwrap_or("check");
    let action = match mode {
        "check" => ota::ACTION_CHECK,
        "start" => ota::ACTION_START,
        other => return Err(Error::Arg(format!("ota <check|start>，未知动作 {other}"))),
    };
    let target = args.pos.get(1).map(|s| s.as_str()).unwrap_or("mqtt");
    match target {
        "mqtt" => {
            let token = args.flag("token").unwrap_or_default();
            let uid = args.flag("user-id").unwrap_or_default();
            let dev = args.flag("device-id").unwrap_or_default();
            let ts = args.flag("timestamp").unwrap_or_else(ota::utc_timestamp);
            let cmd = ota::mqtt_command(&token, &uid, &dev, action, &ts);
            println!("topic: {}", ota::MQTT_TOPIC);
            println!("{}", serde_json::to_string_pretty(&cmd)?);
            Ok(())
        }
        "local" => {
            let cfg = device_config(args)?;
            let mut sess = session::create(&cfg.session_config())?;
            let body = ota::local_update_body(action);
            match control::send(&cfg, &mut sess, "update", &body) {
                Ok(resp) => {
                    println!("[√] update {body} -> {}", serde_json::to_string_pretty(&resp)?);
                    Ok(())
                }
                Err(e) => {
                    println!("[!] 本地 update 无响应（本机型固件不提供该服务，属预期）: {e}");
                    Ok(())
                }
            }
        }
        other => Err(Error::Arg(format!("ota <check|start> [mqtt|local]，未知通道 {other}"))),
    }
}

fn cmd_prov_decode(args: &Args) -> Result<()> {
    let src = args.pos.first().ok_or_else(|| Error::Arg("prov-decode <hex|@file>".into()))?;
    let raw = read_hex(src)?;
    let ap_ssid = args
        .flag("ap-ssid")
        .unwrap_or_else(|| "Hi- OPPLE-READINGLAMP-0134DC".into());
    let info = provision::parse(&raw, &ap_ssid)?;

    println!("报文长度      : {} 字节（未补齐 {}，{}）", raw.len(), info.unpadded_len,
        if info.padded { "末尾 0x00 补齐" } else { "无补齐" });
    println!("byte0 校验1   : 0x{:02x} {}", raw[0], if info.checksum1_ok { "✓" } else { "✗" });
    println!("byte1 校验2   : 0x{:02x} {}", raw[1], if info.checksum2_ok { "✓" } else { "✗" });
    println!("byte2 类型    : 0x{:02x}（设备类别 {}）", info.type_byte, info.kind);
    println!("白盒块        : {}", hex::encode(info.whitebox_block));
    println!("SSID          : {:?}", info.ssid);
    println!("密码密文      : {}", hex::encode(&info.password_cipher));
    println!("注册包密文    : {} 字节", info.register_cipher.len());

    if let Some(k) = args.flag("key") {
        let key = parse_key(&k)?;
        let (pwd, reg) = info.decrypt(&key)?;
        println!("\nAES 密钥      : {}", hex::encode(key));
        println!("WiFi 密码     : {pwd:?}");
        println!("注册包明文    : {}", reg);
    } else {
        println!("\n提示：加 --key <base64|hex> 可解出密码与注册包（密钥来自 hook whiteBoxEncrypt）");
    }
    Ok(())
}

fn cmd_prov_build(args: &Args) -> Result<()> {
    let ap_ssid = args
        .flag("ap-ssid")
        .unwrap_or_else(|| "Hi- OPPLE-READINGLAMP-0134DC".into());
    let ssid = args.flag("ssid").ok_or_else(|| Error::Arg("缺少 --ssid".into()))?;
    let password = args.flag("password").ok_or_else(|| Error::Arg("缺少 --password".into()))?;
    let register_json = match args.flag("register") {
        Some(v) if v.starts_with('@') => std::fs::read_to_string(&v[1..])?,
        Some(v) => v,
        None => return Err(Error::Arg("缺少 --register '<json>' 或 --register @file".into())),
    };
    let key = parse_key(&args.flag("key").ok_or_else(|| Error::Arg("缺少 --key <base64|hex>".into()))?)?;
    let kind: u8 = args.flag("kind").and_then(|v| v.parse().ok()).unwrap_or(100);
    let wb = match args.flag("wb") {
        Some(h) => {
            let v = hex::decode(h.trim()).map_err(|e| Error::Arg(format!("--wb 需 32 位十六进制: {e}")))?;
            if v.len() != 16 {
                return Err(Error::Arg("--wb 应为 16 字节".into()));
            }
            let mut a = [0u8; 16];
            a.copy_from_slice(&v);
            a
        }
        None => [0u8; 16],
    };

    let spec = BuildSpec {
        ap_ssid: &ap_ssid,
        kind,
        whitebox_block: wb,
        ssid: &ssid,
        password: &password,
        register_json: &register_json,
        aes_key: &key,
    };
    let frame = provision::build(&spec)?;
    let hexstr = hex::encode(&frame);
    if let Some(out) = args.flag("out") {
        std::fs::write(&out, &hexstr)?;
        println!("已写入 {out}（{} 字节）", frame.len());
    }
    println!("帧长度  : {} 字节", frame.len());
    println!("帧 HEX  : {hexstr}");
    Ok(())
}

// ---------- 凭据持久化 ----------

fn config_path() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("OPPLE_CONFIG") {
        return std::path::PathBuf::from(p);
    }
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| ".".into());
    std::path::PathBuf::from(home).join(".opple.json")
}

fn load_config() -> serde_json::Map<String, serde_json::Value> {
    let p = config_path();
    match std::fs::read_to_string(&p) {
        Ok(text) => serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&text).unwrap_or_default(),
        Err(_) => serde_json::Map::new(),
    }
}

fn cmd_use(args: &Args) -> Result<()> {
    let mut map = load_config();
    for key in ["ip", "port", "device-id", "account-id", "user-id", "auth-code"] {
        if let Some(v) = args.flags.get(key) {
            let field = key.replace('-', "_");
            map.insert(field, serde_json::Value::String(v.clone()));
        }
    }
    let path = config_path();
    std::fs::write(&path, serde_json::to_string_pretty(&map)?)?;
    println!("已保存到 {}", path.display());
    print_config(&map);
    Ok(())
}

fn cmd_config(_args: &Args) -> Result<()> {
    let map = load_config();
    if map.is_empty() {
        println!("还没有保存配置，可用 `opple use --ip … --device-id … --auth-code …` 写入");
        return Ok(());
    }
    print_config(&map);
    Ok(())
}

fn print_config(map: &serde_json::Map<String, serde_json::Value>) {
    for (k, v) in map {
        let shown = match (k.as_str(), v.as_str()) {
            ("auth_code", Some(s)) if s.len() > 8 => format!("{}…{}", &s[..4], &s[s.len() - 4..]),
            (_, Some(s)) => s.to_string(),
            (_, None) => v.to_string(),
        };
        println!("  {k:<12} {shown}");
    }
}

// ---------- 工具函数 ----------

fn cmd_prov_send(args: &Args) -> Result<()> {
    let src = args
        .pos
        .first()
        .ok_or_else(|| Error::Arg("prov-send <hex|@file>".into()))?;
    let frame = read_hex(src)?;
    let ip = args.flag("ip").unwrap_or_else(|| "192.168.5.1".into());
    let port = args.flag("port").and_then(|p| p.parse().ok()).unwrap_or(5683);
    let timeout = args.flag("timeout").and_then(|v| v.parse().ok()).unwrap_or(2000);
    let retries = args.flag("retries").and_then(|v| v.parse().ok()).unwrap_or(5);
    println!("→ {ip}:{port} 发送 {} 字节配网帧（超时 {timeout}ms，最多 {retries} 次）", frame.len());
    let out = provision::send_frame(&ip, port, &frame, timeout, retries)?;
    println!(
        "[√] 设备应答 {:?}（第 {} 次尝试，{} ms）",
        out.ack.trim(),
        out.attempts,
        out.elapsed_ms
    );
    Ok(())
}

fn parse_json_arg(s: &str) -> Result<serde_json::Value> {
    if let Some(path) = s.strip_prefix('@') {
        let text = std::fs::read_to_string(path)?;
        return Ok(serde_json::from_str(&text)?);
    }
    Ok(serde_json::from_str(s)?)
}

fn read_hex(src: &str) -> Result<Vec<u8>> {
    let text = if let Some(path) = src.strip_prefix('@') {
        std::fs::read_to_string(path)?
    } else if std::path::Path::new(src).is_file() {
        std::fs::read_to_string(src)?
    } else {
        src.to_string()
    };
    let cleaned: String = text.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    hex::decode(&cleaned).map_err(|e| Error::Arg(format!("十六进制解析失败: {e}")))
}

fn parse_key(s: &str) -> Result<[u8; 16]> {
    let t = s.trim();
    let bytes = if t.len() == 32 && t.chars().all(|c| c.is_ascii_hexdigit()) {
        hex::decode(t).map_err(|e| Error::Arg(format!("hex 密钥: {e}")))?
    } else {
        b64_decode(t)?
    };
    if bytes.len() != 16 {
        return Err(Error::Arg(format!("密钥应为 16 字节，实际 {}", bytes.len())));
    }
    let mut k = [0u8; 16];
    k.copy_from_slice(&bytes);
    Ok(k)
}

#[allow(dead_code)]
fn key_to_b64(k: &[u8]) -> String {
    b64_encode(k)
}

fn usage() {
    println!(
        r#"opple — 欧普/HiLink 台灯协议工具（Rust）

用法: opple <命令> [参数]

本地控制（CoAP/UDP 5686，AES-128-CBC + HMAC-SHA256）
  session                     建会话并打印 sessId/sn1/sn2/psk/hmacKey
  on | off                    开 / 关
  brightness <26-255>         亮度（26≈10%）
  cct <2000-6500>             色温
  mode <2|3|4|6>              阅读/读写/电脑/自定义
  side <on|off>               侧边灯
  backlight <on|off>          背光
  raw <serviceId> '<json>'    任意服务，例如 raw netInfo '{{}}'

其它
  services                    内置服务字典
  discover                     GET /.well-known/core?st=cloudSetup（配网态才响应）
  ota check|start [mqtt|local]  生成升级命令；local 直接发 /update
  prov-decode <hex|@file> [--key b64|hex] [--ap-ssid S]
                              解析白盒配网帧（可解密）
  prov-build --ssid S --password P --register '<json>|@file' --key K
             [--ap-ssid S] [--kind 100] [--wb 32hex] [--out file]
                              组帧（白盒块未知时用 --wb 或全 0 占位）
  prov-send <hex|@file> [--ip 192.168.5.1] [--port 5683]
             [--timeout 2000] [--retries 5]
                              把帧发给配网态设备，等明文 HI-ACK

连接参数（也可用环境变量 OPPLE_IP / OPPLE_PORT / OPPLE_DEVICE_ID /
OPPLE_ACCOUNT_ID / OPPLE_USER_ID / OPPLE_AUTH_CODE）
  --ip <IP> --port <PORT> --device-id <ID> --account-id <ID>
  --user-id <UID> --auth-code <32hex> [--timeout ms] [--retries n]
"#
    );
}
