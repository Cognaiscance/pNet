//! pnet_test_probe — headless test app for end-to-end pNet harnesses.
//!
//! Behaves like a stripped-down deliverer: registers with pnet, fetches its
//! data view, accepts incoming pushes, and can send packets to other apps —
//! but with no UI, no token persistence, and a JSON-only HTTP control surface.
//! Every observed event is emitted as one line of JSON on stdout AND appended
//! to an in-memory ring buffer that the harness reads via GET /events.
//!
//! Env vars:
//!   PNET_ADDR             pnet host:port (default 127.0.0.1:7777)
//!   PNET_PROBE_ALIAS      app alias to register (default "probe")
//!   PNET_PROBE_HTTP_BIND  HTTP bind addr (default 0.0.0.0:3000)

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{Json, Router, extract::State, routing::{get, post}};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::net::UdpSocket;

const PNET_ADDR_DEFAULT:  &str = "127.0.0.1:7777";
const PROBE_ALIAS_DEFAULT: &str = "probe";
const HTTP_BIND_DEFAULT:  &str = "0.0.0.0:3000";
const APP_PROTOCOL:       &str = "application/octet-stream";

const PUSH_PORT: u16 = 8888;
const CTRL_PORT: u16 = 8889;

const OP_REGISTER: u8 = 0x00;
const OP_GET_DATA: u8 = 0x02;
const OP_SEND:     u8 = 0x03;
const OP_PUSH:     u8 = 0x04;
const STATUS_OK:   u8 = 0x00;

// ── Data types ────────────────────────────────────────────────────────────────

#[derive(Default, Serialize, Clone)]
struct AppEntry {
    id: u16,
    alias: String,
    user_approved: bool,
}

#[derive(Default, Serialize, Clone)]
struct DeviceEntry {
    uuid_hex: String,
    alias: String,
    grade: String, // "sg" | "dg"
    sg_rank: u8,
    hosts: Vec<String>,
    apps: Vec<AppEntry>,
}

#[derive(Default, Serialize, Clone)]
struct ContactEntry {
    alias: String,
    uuid_hex: String,
    devices: Vec<DeviceEntry>,
}

#[derive(Default, Serialize, Clone)]
struct StatusView {
    registered: bool,
    approved: bool,
    token_hex: Option<String>,
    app_id: Option<u16>,
    app_alias: Option<String>,
    owner_alias: Option<String>,
    owner_uuid_hex: Option<String>,
    local_device_uuid_hex: Option<String>,
    own_devices: Vec<DeviceEntry>,
    contacts: Vec<ContactEntry>,
    last_fetch_ok_ts: Option<u64>,
}

struct Inner {
    token: Option<[u8; 16]>,
    status: StatusView,
    events: Vec<Value>,
    /// (device_uuid, app_id) → display label, used to enrich push events.
    app_labels: HashMap<(Vec<u8>, u16), String>,
}

struct AppState {
    push_socket: Arc<UdpSocket>,
    ctrl_socket: Arc<UdpSocket>,
    pnet_addr: SocketAddr,
    inner: Mutex<Inner>,
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 { return None; }
    (0..s.len()).step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn push_str(buf: &mut Vec<u8>, s: &str) {
    buf.push(s.len() as u8);
    buf.extend_from_slice(s.as_bytes());
}

fn read_str(data: &[u8], pos: &mut usize) -> Option<String> {
    let len = *data.get(*pos)? as usize;
    *pos += 1;
    let s = std::str::from_utf8(data.get(*pos..*pos + len)?).ok()?.to_string();
    *pos += len;
    Some(s)
}

fn read_u16(data: &[u8], pos: &mut usize) -> Option<u16> {
    let v = u16::from_be_bytes(data.get(*pos..*pos + 2)?.try_into().ok()?);
    *pos += 2;
    Some(v)
}

fn read_bytes<const N: usize>(data: &[u8], pos: &mut usize) -> Option<[u8; N]> {
    let arr: [u8; N] = data.get(*pos..*pos + N)?.try_into().ok()?;
    *pos += N;
    Some(arr)
}

fn log_event(inner: &Mutex<Inner>, event: Value) {
    let line = serde_json::to_string(&event).unwrap_or_else(|_| "{}".to_string());
    println!("{line}");
    inner.lock().unwrap().events.push(event);
}

// ── Protocol builders ────────────────────────────────────────────────────────

fn build_register(alias: &str) -> Vec<u8> {
    let mut buf = vec![OP_REGISTER];
    push_str(&mut buf, alias);
    buf.extend_from_slice(&PUSH_PORT.to_be_bytes());
    push_str(&mut buf, APP_PROTOCOL);
    buf
}

fn build_get_data(token: &[u8; 16]) -> Vec<u8> {
    let mut buf = vec![OP_GET_DATA];
    buf.extend_from_slice(token);
    buf
}

fn build_send(token: &[u8; 16], dest_device_uuid: &[u8], dest_app_id: u16, payload: &[u8]) -> Vec<u8> {
    let mut buf = vec![OP_SEND];
    buf.extend_from_slice(token);
    buf.extend_from_slice(dest_device_uuid);
    buf.extend_from_slice(&dest_app_id.to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

// ── get_data parser ──────────────────────────────────────────────────────────

fn parse_get_data(reply: &[u8], inner: &mut Inner) -> Option<()> {
    let mut pos = 1usize; // skip OK byte

    let app_id = read_u16(reply, &mut pos)?;
    let app_alias = read_str(reply, &mut pos)?;
    pos += 6; // ip + port
    let approved_byte = *reply.get(pos)?;
    pos += 1;
    pos += 16; // token (we already have it)
    let local_uuid = read_bytes::<16>(reply, &mut pos)?;

    let owner_alias = read_str(reply, &mut pos)?;
    let owner_uuid = read_bytes::<16>(reply, &mut pos)?;

    let mut app_labels: HashMap<(Vec<u8>, u16), String> = HashMap::new();
    let mut own_devices: Vec<DeviceEntry> = Vec::new();

    let dev_count = *reply.get(pos)?;
    pos += 1;
    for _ in 0..dev_count {
        let dev_uuid = read_bytes::<16>(reply, &mut pos)?;
        let dev_alias = read_str(reply, &mut pos)?;
        let grade_byte = *reply.get(pos)?;
        pos += 1;
        let sg_rank = *reply.get(pos)?;
        pos += 1;
        let host_count = *reply.get(pos)?;
        pos += 1;
        let mut hosts = Vec::with_capacity(host_count as usize);
        for _ in 0..host_count {
            hosts.push(read_str(reply, &mut pos)?);
        }
        let app_count = *reply.get(pos)?;
        pos += 1;
        let mut apps = Vec::with_capacity(app_count as usize);
        for _ in 0..app_count {
            let aid = read_u16(reply, &mut pos)?;
            let aalias = read_str(reply, &mut pos)?;
            pos += 4 + 2; // ip + port
            let approved = *reply.get(pos)? != 0;
            pos += 1;
            app_labels.insert(
                (dev_uuid.to_vec(), aid),
                format!("{dev_alias}/{aalias}"),
            );
            apps.push(AppEntry { id: aid, alias: aalias, user_approved: approved });
        }
        own_devices.push(DeviceEntry {
            uuid_hex: hex(&dev_uuid),
            alias: dev_alias,
            grade: if grade_byte == 1 { "sg".into() } else { "dg".into() },
            sg_rank,
            hosts,
            apps,
        });
    }

    let mut contacts: Vec<ContactEntry> = Vec::new();
    let contact_count = *reply.get(pos)?;
    pos += 1;
    for _ in 0..contact_count {
        let calias = read_str(reply, &mut pos)?;
        let cuuid = read_bytes::<16>(reply, &mut pos)?;
        let cdev_count = *reply.get(pos)?;
        pos += 1;
        let mut cdevs = Vec::with_capacity(cdev_count as usize);
        for _ in 0..cdev_count {
            let dev_uuid = read_bytes::<16>(reply, &mut pos)?;
            let dev_alias = read_str(reply, &mut pos)?;
            let grade_byte = *reply.get(pos)?;
            pos += 1;
            let sg_rank = *reply.get(pos)?;
            pos += 1;
            let host_count = *reply.get(pos)?;
            pos += 1;
            let mut hosts = Vec::with_capacity(host_count as usize);
            for _ in 0..host_count {
                hosts.push(read_str(reply, &mut pos)?);
            }
            let app_count = *reply.get(pos)?;
            pos += 1;
            let mut apps = Vec::with_capacity(app_count as usize);
            for _ in 0..app_count {
                let aid = read_u16(reply, &mut pos)?;
                let aalias = read_str(reply, &mut pos)?;
                // Contact apps: no ip/port/approved byte, only id+alias.
                app_labels.insert(
                    (dev_uuid.to_vec(), aid),
                    format!("{calias}/{dev_alias}/{aalias}"),
                );
                apps.push(AppEntry { id: aid, alias: aalias, user_approved: true });
            }
            cdevs.push(DeviceEntry {
                uuid_hex: hex(&dev_uuid),
                alias: dev_alias,
                grade: if grade_byte == 1 { "sg".into() } else { "dg".into() },
                sg_rank,
                hosts,
                apps,
            });
        }
        contacts.push(ContactEntry {
            alias: calias,
            uuid_hex: hex(&cuuid),
            devices: cdevs,
        });
    }

    inner.status.app_id = Some(app_id);
    inner.status.app_alias = Some(app_alias);
    inner.status.approved = approved_byte != 0;
    inner.status.owner_alias = Some(owner_alias);
    inner.status.owner_uuid_hex = Some(hex(&owner_uuid));
    inner.status.local_device_uuid_hex = Some(hex(&local_uuid));
    inner.status.own_devices = own_devices;
    inner.status.contacts = contacts;
    inner.app_labels = app_labels;
    Some(())
}

// ── Resolution for /send ─────────────────────────────────────────────────────

fn resolve_target(
    status: &StatusView,
    contact_alias: Option<&str>,
    device_alias: &str,
    app_alias: &str,
) -> Option<(Vec<u8>, u16)> {
    let devices: &[DeviceEntry] = if let Some(c) = contact_alias {
        match status.contacts.iter().find(|x| x.alias == c) {
            Some(con) => &con.devices,
            None => return None,
        }
    } else {
        &status.own_devices
    };
    let dev = devices.iter().find(|d| d.alias == device_alias)?;
    let app = dev.apps.iter().find(|a| a.alias == app_alias)?;
    Some((hex_decode(&dev.uuid_hex)?, app.id))
}

// ── Networking ───────────────────────────────────────────────────────────────

async fn register(ctrl: &UdpSocket, pnet_addr: SocketAddr, alias: &str) -> Option<[u8; 16]> {
    ctrl.send_to(&build_register(alias), pnet_addr).await.ok()?;
    let mut buf = [0u8; 512];
    let (len, _) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        ctrl.recv_from(&mut buf),
    ).await.ok()?.ok()?;
    let reply = &buf[..len];
    if reply.len() < 17 || reply[0] != STATUS_OK {
        return None;
    }
    Some(reply[1..17].try_into().unwrap())
}

async fn fetch_data(state: &AppState, token: &[u8; 16]) {
    if state.ctrl_socket.send_to(&build_get_data(token), state.pnet_addr).await.is_err() {
        log_event(&state.inner, json!({"ts": now_secs(), "kind": "get_data_send_err"}));
        return;
    }
    let mut buf = vec![0u8; 8192];
    let recv = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        state.ctrl_socket.recv_from(&mut buf),
    ).await;
    let Ok(Ok((len, _))) = recv else {
        log_event(&state.inner, json!({"ts": now_secs(), "kind": "get_data_timeout"}));
        return;
    };
    let reply = &buf[..len];
    if reply.is_empty() || reply[0] != STATUS_OK {
        log_event(&state.inner, json!({
            "ts": now_secs(),
            "kind": "get_data_error",
            "first_bytes": reply.iter().take(4).map(|b| *b as u32).collect::<Vec<_>>(),
        }));
        return;
    }
    let mut inner = state.inner.lock().unwrap();
    if parse_get_data(reply, &mut inner).is_some() {
        inner.status.last_fetch_ok_ts = Some(now_secs());
        let summary = json!({
            "ts": now_secs(),
            "kind": "get_data_ok",
            "approved": inner.status.approved,
            "own_device_count": inner.status.own_devices.len(),
            "contact_count": inner.status.contacts.len(),
        });
        drop(inner);
        log_event(&state.inner, summary);
    } else {
        drop(inner);
        log_event(&state.inner, json!({"ts": now_secs(), "kind": "get_data_parse_failed"}));
    }
}

async fn push_receive_loop(state: Arc<AppState>) {
    let mut buf = vec![0u8; 8192];
    loop {
        let Ok((len, _)) = state.push_socket.recv_from(&mut buf).await else { continue };
        let data = &buf[..len];
        if data.len() < 3 || data[0] != OP_PUSH {
            continue;
        }
        let sender_app_id = u16::from_be_bytes([data[1], data[2]]);
        let payload = &data[3..];
        let payload_b64 = base64::engine::general_purpose::STANDARD.encode(payload);
        let payload_str = std::str::from_utf8(payload).ok().map(|s| s.to_string());
        // The push packet does NOT carry the sender's device uuid, only app id.
        // App ids are device-scoped, so we can only resolve a label if exactly
        // one (device, app_id) pair in our cache matches; otherwise we leave
        // sender_label null and the harness can disambiguate via timing.
        let label = {
            let inner = state.inner.lock().unwrap();
            let mut matches: Vec<&String> = inner.app_labels.iter()
                .filter(|((_, aid), _)| *aid == sender_app_id)
                .map(|(_, label)| label)
                .collect();
            if matches.len() == 1 { Some(matches.remove(0).clone()) } else { None }
        };
        log_event(&state.inner, json!({
            "ts": now_secs(),
            "kind": "push_received",
            "sender_app_id": sender_app_id,
            "sender_label": label,
            "payload_len": payload.len(),
            "payload_b64": payload_b64,
            "payload_text": payload_str,
        }));
    }
}

async fn data_refresh_loop(state: Arc<AppState>) {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        let token = state.inner.lock().unwrap().token;
        if let Some(token) = token {
            fetch_data(&state, &token).await;
        }
    }
}

// ── HTTP handlers ────────────────────────────────────────────────────────────

async fn handle_status(State(state): State<Arc<AppState>>) -> Json<StatusView> {
    let inner = state.inner.lock().unwrap();
    Json(inner.status.clone())
}

async fn handle_events(State(state): State<Arc<AppState>>) -> Json<Vec<Value>> {
    let inner = state.inner.lock().unwrap();
    Json(inner.events.clone())
}

async fn handle_reset_events(State(state): State<Arc<AppState>>) -> Json<Value> {
    let mut inner = state.inner.lock().unwrap();
    inner.events.clear();
    Json(json!({"ok": true}))
}

async fn handle_refresh(State(state): State<Arc<AppState>>) -> Json<Value> {
    let token = state.inner.lock().unwrap().token;
    if let Some(token) = token {
        fetch_data(&state, &token).await;
        Json(json!({"ok": true}))
    } else {
        Json(json!({"ok": false, "error": "not registered"}))
    }
}

#[derive(Deserialize)]
struct SendRequest {
    // Explicit form (takes priority if both set):
    device_uuid_hex: Option<String>,
    app_id: Option<u16>,
    // Alias form:
    contact_alias: Option<String>,
    device_alias: Option<String>,
    app_alias: Option<String>,
    // Payload (one of):
    payload_b64: Option<String>,
    payload_text: Option<String>,
}

async fn handle_send(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SendRequest>,
) -> Json<Value> {
    let token = match state.inner.lock().unwrap().token {
        Some(t) => t,
        None => return Json(json!({"ok": false, "error": "not registered"})),
    };

    let payload: Vec<u8> = if let Some(b64) = req.payload_b64.as_deref() {
        match base64::engine::general_purpose::STANDARD.decode(b64) {
            Ok(v) => v,
            Err(e) => return Json(json!({"ok": false, "error": format!("bad payload_b64: {e}")})),
        }
    } else if let Some(t) = req.payload_text.as_deref() {
        t.as_bytes().to_vec()
    } else {
        return Json(json!({"ok": false, "error": "payload_b64 or payload_text required"}));
    };

    let (dest_uuid, dest_app_id) = if let (Some(uuid_hex), Some(app_id)) = (req.device_uuid_hex.as_deref(), req.app_id) {
        match hex_decode(uuid_hex) {
            Some(v) if v.len() == 16 => (v, app_id),
            _ => return Json(json!({"ok": false, "error": "bad device_uuid_hex"})),
        }
    } else if let (Some(da), Some(aa)) = (req.device_alias.as_deref(), req.app_alias.as_deref()) {
        let inner = state.inner.lock().unwrap();
        match resolve_target(&inner.status, req.contact_alias.as_deref(), da, aa) {
            Some(t) => t,
            None => return Json(json!({
                "ok": false,
                "error": "could not resolve target",
                "contact_alias": req.contact_alias,
                "device_alias": da,
                "app_alias": aa,
            })),
        }
    } else {
        return Json(json!({
            "ok": false,
            "error": "specify (device_uuid_hex+app_id) or (device_alias+app_alias)"
        }));
    };

    let pkt = build_send(&token, &dest_uuid, dest_app_id, &payload);
    match state.ctrl_socket.send_to(&pkt, state.pnet_addr).await {
        Ok(_) => {
            log_event(&state.inner, json!({
                "ts": now_secs(),
                "kind": "send_sent",
                "dest_device_uuid_hex": hex(&dest_uuid),
                "dest_app_id": dest_app_id,
                "payload_len": payload.len(),
            }));
            Json(json!({"ok": true}))
        }
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

// ── Entry point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let pnet_addr_str = std::env::var("PNET_ADDR").unwrap_or_else(|_| PNET_ADDR_DEFAULT.to_string());
    let probe_alias = std::env::var("PNET_PROBE_ALIAS").unwrap_or_else(|_| PROBE_ALIAS_DEFAULT.to_string());
    let http_bind = std::env::var("PNET_PROBE_HTTP_BIND").unwrap_or_else(|_| HTTP_BIND_DEFAULT.to_string());

    let pnet_addr: SocketAddr = tokio::net::lookup_host(&pnet_addr_str).await
        .unwrap_or_else(|e| panic!("invalid PNET_ADDR {pnet_addr_str:?}: {e}"))
        .next()
        .unwrap_or_else(|| panic!("PNET_ADDR {pnet_addr_str:?} resolved to no addresses"));

    let push_socket = Arc::new(
        UdpSocket::bind(format!("0.0.0.0:{PUSH_PORT}")).await
            .expect("failed to bind push UDP socket"),
    );
    let ctrl_socket = Arc::new(
        UdpSocket::bind(format!("0.0.0.0:{CTRL_PORT}")).await
            .expect("failed to bind ctrl UDP socket"),
    );

    let state = Arc::new(AppState {
        push_socket,
        ctrl_socket,
        pnet_addr,
        inner: Mutex::new(Inner {
            token: None,
            status: StatusView::default(),
            events: Vec::new(),
            app_labels: HashMap::new(),
        }),
    });

    log_event(&state.inner, json!({
        "ts": now_secs(),
        "kind": "startup",
        "pnet_addr": pnet_addr_str,
        "probe_alias": probe_alias,
        "push_port": PUSH_PORT,
        "ctrl_port": CTRL_PORT,
    }));

    // Register with retries — pnet may not have its UDP listener up immediately.
    let mut token: Option<[u8; 16]> = None;
    for attempt in 1..=10 {
        match register(&state.ctrl_socket, pnet_addr, &probe_alias).await {
            Some(t) => { token = Some(t); break; }
            None => {
                log_event(&state.inner, json!({
                    "ts": now_secs(),
                    "kind": "register_retry",
                    "attempt": attempt,
                }));
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }
    }
    let Some(token) = token else {
        log_event(&state.inner, json!({
            "ts": now_secs(),
            "kind": "register_failed_giving_up",
        }));
        std::process::exit(1);
    };

    {
        let mut inner = state.inner.lock().unwrap();
        inner.token = Some(token);
        inner.status.registered = true;
        inner.status.token_hex = Some(hex(&token));
    }
    log_event(&state.inner, json!({
        "ts": now_secs(),
        "kind": "register_ok",
        "token_hex": hex(&token),
    }));

    fetch_data(&state, &token).await;

    tokio::spawn(push_receive_loop(state.clone()));
    tokio::spawn(data_refresh_loop(state.clone()));

    let app = Router::new()
        .route("/status", get(handle_status))
        .route("/events", get(handle_events))
        .route("/reset-events", post(handle_reset_events))
        .route("/refresh", post(handle_refresh))
        .route("/send", post(handle_send))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&http_bind).await
        .unwrap_or_else(|e| panic!("failed to bind HTTP {http_bind}: {e}"));

    eprintln!("[probe] HTTP listening on {http_bind}");
    axum::serve(listener, app).await.unwrap();
}
