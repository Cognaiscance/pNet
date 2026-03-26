use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use super::action_queue::WorkerContext;
use super::data_models::{Application, generate_uuid};

// ── Reply status bytes ────────────────────────────────────────────────────────
const OK:                u8 = 0x00;
const ERR_BAD_PACKET:    u8 = 0x01;
const ERR_TOKEN_UNKNOWN: u8 = 0x02;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn send(ctx: &WorkerContext, dest: SocketAddr, data: &[u8]) {
    ctx.udp_socket.send_to(data, dest).ok();
}

fn send_error(ctx: &WorkerContext, dest: SocketAddr, code: u8) {
    send(ctx, dest, &[0x01, code]);
}

/// Extract an IPv4 address from a SocketAddr, mapping IPv4-in-IPv6 if needed.
fn ipv4_from(addr: SocketAddr) -> Option<Ipv4Addr> {
    match addr {
        SocketAddr::V4(v4) => Some(*v4.ip()),
        SocketAddr::V6(v6) => v6.ip().to_ipv4_mapped(),
    }
}

// ── App handlers ──────────────────────────────────────────────────────────────

/// Op 0 — Application registration.
///
/// Request body (after op byte):
///   [alias_len: u8][alias: alias_len bytes][port: u16 be]
///
/// Reply on success:  [0x00][token: 16 bytes]
/// Reply on error:    [0x01][error_code: u8]
pub fn app_register(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    // Parse.
    if buf.is_empty() {
        return send_error(ctx, src, ERR_BAD_PACKET);
    }
    let alias_len = buf[0] as usize;
    if buf.len() < 1 + alias_len + 2 {
        return send_error(ctx, src, ERR_BAD_PACKET);
    }
    let alias = match std::str::from_utf8(&buf[1..1 + alias_len]) {
        Ok(s) if !s.is_empty() => s.to_string(),
        _ => return send_error(ctx, src, ERR_BAD_PACKET),
    };
    let port = u16::from_be_bytes([buf[1 + alias_len], buf[2 + alias_len]]);
    if port == 0 {
        return send_error(ctx, src, ERR_BAD_PACKET);
    }
    let ip = match ipv4_from(src) {
        Some(ip) => ip,
        None => return send_error(ctx, src, ERR_BAD_PACKET),
    };

    // Update node.
    let token = {
        let mut node = ctx.node.write().unwrap();
        let device_uuid = node.device_uuid;

        let device = node
            .owner
            .user
            .devices
            .iter_mut()
            .find(|d| d.uuid == device_uuid)
            .expect("local device not found in node");

        let next_id = device
            .applications
            .iter()
            .map(|a| a.id)
            .max()
            .unwrap_or(0)
            .saturating_add(1);

        let token = generate_uuid();
        device.applications.push(Application {
            id: next_id,
            alias,
            host: SocketAddrV4::new(ip, port),
            user_approved: false,
            token,
        });
        token
        // write lock released here
    };

    // TODO: persist — ctx.writer_tx.send(WriteRequest::AppData(serialize_apps(&node))).ok();

    // Reply: [OK][token: 16 bytes]
    let mut reply = [0u8; 17];
    reply[0] = OK;
    reply[1..17].copy_from_slice(&token);
    send(ctx, src, &reply);
}

/// Op 1 — Application update.
///
/// Request body (after op byte):
///   [token: 16 bytes][flags: u8]
///   if flags & 0x01: [alias_len: u8][alias: alias_len bytes]
///   if flags & 0x02: [port: u16 be]  (IP is taken from src)
///
/// Reply on success:  [0x00]
/// Reply on error:    [0x01][error_code: u8]
pub fn app_update(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    // Parse header.
    if buf.len() < 17 {
        return send_error(ctx, src, ERR_BAD_PACKET);
    }
    let token: [u8; 16] = buf[0..16].try_into().unwrap();
    let flags = buf[16];
    let mut pos = 17usize;

    let mut new_alias: Option<String> = None;
    let mut new_port:  Option<u16>   = None;

    if flags & 0x01 != 0 {
        if pos >= buf.len() {
            return send_error(ctx, src, ERR_BAD_PACKET);
        }
        let alias_len = buf[pos] as usize;
        pos += 1;
        if pos + alias_len > buf.len() {
            return send_error(ctx, src, ERR_BAD_PACKET);
        }
        match std::str::from_utf8(&buf[pos..pos + alias_len]) {
            Ok(s) if !s.is_empty() => new_alias = Some(s.to_string()),
            _ => return send_error(ctx, src, ERR_BAD_PACKET),
        }
        pos += alias_len;
    }

    if flags & 0x02 != 0 {
        if pos + 2 > buf.len() {
            return send_error(ctx, src, ERR_BAD_PACKET);
        }
        new_port = Some(u16::from_be_bytes([buf[pos], buf[pos + 1]]));
    }

    // Update node.
    let found = {
        let mut node = ctx.node.write().unwrap();
        let device_uuid = node.device_uuid;
        let device = node
            .owner
            .user
            .devices
            .iter_mut()
            .find(|d| d.uuid == device_uuid)
            .expect("local device not found in node");

        if let Some(app) = device.applications.iter_mut().find(|a| a.token == token) {
            if let Some(alias) = new_alias {
                app.alias = alias;
            }
            if let Some(port) = new_port {
                if let Some(ip) = ipv4_from(src) {
                    app.host = SocketAddrV4::new(ip, port);
                }
            }
            true
        } else {
            false
        }
        // write lock released here
    };

    // TODO: persist

    if found {
        send(ctx, src, &[OK]);
    } else {
        send_error(ctx, src, ERR_TOKEN_UNKNOWN);
    }
}

/// Op 2 — Application get data.
///
/// Request body (after op byte):
///   [token: 16 bytes]
///
/// Authenticates the app and returns its view of the node data tree.
/// Serialization format TBD — returns a stub OK for now.
pub fn app_get_data(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    if buf.len() < 16 {
        return send_error(ctx, src, ERR_BAD_PACKET);
    }
    let token: [u8; 16] = buf[0..16].try_into().unwrap();

    let node = ctx.node.read().unwrap();
    let device_uuid = node.device_uuid;
    let device = node
        .owner
        .user
        .devices
        .iter()
        .find(|d| d.uuid == device_uuid)
        .expect("local device not found in node");

    let app_exists = device.applications.iter().any(|a| a.token == token);
    drop(node);

    if app_exists {
        // TODO: serialize and send the data tree
        send(ctx, src, &[OK]);
    } else {
        send_error(ctx, src, ERR_TOKEN_UNKNOWN);
    }
}

/// Op 3 — Application send packet.
///
/// Request body (after op byte):
///   [token: 16 bytes][target_device_uuid: 16 bytes][target_app_id: u16 be][payload: ...]
///
/// Looks up the active connection for the target device, encrypts the payload,
/// and forwards the packet to the peer pnet node.
/// Not yet implemented — requires ephemeral key exchange to be established first.
pub fn app_send_packet(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    let _ = (src, buf, ctx); // TODO
}

// ── Scheduled action handlers ─────────────────────────────────────────────────

/// Ping all known peers to keep connections alive.
pub fn heartbeat(ctx: &WorkerContext) {
    let _ = ctx; // TODO
}

/// Check for active connections whose ephemeral keys are expiring soon and
/// initiate a re-exchange.
pub fn key_rotation(ctx: &WorkerContext) {
    let _ = ctx; // TODO
}

/// Retry an unacknowledged outbound message.
pub fn retry_message(message_id: u64, ctx: &WorkerContext) {
    let _ = (message_id, ctx); // TODO
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::sync::{Arc, RwLock, mpsc};
    use std::time::Duration;
    use super::super::action_queue::WorkerContext;
    use super::super::data_models::Node;
    use super::super::writer::WriteRequest;

    /// All the state needed to exercise a handler in isolation.
    struct TestCtx {
        ctx:        WorkerContext,
        app_socket: UdpSocket,   // receives the handler's reply
        _writer_rx: mpsc::Receiver<WriteRequest>,
        _sched_rx:  mpsc::Receiver<super::super::action_queue::ScheduleRequest>,
    }

    impl TestCtx {
        fn new() -> Self {
            // The "app" receives replies on this socket.
            let app_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            app_socket.set_read_timeout(Some(Duration::from_millis(300))).unwrap();

            // pnet replies via this socket.
            let pnet_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());

            let node = Arc::new(RwLock::new(Node::new()));
            let (writer_tx, _writer_rx) = mpsc::sync_channel(64);
            let (scheduler_tx, _sched_rx) = mpsc::channel();

            let ctx = WorkerContext { node, udp_socket: pnet_socket, writer_tx, scheduler_tx };
            TestCtx { ctx, app_socket, _writer_rx, _sched_rx }
        }

        /// The SocketAddr the "app" is listening on (used as `src` in requests).
        fn app_addr(&self) -> SocketAddr {
            self.app_socket.local_addr().unwrap()
        }

        /// Block until a reply arrives at the app socket.
        fn recv_reply(&self) -> Vec<u8> {
            let mut buf = [0u8; 64];
            let (len, _) = self.app_socket.recv_from(&mut buf)
                .expect("no reply received within timeout");
            buf[..len].to_vec()
        }
    }

    // ── AppRegister ───────────────────────────────────────────────────────────

    fn register_packet(alias: &str, port: u16) -> Vec<u8> {
        let mut buf = vec![alias.len() as u8];
        buf.extend_from_slice(alias.as_bytes());
        buf.extend_from_slice(&port.to_be_bytes());
        buf
    }

    #[test]
    fn app_register_returns_token() {
        let t = TestCtx::new();
        app_register(t.app_addr(), register_packet("myapp", 9001), &t.ctx);

        let reply = t.recv_reply();
        assert_eq!(reply[0], OK);
        assert_eq!(reply.len(), 17, "reply should be status + 16-byte token");
    }

    #[test]
    fn app_register_adds_application_to_node() {
        let t = TestCtx::new();
        app_register(t.app_addr(), register_packet("myapp", 9001), &t.ctx);

        let node = t.ctx.node.read().unwrap();
        let device_uuid = node.device_uuid;
        let device = node.owner.user.devices.iter().find(|d| d.uuid == device_uuid).unwrap();
        assert_eq!(device.applications.len(), 1);
        assert_eq!(device.applications[0].alias, "myapp");
        assert_eq!(device.applications[0].host.port(), 9001);
        assert!(!device.applications[0].user_approved);
    }

    #[test]
    fn app_register_each_app_gets_unique_id_and_token() {
        let t = TestCtx::new();
        app_register(t.app_addr(), register_packet("app1", 9001), &t.ctx);
        let reply1 = t.recv_reply();
        app_register(t.app_addr(), register_packet("app2", 9002), &t.ctx);
        let reply2 = t.recv_reply();

        let token1 = &reply1[1..17];
        let token2 = &reply2[1..17];
        assert_ne!(token1, token2, "tokens must be unique");

        let node = t.ctx.node.read().unwrap();
        let device_uuid = node.device_uuid;
        let device = node.owner.user.devices.iter().find(|d| d.uuid == device_uuid).unwrap();
        assert_eq!(device.applications.len(), 2);
        assert_ne!(device.applications[0].id, device.applications[1].id);
    }

    #[test]
    fn app_register_rejects_bad_packet() {
        let t = TestCtx::new();
        app_register(t.app_addr(), vec![], &t.ctx); // empty buf

        let reply = t.recv_reply();
        assert_eq!(reply[0], 0x01); // error
        assert_eq!(reply[1], ERR_BAD_PACKET);
    }

    // ── AppUpdate ─────────────────────────────────────────────────────────────

    /// Register an app and return its token.
    fn register_and_get_token(t: &TestCtx, alias: &str, port: u16) -> [u8; 16] {
        app_register(t.app_addr(), register_packet(alias, port), t.ctx());
        let reply = t.recv_reply();
        assert_eq!(reply[0], OK);
        reply[1..17].try_into().unwrap()
    }

    fn update_packet(token: &[u8; 16], new_alias: Option<&str>, new_port: Option<u16>) -> Vec<u8> {
        let mut buf = token.to_vec();
        let mut flags: u8 = 0;
        let mut extra: Vec<u8> = Vec::new();

        if let Some(alias) = new_alias {
            flags |= 0x01;
            extra.push(alias.len() as u8);
            extra.extend_from_slice(alias.as_bytes());
        }
        if let Some(port) = new_port {
            flags |= 0x02;
            extra.extend_from_slice(&port.to_be_bytes());
        }

        buf.push(flags);
        buf.extend(extra);
        buf
    }

    impl TestCtx {
        fn ctx(&self) -> &WorkerContext { &self.ctx }
    }

    #[test]
    fn app_update_alias() {
        let t = TestCtx::new();
        let token = register_and_get_token(&t, "original", 9001);

        app_update(t.app_addr(), update_packet(&token, Some("renamed"), None), &t.ctx);
        assert_eq!(t.recv_reply(), vec![OK]);

        let node = t.ctx.node.read().unwrap();
        let device_uuid = node.device_uuid;
        let device = node.owner.user.devices.iter().find(|d| d.uuid == device_uuid).unwrap();
        assert_eq!(device.applications[0].alias, "renamed");
    }

    #[test]
    fn app_update_port() {
        let t = TestCtx::new();
        let token = register_and_get_token(&t, "myapp", 9001);

        app_update(t.app_addr(), update_packet(&token, None, Some(9999)), &t.ctx);
        assert_eq!(t.recv_reply(), vec![OK]);

        let node = t.ctx.node.read().unwrap();
        let device_uuid = node.device_uuid;
        let device = node.owner.user.devices.iter().find(|d| d.uuid == device_uuid).unwrap();
        assert_eq!(device.applications[0].host.port(), 9999);
    }

    #[test]
    fn app_update_unknown_token_returns_error() {
        let t = TestCtx::new();
        let bad_token = [0xFFu8; 16];
        app_update(t.app_addr(), update_packet(&bad_token, Some("x"), None), &t.ctx);

        let reply = t.recv_reply();
        assert_eq!(reply[0], 0x01);
        assert_eq!(reply[1], ERR_TOKEN_UNKNOWN);
    }

    // ── AppGetData ────────────────────────────────────────────────────────────

    #[test]
    fn app_get_data_valid_token_returns_ok() {
        let t = TestCtx::new();
        let token = register_and_get_token(&t, "myapp", 9001);

        app_get_data(t.app_addr(), token.to_vec(), &t.ctx);
        let reply = t.recv_reply();
        assert_eq!(reply[0], OK);
    }

    #[test]
    fn app_get_data_unknown_token_returns_error() {
        let t = TestCtx::new();
        app_get_data(t.app_addr(), vec![0xFFu8; 16], &t.ctx);

        let reply = t.recv_reply();
        assert_eq!(reply[0], 0x01);
        assert_eq!(reply[1], ERR_TOKEN_UNKNOWN);
    }
}
