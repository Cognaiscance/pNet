//! Wire-format constants and shared binary parse helpers for the pNet fabric.
//!
//! Op bytes, reply codes, and length-prefixed readers/writers live here so
//! handlers stay free of magic numbers. Domain payloads (bootstrap, change
//! types, full directory blobs) stay in their own modules when extracted.

use super::data_models::{Scope, SyncVersion, Uuid};

// ── Local app control-plane replies (UDP app API) ─────────────────────────────

pub(crate) const OK: u8 = 0x00;
pub(crate) const ERR_BAD_PACKET: u8 = 0x01;
pub(crate) const ERR_TOKEN_UNKNOWN: u8 = 0x02;
pub(crate) const ERR_NO_WRITER: u8 = 0x03;

// ── Local app op bytes ────────────────────────────────────────────────────────

pub(crate) const APP_REGISTER_OP: u8 = 0x00;
pub(crate) const APP_UPDATE_OP: u8 = 0x01;
pub(crate) const APP_GET_DATA_OP: u8 = 0x02;
pub(crate) const APP_SEND_PACKET_OP: u8 = 0x03;
pub(crate) const APP_PUSH_OP: u8 = 0x04;

// ── Peer fabric op bytes ──────────────────────────────────────────────────────

pub(crate) const SG_PING_OP: u8 = 0x10;
pub(crate) const SG_PONG_OP: u8 = 0x11;
pub(crate) const DG_KEEPALIVE_OP: u8 = 0x12;
pub(crate) const CONN_RESET_OP: u8 = 0x13;

pub(crate) const CONNECT_REQUEST_OP: u8 = 0x20;
pub(crate) const CONNECT_ACK_OP: u8 = 0x21;

pub(crate) const BOOTSTRAP_REQUEST_OP: u8 = 0x30;
pub(crate) const BOOTSTRAP_RESPONSE_OP: u8 = 0x31;
pub(crate) const DEVICE_REGISTER_OP: u8 = 0x32;
pub(crate) const CONTACT_REQUEST_OP: u8 = 0x33;
pub(crate) const CONTACT_RESPONSE_OP: u8 = 0x34;
/// DG asks top-ranked online SG to mint an invitation and return the code.
pub(crate) const GENERATE_INVITATION_REQUEST_OP: u8 = 0x35;
pub(crate) const GENERATE_INVITATION_RESPONSE_OP: u8 = 0x36;

pub(crate) const RELAY_PACKET_OP: u8 = 0x40;
pub(crate) const APP_PACKET_OP: u8 = 0x41;

pub(crate) const TUNNEL_INIT_OP: u8 = 0x50;
pub(crate) const TUNNEL_FORWARD_OP: u8 = 0x51;
pub(crate) const TUNNEL_CONNECT_REQUEST_OP: u8 = 0x52;
pub(crate) const TUNNEL_CONNECT_ACK_OP: u8 = 0x53;
pub(crate) const TUNNEL_DELIVERY_OP: u8 = 0x54;

// Sync v1 (see descriptions/data sync.md).
pub(crate) const SYNC_WRITE_REQUEST_OP: u8 = 0x70;
pub(crate) const SYNC_WRITE_ACK_OP: u8 = 0x71;
pub(crate) const SYNC_UPDATE_AVAILABLE_OP: u8 = 0x72;
pub(crate) const SYNC_PULL_REQUEST_OP: u8 = 0x73;
pub(crate) const SYNC_PULL_RESPONSE_OP: u8 = 0x74;
pub(crate) const CROSS_USER_UPDATE_AVAILABLE_OP: u8 = 0x75;
pub(crate) const CROSS_USER_PULL_REQUEST_OP: u8 = 0x76;
pub(crate) const CROSS_USER_PULL_RESPONSE_OP: u8 = 0x77;
// Sync v2 merge + watermark.
pub(crate) const MERGE_PROPOSAL_OP: u8 = 0x78;
pub(crate) const MERGE_ACK_OP: u8 = 0x79;
pub(crate) const WATERMARK_PROBE_REQUEST_OP: u8 = 0x7A;
pub(crate) const WATERMARK_PROBE_RESPONSE_OP: u8 = 0x7B;

// ── Invitation mint (0x35/0x36 body codes) ────────────────────────────────────

pub(crate) const INVITE_TYPE_DEVICE: u8 = 0x00;
pub(crate) const INVITE_TYPE_CONTACT: u8 = 0x01;
pub(crate) const INVITE_RESULT_OK: u8 = 0x00;
pub(crate) const INVITE_RESULT_ERROR: u8 = 0x01;

// ── Sync result / scope bytes ─────────────────────────────────────────────────

pub(crate) const SCOPE_PRIVATE: u8 = 0;
pub(crate) const SCOPE_PUBLIC: u8 = 1;

pub(crate) const WRITE_ACK_OK: u8 = 0;
pub(crate) const WRITE_ACK_NOT_WRITER: u8 = 1;
pub(crate) const WRITE_ACK_VALIDATION_ERROR: u8 = 2;

pub(crate) const PULL_RESULT_NO_UPDATES: u8 = 0;
pub(crate) const PULL_RESULT_FULL_STATE: u8 = 1;

/// Wire size of `SyncVersion`: 16 (uuid) + 4 (epoch) + 8 (seq).
pub(crate) const SYNC_VERSION_WIRE_LEN: usize = 28;

pub(crate) const MERGE_ACK_RESULT_APPLIED: u8 = 0;
pub(crate) const MERGE_ACK_RESULT_RETENTION_EXHAUSTED: u8 = 1;
pub(crate) const MERGE_ACK_RESULT_MALFORMED: u8 = 2;

// ── Change kind bytes (sync write payload) ────────────────────────────────────

pub(crate) const CHANGE_KIND_ADD_APPLICATION: u8 = 0x01;
pub(crate) const CHANGE_KIND_REMOVE_APPLICATION: u8 = 0x02;
pub(crate) const CHANGE_KIND_ADD_DEVICE: u8 = 0x03;
pub(crate) const CHANGE_KIND_UPDATE_APPLICATION_ALIAS: u8 = 0x04;
pub(crate) const CHANGE_KIND_UPSERT_CONTACT: u8 = 0x05;

// ── Shared min lengths (unencrypted headers / common envelopes) ───────────────

/// ConnectRequest after op: conn_id(2) + device_uuid(16) + longterm_pk(32)
/// + ephemeral_pk(32) + signature(64).
pub(crate) const CONNECT_REQUEST_MIN_LEN: usize = 2 + 16 + 32 + 32 + 64;

/// ConnectAck after op: responder_conn_id(2) + our_conn_id(2) + ephemeral_pk(32)
/// + signature(64).
pub(crate) const CONNECT_ACK_MIN_LEN: usize = 2 + 2 + 32 + 64;

/// Encrypted body header for session packets: conn_id(2) + nonce(24).
pub(crate) const ENCRYPTED_BODY_HEADER_LEN: usize = 2 + 24;

// ── Length-prefixed / fixed-width readers ─────────────────────────────────────

/// Length-prefixed UTF-8 string: `[len:u8][bytes…]` (len max 255).
pub(crate) fn push_str(buf: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    buf.push(b.len() as u8);
    buf.extend_from_slice(b);
}

pub(crate) fn read_str(data: &[u8], pos: &mut usize) -> Option<String> {
    let len = *data.get(*pos)? as usize;
    *pos += 1;
    let s = std::str::from_utf8(data.get(*pos..*pos + len)?)
        .ok()?
        .to_string();
    *pos += len;
    Some(s)
}

pub(crate) fn read_arr<const N: usize>(data: &[u8], pos: &mut usize) -> Option<[u8; N]> {
    let slice: [u8; N] = data.get(*pos..*pos + N)?.try_into().ok()?;
    *pos += N;
    Some(slice)
}

/// 32-char lowercase hex of a 16-byte uuid (UI form values / logs).
pub(crate) fn uuid_hex(uuid: &Uuid) -> String {
    uuid.iter().map(|b| format!("{b:02x}")).collect()
}

/// Inverse of [`uuid_hex`]. Returns `None` for malformed input.
pub(crate) fn uuid_from_hex(s: &str) -> Option<Uuid> {
    if s.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

pub(crate) fn write_scope(buf: &mut Vec<u8>, scope: Scope) {
    buf.push(match scope {
        Scope::Private => SCOPE_PRIVATE,
        Scope::Public => SCOPE_PUBLIC,
    });
}

pub(crate) fn read_scope(data: &[u8], pos: &mut usize) -> Option<Scope> {
    let b = *data.get(*pos)?;
    *pos += 1;
    match b {
        SCOPE_PRIVATE => Some(Scope::Private),
        SCOPE_PUBLIC => Some(Scope::Public),
        _ => None,
    }
}

pub(crate) fn write_sync_version(buf: &mut Vec<u8>, v: &SyncVersion) {
    buf.extend_from_slice(&v.writer_sg_uuid);
    buf.extend_from_slice(&v.epoch.to_be_bytes());
    buf.extend_from_slice(&v.seq.to_be_bytes());
}

pub(crate) fn read_sync_version(data: &[u8], pos: &mut usize) -> Option<SyncVersion> {
    let writer_sg_uuid: Uuid = read_arr(data, pos)?;
    let epoch_bytes: [u8; 4] = read_arr(data, pos)?;
    let seq_bytes: [u8; 8] = read_arr(data, pos)?;
    Some(SyncVersion {
        writer_sg_uuid,
        epoch: u32::from_be_bytes(epoch_bytes),
        seq: u64::from_be_bytes(seq_bytes),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::data_models::SyncVersion;

    #[test]
    fn push_read_str_roundtrip() {
        let mut buf = Vec::new();
        push_str(&mut buf, "hello");
        let mut pos = 0;
        assert_eq!(read_str(&buf, &mut pos).as_deref(), Some("hello"));
        assert_eq!(pos, buf.len());
    }

    #[test]
    fn read_arr_advances() {
        let data = [1u8, 2, 3, 4, 5];
        let mut pos = 1;
        let a: [u8; 3] = read_arr(&data, &mut pos).unwrap();
        assert_eq!(a, [2, 3, 4]);
        assert_eq!(pos, 4);
    }

    #[test]
    fn uuid_hex_roundtrip() {
        let id = [0xabu8; 16];
        let s = uuid_hex(&id);
        assert_eq!(s.len(), 32);
        assert_eq!(uuid_from_hex(&s), Some(id));
        assert!(uuid_from_hex("zz").is_none());
    }

    #[test]
    fn sync_version_roundtrips_through_wire_format() {
        let v = SyncVersion {
            writer_sg_uuid: [0xAB; 16],
            epoch: 0xCAFEBABE,
            seq: 0x0102_0304_0506_0708,
        };
        let mut buf = Vec::new();
        write_sync_version(&mut buf, &v);
        assert_eq!(buf.len(), SYNC_VERSION_WIRE_LEN);

        let mut pos = 0usize;
        let restored = read_sync_version(&buf, &mut pos).expect("read version");
        assert_eq!(pos, SYNC_VERSION_WIRE_LEN);
        assert_eq!(restored, v);
    }

    #[test]
    fn sync_version_zero_roundtrips() {
        let v = SyncVersion::zero();
        let mut buf = Vec::new();
        write_sync_version(&mut buf, &v);
        let mut pos = 0usize;
        let restored = read_sync_version(&buf, &mut pos).expect("read zero");
        assert_eq!(restored, v);
        assert!(restored.is_initial());
    }

    #[test]
    fn sync_version_truncated_returns_none() {
        let v = SyncVersion {
            writer_sg_uuid: [1; 16],
            epoch: 7,
            seq: 9,
        };
        let mut buf = Vec::new();
        write_sync_version(&mut buf, &v);
        buf.pop();
        let mut pos = 0usize;
        assert!(read_sync_version(&buf, &mut pos).is_none());
    }

    #[test]
    fn scope_roundtrips_both_variants() {
        for scope in [Scope::Private, Scope::Public] {
            let mut buf = Vec::new();
            write_scope(&mut buf, scope);
            assert_eq!(buf.len(), 1);
            let mut pos = 0usize;
            let restored = read_scope(&buf, &mut pos).expect("read scope");
            assert_eq!(restored, scope);
            assert_eq!(pos, 1);
        }
    }

    #[test]
    fn read_scope_rejects_unknown_byte() {
        let buf = [0x99u8];
        let mut pos = 0usize;
        assert!(read_scope(&buf, &mut pos).is_none());
    }
}
