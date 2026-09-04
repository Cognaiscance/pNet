//! App-layer installer packets (opaque pNet payloads).

use crate::state::{DesiredApp, InstallStatus};

pub const VER: u8 = 1;
pub const T_ACK: u8 = 0;
pub const T_HELLO: u8 = 1;
pub const T_DESIRE: u8 = 2;
pub const T_STATUS: u8 = 3;
pub const HEADER_LEN: usize = 10;
pub const MAX_PAYLOAD: usize = 3500;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    pub typ: u8,
    pub msg_id: u64,
    pub body: Vec<u8>,
}

pub fn encode(p: &Packet) -> Vec<u8> {
    let mut o = Vec::with_capacity(HEADER_LEN + p.body.len());
    o.push(VER);
    o.push(p.typ);
    o.extend_from_slice(&p.msg_id.to_be_bytes());
    o.extend_from_slice(&p.body);
    o
}

pub fn decode(buf: &[u8]) -> Option<Packet> {
    if buf.len() < HEADER_LEN || buf[0] != VER {
        return None;
    }
    Some(Packet {
        typ: buf[1],
        msg_id: u64::from_be_bytes(buf[2..10].try_into().ok()?),
        body: buf[10..].to_vec(),
    })
}

pub fn ack(id: u64) -> Packet {
    Packet {
        typ: T_ACK,
        msg_id: 0,
        body: id.to_be_bytes().to_vec(),
    }
}

pub fn parse_ack(body: &[u8]) -> Option<u64> {
    if body.len() != 8 {
        return None;
    }
    Some(u64::from_be_bytes(body.try_into().ok()?))
}

pub fn hello(replica: &[u8; 16], writer: bool) -> Packet {
    let mut body = replica.to_vec();
    body.push(writer as u8);
    Packet {
        typ: T_HELLO,
        msg_id: 0,
        body,
    }
}

pub fn desire_packet(list: &[DesiredApp]) -> Option<Packet> {
    let body = serde_json::to_vec(list).ok()?;
    if HEADER_LEN + body.len() > MAX_PAYLOAD {
        return None;
    }
    Some(Packet {
        typ: T_DESIRE,
        msg_id: 0,
        body,
    })
}

pub fn parse_desire(body: &[u8]) -> Option<Vec<DesiredApp>> {
    serde_json::from_slice(body).ok()
}

pub fn status_packet(list: &[InstallStatus]) -> Option<Packet> {
    let body = serde_json::to_vec(list).ok()?;
    if HEADER_LEN + body.len() > MAX_PAYLOAD {
        return None;
    }
    Some(Packet {
        typ: T_STATUS,
        msg_id: 0,
        body,
    })
}

pub fn parse_status(body: &[u8]) -> Option<Vec<InstallStatus>> {
    serde_json::from_slice(body).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desire_json_roundtrip() {
        let d = vec![DesiredApp {
            catalog_id: "filesync".into(),
            version: "manual".into(),
            enabled: true,
            device_uuids: vec!["ab".repeat(16)],
            updated_at: 10,
            updated_by: "cd".repeat(16),
        }];
        let p = desire_packet(&d).unwrap();
        assert!(encode(&p).len() < MAX_PAYLOAD);
        assert_eq!(parse_desire(&p.body).unwrap(), d);
        assert_eq!(decode(&encode(&p)).unwrap().typ, T_DESIRE);
    }
}
