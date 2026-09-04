//! Local pNet app API (register / get_data / send) and directory parse.

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

pub const OP_REGISTER: u8 = 0x00;
pub const OP_GET_DATA: u8 = 0x02;
pub const OP_SEND: u8 = 0x03;
pub const OP_PUSH: u8 = 0x04;
pub const STATUS_OK: u8 = 0x00;

pub const APP_ALIAS: &str = "filesync";
pub const APP_PROTOCOL: &str = "pnet-filesync/1";

#[derive(Clone, Debug)]
pub struct Peer {
    pub device: [u8; 16],
    pub app_id: [u8; 16],
    pub device_alias: String,
}

#[derive(Clone, Debug)]
pub struct Directory {
    pub app_id: [u8; 16],
    pub device_uuid: [u8; 16],
    pub approved: bool,
    pub peers: Vec<Peer>,
}

pub fn register(
    ctrl: &UdpSocket,
    dest: SocketAddr,
    alias: &str,
    push_port: u16,
) -> Result<[u8; 16], String> {
    let mut pkt = vec![OP_REGISTER];
    push_str(&mut pkt, alias);
    pkt.extend_from_slice(&push_port.to_be_bytes());
    push_str(&mut pkt, APP_PROTOCOL);
    ctrl.send_to(&pkt, dest).map_err(|e| e.to_string())?;
    let mut buf = [0u8; 64];
    let (n, _) = ctrl.recv_from(&mut buf).map_err(|e| e.to_string())?;
    if n < 17 || buf[0] != STATUS_OK {
        return Err(format!(
            "register reply status={}",
            buf.first().copied().unwrap_or(0xff)
        ));
    }
    let mut token = [0u8; 16];
    token.copy_from_slice(&buf[1..17]);
    Ok(token)
}

pub fn get_data(ctrl: &UdpSocket, dest: SocketAddr, token: &[u8; 16]) -> Result<Vec<u8>, String> {
    let mut pkt = vec![OP_GET_DATA];
    pkt.extend_from_slice(token);
    ctrl.send_to(&pkt, dest).map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 65536];
    let (n, _) = ctrl.recv_from(&mut buf).map_err(|e| e.to_string())?;
    buf.truncate(n);
    if buf.first().copied() != Some(STATUS_OK) {
        return Err("get_data not ok".into());
    }
    Ok(buf)
}

pub fn send_payload(
    ctrl: &UdpSocket,
    dest: SocketAddr,
    token: &[u8; 16],
    dest_device: &[u8; 16],
    dest_app: &[u8; 16],
    payload: &[u8],
) -> Result<(), String> {
    let mut pkt = Vec::with_capacity(1 + 48 + payload.len());
    pkt.push(OP_SEND);
    pkt.extend_from_slice(token);
    pkt.extend_from_slice(dest_device);
    pkt.extend_from_slice(dest_app);
    pkt.extend_from_slice(payload);
    ctrl.send_to(&pkt, dest).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn parse_push(buf: &[u8]) -> Option<([u8; 16], &[u8])> {
    if buf.len() < 17 || buf[0] != OP_PUSH {
        return None;
    }
    let mut sender = [0u8; 16];
    sender.copy_from_slice(&buf[1..17]);
    Some((sender, &buf[17..]))
}

/// Own-user `filesync` apps other than us. Intra-user only (v1).
pub fn parse_directory(reply: &[u8], alias: &str) -> Option<Directory> {
    let mut pos = 1usize;
    let app_id = read_arr::<16>(reply, &mut pos)?;
    let _app_alias = read_str(reply, &mut pos)?;
    pos += 6; // ip+port
    let approved = *reply.get(pos)? != 0;
    pos += 1;
    pos += 16; // token
    let device_uuid = read_arr::<16>(reply, &mut pos)?;
    let _owner_alias = read_str(reply, &mut pos)?;
    let _owner_uuid = read_arr::<16>(reply, &mut pos)?;

    let mut peers = Vec::new();
    let dev_count = *reply.get(pos)? as usize;
    pos += 1;
    for _ in 0..dev_count {
        let dev_uuid = read_arr::<16>(reply, &mut pos)?;
        let dev_alias = read_str(reply, &mut pos)?;
        pos += 1; // grade
        pos += 1; // sg_rank
        let host_count = *reply.get(pos)? as usize;
        pos += 1;
        for _ in 0..host_count {
            let _ = read_str(reply, &mut pos)?;
        }
        let app_count = *reply.get(pos)? as usize;
        pos += 1;
        for _ in 0..app_count {
            let aid = read_arr::<16>(reply, &mut pos)?;
            let aalias = read_str(reply, &mut pos)?;
            pos += 4 + 2; // ip+port
            let a_approved = *reply.get(pos)? != 0;
            pos += 1;
            if a_approved && aalias == alias && aid != app_id {
                peers.push(Peer {
                    device: dev_uuid,
                    app_id: aid,
                    device_alias: dev_alias.clone(),
                });
            }
        }
    }
    // Skip contacts (v1 is own-user only).
    Some(Directory {
        app_id,
        device_uuid,
        approved,
        peers,
    })
}

pub fn bind_udp() -> Result<UdpSocket, String> {
    let s = UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|e| e.to_string())?;
    Ok(s)
}

fn push_str(buf: &mut Vec<u8>, s: &str) {
    buf.push(s.len() as u8);
    buf.extend_from_slice(s.as_bytes());
}

fn read_str(data: &[u8], pos: &mut usize) -> Option<String> {
    let len = *data.get(*pos)? as usize;
    *pos += 1;
    let s = std::str::from_utf8(data.get(*pos..*pos + len)?)
        .ok()?
        .to_string();
    *pos += len;
    Some(s)
}

fn read_arr<const N: usize>(data: &[u8], pos: &mut usize) -> Option<[u8; N]> {
    let arr: [u8; N] = data.get(*pos..*pos + N)?.try_into().ok()?;
    *pos += N;
    Some(arr)
}
