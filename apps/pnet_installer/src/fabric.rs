//! Local pNet app API and own-user directory parse.

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

pub const OP_REGISTER: u8 = 0x00;
pub const OP_GET_DATA: u8 = 0x02;
pub const OP_SEND: u8 = 0x03;
pub const OP_PUSH: u8 = 0x04;
pub const STATUS_OK: u8 = 0x00;

pub const APP_ALIAS: &str = "installer";
pub const APP_PROTOCOL: &str = "pnet-installer/1";

#[derive(Clone, Debug)]
pub struct Peer {
    pub device: [u8; 16],
    pub app_id: [u8; 16],
    pub device_alias: String,
}

#[derive(Clone, Debug)]
pub struct AppView {
    pub alias: String,
    pub approved: bool,
}

#[derive(Clone, Debug)]
pub struct DevView {
    pub uuid: [u8; 16],
    pub alias: String,
    pub is_sg: bool,
    pub sg_rank: u8,
    pub apps: Vec<AppView>,
}

#[derive(Clone, Debug)]
pub struct DirView {
    pub app_id: [u8; 16],
    pub device_uuid: [u8; 16],
    pub approved: bool,
    pub devices: Vec<DevView>,
    pub installer_peers: Vec<Peer>,
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

pub fn parse_directory(reply: &[u8], installer_alias: &str) -> Option<DirView> {
    let mut pos = 1usize;
    let app_id = read_arr::<16>(reply, &mut pos)?;
    let _app_alias = read_str(reply, &mut pos)?;
    pos += 6;
    let approved = *reply.get(pos)? != 0;
    pos += 1;
    pos += 16;
    let device_uuid = read_arr::<16>(reply, &mut pos)?;
    let _owner_alias = read_str(reply, &mut pos)?;
    let _owner_uuid = read_arr::<16>(reply, &mut pos)?;

    let mut devices = Vec::new();
    let mut installer_peers = Vec::new();
    let dev_count = *reply.get(pos)? as usize;
    pos += 1;
    for _ in 0..dev_count {
        let dev_uuid = read_arr::<16>(reply, &mut pos)?;
        let dev_alias = read_str(reply, &mut pos)?;
        let is_sg = *reply.get(pos)? != 0;
        pos += 1;
        let sg_rank = *reply.get(pos)?;
        pos += 1;
        let host_count = *reply.get(pos)? as usize;
        pos += 1;
        for _ in 0..host_count {
            let _ = read_str(reply, &mut pos)?;
        }
        let app_count = *reply.get(pos)? as usize;
        pos += 1;
        let mut apps = Vec::new();
        for _ in 0..app_count {
            let aid = read_arr::<16>(reply, &mut pos)?;
            let aalias = read_str(reply, &mut pos)?;
            pos += 4 + 2;
            let a_approved = *reply.get(pos)? != 0;
            pos += 1;
            if a_approved && aalias == installer_alias && aid != app_id {
                installer_peers.push(Peer {
                    device: dev_uuid,
                    app_id: aid,
                    device_alias: dev_alias.clone(),
                });
            }
            apps.push(AppView {
                alias: aalias,
                approved: a_approved,
            });
        }
        devices.push(DevView {
            uuid: dev_uuid,
            alias: dev_alias,
            is_sg,
            sg_rank,
            apps,
        });
    }
    Some(DirView {
        app_id,
        device_uuid,
        approved,
        devices,
        installer_peers,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_own_device_and_peer() {
        let mut r = vec![STATUS_OK];
        r.extend_from_slice(&[0x11; 16]); // our app id
        r.push(9);
        r.extend_from_slice(b"installer");
        r.extend_from_slice(&[127, 0, 0, 1, 0, 1]); // ip+port
        r.push(1); // approved
        r.extend_from_slice(&[0x22; 16]); // token
        r.extend_from_slice(&[0x01; 16]); // local device
        r.push(5);
        r.extend_from_slice(b"Alice");
        r.extend_from_slice(&[0x03; 16]); // owner uuid
        r.push(2); // two devices
        // device A (us)
        r.extend_from_slice(&[0x01; 16]);
        r.push(2);
        r.extend_from_slice(b"sg");
        r.push(1); // SG
        r.push(1); // rank 1
        r.push(0); // hosts
        r.push(1); // one app (us)
        r.extend_from_slice(&[0x11; 16]);
        r.push(9);
        r.extend_from_slice(b"installer");
        r.extend_from_slice(&[127, 0, 0, 1, 0, 2]);
        r.push(1);
        // device B
        r.extend_from_slice(&[0x02; 16]);
        r.push(2);
        r.extend_from_slice(b"dg");
        r.push(0);
        r.push(0);
        r.push(0);
        r.push(1);
        r.extend_from_slice(&[0x44; 16]);
        r.push(9);
        r.extend_from_slice(b"installer");
        r.extend_from_slice(&[127, 0, 0, 1, 0, 3]);
        r.push(1);
        let d = parse_directory(&r, "installer").expect("parse");
        assert_eq!(d.device_uuid, [0x01; 16]);
        assert_eq!(d.devices.len(), 2);
        assert_eq!(d.installer_peers.len(), 1);
        assert_eq!(d.installer_peers[0].device, [0x02; 16]);
        assert!(d.devices[0].is_sg);
    }
}
