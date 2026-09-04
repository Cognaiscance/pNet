//! App-layer filesync packets (opaque pNet payloads).
//!
//! One datagram = one message. Stay under [`MAX_PAYLOAD`] (pNet caps at 4096;
//! ~1 KiB is the WAN-friendly budget, 2 KiB chunks are a compromise that
//! still fits the envelope). Reliability (ACK + retry) is in `sync`.

use crate::store::FileRec;

pub const VER: u8 = 1;

pub const T_ACK: u8 = 0;
pub const T_HELLO: u8 = 1;
pub const T_INDEX: u8 = 2;
pub const T_WANT: u8 = 3;
pub const T_CHUNK: u8 = 4;

/// Bytes of file data per CHUNK (plus hash/offset headers).
pub const CHUNK_SIZE: usize = 2048;
/// Keep encoded packets under pNet `MAX_APP_PAYLOAD` (4096).
pub const MAX_PAYLOAD: usize = 3500;
pub const HEADER_LEN: usize = 1 + 1 + 8; // ver + type + msg_id

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
    if buf.len() < HEADER_LEN {
        return None;
    }
    if buf[0] != VER {
        return None;
    }
    let typ = buf[1];
    let msg_id = u64::from_be_bytes(buf[2..10].try_into().ok()?);
    Some(Packet {
        typ,
        msg_id,
        body: buf[10..].to_vec(),
    })
}

pub fn ack(acked: u64) -> Packet {
    Packet {
        typ: T_ACK,
        msg_id: 0,
        body: acked.to_be_bytes().to_vec(),
    }
}

pub fn parse_ack(body: &[u8]) -> Option<u64> {
    if body.len() != 8 {
        return None;
    }
    Some(u64::from_be_bytes(body.try_into().ok()?))
}

pub fn hello(replica: &[u8; 16], gen: u64) -> Packet {
    let mut body = Vec::with_capacity(24);
    body.extend_from_slice(replica);
    body.extend_from_slice(&gen.to_be_bytes());
    Packet {
        typ: T_HELLO,
        msg_id: 0, // filled by sender
        body,
    }
}

pub fn parse_hello(body: &[u8]) -> Option<([u8; 16], u64)> {
    if body.len() != 24 {
        return None;
    }
    let mut replica = [0u8; 16];
    replica.copy_from_slice(&body[..16]);
    let gen = u64::from_be_bytes(body[16..24].try_into().ok()?);
    Some((replica, gen))
}

pub fn want(hash: &[u8; 32]) -> Packet {
    Packet {
        typ: T_WANT,
        msg_id: 0,
        body: hash.to_vec(),
    }
}

pub fn parse_want(body: &[u8]) -> Option<[u8; 32]> {
    if body.len() != 32 {
        return None;
    }
    let mut h = [0u8; 32];
    h.copy_from_slice(body);
    Some(h)
}

pub fn chunk(hash: &[u8; 32], total: u64, offset: u64, data: &[u8]) -> Packet {
    let mut body = Vec::with_capacity(48 + data.len());
    body.extend_from_slice(hash);
    body.extend_from_slice(&total.to_be_bytes());
    body.extend_from_slice(&offset.to_be_bytes());
    body.extend_from_slice(data);
    Packet {
        typ: T_CHUNK,
        msg_id: 0,
        body,
    }
}

pub fn parse_chunk(body: &[u8]) -> Option<([u8; 32], u64, u64, &[u8])> {
    if body.len() < 48 {
        return None;
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&body[..32]);
    let total = u64::from_be_bytes(body[32..40].try_into().ok()?);
    let offset = u64::from_be_bytes(body[40..48].try_into().ok()?);
    Some((hash, total, offset, &body[48..]))
}

fn encode_record(r: &FileRec) -> Vec<u8> {
    let path = r.path.as_bytes();
    let mut o = Vec::with_capacity(1 + 8 + 8 + 32 + 2 + path.len());
    o.push(if r.deleted { 1 } else { 0 });
    o.extend_from_slice(&r.mtime.to_be_bytes());
    o.extend_from_slice(&r.size.to_be_bytes());
    o.extend_from_slice(&r.hash);
    o.extend_from_slice(&(path.len() as u16).to_be_bytes());
    o.extend_from_slice(path);
    o
}

fn decode_record(buf: &[u8], pos: &mut usize) -> Option<FileRec> {
    if *pos + 1 + 8 + 8 + 32 + 2 > buf.len() {
        return None;
    }
    let deleted = buf[*pos] != 0;
    *pos += 1;
    let mtime = u64::from_be_bytes(buf[*pos..*pos + 8].try_into().ok()?);
    *pos += 8;
    let size = u64::from_be_bytes(buf[*pos..*pos + 8].try_into().ok()?);
    *pos += 8;
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&buf[*pos..*pos + 32]);
    *pos += 32;
    let plen = u16::from_be_bytes(buf[*pos..*pos + 2].try_into().ok()?) as usize;
    *pos += 2;
    if *pos + plen > buf.len() {
        return None;
    }
    let path = std::str::from_utf8(&buf[*pos..*pos + plen]).ok()?.to_string();
    *pos += plen;
    Some(FileRec {
        path,
        size,
        mtime,
        hash,
        deleted,
    })
}

/// Split the index into as many INDEX packets as needed.
pub fn encode_index(gen: u64, recs: &[FileRec]) -> Vec<Vec<u8>> {
    // First pass: encode records.
    let encoded: Vec<Vec<u8>> = recs.iter().map(encode_record).collect();
    let max_body = MAX_PAYLOAD.saturating_sub(HEADER_LEN + 8 + 2 + 2);
    let mut parts: Vec<Vec<&[u8]>> = Vec::new();
    let mut cur: Vec<&[u8]> = Vec::new();
    let mut cur_len = 0usize;
    for e in &encoded {
        if !cur.is_empty() && cur_len + e.len() > max_body {
            parts.push(cur);
            cur = Vec::new();
            cur_len = 0;
        }
        cur_len += e.len();
        cur.push(e);
    }
    if !cur.is_empty() || parts.is_empty() {
        parts.push(cur);
    }
    let nparts = parts.len() as u16;
    let mut out = Vec::with_capacity(parts.len());
    for (i, recs) in parts.iter().enumerate() {
        let mut body = Vec::new();
        body.extend_from_slice(&gen.to_be_bytes());
        body.extend_from_slice(&(i as u16).to_be_bytes());
        body.extend_from_slice(&nparts.to_be_bytes());
        for r in recs {
            body.extend_from_slice(r);
        }
        out.push(body);
    }
    out
}

pub fn parse_index(body: &[u8]) -> Option<(u64, u16, u16, Vec<FileRec>)> {
    if body.len() < 12 {
        return None;
    }
    let gen = u64::from_be_bytes(body[0..8].try_into().ok()?);
    let part = u16::from_be_bytes(body[8..10].try_into().ok()?);
    let parts = u16::from_be_bytes(body[10..12].try_into().ok()?);
    let mut pos = 12usize;
    let mut recs = Vec::new();
    while pos < body.len() {
        recs.push(decode_record(body, &mut pos)?);
    }
    Some((gen, part, parts, recs))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(path: &str, size: u64, mtime: u64, deleted: bool) -> FileRec {
        FileRec {
            path: path.into(),
            size,
            mtime,
            hash: [size as u8; 32],
            deleted,
        }
    }

    #[test]
    fn packet_roundtrip() {
        let p = Packet {
            typ: T_WANT,
            msg_id: 42,
            body: vec![9; 32],
        };
        let enc = encode(&p);
        assert!(enc.len() < MAX_PAYLOAD);
        assert_eq!(decode(&enc), Some(p));
    }

    #[test]
    fn index_roundtrip_and_split() {
        let recs: Vec<_> = (0..80)
            .map(|i| rec(&format!("dir/file-{i}.txt"), 10 + i, 1_700_000_000 + i, false))
            .collect();
        let bodies = encode_index(7, &recs);
        assert!(bodies.len() >= 1);
        let mut got = Vec::new();
        for b in &bodies {
            assert!(b.len() + HEADER_LEN <= MAX_PAYLOAD);
            let (gen, _part, parts, chunk) = parse_index(b).unwrap();
            assert_eq!(gen, 7);
            assert_eq!(parts as usize, bodies.len());
            got.extend(chunk);
        }
        assert_eq!(got, recs);
    }

    #[test]
    fn chunk_roundtrip() {
        let hash = [3u8; 32];
        let data = vec![1, 2, 3, 4, 5];
        let p = chunk(&hash, 100, 40, &data);
        let (h, total, off, d) = parse_chunk(&p.body).unwrap();
        assert_eq!(h, hash);
        assert_eq!(total, 100);
        assert_eq!(off, 40);
        assert_eq!(d, &data);
    }

    #[test]
    fn ack_and_hello_roundtrip() {
        let a = ack(99);
        assert_eq!(parse_ack(&a.body), Some(99));
        let replica = [7u8; 16];
        let h = hello(&replica, 12);
        assert_eq!(parse_hello(&h.body), Some((replica, 12)));
    }
}
