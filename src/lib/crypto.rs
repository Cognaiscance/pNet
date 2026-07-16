//! Core cryptographic helpers used by the pNet fabric.
//!
//! X25519 for ephemeral DH, Ed25519 for long-term identity signatures,
//! XChaCha20-Poly1305 for AEAD, plus session-packet seal/open helpers.
//!
//! Extracted from `handlers` so the dispatch module stays free of crypto
//! implementation detail. Key typing / HKDF hygiene are Phase 4 work.

use super::data_models::{ActiveConnection, KeyPair, Node, generate_key_bytes};
use super::wire::ENCRYPTED_BODY_HEADER_LEN;

/// X25519 Diffie-Hellman: returns the 32-byte shared secret.
pub(crate) fn x25519_shared(our_sk: &[u8; 32], their_pk: &[u8; 32]) -> [u8; 32] {
    use x25519_dalek::{PublicKey as X25519Pk, StaticSecret};
    StaticSecret::from(*our_sk)
        .diffie_hellman(&X25519Pk::from(*their_pk))
        .to_bytes()
}

/// Generate a proper X25519 key pair: random scalar + corresponding public point.
pub(crate) fn generate_x25519_keypair() -> KeyPair {
    use x25519_dalek::{PublicKey as X25519Pk, StaticSecret};
    let sk = StaticSecret::from(generate_key_bytes());
    KeyPair {
        private_key: sk.to_bytes(),
        public_key:  *X25519Pk::from(&sk).as_bytes(),
    }
}

/// Generate a proper Ed25519 key pair for long-term identity signing.
pub(crate) fn generate_ed25519_keypair() -> KeyPair {
    use ed25519_dalek::SigningKey;
    let seed = generate_key_bytes();
    let signing_key = SigningKey::from_bytes(&seed);
    KeyPair {
        private_key: seed,
        public_key:  *signing_key.verifying_key().as_bytes(),
    }
}

/// Ed25519 sign: returns a 64-byte signature over `message` using a 32-byte seed.
pub(crate) fn ed25519_sign(private_key: &[u8; 32], message: &[u8]) -> [u8; 64] {
    use ed25519_dalek::{Signer, SigningKey};
    SigningKey::from_bytes(private_key).sign(message).to_bytes()
}

/// Ed25519 verify: returns true if the 64-byte signature is valid over `message`.
pub(crate) fn ed25519_verify(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let Ok(vk) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    let sig = Signature::from_bytes(signature);
    vk.verify(message, &sig).is_ok()
}

/// XChaCha20-Poly1305 authenticated encryption. Returns (ciphertext, 24-byte nonce).
pub(crate) fn xchacha20_encrypt(key: &[u8; 32], plaintext: &[u8]) -> (Vec<u8>, [u8; 24]) {
    use chacha20poly1305::{
        XChaCha20Poly1305, XNonce,
        aead::{Aead, KeyInit},
    };
    let nonce_bytes: [u8; 24] = {
        use std::io::Read;
        let mut b = [0u8; 24];
        std::fs::File::open("/dev/urandom")
            .unwrap()
            .read_exact(&mut b)
            .unwrap();
        b
    };
    let cipher = XChaCha20Poly1305::new_from_slice(key).expect("32-byte key");
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext).expect("encryption failed");
    (ciphertext, nonce_bytes)
}

/// XChaCha20-Poly1305 authenticated decryption. Returns `None` on auth failure.
pub(crate) fn xchacha20_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    ciphertext: &[u8],
) -> Option<Vec<u8>> {
    use chacha20poly1305::{
        XChaCha20Poly1305, XNonce,
        aead::{Aead, KeyInit},
    };
    let cipher = XChaCha20Poly1305::new_from_slice(key).ok()?;
    let nonce = XNonce::from_slice(nonce);
    cipher.decrypt(nonce, ciphertext).ok()
}

/// Build a complete relay or app packet: unencrypted header + encrypted body.
///
/// Header: `[op: 1][peer_active_conn_id: u16][nonce: 24]`
/// Body: XChaCha20-Poly1305 encrypted plaintext using the X25519 shared secret.
pub(crate) fn build_encrypted_packet(
    op: u8,
    conn: &ActiveConnection,
    plaintext: &[u8],
) -> Vec<u8> {
    let shared = x25519_shared(&conn.key_pair.private_key, &conn.peer_public_key);
    let (ct, nonce) = xchacha20_encrypt(&shared, plaintext);
    let mut pkt = Vec::with_capacity(1 + 2 + 24 + ct.len());
    pkt.push(op);
    pkt.extend_from_slice(&conn.peer_active_connection_id.to_be_bytes());
    pkt.extend_from_slice(&nonce);
    pkt.extend_from_slice(&ct);
    pkt
}

/// Decrypt the body of a relay or app packet (`buf` starts after the op byte).
///
/// `buf` layout: `[receiver_active_conn_id: u16][nonce: 24][ciphertext]`
///
/// Looks up the named active connection and decrypts with the X25519 shared
/// secret for that connection.
pub(crate) fn decrypt_packet_body(node: &Node, buf: &[u8]) -> Option<Vec<u8>> {
    if buf.len() < ENCRYPTED_BODY_HEADER_LEN {
        return None;
    }
    let conn_id = u16::from_be_bytes([buf[0], buf[1]]);
    let nonce: [u8; 24] = buf[2..ENCRYPTED_BODY_HEADER_LEN].try_into().ok()?;
    let ciphertext = &buf[ENCRYPTED_BODY_HEADER_LEN..];
    let conn = node.owner.active_connections.get(&conn_id)?;
    let shared = x25519_shared(&conn.key_pair.private_key, &conn.peer_public_key);
    xchacha20_decrypt(&shared, &nonce, ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::data_models::generate_uuid;
    use std::time::{Duration, SystemTime};

    #[test]
    fn ed25519_roundtrip_valid_signature() {
        let kp = generate_ed25519_keypair();
        let msg = b"hello pnet";
        let sig = ed25519_sign(&kp.private_key, msg);
        assert!(ed25519_verify(&kp.public_key, msg, &sig));
    }

    #[test]
    fn ed25519_verify_rejects_wrong_key() {
        let kp1 = generate_ed25519_keypair();
        let kp2 = generate_ed25519_keypair();
        let sig = ed25519_sign(&kp1.private_key, b"msg");
        assert!(!ed25519_verify(&kp2.public_key, b"msg", &sig));
    }

    #[test]
    fn ed25519_verify_rejects_tampered_signature() {
        let kp = generate_ed25519_keypair();
        let mut sig = ed25519_sign(&kp.private_key, b"msg");
        sig[0] ^= 0xFF;
        assert!(!ed25519_verify(&kp.public_key, b"msg", &sig));
    }

    #[test]
    fn x25519_shared_is_symmetric() {
        let a = generate_x25519_keypair();
        let b = generate_x25519_keypair();
        let ab = x25519_shared(&a.private_key, &b.public_key);
        let ba = x25519_shared(&b.private_key, &a.public_key);
        assert_eq!(ab, ba);
    }

    #[test]
    fn xchacha20_roundtrip() {
        let key = generate_key_bytes();
        let (ct, nonce) = xchacha20_encrypt(&key, b"payload");
        let pt = xchacha20_decrypt(&key, &nonce, &ct).expect("decrypt");
        assert_eq!(pt, b"payload");
        assert!(xchacha20_decrypt(&key, &nonce, b"tampered").is_none());
    }

    #[test]
    fn build_and_decrypt_packet_roundtrip() {
        let sender_kp = generate_x25519_keypair();
        let receiver_kp = generate_x25519_keypair();
        const OP: u8 = 0x50;

        let conn = ActiveConnection {
            id: 1,
            timeout: SystemTime::now() + Duration::from_secs(3600),
            key_pair: sender_kp.clone(),
            peer_public_key: receiver_kp.public_key,
            peer_active_connection_id: 7,
            device_uuid: generate_uuid(),
            peer_addr: "127.0.0.1:0".parse().unwrap(),
        };
        let plaintext = b"hello relay";
        let pkt = build_encrypted_packet(OP, &conn, plaintext);
        assert_eq!(pkt[0], OP);
        assert_eq!(u16::from_be_bytes([pkt[1], pkt[2]]), 7);

        let mut node = Node::new();
        node.owner.active_connections.insert(
            7,
            ActiveConnection {
                id: 7,
                timeout: SystemTime::now() + Duration::from_secs(3600),
                key_pair: receiver_kp,
                peer_public_key: sender_kp.public_key,
                peer_active_connection_id: 1,
                device_uuid: generate_uuid(),
                peer_addr: "127.0.0.1:0".parse().unwrap(),
            },
        );

        let decrypted = decrypt_packet_body(&node, &pkt[1..]).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
