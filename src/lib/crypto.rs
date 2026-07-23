//! Core cryptographic helpers used by the pNet fabric.
//!
//! X25519 for ephemeral DH, Ed25519 for long-term identity signatures,
//! HKDF-SHA256 to derive AEAD keys from DH shared secrets (domain-separated),
//! XChaCha20-Poly1305 for AEAD, plus session-packet seal/open helpers.
//!
//! Ed25519 and X25519 keys are distinct types so identity material cannot be
//! passed into DH (or the reverse) at compile time.

use super::data_models::{
    ActiveConnection, Ed25519KeyPair, Ed25519PublicKey, Ed25519SecretKey, Node, X25519KeyPair,
    X25519PublicKey, X25519SecretKey, fill_random, generate_key_bytes,
};
use super::wire::ENCRYPTED_BODY_HEADER_LEN;

/// HKDF-Expand `info` labels for AEAD key derivation from X25519 shared secrets.
///
/// Never use the raw DH output as an AEAD key. Domain separation keeps session
/// traffic, bootstrap/contact invitation exchanges, and DG↔DG tunnels from
/// sharing key material even if the same DH output were ever reused.
pub(crate) mod aead_domain {
    /// ActiveConnection-sealed packets (relay, app packet, sync, keepalive, invites over session).
    pub const SESSION: &[u8] = b"pnet-aead-v1-session";
    /// Device bootstrap and contact-invitation handshakes (ephemeral × invitation PK).
    pub const BOOTSTRAP: &[u8] = b"pnet-aead-v1-bootstrap";
    /// Lazy tunnel end-to-end payload (DG↔DG ephemerals; SG only forwards ciphertext).
    pub const TUNNEL: &[u8] = b"pnet-aead-v1-tunnel";
}

/// X25519 Diffie-Hellman: returns the 32-byte shared secret (raw IKM, not an AEAD key).
pub(crate) fn x25519_shared(our_sk: &X25519SecretKey, their_pk: &X25519PublicKey) -> [u8; 32] {
    use x25519_dalek::{PublicKey as X25519Pk, StaticSecret};
    StaticSecret::from(our_sk.0)
        .diffie_hellman(&X25519Pk::from(their_pk.0))
        .to_bytes()
}

/// Derive a 32-byte XChaCha20-Poly1305 key from an X25519 shared secret via HKDF-SHA256.
///
/// `domain` must be one of [`aead_domain`] constants (or a future label with the
/// same `pnet-aead-v1-…` prefix). Salt is empty; the domain is the info string.
pub(crate) fn derive_aead_key(shared_secret: &[u8; 32], domain: &[u8]) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut okm = [0u8; 32];
    // 32-byte OKM is well under the 255*HashLen expand limit.
    hk.expand(domain, &mut okm)
        .expect("HKDF-Expand 32-byte OKM");
    okm
}

/// X25519 DH then HKDF into an AEAD key for `domain`.
pub(crate) fn aead_key_from_dh(
    our_sk: &X25519SecretKey,
    their_pk: &X25519PublicKey,
    domain: &[u8],
) -> [u8; 32] {
    derive_aead_key(&x25519_shared(our_sk, their_pk), domain)
}

/// Generate a proper X25519 key pair: random scalar + corresponding public point.
pub(crate) fn generate_x25519_keypair() -> X25519KeyPair {
    use x25519_dalek::{PublicKey as X25519Pk, StaticSecret};
    let sk = StaticSecret::from(generate_key_bytes());
    X25519KeyPair {
        private_key: X25519SecretKey(sk.to_bytes()),
        public_key:  X25519PublicKey(*X25519Pk::from(&sk).as_bytes()),
    }
}

/// Generate a proper Ed25519 key pair for long-term identity signing.
pub(crate) fn generate_ed25519_keypair() -> Ed25519KeyPair {
    use ed25519_dalek::SigningKey;
    let seed = generate_key_bytes();
    let signing_key = SigningKey::from_bytes(&seed);
    Ed25519KeyPair {
        private_key: Ed25519SecretKey(seed),
        public_key:  Ed25519PublicKey(*signing_key.verifying_key().as_bytes()),
    }
}

/// Ed25519 sign: returns a 64-byte signature over `message`.
pub(crate) fn ed25519_sign(private_key: &Ed25519SecretKey, message: &[u8]) -> [u8; 64] {
    use ed25519_dalek::{Signer, SigningKey};
    SigningKey::from_bytes(&private_key.0)
        .sign(message)
        .to_bytes()
}

/// Ed25519 verify: returns true if the 64-byte signature is valid over `message`.
pub(crate) fn ed25519_verify(
    public_key: &Ed25519PublicKey,
    message: &[u8],
    signature: &[u8; 64],
) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let Ok(vk) = VerifyingKey::from_bytes(&public_key.0) else {
        return false;
    };
    let sig = Signature::from_bytes(signature);
    vk.verify(message, &sig).is_ok()
}

/// XChaCha20-Poly1305 authenticated encryption. Returns (ciphertext, 24-byte nonce).
///
/// Nonce bytes come from [`fill_random`] (OS CSPRNG via `getrandom`), not an
/// ad-hoc `/dev/urandom` open per call. CSPRNG failure panics: a zero or reused
/// nonce is worse than aborting the encrypt (return-type churn deferred).
pub(crate) fn xchacha20_encrypt(key: &[u8; 32], plaintext: &[u8]) -> (Vec<u8>, [u8; 24]) {
    use chacha20poly1305::{
        XChaCha20Poly1305, XNonce,
        aead::{Aead, KeyInit},
    };
    let mut nonce_bytes = [0u8; 24];
    fill_random(&mut nonce_bytes);
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
/// Body: XChaCha20-Poly1305 encrypted with the session AEAD key
/// (`aead_domain::SESSION` over the connection's X25519 shared secret).
pub(crate) fn build_encrypted_packet(
    op: u8,
    conn: &ActiveConnection,
    plaintext: &[u8],
) -> Vec<u8> {
    let key = aead_key_from_dh(
        &conn.key_pair.private_key,
        &conn.peer_public_key,
        aead_domain::SESSION,
    );
    let (ct, nonce) = xchacha20_encrypt(&key, plaintext);
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
/// Looks up the named active connection and decrypts with the session AEAD key
/// for that connection.
pub(crate) fn decrypt_packet_body(node: &Node, buf: &[u8]) -> Option<Vec<u8>> {
    if buf.len() < ENCRYPTED_BODY_HEADER_LEN {
        return None;
    }
    let conn_id = u16::from_be_bytes([buf[0], buf[1]]);
    let nonce: [u8; 24] = buf[2..ENCRYPTED_BODY_HEADER_LEN].try_into().ok()?;
    let ciphertext = &buf[ENCRYPTED_BODY_HEADER_LEN..];
    let conn = node.owner.active_connections.get(&conn_id)?;
    let key = aead_key_from_dh(
        &conn.key_pair.private_key,
        &conn.peer_public_key,
        aead_domain::SESSION,
    );
    xchacha20_decrypt(&key, &nonce, ciphertext)
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
    fn derive_aead_key_is_deterministic_and_domain_separated() {
        let a = generate_x25519_keypair();
        let b = generate_x25519_keypair();
        let shared = x25519_shared(&a.private_key, &b.public_key);
        let k1 = derive_aead_key(&shared, aead_domain::SESSION);
        let k2 = derive_aead_key(&shared, aead_domain::SESSION);
        assert_eq!(k1, k2);
        // Same IKM, different domains → different keys.
        let k_boot = derive_aead_key(&shared, aead_domain::BOOTSTRAP);
        let k_tun = derive_aead_key(&shared, aead_domain::TUNNEL);
        assert_ne!(k1, k_boot);
        assert_ne!(k1, k_tun);
        assert_ne!(k_boot, k_tun);
        // Raw DH output must not equal any derived key (except by astronomical chance).
        assert_ne!(shared, k1);
        assert_ne!(shared, k_boot);
        assert_ne!(shared, k_tun);
        // Both sides of the DH agree on the derived key.
        let from_b = aead_key_from_dh(&b.private_key, &a.public_key, aead_domain::SESSION);
        assert_eq!(k1, from_b);
    }

    #[test]
    fn key_type_generators_return_distinct_structs() {
        // Compile-time: return types differ. Runtime: non-zero material.
        let e = generate_ed25519_keypair();
        let x = generate_x25519_keypair();
        assert_ne!(e.public_key.0, [0u8; 32]);
        assert_ne!(x.public_key.0, [0u8; 32]);
        // Identity and DH pairs are not interchangeable at the type level —
        // this would not compile: ed25519_sign(&x.private_key, b"x");
        let _ = ed25519_sign(&e.private_key, b"typed");
        let _ = x25519_shared(&x.private_key, &x.public_key);
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
    fn xchacha20_nonces_differ_across_encrypts() {
        let key = generate_key_bytes();
        let (_, n1) = xchacha20_encrypt(&key, b"a");
        let (_, n2) = xchacha20_encrypt(&key, b"a");
        assert_ne!(n1, n2);
        assert_ne!(n1, [0u8; 24]);
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
