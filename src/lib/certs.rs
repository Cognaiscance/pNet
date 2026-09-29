//! User → device → app certificates.
//!
//! The public key is the cryptographic identity. A certificate payload is the
//! alias, the public keys it attests, validity, a version byte, and (for a
//! device or app) the issuer's public key. It does not contain a UUID.
//! UUIDs stay local database keys.
//!
//! The user certificate is self-signed by the user Ed25519 key. That key signs
//! each device certificate (device Ed25519 signing key + X25519 static key).
//! The device signing key signs each app certificate. This fabric's identity
//! algorithm is Ed25519 end to end; an Ed448 user key would be a separate
//! wire break.

use std::time::{SystemTime, UNIX_EPOCH};

use super::crypto::{ed25519_sign, ed25519_verify, generate_ed25519_keypair};
use super::data_models::{
    Application, Device, Ed25519KeyPair, Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature,
    X25519PublicKey,
};

pub const CERT_VERSION: u8 = 1;

const USER_DOMAIN: &[u8] = b"pnet-user-cert-v1";
const DEVICE_DOMAIN: &[u8] = b"pnet-device-cert-v1";
const APP_DOMAIN: &[u8] = b"pnet-app-cert-v1";

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn push_lp(buf: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    let n = b.len().min(255);
    buf.push(n as u8);
    buf.extend_from_slice(&b[..n]);
}

fn user_payload(alias: &str, public_key: &Ed25519PublicKey, issued_at: u64, expires_at: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(USER_DOMAIN);
    buf.push(CERT_VERSION);
    buf.extend_from_slice(&issued_at.to_le_bytes());
    buf.extend_from_slice(&expires_at.to_le_bytes());
    push_lp(&mut buf, alias);
    buf.extend_from_slice(public_key.as_bytes());
    buf
}

fn device_payload(
    alias: &str,
    signing_pk: &Ed25519PublicKey,
    dh_pk: &X25519PublicKey,
    issuer: &Ed25519PublicKey,
    issued_at: u64,
    expires_at: u64,
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(DEVICE_DOMAIN);
    buf.push(CERT_VERSION);
    buf.extend_from_slice(&issued_at.to_le_bytes());
    buf.extend_from_slice(&expires_at.to_le_bytes());
    push_lp(&mut buf, alias);
    buf.extend_from_slice(signing_pk.as_bytes());
    buf.extend_from_slice(dh_pk.as_bytes());
    buf.extend_from_slice(issuer.as_bytes());
    buf
}

fn app_payload(
    alias: &str,
    signing_pk: &Ed25519PublicKey,
    issuer: &Ed25519PublicKey,
    issued_at: u64,
    expires_at: u64,
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(APP_DOMAIN);
    buf.push(CERT_VERSION);
    buf.extend_from_slice(&issued_at.to_le_bytes());
    buf.extend_from_slice(&expires_at.to_le_bytes());
    push_lp(&mut buf, alias);
    buf.extend_from_slice(signing_pk.as_bytes());
    buf.extend_from_slice(issuer.as_bytes());
    buf
}

pub fn sign_user_cert(secret: &Ed25519SecretKey, alias: &str, public_key: &Ed25519PublicKey) -> (Ed25519Signature, u64) {
    let issued_at = now_secs();
    let payload = user_payload(alias, public_key, issued_at, 0);
    (Ed25519Signature(ed25519_sign(secret, &payload)), issued_at)
}

pub fn verify_user_cert(alias: &str, public_key: &Ed25519PublicKey, issued_at: u64, signature: &Ed25519Signature) -> bool {
    if *public_key == Ed25519PublicKey::ZERO || signature.0 == [0u8; 64] {
        return false;
    }
    let payload = user_payload(alias, public_key, issued_at, 0);
    ed25519_verify(public_key, &payload, &signature.0)
}

pub fn sign_device_cert(
    user_secret: &Ed25519SecretKey,
    alias: &str,
    signing_pk: &Ed25519PublicKey,
    dh_pk: &X25519PublicKey,
    issuer: &Ed25519PublicKey,
) -> (Ed25519Signature, u64) {
    let issued_at = now_secs();
    let payload = device_payload(alias, signing_pk, dh_pk, issuer, issued_at, 0);
    (Ed25519Signature(ed25519_sign(user_secret, &payload)), issued_at)
}

pub fn verify_device_cert(
    alias: &str,
    signing_pk: &Ed25519PublicKey,
    dh_pk: &X25519PublicKey,
    issuer: &Ed25519PublicKey,
    issued_at: u64,
    signature: &Ed25519Signature,
) -> bool {
    if *signing_pk == Ed25519PublicKey::ZERO || signature.0 == [0u8; 64] {
        return false;
    }
    let payload = device_payload(alias, signing_pk, dh_pk, issuer, issued_at, 0);
    ed25519_verify(issuer, &payload, &signature.0)
}

pub fn device_on_record_verifies(device: &Device, user_pk: &Ed25519PublicKey) -> bool {
    verify_device_cert(
        &device.cert_alias,
        &device.signing_pk,
        &device.dh_pk,
        user_pk,
        device.cert_issued_at,
        &device.cert_sig,
    )
}

pub fn sign_app_cert(
    device_secret: &Ed25519SecretKey,
    alias: &str,
    app_pk: &Ed25519PublicKey,
    issuer: &Ed25519PublicKey,
) -> (Ed25519Signature, u64) {
    let issued_at = now_secs();
    let payload = app_payload(alias, app_pk, issuer, issued_at, 0);
    (Ed25519Signature(ed25519_sign(device_secret, &payload)), issued_at)
}

pub fn verify_app_cert(
    alias: &str,
    app_pk: &Ed25519PublicKey,
    issuer: &Ed25519PublicKey,
    issued_at: u64,
    signature: &Ed25519Signature,
) -> bool {
    if *app_pk == Ed25519PublicKey::ZERO || signature.0 == [0u8; 64] {
        return false;
    }
    let payload = app_payload(alias, app_pk, issuer, issued_at, 0);
    ed25519_verify(issuer, &payload, &signature.0)
}

pub fn app_on_record_verifies(app: &Application, device_pk: &Ed25519PublicKey) -> bool {
    verify_app_cert(
        &app.cert_alias,
        &app.identity.public_key,
        device_pk,
        app.cert_issued_at,
        &app.cert_sig,
    )
}

/// Attach a freshly signed device certificate. The device's display alias is
/// copied into `cert_alias` so a later rename does not invalidate the signature.
pub fn issue_device_cert(
    device: &mut Device,
    user_secret: &Ed25519SecretKey,
    user_pk: &Ed25519PublicKey,
    signing: &Ed25519KeyPair,
    dh_pk: &X25519PublicKey,
) {
    let (sig, issued_at) = sign_device_cert(
        user_secret,
        &device.alias,
        &signing.public_key,
        dh_pk,
        user_pk,
    );
    device.signing_pk = signing.public_key;
    device.dh_pk = *dh_pk;
    device.cert_sig = sig;
    device.cert_issued_at = issued_at;
    device.cert_alias = device.alias.clone();
}

/// Mint an app identity if the app does not have one yet, then sign it with
/// the local device key. No-op when the device has no signing key.
pub fn issue_app_cert(app: &mut Application, device_secret: &Ed25519SecretKey, device_pk: &Ed25519PublicKey) {
    if *device_secret == Ed25519SecretKey::ZERO || *device_pk == Ed25519PublicKey::ZERO {
        return;
    }
    if app.identity.public_key == Ed25519PublicKey::ZERO {
        app.identity = generate_ed25519_keypair();
    }
    let (sig, issued_at) = sign_app_cert(
        device_secret,
        &app.alias,
        &app.identity.public_key,
        device_pk,
    );
    app.cert_sig = sig;
    app.cert_issued_at = issued_at;
    app.cert_alias = app.alias.clone();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_x25519_keypair;

    #[test]
    fn user_signs_device_which_signs_app() {
        let user = generate_ed25519_keypair();
        let (user_sig, user_issued) = sign_user_cert(&user.private_key, "alice", &user.public_key);
        assert!(verify_user_cert("alice", &user.public_key, user_issued, &user_sig));

        let device_key = generate_ed25519_keypair();
        let dh = generate_x25519_keypair();
        let mut device = Device {
            alias: "phone".into(),
            uuid: [1u8; 16],
            grade: crate::data_models::DeviceGrade::DG,
            sg_rank: None,
            hosts: Vec::new(),
            applications: Vec::new(),
            signing_pk: Ed25519PublicKey::ZERO,
            dh_pk: X25519PublicKey::ZERO,
            cert_sig: Ed25519Signature::ZERO,
            cert_issued_at: 0,
            cert_alias: String::new(),
        };
        issue_device_cert(&mut device, &user.private_key, &user.public_key, &device_key, &dh.public_key);
        assert!(device_on_record_verifies(&device, &user.public_key));
        device.cert_alias = "other".into();
        assert!(!device_on_record_verifies(&device, &user.public_key));
        device.cert_alias = "phone".into();

        let mut app = Application {
            id: [2u8; 16],
            alias: "chat".into(),
            protocol: "text".into(),
            host: "127.0.0.1:9".parse().unwrap(),
            user_approved: true,
            token: [0u8; 16],
            identity: Ed25519KeyPair::ZERO,
            cert_sig: Ed25519Signature::ZERO,
            cert_issued_at: 0,
            cert_alias: String::new(),
        };
        issue_app_cert(&mut app, &device_key.private_key, &device_key.public_key);
        assert!(app_on_record_verifies(&app, &device.signing_pk));
        assert!(!app_on_record_verifies(&app, &user.public_key));
    }
}
