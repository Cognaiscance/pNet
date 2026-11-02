//! First-run user setup and the device-certificate upgrade path.
//!
//! These run from `main` on both builds. The owner portal stays in `admin_ui`,
//! which the device build does not compile.

use super::super::action_queue::WorkerContext;
use super::super::crypto::{generate_ed25519_keypair, generate_x25519_keypair};
use super::super::data_models::{DeviceGrade, Ed25519SecretKey};
use super::{parse_pnet_hosts, request_change, Change};

/// Extract a URL-encoded form field value from a POST body (e.g. `id=5`).
pub(crate) fn form_field<'a>(body: &'a [u8], field: &str) -> Option<&'a str> {
    let s = std::str::from_utf8(body).ok()?;
    let prefix = format!("{field}=");
    for part in s.split('&') {
        if let Some(val) = part.strip_prefix(prefix.as_str()) {
            return Some(val);
        }
    }
    None
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Decode a percent-encoded URL form value (`hello+world` becomes `hello world`).
pub(crate) fn url_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => {
                out.push(' ');
                i += 1;
            }
            b'%' if i + 2 < b.len() => match (hex_nibble(b[i + 1]), hex_nibble(b[i + 2])) {
                (Some(hi), Some(lo)) => {
                    out.push(char::from(hi << 4 | lo));
                    i += 3;
                }
                _ => {
                    out.push('%');
                    i += 1;
                }
            },
            c => {
                out.push(char::from(c));
                i += 1;
            }
        }
    }
    out
}

/// Typed entry point for first-run new-user setup. Used by the HTTP form
/// handler and `main`'s env-driven startup path.
pub fn apply_new_user_setup(
    alias: &str,
    device_alias: &str,
    grade: DeviceGrade,
    sg_rank: Option<u32>,
    ctx: &WorkerContext,
) -> Option<&'static str> {
    if alias.is_empty() || device_alias.is_empty() {
        return Some("fields");
    }
    if !super::super::keystore::is_installed() {
        return Some("passphrase");
    }

    let key_pair = generate_ed25519_keypair();
    let (user_sig, user_issued) = super::super::certs::sign_user_cert(
        &key_pair.private_key,
        alias,
        &key_pair.public_key,
    );
    let device_signing = generate_ed25519_keypair();
    let device_dh = generate_x25519_keypair();

    {
        let mut node = ctx.node.write().unwrap();
        node.owner.user.alias = alias.to_string();
        node.owner.key_pair = key_pair.clone();
        node.owner.user_cert_sig = user_sig;
        node.owner.user_cert_issued_at = user_issued;
        node.device_signing = device_signing.clone();
        node.device_dh = device_dh.clone();

        let device_uuid = node.device_uuid;
        if let Some(dev) = node.owner.user.devices.iter_mut().find(|d| d.uuid == device_uuid) {
            dev.alias = device_alias.to_string();
            dev.grade = grade;
            dev.sg_rank = sg_rank;
            if matches!(dev.grade, DeviceGrade::SG) {
                let hosts = parse_pnet_hosts();
                if !hosts.is_empty() {
                    dev.hosts = hosts;
                }
            }
            super::super::certs::issue_device_cert(
                dev,
                &key_pair.private_key,
                &key_pair.public_key,
                &device_signing,
                &device_dh.public_key,
            );
        }
    }
    ctx.save_node();
    None
}

/// A node upgraded from the shared-user-key build still has the user seed and
/// no device certificate. Mint the local device key, sign it, and publish the
/// certificate when this process holds the user private key.
pub fn ensure_local_device_cert(ctx: &WorkerContext) {
    let change = {
        let mut node = ctx.node.write().unwrap();
        if !node.is_initialized() || node.owner.key_pair.private_key == Ed25519SecretKey::ZERO {
            return;
        }
        let user_pk = node.owner.key_pair.public_key;
        let user_sk = node.owner.key_pair.private_key;
        let device_uuid = node.device_uuid;
        let already = node
            .owner
            .user
            .devices
            .iter()
            .find(|d| d.uuid == device_uuid)
            .is_some_and(|d| super::super::certs::device_on_record_verifies(d, &user_pk));
        if already {
            return;
        }
        if node.device_signing.private_key == Ed25519SecretKey::ZERO {
            node.device_signing = generate_ed25519_keypair();
            node.device_dh = generate_x25519_keypair();
        }
        let signing = node.device_signing.clone();
        let dh_pk = node.device_dh.public_key;
        let Some(dev) = node.owner.user.devices.iter_mut().find(|d| d.uuid == device_uuid) else {
            return;
        };
        super::super::certs::issue_device_cert(dev, &user_sk, &user_pk, &signing, &dh_pk);
        Change::AddDevice {
            uuid: dev.uuid,
            alias: dev.alias.clone(),
            grade: dev.grade,
            sg_rank: dev.sg_rank,
            hosts: dev.hosts.clone(),
            signing_pk: dev.signing_pk,
            dh_pk: dev.dh_pk,
            cert_sig: dev.cert_sig,
            cert_issued_at: dev.cert_issued_at,
            cert_alias: dev.cert_alias.clone(),
        }
    };
    ctx.save_node();
    if let Err(e) = request_change(change, ctx) {
        eprintln!(
            "[ensure_local_device_cert] device certificate is local but was not published: {e:?}"
        );
    }
}
