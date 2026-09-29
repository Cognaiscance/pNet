//! Passphrase-sealed secrets at rest.
//!
//! One module owns key encryption. Callers persist the envelope this module
//! returns and never write a raw long-term private key.
//!
//! Envelope version 1:
//! ```text
//! [version:u8=1][salt:16][m_kib:u32 le][t_cost:u32 le][p_cost:u32 le]
//! [nonce:24][XChaCha20-Poly1305 ciphertext]
//! ```
//! The wrapping key is Argon2id over the passphrase and salt. Parameters live
//! in the envelope so a later migration can re-wrap without a flag day.
//! Argon2id runs once per process; later seals reuse the derived key.

use std::sync::Mutex;

use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;

use super::crypto::{xchacha20_decrypt, xchacha20_encrypt};
use super::data_models::{
    fill_random, Ed25519KeyPair, Ed25519PublicKey, Ed25519SecretKey, Node, X25519KeyPair,
    X25519PublicKey, X25519SecretKey,
};

const VERSION: u8 = 1;
const SALT_LEN: usize = 16;

/// Minimum length for `PNET_KEY_PASSPHRASE` and the setup form field.
pub const MIN_PASSPHRASE_LEN: usize = 8;

/// Interactive parameters for a real node (libsodium-style memory hardness).
const PROD_M_KIB: u32 = 65_536;
const PROD_T: u32 = 3;
const PROD_P: u32 = 1;

/// Tests derive once per process. The envelope still records these parameters.
const TEST_M_KIB: u32 = 8_192;
const TEST_T: u32 = 2;
const TEST_P: u32 = 1;

struct Cache {
    passphrase: String,
    salt: [u8; SALT_LEN],
    key: [u8; 32],
    m_kib: u32,
    t_cost: u32,
    p_cost: u32,
}

static CACHE: Mutex<Option<Cache>> = Mutex::new(None);

fn kdf_params() -> (u32, u32, u32) {
    if cfg!(test) {
        (TEST_M_KIB, TEST_T, TEST_P)
    } else {
        (PROD_M_KIB, PROD_T, PROD_P)
    }
}

/// Remember the passphrase for this process. Replaces any previous one.
pub fn install_passphrase(passphrase: &str) {
    let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    *guard = Some(Cache {
        passphrase: passphrase.to_string(),
        salt: [0u8; SALT_LEN],
        key: [0u8; 32],
        m_kib: 0,
        t_cost: 0,
        p_cost: 0,
    });
}

pub fn is_installed() -> bool {
    CACHE.lock().unwrap_or_else(|e| e.into_inner()).is_some()
}

fn derive(passphrase: &str, salt: &[u8], m_kib: u32, t_cost: u32, p_cost: u32) -> Result<[u8; 32], String> {
    let params = Params::new(m_kib, t_cost, p_cost, Some(32))
        .map_err(|e| format!("argon2 params: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .map_err(|e| format!("argon2: {e}"))?;
    Ok(out)
}

fn wrapping_key(salt: &[u8; SALT_LEN], m_kib: u32, t_cost: u32, p_cost: u32) -> Result<[u8; 32], String> {
    let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let cache = guard.as_mut().ok_or("key passphrase is not set")?;
    if cache.m_kib == m_kib
        && cache.t_cost == t_cost
        && cache.p_cost == p_cost
        && cache.salt == *salt
        && cache.key != [0u8; 32]
    {
        return Ok(cache.key);
    }
    let key = derive(&cache.passphrase, salt, m_kib, t_cost, p_cost)?;
    cache.salt = *salt;
    cache.key = key;
    cache.m_kib = m_kib;
    cache.t_cost = t_cost;
    cache.p_cost = p_cost;
    Ok(key)
}

fn seal_raw(
    key: &[u8; 32],
    salt: &[u8; SALT_LEN],
    m_kib: u32,
    t_cost: u32,
    p_cost: u32,
    plaintext: &[u8],
) -> String {
    let (ciphertext, nonce) = xchacha20_encrypt(key, plaintext);
    let mut raw = Vec::with_capacity(1 + SALT_LEN + 12 + 24 + ciphertext.len());
    raw.push(VERSION);
    raw.extend_from_slice(salt);
    raw.extend_from_slice(&m_kib.to_le_bytes());
    raw.extend_from_slice(&t_cost.to_le_bytes());
    raw.extend_from_slice(&p_cost.to_le_bytes());
    raw.extend_from_slice(&nonce);
    raw.extend_from_slice(&ciphertext);
    base64::engine::general_purpose::STANDARD.encode(raw)
}

/// Seal `plaintext`. Fails if no passphrase has been installed.
pub fn seal(plaintext: &[u8]) -> Result<String, String> {
    let (m_kib, t_cost, p_cost) = kdf_params();
    let mut salt = [0u8; SALT_LEN];
    // Reuse the cached salt when this process already derived a key, so a
    // save does not run Argon2id again.
    let reuse_salt = {
        let guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
        guard.as_ref().and_then(|c| {
            if c.m_kib == m_kib && c.t_cost == t_cost && c.p_cost == p_cost && c.key != [0u8; 32] {
                Some(c.salt)
            } else {
                None
            }
        })
    };
    if let Some(existing) = reuse_salt {
        salt = existing;
    } else {
        fill_random(&mut salt);
    }
    let key = wrapping_key(&salt, m_kib, t_cost, p_cost)?;
    Ok(seal_raw(&key, &salt, m_kib, t_cost, p_cost, plaintext))
}

/// Seal with an explicit passphrase and do not touch the process cache.
/// Tests use this so a negative case cannot race other tests.
#[cfg(test)]
fn seal_with(passphrase: &str, plaintext: &[u8]) -> Result<String, String> {
    let (m_kib, t_cost, p_cost) = kdf_params();
    let mut salt = [0u8; SALT_LEN];
    fill_random(&mut salt);
    let key = derive(passphrase, &salt, m_kib, t_cost, p_cost)?;
    Ok(seal_raw(&key, &salt, m_kib, t_cost, p_cost, plaintext))
}

/// Open with an explicit passphrase and do not touch the process cache.
#[cfg(test)]
fn open_with(passphrase: &str, envelope: &str) -> Option<Vec<u8>> {
    let raw = base64::engine::general_purpose::STANDARD.decode(envelope.trim()).ok()?;
    if raw.len() < 1 + SALT_LEN + 12 + 24 + 16 || raw[0] != VERSION {
        return None;
    }
    let salt: [u8; SALT_LEN] = raw[1..1 + SALT_LEN].try_into().ok()?;
    let m_kib = u32::from_le_bytes(raw[17..21].try_into().ok()?);
    let t_cost = u32::from_le_bytes(raw[21..25].try_into().ok()?);
    let p_cost = u32::from_le_bytes(raw[25..29].try_into().ok()?);
    let nonce: [u8; 24] = raw[29..53].try_into().ok()?;
    let key = derive(passphrase, &salt, m_kib, t_cost, p_cost).ok()?;
    xchacha20_decrypt(&key, &nonce, &raw[53..])
}

/// Open an envelope produced by [`seal`]. `None` on malformed input or a bad passphrase.
pub fn open(envelope: &str) -> Option<Vec<u8>> {
    let raw = base64::engine::general_purpose::STANDARD.decode(envelope.trim()).ok()?;
    if raw.len() < 1 + SALT_LEN + 12 + 24 + 16 || raw[0] != VERSION {
        return None;
    }
    let salt: [u8; SALT_LEN] = raw[1..1 + SALT_LEN].try_into().ok()?;
    let m_kib = u32::from_le_bytes(raw[17..21].try_into().ok()?);
    let t_cost = u32::from_le_bytes(raw[21..25].try_into().ok()?);
    let p_cost = u32::from_le_bytes(raw[25..29].try_into().ok()?);
    let nonce: [u8; 24] = raw[29..53].try_into().ok()?;
    let key = wrapping_key(&salt, m_kib, t_cost, p_cost).ok()?;
    xchacha20_decrypt(&key, &nonce, &raw[53..])
}

/// Write the local device secret bundle into `device_secrets_sealed`.
///
/// The user key and any app identity keys seal themselves when the node is
/// serialized. This covers the device signing seed and static X25519 secret,
/// which are not part of that path.
pub fn refresh_device_secrets(node: &mut Node) {
    if node.device_signing.private_key == Ed25519SecretKey::ZERO {
        return;
    }
    let mut plain = Vec::with_capacity(96);
    plain.extend_from_slice(node.device_signing.private_key.as_bytes());
    plain.extend_from_slice(node.device_signing.public_key.as_bytes());
    plain.extend_from_slice(node.device_dh.private_key.as_bytes());
    plain.extend_from_slice(node.device_dh.public_key.as_bytes());
    match seal(&plain) {
        Ok(env) => node.device_secrets_sealed = env,
        Err(e) => eprintln!("[keystore] refusing to persist device secrets: {e}"),
    }
}

/// Open sealed secrets into memory after a load.
///
/// A legacy `node.toml` that still carries a plaintext user seed is left in
/// place so the next save can wrap it. A sealed blob that fails to open
/// leaves the in-memory seed zero and logs the failure.
pub fn restore_secrets(node: &mut Node) {
    if !node.owner.key_pair.private_key_sealed.is_empty() {
        match open(&node.owner.key_pair.private_key_sealed) {
            Some(bytes) if bytes.len() == 32 => {
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&bytes);
                node.owner.key_pair.private_key = Ed25519SecretKey(seed);
            }
            Some(_) => eprintln!("[keystore] user key envelope has an unexpected length"),
            None => {
                eprintln!("[keystore] could not open the user private key (passphrase?)");
                if node.owner.key_pair.private_key != Ed25519SecretKey::ZERO {
                    eprintln!("[keystore] keeping legacy plaintext user seed until the next save");
                }
            }
        }
    }
    restore_app_keys(node);
    if node.device_secrets_sealed.is_empty() {
        return;
    }
    match open(&node.device_secrets_sealed) {
        Some(bytes) if bytes.len() == 128 => {
            let mut signing_sk = [0u8; 32];
            let mut signing_pk = [0u8; 32];
            let mut dh_sk = [0u8; 32];
            let mut dh_pk = [0u8; 32];
            signing_sk.copy_from_slice(&bytes[0..32]);
            signing_pk.copy_from_slice(&bytes[32..64]);
            dh_sk.copy_from_slice(&bytes[64..96]);
            dh_pk.copy_from_slice(&bytes[96..128]);
            node.device_signing = Ed25519KeyPair {
                public_key: Ed25519PublicKey(signing_pk),
                private_key: Ed25519SecretKey(signing_sk),
                private_key_sealed: String::new(),
            };
            node.device_dh = X25519KeyPair {
                public_key: X25519PublicKey(dh_pk),
                private_key: X25519SecretKey(dh_sk),
            };
        }
        Some(_) => eprintln!("[keystore] device secret envelope has an unexpected length"),
        None => eprintln!("[keystore] could not open device secrets (passphrase?)"),
    }
}

fn restore_app_keys(node: &mut Node) {
    for dev in &mut node.owner.user.devices {
        for app in &mut dev.applications {
            open_identity(&mut app.identity);
        }
    }
}

fn open_identity(kp: &mut Ed25519KeyPair) {
    if kp.private_key_sealed.is_empty() {
        return;
    }
    match open(&kp.private_key_sealed) {
        Some(bytes) if bytes.len() == 32 => {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes);
            kp.private_key = Ed25519SecretKey(seed);
        }
        Some(_) => eprintln!("[keystore] app key envelope has an unexpected length"),
        None => eprintln!("[keystore] could not open an app identity key (passphrase?)"),
    }
}

/// Read a passphrase from the controlling terminal with echo disabled.
/// Returns `None` when no terminal is available.
pub fn prompt_tty() -> Option<String> {
    use std::io::{BufRead, BufReader, Write};
    let mut tty_in = std::fs::File::open("/dev/tty").ok()?;
    let mut tty_out = std::fs::OpenOptions::new().write(true).open("/dev/tty").ok()?;
    let _ = write!(
        tty_out,
        "pNet key passphrase (seals the user and device private keys): "
    );
    let _ = tty_out.flush();
    let echo = disable_echo(&tty_in);
    let mut reader = BufReader::new(&mut tty_in);
    let mut line = String::new();
    let ok = reader.read_line(&mut line).is_ok();
    if let Some(echo) = echo {
        let _ = restore_echo(&tty_in, echo);
    }
    let _ = writeln!(tty_out);
    if !ok {
        return None;
    }
    let line = line.trim_end_matches(['\n', '\r']).to_string();
    if line.is_empty() { None } else { Some(line) }
}

#[cfg(unix)]
fn disable_echo(tty: &std::fs::File) -> Option<Termios> {
    let fd = std::os::unix::io::AsRawFd::as_raw_fd(tty);
    let mut term = unsafe { std::mem::zeroed::<Termios>() };
    if unsafe { tcgetattr(fd, &mut term) } != 0 {
        return None;
    }
    let saved = term;
    term.c_lflag &= !ECHO;
    if unsafe { tcsetattr(fd, &term) } != 0 {
        return None;
    }
    Some(saved)
}

#[cfg(unix)]
fn restore_echo(tty: &std::fs::File, term: Termios) -> bool {
    let fd = std::os::unix::io::AsRawFd::as_raw_fd(tty);
    let rc = unsafe { tcsetattr(fd, &term) };
    rc == 0
}

#[cfg(not(unix))]
fn disable_echo(_tty: &std::fs::File) -> Option<()> { None }
#[cfg(not(unix))]
fn restore_echo(_tty: &std::fs::File, _term: ()) -> bool { true }

/// Linux `struct termios`. Layout matches glibc on the platforms pNet runs.
#[cfg(unix)]
#[repr(C)]
#[derive(Clone, Copy)]
struct Termios {
    c_iflag: u32,
    c_oflag: u32,
    c_cflag: u32,
    c_lflag: u32,
    c_line: u8,
    c_cc: [u8; 32],
    c_ispeed: u32,
    c_ospeed: u32,
}

#[cfg(unix)]
const ECHO: u32 = 0o0000010;
#[cfg(unix)]
const TCGETS: u64 = 0x5401;
#[cfg(unix)]
const TCSETS: u64 = 0x5402;

#[cfg(unix)]
unsafe fn tcgetattr(fd: i32, term: *mut Termios) -> i32 {
    unsafe { ioctl(fd, TCGETS, term) }
}
#[cfg(unix)]
unsafe fn tcsetattr(fd: i32, term: *const Termios) -> i32 {
    unsafe { ioctl(fd, TCSETS, term) }
}

#[cfg(unix)]
unsafe extern "C" {
    fn ioctl(fd: i32, req: u64, ...) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip_hides_plaintext() {
        install_passphrase("test-passphrase");
        let secret = b"0123456789abcdef0123456789abcdef";
        let env = seal(secret).expect("seal");
        assert!(!env.contains("0123456789abcdef"), "envelope must not carry the plaintext");
        let opened = open(&env).expect("open");
        assert_eq!(opened, secret);
    }

    #[test]
    fn wrong_passphrase_does_not_open() {
        let secret = b"0123456789abcdef0123456789abcdef";
        let env = seal_with("one", secret).unwrap();
        assert!(open_with("two", &env).is_none());
        assert_eq!(open_with("one", &env).as_deref(), Some(secret.as_slice()));
    }
}
