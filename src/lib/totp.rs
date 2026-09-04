//! RFC 6238 TOTP (HMAC-SHA1, 30s, 6 digits) for owner-portal 2FA.
//!
//! Node-local only: the secret lives in `node.toml` beside the admin password
//! hash and is never synced. Compatible with Google Authenticator, Aegis,
//! 1Password, and other `otpauth://totp` apps.

use hmac::{Hmac, Mac};
use sha1::Sha1;

use super::data_models::fill_random;

type HmacSha1 = Hmac<Sha1>;

/// TOTP shared-secret length (160-bit, RFC 4226 / RFC 6238 default).
pub const SECRET_LEN: usize = 20;
pub const PERIOD_SECS: u64 = 30;
pub const DIGITS: u32 = 6;
/// Accept previous, current, and next time step (clock skew).
pub const SKEW_STEPS: i64 = 1;
pub const RECOVERY_CODE_COUNT: usize = 8;

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Generate a fresh 20-byte TOTP secret.
pub fn generate_secret() -> [u8; SECRET_LEN] {
    let mut s = [0u8; SECRET_LEN];
    fill_random(&mut s);
    s
}

/// RFC 4648 base32, no padding (otpauth convention).
pub fn encode_base32(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let mut out = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut acc: u64 = 0;
    let mut bits: u32 = 0;
    for &b in bytes {
        acc = (acc << 8) | u64::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((acc >> bits) & 0x1f) as usize;
            out.push(B32[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((acc << (5 - bits)) & 0x1f) as usize;
        out.push(B32[idx] as char);
    }
    out
}

/// Decode unpadded or padded RFC 4648 base32 (ignores whitespace and case).
pub fn decode_base32(s: &str) -> Option<Vec<u8>> {
    let mut acc: u64 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();
    for c in s.chars() {
        if c.is_ascii_whitespace() || c == '=' {
            continue;
        }
        let u = c.to_ascii_uppercase() as u8;
        let val = match u {
            b'A'..=b'Z' => u - b'A',
            b'2'..=b'7' => 26 + (u - b'2'),
            _ => return None,
        };
        acc = (acc << 5) | u64::from(val);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

fn hotp(secret: &[u8], counter: u64) -> u32 {
    let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC-SHA1 accepts any key length");
    mac.update(&counter.to_be_bytes());
    let result = mac.finalize().into_bytes();
    let offset = (result[19] & 0x0f) as usize;
    let bin = u32::from_be_bytes([
        result[offset],
        result[offset + 1],
        result[offset + 2],
        result[offset + 3],
    ]) & 0x7fff_ffff;
    let modulo = 10u32.pow(DIGITS);
    bin % modulo
}

/// 6-digit TOTP for `unix_secs` (no skew).
pub fn totp_at(secret: &[u8], unix_secs: u64) -> u32 {
    hotp(secret, unix_secs / PERIOD_SECS)
}

pub fn totp_code_string(secret: &[u8], unix_secs: u64) -> String {
    format!("{:06}", totp_at(secret, unix_secs))
}

/// Strip spaces/dashes; require exactly 6 digits.
pub fn parse_totp_code(raw: &str) -> Option<u32> {
    let digits: String = raw.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() != DIGITS as usize {
        return None;
    }
    digits.parse().ok()
}

/// Verify `code` against `secret` at `unix_secs` with ±1 step skew.
///
/// Returns the matching time-step so the caller can reject replays
/// (`last_step` equal to the matched step is rejected).
pub fn verify_totp(
    secret: &[u8],
    code: &str,
    unix_secs: u64,
    last_step: Option<u64>,
) -> Option<u64> {
    let Some(got) = parse_totp_code(code) else {
        return None;
    };
    let now_step = unix_secs / PERIOD_SECS;
    for delta in -SKEW_STEPS..=SKEW_STEPS {
        let step = now_step as i64 + delta;
        if step < 0 {
            continue;
        }
        let step = step as u64;
        if last_step == Some(step) {
            continue;
        }
        if hotp(secret, step) == got {
            return Some(step);
        }
    }
    None
}

/// `otpauth://` URI for authenticator apps. Account is URL-encoded.
pub fn otpauth_url(account: &str, secret_b32: &str) -> String {
    let label = url_encode_component(&format!("pNet:{account}"));
    format!(
        "otpauth://totp/{label}?secret={secret_b32}&issuer=pNet&period={PERIOD_SECS}&digits={DIGITS}&algorithm=SHA1"
    )
}

fn url_encode_component(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            b' ' => out.push_str("%20"),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Eight high-entropy recovery codes (`xxxxxxxx-xxxxxxxx` hex).
pub fn generate_recovery_codes() -> Vec<String> {
    (0..RECOVERY_CODE_COUNT)
        .map(|_| {
            let mut b = [0u8; 8];
            fill_random(&mut b);
            format!(
                "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}",
                b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]
            )
        })
        .collect()
}

/// Normalize a recovery code for compare (strip spaces, lower-case).
pub fn normalize_recovery_code(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_ascii_hexdigit())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4226 Appendix D — secret "12345678901234567890"
    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn hotp_rfc4226_vectors() {
        assert_eq!(hotp(RFC_SECRET, 0), 755224);
        assert_eq!(hotp(RFC_SECRET, 1), 287082);
        assert_eq!(hotp(RFC_SECRET, 2), 359152);
    }

    #[test]
    fn totp_at_uses_30s_steps() {
        // step 1 → HOTP(1)
        assert_eq!(totp_at(RFC_SECRET, 30), 287082);
        assert_eq!(totp_code_string(RFC_SECRET, 30), "287082");
    }

    #[test]
    fn verify_accepts_skew_and_rejects_replay() {
        let t = 30u64;
        let code = totp_code_string(RFC_SECRET, t);
        let step = verify_totp(RFC_SECRET, &code, t, None).expect("current step");
        assert_eq!(step, 1);
        assert!(verify_totp(RFC_SECRET, &code, t, Some(step)).is_none());
        // previous window
        let prev = totp_code_string(RFC_SECRET, 0);
        assert!(verify_totp(RFC_SECRET, &prev, t, None).is_some());
        assert!(verify_totp(RFC_SECRET, "000000", t, None).is_none());
        assert!(verify_totp(RFC_SECRET, "abc", t, None).is_none());
    }

    #[test]
    fn base32_roundtrip_unpadded() {
        let secret = b"12345678901234567890";
        let enc = encode_base32(secret);
        assert_eq!(enc, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        let dec = decode_base32(&enc).unwrap();
        assert_eq!(dec, secret);
        assert_eq!(decode_base32("gez dgnbvgy3tqojqgez dgnbvgy3tqojq").unwrap(), secret);
    }

    #[test]
    fn otpauth_url_contains_secret_and_issuer() {
        let url = otpauth_url("Alice", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assert!(url.starts_with("otpauth://totp/pNet%3AAlice?"));
        assert!(url.contains("secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"));
        assert!(url.contains("issuer=pNet"));
        assert!(url.contains("algorithm=SHA1"));
    }

    #[test]
    fn recovery_codes_are_unique_and_normalizable() {
        let codes = generate_recovery_codes();
        assert_eq!(codes.len(), RECOVERY_CODE_COUNT);
        let mut set = std::collections::HashSet::new();
        for c in &codes {
            assert!(c.contains('-'));
            assert_eq!(normalize_recovery_code(c).len(), 16);
            assert!(set.insert(c.clone()));
        }
        assert_eq!(
            normalize_recovery_code("ABCD-EF01 "),
            normalize_recovery_code("abcd-ef01")
        );
    }
}
