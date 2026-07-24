//! Wire-format fuzz entry points (§8.2).
//!
//! These functions must never panic on any input. They are the contract for
//! the mutational harness (`pnet_fuzz_wire`) and short CI stress tests.
//!
//! Targets (checklist: bootstrap / directory / change payloads):
//! - bootstrap user blob (`serialize_bootstrap_payload`)
//! - public directory snapshot + contact-directory slices
//! - write-log `Change` payloads
//! - contact-card exchange payload

use crate::handlers::{
    bootstrap_payload_well_formed, change_payload_well_formed, contact_data_well_formed,
    contact_payload_well_formed, public_state_well_formed, serialize_bootstrap_payload,
    serialize_change, serialize_contact_data, serialize_contact_payload, serialize_public_state,
    Change, ContactDeviceCard,
};
use crate::data_models::{
    Device, DeviceGrade, Ed25519KeyPair, Ed25519PublicKey, Ed25519SecretKey, Node, User,
};

/// Which pure parser to exercise for one input buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FuzzTarget {
    BootstrapPayload,
    PublicState,
    ContactData,
    ContactPayload,
    ChangePayload,
}

impl FuzzTarget {
    pub const ALL: [FuzzTarget; 5] = [
        FuzzTarget::BootstrapPayload,
        FuzzTarget::PublicState,
        FuzzTarget::ContactData,
        FuzzTarget::ContactPayload,
        FuzzTarget::ChangePayload,
    ];

    pub fn name(self) -> &'static str {
        match self {
            FuzzTarget::BootstrapPayload => "bootstrap_payload",
            FuzzTarget::PublicState => "public_state",
            FuzzTarget::ContactData => "contact_data",
            FuzzTarget::ContactPayload => "contact_payload",
            FuzzTarget::ChangePayload => "change_payload",
        }
    }
}

/// Parse `data` with the selected codec. Returns whether the blob was well-formed.
/// **Must not panic** for any `data`.
pub fn fuzz_parse(target: FuzzTarget, data: &[u8]) -> bool {
    match target {
        FuzzTarget::BootstrapPayload => bootstrap_payload_well_formed(data),
        FuzzTarget::PublicState => public_state_well_formed(data),
        FuzzTarget::ContactData => contact_data_well_formed(data),
        FuzzTarget::ContactPayload => contact_payload_well_formed(data),
        FuzzTarget::ChangePayload => change_payload_well_formed(data),
    }
}

/// Run every codec against `data` (useful for single-file AFL-style inputs).
pub fn fuzz_all_parsers(data: &[u8]) {
    for t in FuzzTarget::ALL {
        let _ = fuzz_parse(t, data);
    }
}

// ── Seed corpus (valid encodings) ─────────────────────────────────────────────

fn fixed_ed25519() -> Ed25519KeyPair {
    // Deterministic seed → fixed public key (ed25519_dalek).
    use ed25519_dalek::SigningKey;
    let seed = [0x42u8; 32];
    let sk = SigningKey::from_bytes(&seed);
    Ed25519KeyPair {
        private_key: Ed25519SecretKey(seed),
        public_key: Ed25519PublicKey(*sk.verifying_key().as_bytes()),
    }
}

fn seed_node() -> Node {
    let mut n = Node::new();
    n.owner.user.alias = "fuzz-owner".into();
    n.owner.user.uuid = [0x11; 16];
    n.device_uuid = [0x22; 16];
    n.owner.key_pair = fixed_ed25519();
    n.owner.user.devices = vec![Device {
        alias: "dev".into(),
        uuid: [0x22; 16],
        grade: DeviceGrade::SG,
        sg_rank: Some(1),
        hosts: vec!["127.0.0.1:7777".into()],
        applications: Vec::new(),
    }];
    n.owner.contact_users = vec![crate::data_models::Contact {
        public_key: fixed_ed25519().public_key,
        user: User {
            alias: "peer".into(),
            uuid: [0x33; 16],
            devices: vec![Device {
                alias: "peer-dev".into(),
                uuid: [0x44; 16],
                grade: DeviceGrade::DG,
                sg_rank: None,
                hosts: vec!["10.0.0.2:7777".into()],
                applications: Vec::new(),
            }],
        },
        last_seen_public_version: Default::default(),
    }];
    n
}

/// Small valid seeds used as mutation bases (and as regression corpus).
pub fn seed_corpus(target: FuzzTarget) -> Vec<Vec<u8>> {
    let node = seed_node();
    match target {
        FuzzTarget::BootstrapPayload => vec![
            serialize_bootstrap_payload(&node),
            // empty-ish: no devices/contacts
            {
                let mut n = Node::new();
                n.owner.user.alias = "x".into();
                n.owner.user.uuid = [0; 16];
                n.owner.key_pair = fixed_ed25519();
                n.owner.user.devices.clear();
                serialize_bootstrap_payload(&n)
            },
        ],
        FuzzTarget::PublicState => vec![serialize_public_state(&node)],
        FuzzTarget::ContactData => vec![serialize_contact_data(&node)],
        FuzzTarget::ContactPayload => vec![serialize_contact_payload(&node)],
        FuzzTarget::ChangePayload => vec![
            serialize_change(&Change::AddApplication {
                device_uuid: [0x22; 16],
                app_id: [0xAB; 16],
                app_alias: "chat".into(),
            }),
            serialize_change(&Change::RemoveApplication {
                device_uuid: [0x22; 16],
                app_id: [0xAB; 16],
            }),
            serialize_change(&Change::AddDevice {
                uuid: [0x55; 16],
                alias: "new".into(),
                grade: DeviceGrade::DG,
                sg_rank: None,
                hosts: vec!["h:1".into()],
            }),
            serialize_change(&Change::UpdateApplicationAlias {
                device_uuid: [0x22; 16],
                app_id: [0xAB; 16],
                new_alias: "renamed".into(),
            }),
            serialize_change(&Change::UpsertContact {
                uuid: [0x33; 16],
                alias: "peer".into(),
                public_key: fixed_ed25519().public_key,
                devices: vec![ContactDeviceCard {
                    uuid: [0x44; 16],
                    alias: "peer-dev".into(),
                    grade: DeviceGrade::DG,
                    sg_rank: None,
                    hosts: vec![],
                    apps: vec![([0x01; 16], "a".into())],
                }],
            }),
            serialize_change(&Change::RemoveDevice { uuid: [0x55; 16] }),
            serialize_change(&Change::RemoveContact { uuid: [0x33; 16] }),
            Vec::new(), // empty
            vec![0xFF], // unknown kind
        ],
    }
}

// ── Mutational engine (pure Rust; no libFuzzer / clang) ───────────────────────

/// Tiny xorshift64 for deterministic campaigns (`--seed`).
#[derive(Clone, Debug)]
pub struct Rng64 {
    state: u64,
}

impl Rng64 {
    pub fn new(seed: u64) -> Self {
        // Avoid zero state (xorshift degenerates).
        Self {
            state: if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed },
        }
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    pub fn gen_range(&mut self, max_exclusive: usize) -> usize {
        if max_exclusive == 0 {
            return 0;
        }
        (self.next_u64() as usize) % max_exclusive
    }

    pub fn fill_bytes(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            let n = chunk.len();
            chunk.copy_from_slice(&v[..n]);
        }
    }
}

/// One mutation step on a buffer (in place, may grow/shrink).
pub fn mutate(buf: &mut Vec<u8>, rng: &mut Rng64) {
    if buf.is_empty() {
        // Grow from empty.
        let n = 1 + rng.gen_range(64);
        buf.resize(n, 0);
        rng.fill_bytes(buf);
        return;
    }
    match rng.gen_range(6) {
        0 => {
            // Bit flip
            let i = rng.gen_range(buf.len());
            let bit = 1u8 << (rng.gen_range(8) as u8);
            buf[i] ^= bit;
        }
        1 => {
            // Random byte
            let i = rng.gen_range(buf.len());
            buf[i] = rng.next_u32() as u8;
        }
        2 => {
            // Truncate
            let new_len = rng.gen_range(buf.len());
            buf.truncate(new_len);
        }
        3 => {
            // Append random
            let n = 1 + rng.gen_range(32);
            let start = buf.len();
            buf.resize(start + n, 0);
            rng.fill_bytes(&mut buf[start..]);
        }
        4 => {
            // Delete a slice
            let start = rng.gen_range(buf.len());
            let end = start + rng.gen_range(buf.len() - start + 1);
            buf.drain(start..end);
        }
        _ => {
            // Overwrite a window with random
            let start = rng.gen_range(buf.len());
            let end = (start + 1 + rng.gen_range(16)).min(buf.len());
            rng.fill_bytes(&mut buf[start..end]);
        }
    }
    // Cap size so pathological growth cannot OOM during long runs.
    const MAX: usize = 64 * 1024;
    if buf.len() > MAX {
        buf.truncate(MAX);
    }
}

/// Run `iters` mutational inputs per target. Returns (inputs, accepted_well_formed).
pub fn run_campaign(iters: usize, seed: u64) -> (u64, u64) {
    let mut rng = Rng64::new(seed);
    let mut inputs: u64 = 0;
    let mut ok: u64 = 0;
    for target in FuzzTarget::ALL {
        let seeds = seed_corpus(target);
        // Always exercise seeds first (must be accepted where non-empty valid).
        for s in &seeds {
            inputs += 1;
            if fuzz_parse(target, s) {
                ok += 1;
            }
        }
        // Mutational stage: cycle seeds as bases.
        for i in 0..iters {
            let base = &seeds[i % seeds.len()];
            let mut buf = base.clone();
            // 1–4 mutations per input
            let steps = 1 + rng.gen_range(4);
            for _ in 0..steps {
                mutate(&mut buf, &mut rng);
            }
            inputs += 1;
            if fuzz_parse(target, &buf) {
                ok += 1;
            }
        }
        // Pure random buffers (not seed-derived)
        for _ in 0..(iters / 4).max(1) {
            let n = rng.gen_range(512);
            let mut buf = vec![0u8; n];
            rng.fill_bytes(&mut buf);
            inputs += 1;
            if fuzz_parse(target, &buf) {
                ok += 1;
            }
        }
    }
    (inputs, ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_corpus_parses_where_expected() {
        for target in FuzzTarget::ALL {
            for (i, s) in seed_corpus(target).into_iter().enumerate() {
                // Empty / unknown-kind change seeds are intentionally malformed.
                if target == FuzzTarget::ChangePayload && (s.is_empty() || s == [0xFF]) {
                    assert!(
                        !fuzz_parse(target, &s),
                        "{:?} seed {i} should reject empty/unknown",
                        target
                    );
                    continue;
                }
                assert!(
                    fuzz_parse(target, &s),
                    "{:?} seed {i} must parse (len={})",
                    target,
                    s.len()
                );
            }
        }
    }

    #[test]
    fn mutational_campaign_does_not_panic() {
        // Short CI run; longer campaigns use `pnet_fuzz_wire`.
        let (inputs, ok) = run_campaign(2_000, 0xC0FFEE);
        assert!(inputs > 0);
        // Seeds alone produce some well-formed accepts.
        assert!(ok > 0, "expected some well-formed accepts from seeds");
    }

    #[test]
    fn empty_and_junk_never_panic() {
        fuzz_all_parsers(&[]);
        fuzz_all_parsers(&[0u8; 1]);
        fuzz_all_parsers(&[0xFFu8; 256]);
        let big = vec![0xAAu8; 8 * 1024];
        fuzz_all_parsers(&big);
    }
}
