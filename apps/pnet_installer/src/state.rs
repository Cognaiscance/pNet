//! Desired apps + observed status. Never executes packages.

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::catalog;
use crate::fabric::DirView;

pub const STATE_PENDING: &str = "pending";
pub const STATE_INSTALLED: &str = "installed";
#[allow(dead_code)]
pub const STATE_REMOVED: &str = "removed";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesiredApp {
    pub catalog_id: String,
    #[serde(default)]
    pub version: String,
    pub enabled: bool,
    /// Hex device uuids that should run this app.
    pub device_uuids: Vec<String>,
    pub updated_at: u64,
    pub updated_by: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallStatus {
    pub catalog_id: String,
    #[serde(default)]
    pub version: String,
    pub device_uuid: String,
    pub state: String,
    #[serde(default)]
    pub detail: String,
    pub reported_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Disk {
    replica_id: String,
    #[serde(default)]
    desire: Vec<DesiredApp>,
    #[serde(default)]
    status: Vec<InstallStatus>,
}

#[derive(Clone, Debug)]
pub struct State {
    pub dir: PathBuf,
    pub replica_id: [u8; 16],
    pub desire: Vec<DesiredApp>,
    pub status: Vec<InstallStatus>,
}

impl State {
    pub fn open(dir: PathBuf) -> std::io::Result<Self> {
        fs::create_dir_all(&dir)?;
        let path = dir.join("state.json");
        if path.is_file() {
            if let Ok(text) = fs::read_to_string(&path) {
                if let Ok(disk) = serde_json::from_str::<Disk>(&text) {
                    let replica_id = hex16_decode(&disk.replica_id).unwrap_or_else(random_id);
                    return Ok(State {
                        dir,
                        replica_id,
                        desire: disk.desire,
                        status: disk.status,
                    });
                }
            }
        }
        Ok(State {
            dir,
            replica_id: random_id(),
            desire: Vec::new(),
            status: Vec::new(),
        })
    }

    pub fn persist(&self) -> std::io::Result<()> {
        let disk = Disk {
            replica_id: hex16(&self.replica_id),
            desire: self.desire.clone(),
            status: self.status.clone(),
        };
        let text = serde_json::to_string_pretty(&disk).unwrap_or_else(|_| "{}".into());
        let tmp = self.dir.join("state.json.tmp");
        fs::write(&tmp, text)?;
        fs::rename(tmp, self.dir.join("state.json"))?;
        Ok(())
    }

    /// Rank-1 SG (lowest `sg_rank` among SGs) writes desire. Solo node may write.
    pub fn is_writer(&self, dir: &DirView) -> bool {
        match policy_writer_uuid(dir) {
            None => true,
            Some(u) => u == dir.device_uuid,
        }
    }

    pub fn set_desire(
        &mut self,
        catalog_id: &str,
        enabled: bool,
        device_uuids: Vec<String>,
        writer_device: [u8; 16],
    ) -> Result<(), &'static str> {
        if catalog::get(catalog_id).is_none() {
            return Err("unknown_app");
        }
        let now = unix_now();
        let by = hex16(&writer_device);
        if let Some(d) = self.desire.iter_mut().find(|d| d.catalog_id == catalog_id) {
            d.enabled = enabled;
            d.device_uuids = device_uuids;
            d.updated_at = now;
            d.updated_by = by;
            d.version = "manual".into();
        } else {
            self.desire.push(DesiredApp {
                catalog_id: catalog_id.into(),
                version: "manual".into(),
                enabled,
                device_uuids,
                updated_at: now,
                updated_by: by,
            });
        }
        let _ = self.persist();
        Ok(())
    }

    /// LWW per catalog_id by `updated_at`.
    pub fn merge_desire(&mut self, incoming: &[DesiredApp]) -> bool {
        let mut changed = false;
        for rem in incoming {
            if catalog::get(&rem.catalog_id).is_none() {
                continue;
            }
            match self
                .desire
                .iter()
                .position(|d| d.catalog_id == rem.catalog_id)
            {
                None => {
                    self.desire.push(rem.clone());
                    changed = true;
                }
                Some(i) => {
                    if rem.updated_at > self.desire[i].updated_at {
                        self.desire[i] = rem.clone();
                        changed = true;
                    }
                }
            }
        }
        if changed {
            let _ = self.persist();
        }
        changed
    }

    /// Replace this device's status rows when incoming is newer.
    pub fn merge_status(&mut self, incoming: &[InstallStatus]) -> bool {
        let mut changed = false;
        for rem in incoming {
            let key = (rem.catalog_id.as_str(), rem.device_uuid.as_str());
            match self
                .status
                .iter()
                .position(|s| s.catalog_id == key.0 && s.device_uuid == key.1)
            {
                None => {
                    self.status.push(rem.clone());
                    changed = true;
                }
                Some(i) => {
                    if rem.reported_at >= self.status[i].reported_at {
                        self.status[i] = rem.clone();
                        changed = true;
                    }
                }
            }
        }
        if changed {
            let _ = self.persist();
        }
        changed
    }

    /// Observe local directory vs desire. Notify only — no exec.
    pub fn observe_local(&mut self, dir: &DirView) -> bool {
        let local_hex = hex16(&dir.device_uuid);
        let running: Vec<String> = dir
            .devices
            .iter()
            .find(|d| d.uuid == dir.device_uuid)
            .map(|d| {
                d.apps
                    .iter()
                    .filter(|a| a.approved)
                    .map(|a| a.alias.clone())
                    .collect()
            })
            .unwrap_or_default();
        let now = unix_now();
        let mut rows = Vec::new();
        for d in &self.desire {
            let wanted = d.enabled && d.device_uuids.iter().any(|u| u == &local_hex);
            let Some(cat) = catalog::get(&d.catalog_id) else {
                continue;
            };
            let present = running.iter().any(|a| a == cat.fabric_alias);
            let (state, detail) = if wanted && present {
                (
                    STATE_INSTALLED,
                    format!("{} registered on this device", cat.fabric_alias),
                )
            } else if wanted && !present {
                (
                    STATE_PENDING,
                    format!(
                        "Desired here. Run `{cmd}` (notify only — agent does not install).",
                        cmd = cat.crate_name
                    ),
                )
            } else if !wanted && present {
                (
                    STATE_INSTALLED,
                    "Running but not in desire for this device.".into(),
                )
            } else {
                continue;
            };
            rows.push(InstallStatus {
                catalog_id: d.catalog_id.clone(),
                version: d.version.clone(),
                device_uuid: local_hex.clone(),
                state: state.into(),
                detail,
                reported_at: now,
            });
        }
        // Drop stale local rows we no longer emit, then merge.
        let before = self.status.clone();
        self.status
            .retain(|s| s.device_uuid != local_hex || rows.iter().any(|n| n.catalog_id == s.catalog_id));
        let _ = self.merge_status(&rows);
        self.status != before
    }
}

/// Lowest sg_rank among own-user SGs. Tie: smaller uuid hex.
pub fn policy_writer_uuid(dir: &DirView) -> Option<[u8; 16]> {
    let mut sgs: Vec<_> = dir.devices.iter().filter(|d| d.is_sg).collect();
    if sgs.is_empty() {
        return None;
    }
    sgs.sort_by(|a, b| {
        a.sg_rank
            .cmp(&b.sg_rank)
            .then_with(|| a.uuid.cmp(&b.uuid))
    });
    Some(sgs[0].uuid)
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn hex16(b: &[u8; 16]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn hex16_decode(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 {
        return None;
    }
    let mut o = [0u8; 16];
    for i in 0..16 {
        o[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(o)
}

fn random_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    let _ = getrandom::getrandom(&mut id);
    id
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fabric::{AppView, DevView, DirView};

    fn tmp() -> PathBuf {
        let mut n = [0u8; 8];
        let _ = getrandom::getrandom(&mut n);
        let p = std::env::temp_dir().join(format!("pnet-ins-{:x}", u64::from_le_bytes(n)));
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn dir(local: [u8; 16], is_sg: bool, rank: u8, aliases: &[&str]) -> DirView {
        DirView {
            app_id: [1u8; 16],
            device_uuid: local,
            approved: true,
            devices: vec![DevView {
                uuid: local,
                alias: "me".into(),
                is_sg,
                sg_rank: rank,
                apps: aliases
                    .iter()
                    .map(|a| AppView {
                        alias: (*a).into(),
                        approved: true,
                    })
                    .collect(),
            }],
            installer_peers: Vec::new(),
        }
    }

    #[test]
    fn desire_lww_newer_wins() {
        let mut s = State::open(tmp()).unwrap();
        s.set_desire("filesync", true, vec!["aa".repeat(16)], [9u8; 16])
            .unwrap();
        let mut older = s.desire[0].clone();
        older.enabled = false;
        older.updated_at = s.desire[0].updated_at.saturating_sub(10);
        assert!(!s.merge_desire(&[older]));
        let mut newer = s.desire[0].clone();
        newer.enabled = false;
        newer.updated_at = s.desire[0].updated_at + 5;
        assert!(s.merge_desire(&[newer]));
        assert!(!s.desire[0].enabled);
    }

    #[test]
    fn observe_pending_then_installed() {
        let local = [2u8; 16];
        let mut s = State::open(tmp()).unwrap();
        s.set_desire("filesync", true, vec![hex16(&local)], local)
            .unwrap();
        s.observe_local(&dir(local, true, 1, &[]));
        let st = s
            .status
            .iter()
            .find(|x| x.catalog_id == "filesync")
            .unwrap();
        assert_eq!(st.state, STATE_PENDING);
        s.observe_local(&dir(local, true, 1, &["filesync"]));
        let st = s
            .status
            .iter()
            .find(|x| x.catalog_id == "filesync")
            .unwrap();
        assert_eq!(st.state, STATE_INSTALLED);
    }

    #[test]
    fn writer_is_lowest_sg_rank() {
        let a = [0x0au8; 16];
        let b = [0x0bu8; 16];
        let d = DirView {
            app_id: [1u8; 16],
            device_uuid: b,
            approved: true,
            devices: vec![
                DevView {
                    uuid: a,
                    alias: "sg1".into(),
                    is_sg: true,
                    sg_rank: 1,
                    apps: vec![],
                },
                DevView {
                    uuid: b,
                    alias: "sg2".into(),
                    is_sg: true,
                    sg_rank: 2,
                    apps: vec![],
                },
            ],
            installer_peers: Vec::new(),
        };
        assert_eq!(policy_writer_uuid(&d), Some(a));
        assert!(!State::open(tmp()).unwrap().is_writer(&d));
        let mut d2 = d.clone();
        d2.device_uuid = a;
        assert!(State::open(tmp()).unwrap().is_writer(&d2));
    }

    #[test]
    fn rejects_unknown_catalog() {
        let mut s = State::open(tmp()).unwrap();
        assert_eq!(
            s.set_desire("malware", true, vec![], [1u8; 16]),
            Err("unknown_app")
        );
    }
}
