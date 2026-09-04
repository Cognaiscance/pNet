//! Local replica: watched folder + index + content hashes.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::paths::sanitize_rel;

/// v1 cap so a replica cannot fill the disk from a peer (web uploads are 4 MiB).
pub const MAX_FILE_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRec {
    pub path: String,
    pub size: u64,
    pub mtime: u64,
    #[serde(with = "hex32")]
    pub hash: [u8; 32],
    pub deleted: bool,
}

mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.iter().map(|b| format!("{b:02x}")).collect::<String>())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        if s.len() != 64 {
            return Err(serde::de::Error::custom("hash hex len"));
        }
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .map_err(serde::de::Error::custom)?;
        }
        Ok(out)
    }
}

#[derive(Serialize, Deserialize)]
struct DiskIndex {
    replica_id: String,
    gen: u64,
    files: Vec<FileRec>,
}

pub struct Store {
    pub root: PathBuf,
    pub state_dir: PathBuf,
    pub replica_id: [u8; 16],
    pub gen: u64,
    pub files: BTreeMap<String, FileRec>,
}

impl Store {
    pub fn open(root: PathBuf, state_dir: PathBuf) -> std::io::Result<Self> {
        fs::create_dir_all(&root)?;
        fs::create_dir_all(&state_dir)?;
        let path = state_dir.join("index.json");
        if path.is_file() {
            if let Ok(text) = fs::read_to_string(&path) {
                if let Ok(disk) = serde_json::from_str::<DiskIndex>(&text) {
                    let replica_id = hex16_decode(&disk.replica_id).unwrap_or_else(random_id);
                    let files = disk
                        .files
                        .into_iter()
                        .filter_map(|r| sanitize_rel(&r.path).map(|p| {
                            let mut r = r;
                            r.path = p.clone();
                            (p, r)
                        }))
                        .collect();
                    return Ok(Store {
                        root,
                        state_dir,
                        replica_id,
                        gen: disk.gen,
                        files,
                    });
                }
            }
        }
        Ok(Store {
            root,
            state_dir,
            replica_id: random_id(),
            gen: 0,
            files: BTreeMap::new(),
        })
    }

    pub fn persist(&self) -> std::io::Result<()> {
        let disk = DiskIndex {
            replica_id: hex16(&self.replica_id),
            gen: self.gen,
            files: self.files.values().cloned().collect(),
        };
        let text = serde_json::to_string_pretty(&disk).unwrap_or_else(|_| "{}".into());
        let tmp = self.state_dir.join("index.json.tmp");
        fs::write(&tmp, text)?;
        fs::rename(tmp, self.state_dir.join("index.json"))?;
        Ok(())
    }

    /// Walk the folder; update index. Returns true if anything changed.
    pub fn scan(&mut self) -> bool {
        let mut seen = std::collections::HashSet::new();
        let mut changed = false;
        let root = self.root.clone();
        let _ = walk(&root, &root, &mut |rel, full| {
            let Some(rel) = sanitize_rel(&rel) else { return; };
            seen.insert(rel.clone());
            let meta = match fs::metadata(&full) {
                Ok(m) if m.is_file() => m,
                _ => return,
            };
            let size = meta.len();
            if size > MAX_FILE_BYTES {
                eprintln!("[filesync] skip {} ({} bytes > cap)", rel, size);
                return;
            }
            let mtime = mtime_secs(&meta);
            if let Some(existing) = self.files.get(&rel) {
                if !existing.deleted && existing.size == size && existing.mtime == mtime {
                    return;
                }
            }
            let Ok(hash) = hash_file(&full) else { return; };
            self.files.insert(
                rel.clone(),
                FileRec {
                    path: rel,
                    size,
                    mtime,
                    hash,
                    deleted: false,
                },
            );
            changed = true;
        });
        // Local disappearances → tombstones.
        let now = unix_now();
        let missing: Vec<String> = self
            .files
            .iter()
            .filter(|(p, r)| !r.deleted && !seen.contains(*p))
            .map(|(p, _)| p.clone())
            .collect();
        for p in missing {
            if let Some(r) = self.files.get_mut(&p) {
                r.deleted = true;
                r.mtime = now.max(r.mtime + 1);
                r.size = 0;
                r.hash = [0u8; 32];
                changed = true;
            }
        }
        if changed {
            self.gen = self.gen.saturating_add(1);
            let _ = self.persist();
        }
        changed
    }

    /// Merge remote records (LWW by mtime, then hash). Returns hashes to fetch.
    pub fn merge_remote(&mut self, recs: &[FileRec]) -> Vec<[u8; 32]> {
        let mut want = Vec::new();
        let mut changed = false;
        for remote in recs {
            let Some(path) = sanitize_rel(&remote.path) else { continue; };
            let mut remote = remote.clone();
            remote.path = path.clone();
            let replace = match self.files.get(&path) {
                None => true,
                Some(local) => rec_beats(&remote, local),
            };
            if !replace {
                continue;
            }
            if !remote.deleted {
                let dest = self.root.join(path_to_os(&path));
                let have = dest.is_file()
                    && hash_file(&dest)
                        .ok()
                        .map(|h| h == remote.hash)
                        .unwrap_or(false);
                if !have && remote.size > 0 {
                    if !want.contains(&remote.hash) {
                        want.push(remote.hash);
                    }
                } else if remote.size == 0 {
                    // empty file: create now
                    if let Some(parent) = dest.parent() {
                        let _ = fs::create_dir_all(parent);
                    }
                    let _ = fs::write(&dest, b"");
                    let _ = set_mtime(&dest, remote.mtime);
                }
            } else {
                let dest = self.root.join(path_to_os(&path));
                if dest.is_file() {
                    let _ = fs::remove_file(&dest);
                }
            }
            self.files.insert(path, remote);
            changed = true;
        }
        if changed {
            self.gen = self.gen.saturating_add(1);
            let _ = self.persist();
        }
        want
    }

    /// Write a completed blob to every live path that names this hash.
    pub fn install_blob(&mut self, hash: &[u8; 32], data: &[u8]) -> std::io::Result<()> {
        if data.len() as u64 > MAX_FILE_BYTES {
            return Ok(());
        }
        let got = sha256(data);
        if &got != hash {
            return Ok(());
        }
        for rec in self.files.values() {
            if rec.deleted || &rec.hash != hash {
                continue;
            }
            let dest = self.root.join(path_to_os(&rec.path));
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&dest, data)?;
            let _ = set_mtime(&dest, rec.mtime);
        }
        Ok(())
    }

    pub fn read_file(&self, rel: &str) -> Option<Vec<u8>> {
        let rel = sanitize_rel(rel)?;
        let rec = self.files.get(&rel)?;
        if rec.deleted {
            return None;
        }
        fs::read(self.root.join(path_to_os(&rel))).ok()
    }

    pub fn write_file(&mut self, rel: &str, data: &[u8]) -> Result<(), &'static str> {
        let rel = sanitize_rel(rel).ok_or("bad_path")?;
        if data.len() as u64 > MAX_FILE_BYTES {
            return Err("too_large");
        }
        let dest = self.root.join(path_to_os(&rel));
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(|_| "io")?;
        }
        fs::write(&dest, data).map_err(|_| "io")?;
        self.scan();
        Ok(())
    }

    pub fn remove_file(&mut self, rel: &str) -> Result<(), &'static str> {
        let rel = sanitize_rel(rel).ok_or("bad_path")?;
        let dest = self.root.join(path_to_os(&rel));
        if dest.is_file() {
            fs::remove_file(&dest).map_err(|_| "io")?;
        }
        self.scan();
        Ok(())
    }

    pub fn blob(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
        for rec in self.files.values() {
            if rec.deleted || &rec.hash != hash {
                continue;
            }
            let data = fs::read(self.root.join(path_to_os(&rec.path))).ok()?;
            if sha256(&data) == *hash {
                return Some(data);
            }
        }
        None
    }

    pub fn live_list(&self) -> Vec<FileRec> {
        self.files
            .values()
            .filter(|r| !r.deleted)
            .cloned()
            .collect()
    }
}

/// True if `a` should replace `b` (last-write-wins, then hash).
pub fn rec_beats(a: &FileRec, b: &FileRec) -> bool {
    if a.mtime != b.mtime {
        return a.mtime > b.mtime;
    }
    if a.deleted != b.deleted {
        return a.deleted;
    }
    a.hash > b.hash
}

fn walk(root: &Path, dir: &Path, cb: &mut impl FnMut(String, PathBuf)) -> std::io::Result<()> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };
    for ent in entries.flatten() {
        let name = ent.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') {
            continue;
        }
        let full = ent.path();
        let rel = match full.strip_prefix(root) {
            Ok(r) => r.to_string_lossy().replace('\\', "/"),
            Err(_) => continue,
        };
        let ft = match ent.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if ft.is_dir() {
            walk(root, &full, cb)?;
        } else if ft.is_file() {
            cb(rel, full);
        }
    }
    Ok(())
}

pub fn hash_file(path: &Path) -> std::io::Result<[u8; 32]> {
    let mut f = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

fn mtime_secs(meta: &fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn set_mtime(path: &Path, secs: u64) -> std::io::Result<()> {
    let t = UNIX_EPOCH + std::time::Duration::from_secs(secs);
    File::options().write(true).open(path)?.set_modified(t)
}

fn path_to_os(rel: &str) -> PathBuf {
    rel.split('/').collect()
}

fn random_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    let _ = getrandom::getrandom(&mut id);
    id
}

pub fn hex16(b: &[u8; 16]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hex16_decode(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 {
        return None;
    }
    let mut o = [0u8; 16];
    for i in 0..16 {
        o[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(o)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> (PathBuf, PathBuf) {
        let mut nonce = [0u8; 8];
        let _ = getrandom::getrandom(&mut nonce);
        let t = std::env::temp_dir().join(format!(
            "pnet-fs-{}-{:x}{:x}",
            std::process::id(),
            u64::from_le_bytes(nonce),
            unix_now()
        ));
        let root = t.join("root");
        let state = t.join("state");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&state).unwrap();
        (root, state)
    }

    #[test]
    fn scan_sees_new_file_and_delete() {
        let (root, state) = tmp();
        let mut s = Store::open(root.clone(), state).unwrap();
        fs::write(root.join("hello.txt"), b"hi").unwrap();
        assert!(s.scan());
        assert_eq!(s.live_list().len(), 1);
        assert_eq!(s.live_list()[0].path, "hello.txt");
        fs::remove_file(root.join("hello.txt")).unwrap();
        assert!(s.scan());
        assert!(s.live_list().is_empty());
        assert!(s.files.get("hello.txt").unwrap().deleted);
    }

    #[test]
    fn merge_lww_prefers_newer_mtime() {
        let (root, state) = tmp();
        let mut s = Store::open(root, state).unwrap();
        s.files.insert(
            "a.txt".into(),
            FileRec {
                path: "a.txt".into(),
                size: 1,
                mtime: 10,
                hash: [1u8; 32],
                deleted: false,
            },
        );
        let newer = FileRec {
            path: "a.txt".into(),
            size: 2,
            mtime: 20,
            hash: [2u8; 32],
            deleted: false,
        };
        let want = s.merge_remote(&[newer.clone()]);
        assert_eq!(s.files.get("a.txt").unwrap().mtime, 20);
        assert_eq!(want, vec![[2u8; 32]]);
        let older = FileRec {
            path: "a.txt".into(),
            size: 3,
            mtime: 5,
            hash: [3u8; 32],
            deleted: false,
        };
        let want2 = s.merge_remote(&[older]);
        assert_eq!(s.files.get("a.txt").unwrap().hash, [2u8; 32]);
        assert!(want2.is_empty());
    }

    #[test]
    fn install_blob_writes_tree() {
        let (root, state) = tmp();
        let mut s = Store::open(root.clone(), state).unwrap();
        let data = b"hello-sync";
        let hash = sha256(data);
        s.files.insert(
            "n/a.txt".into(),
            FileRec {
                path: "n/a.txt".into(),
                size: data.len() as u64,
                mtime: 1,
                hash,
                deleted: false,
            },
        );
        s.install_blob(&hash, data).unwrap();
        assert_eq!(fs::read(root.join("n/a.txt")).unwrap(), data);
    }
}
