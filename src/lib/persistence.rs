use std::fs;
use std::io;
use std::path::Path;

use super::data_models::Node;

/// Ensure the data directory exists with private permissions and tighten
/// known data files if they already exist.
///
/// * Directory: `0700` (owner rwx only)
/// * Files `node.toml` / `apps.toml`: `0600` (owner rw only)
/// * If the immediate parent is named `.pnet`, it is also set to `0700`
///
/// Mode bits are applied on Unix only. Wrong owner / unwritable path still
/// surfaces as a normal I/O error for the operator to fix.
pub fn ensure_data_dir(data_dir: &Path) -> io::Result<()> {
    fs::create_dir_all(data_dir)?;

    #[cfg(unix)]
    {
        set_mode(data_dir, 0o700)?;
        if let Some(parent) = data_dir.parent() {
            if parent
                .file_name()
                .map(|n| n == ".pnet")
                .unwrap_or(false)
                && parent.exists()
            {
                set_mode(parent, 0o700)?;
            }
        }
        for name in ["node.toml", "apps.toml"] {
            let path = data_dir.join(name);
            if path.is_file() {
                set_mode(&path, 0o600)?;
            }
        }
    }

    Ok(())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

/// Load node state from `data_dir/node.toml`.
/// Falls back to a fresh `Node::new()` if the file doesn't exist or can't be parsed.
pub fn load(data_dir: &Path) -> Node {
    let path = data_dir.join("node.toml");
    if path.exists() {
        match std::fs::read_to_string(&path) {
            Ok(content) => match toml::from_str::<Node>(&content) {
                Ok(node) => {
                    println!("[persistence] loaded node from {}", path.display());
                    return node;
                }
                Err(e) => eprintln!("[persistence] failed to parse node.toml: {e}"),
            },
            Err(e) => eprintln!("[persistence] failed to read node.toml: {e}"),
        }
    }
    println!("[persistence] no saved state — creating new node");
    Node::new()
}

/// Serialize `node` to a TOML string for writing to disk.
pub fn save(node: &Node) -> String {
    toml::to_string(node).expect("node serialization failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lib::data_models::{DeviceGrade, Invitation, KeyPair, generate_uuid};
    use std::time::{Duration, UNIX_EPOCH};

    fn roundtrip(node: &Node) -> Node {
        let toml_str = save(node);
        toml::from_str::<Node>(&toml_str).expect("roundtrip deserialize failed")
    }

    fn unique_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "pnet_persistence_{name}_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn default_node_roundtrips() {
        let original = Node::new();
        let restored = roundtrip(&original);
        assert_eq!(original.device_uuid, restored.device_uuid);
        assert_eq!(original.owner.user.alias, restored.owner.user.alias);
        assert_eq!(original.owner.user.uuid, restored.owner.user.uuid);
        assert_eq!(original.owner.user.devices.len(), restored.owner.user.devices.len());
    }

    #[test]
    fn device_grade_roundtrips() {
        let original = Node::new();
        let restored = roundtrip(&original);
        let dev = &restored.owner.user.devices[0];
        assert!(matches!(dev.grade, DeviceGrade::DG));
    }

    #[test]
    fn key_pair_roundtrips() {
        let mut node = Node::new();
        node.owner.key_pair = KeyPair {
            public_key:  [0xAB; 32],
            private_key: [0xCD; 32],
        };
        let restored = roundtrip(&node);
        assert_eq!(restored.owner.key_pair.public_key,  [0xAB; 32]);
        assert_eq!(restored.owner.key_pair.private_key, [0xCD; 32]);
    }

    #[test]
    fn invitation_roundtrips() {
        let mut node = Node::new();
        let expires = UNIX_EPOCH + Duration::from_secs(9_999_999_999);
        node.owner.device_invitations.push(Invitation {
            id:         generate_uuid(),
            key_pair:   KeyPair { public_key: [0x12; 32], private_key: [0x34; 32] },
            expires_at: expires,
        });
        let restored = roundtrip(&node);
        assert_eq!(restored.owner.device_invitations.len(), 1);
        let inv = &restored.owner.device_invitations[0];
        assert_eq!(inv.key_pair.public_key, [0x12; 32]);
        // SystemTime is serialized as whole seconds, so compare at that precision.
        let orig_secs  = expires.duration_since(UNIX_EPOCH).unwrap().as_secs();
        let resto_secs = inv.expires_at.duration_since(UNIX_EPOCH).unwrap().as_secs();
        assert_eq!(orig_secs, resto_secs);
    }

    #[test]
    fn ephemeral_fields_are_empty_after_load() {
        let node = Node::new();
        let restored = roundtrip(&node);
        assert!(restored.owner.active_connections.is_empty());
        assert!(restored.owner.pending_connections.is_empty());
        assert!(restored.owner.pending_bootstrap.is_none());
        assert!(restored.owner.pending_device_acceptances.is_empty());
        assert!(restored.sg_statuses.is_empty());
    }

    #[test]
    fn load_returns_new_node_when_file_missing() {
        let dir = unique_dir("missing");
        fs::create_dir_all(&dir).unwrap();
        let node = load(&dir);
        assert_eq!(node.owner.user.alias, "Owner");
    }

    #[test]
    fn load_roundtrips_through_file() {
        let dir = unique_dir("file");
        fs::create_dir_all(&dir).unwrap();

        let mut original = Node::new();
        original.owner.user.alias = "TestUser".to_string();

        let toml_str = save(&original);
        fs::write(dir.join("node.toml"), &toml_str).unwrap();

        let restored = load(&dir);
        assert_eq!(restored.owner.user.alias, "TestUser");
        assert_eq!(restored.device_uuid, original.device_uuid);
    }

    #[cfg(unix)]
    #[test]
    fn ensure_data_dir_creates_0700_and_tightens_files() {
        use std::os::unix::fs::PermissionsExt;

        // Layout: <tmp>/.pnet/data  — parent named .pnet should also go 0700.
        let root = unique_dir("ensure");
        let pnet = root.join(".pnet");
        let data = pnet.join("data");

        // Pre-create loose parent + loose file to prove we tighten on load.
        fs::create_dir_all(&data).unwrap();
        fs::set_permissions(&pnet, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&data, fs::Permissions::from_mode(0o755)).unwrap();
        let node_path = data.join("node.toml");
        fs::write(&node_path, "x = 1\n").unwrap();
        fs::set_permissions(&node_path, fs::Permissions::from_mode(0o644)).unwrap();

        ensure_data_dir(&data).unwrap();

        let data_mode = fs::metadata(&data).unwrap().permissions().mode() & 0o777;
        let pnet_mode = fs::metadata(&pnet).unwrap().permissions().mode() & 0o777;
        let file_mode = fs::metadata(&node_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(data_mode, 0o700, "data dir mode {data_mode:o}");
        assert_eq!(pnet_mode, 0o700, ".pnet dir mode {pnet_mode:o}");
        assert_eq!(file_mode, 0o600, "node.toml mode {file_mode:o}");
    }

    #[cfg(unix)]
    #[test]
    fn ensure_data_dir_fresh_create_is_0700() {
        use std::os::unix::fs::PermissionsExt;
        let data = unique_dir("fresh").join("data");
        ensure_data_dir(&data).unwrap();
        let mode = fs::metadata(&data).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }
}
