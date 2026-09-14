//! Fallback catalog when the installer agent is not mounted.
//!
//! The live store is the installer (`/apps/installer/`), fed by GitHub URL
//! lists in `~/.pnet/installer/app_sources/`. Portal `/store` redirects there
//! when the agent is up. These entries are the official baked set only.

/// One verified catalog entry (official GitHub apps the project is willing to name).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CatalogApp {
    pub id: &'static str,
    pub name: &'static str,
    pub summary: &'static str,
    /// Where this app usually belongs (SG vs desktop DG, etc.).
    pub placement: &'static str,
    pub os: &'static str,
    pub crate_name: &'static str,
    pub github_url: &'static str,
    pub install_cmd: &'static str,
    pub notes: &'static str,
    /// Portal slug once the process self-registers, if any.
    pub web_slug: Option<&'static str>,
    /// `available` = documented run path; `preview` = incomplete.
    pub status: &'static str,
}

const CATALOG: &[CatalogApp] = &[
    CatalogApp {
        id: "installer",
        name: "Installer",
        summary: "Agent for catalog, desired apps, and per-device status (notify only).",
        placement: "Every pNet device; UI on the rank-1 SG at /apps/installer/.",
        os: "Linux (v1)",
        crate_name: "pnet_installer",
        github_url: "https://github.com/Cognaiscance/pnet_installer",
        install_cmd: "\
git clone https://github.com/Cognaiscance/pnet_installer\n\
cd pnet_installer\n\
cargo run\n# UI: /apps/installer/\n\
# Extra apps: drop a GitHub URL list in ~/.pnet/installer/app_sources/",
        notes: "bootstrap copies local binaries only — no network fetch. \
                Catalog apps stay notify-only until signed install (phase 4).",
        web_slug: Some("installer"),
        status: "available",
    },
    CatalogApp {
        id: "filesync",
        name: "Filesync",
        summary: "Folder replica on each device plus a web viewport on the portal.",
        placement: "Each desktop/laptop you want in the set; also the rank-1 SG \
                    so the site still has files when laptops are off.",
        os: "Linux (v1)",
        crate_name: "pnet_filesync",
        github_url: "https://github.com/Cognaiscance/pnet_filesync",
        install_cmd: "\
git clone https://github.com/Cognaiscance/pnet_filesync\n\
cd pnet_filesync\n\
cargo run\n\
# Folder: ~/pnet-filesync   UI: /apps/filesync/",
        notes: "Approve the app in Config → Pending Apps unless \
                PNET_AUTO_APPROVE_APPS=1. Intra-user only; not a contact share.",
        web_slug: Some("filesync"),
        status: "available",
    },
    CatalogApp {
        id: "hello",
        name: "Hello",
        summary: "Tiny sample hybrid page that registers /apps/hello/.",
        placement: "Any node whose portal you want to demo; usually the SG.",
        os: "Linux (v1)",
        crate_name: "pnet_web_hello",
        github_url: "https://github.com/Cognaiscance/pnet_web_hello",
        install_cmd: "\
git clone https://github.com/Cognaiscance/pnet_web_hello\n\
cd pnet_web_hello\n\
cargo run\n# UI: /apps/hello/",
        notes: "Smoke-test for portal mounts. Not a real product app.",
        web_slug: Some("hello"),
        status: "available",
    },
    CatalogApp {
        id: "chat",
        name: "Chat",
        summary: "Room-oriented chat over the app API (pipe + framing; rooms later).",
        placement: "Room host on rank-1 SG when rooms land; agents on member devices.",
        os: "Linux (preview)",
        crate_name: "pnet_chat",
        github_url: "https://github.com/Cognaiscance/pnet_chat",
        install_cmd: "\
git clone https://github.com/Cognaiscance/pnet_chat\n\
cd pnet_chat\n\
cargo run\n# Dev HTTP UI default :3100 (not a portal mount yet).",
        notes: "Phase-1 skeleton: register / get-data / send / push only. \
                Not a full Discord-style product yet.",
        web_slug: None,
        status: "preview",
    },
];

pub fn all() -> &'static [CatalogApp] {
    CATALOG
}

pub fn get(id: &str) -> Option<&'static CatalogApp> {
    CATALOG.iter().find(|a| a.id == id)
}

/// Catalog ids are lowercase `[a-z0-9-]+` (same idea as portal slugs).
pub fn valid_id(id: &str) -> bool {
    if id.is_empty() || id.len() > 32 {
        return false;
    }
    id.bytes()
        .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_unique_and_valid() {
        let mut seen = std::collections::HashSet::new();
        for a in all() {
            assert!(valid_id(a.id), "bad id {}", a.id);
            assert!(seen.insert(a.id), "duplicate {}", a.id);
            assert!(!a.install_cmd.is_empty());
            assert!(a.crate_name.starts_with("pnet_"));
            assert!(a.github_url.starts_with("https://github.com/Cognaiscance/"));
        }
        assert!(get("filesync").is_some());
        assert!(get("nope").is_none());
    }

    #[test]
    fn phase1_does_not_claim_auto_install() {
        for a in all() {
            let blob = format!("{} {} {}", a.summary, a.install_cmd, a.notes).to_ascii_lowercase();
            assert!(
                !blob.contains("auto-install") && !blob.contains("will install on all"),
                "{} must not imply auto-install",
                a.id
            );
        }
    }
}
