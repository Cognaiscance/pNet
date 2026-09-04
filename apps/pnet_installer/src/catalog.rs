//! Verified in-tree apps (same set as portal `/store`, plus this agent).

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CatalogApp {
    pub id: &'static str,
    pub name: &'static str,
    pub summary: &'static str,
    pub placement: &'static str,
    pub crate_name: &'static str,
    pub install_cmd: &'static str,
    /// Fabric `app_register` alias used to detect “installed” (running).
    pub fabric_alias: &'static str,
    pub web_slug: Option<&'static str>,
    pub notes: &'static str,
}

pub const CATALOG: &[CatalogApp] = &[
    CatalogApp {
        id: "installer",
        name: "Installer",
        summary: "This agent: catalog, desire, and status across your devices.",
        placement: "Every device that runs pNet (especially the rank-1 SG for the UI).",
        crate_name: "pnet_installer",
        install_cmd: "cargo run -p pnet_installer\n# UI: /apps/installer/",
        fabric_alias: "installer",
        web_slug: Some("installer"),
        notes: "Phase 2 is notify-only. It never downloads or starts other packages.",
    },
    CatalogApp {
        id: "filesync",
        name: "Filesync",
        summary: "Folder replica plus portal web viewport.",
        placement: "Desktops you want in the set; also the rank-1 SG for always-on web.",
        crate_name: "pnet_filesync",
        install_cmd: "cargo run -p pnet_filesync\n# Folder: ~/pnet-filesync   UI: /apps/filesync/",
        fabric_alias: "filesync",
        web_slug: Some("filesync"),
        notes: "Approve in Config → Pending Apps unless PNET_AUTO_APPROVE_APPS=1.",
    },
    CatalogApp {
        id: "hello",
        name: "Hello",
        summary: "Sample hybrid page at /apps/hello/.",
        placement: "Usually the SG (portal demo).",
        crate_name: "pnet_web_hello",
        install_cmd: "cargo run -p pnet_web_hello\n# UI: /apps/hello/",
        fabric_alias: "web-hello",
        web_slug: Some("hello"),
        notes: "Smoke-test for portal mounts.",
    },
    CatalogApp {
        id: "chat",
        name: "Chat",
        summary: "Room-oriented chat (pipe + framing; rooms later).",
        placement: "Host on rank-1 SG when rooms land; agents on member devices.",
        crate_name: "pnet_chat",
        install_cmd: "cargo run -p pnet_chat\n# Dev HTTP :3100 (not a portal mount yet).",
        fabric_alias: "pnet-chat",
        web_slug: None,
        notes: "Preview / skeleton. Not a full product yet.",
    },
];

pub fn all() -> &'static [CatalogApp] {
    CATALOG
}

pub fn get(id: &str) -> Option<&'static CatalogApp> {
    CATALOG.iter().find(|a| a.id == id)
}

pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 32
        && id
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_unique() {
        let mut s = std::collections::HashSet::new();
        for a in all() {
            assert!(valid_id(a.id));
            assert!(s.insert(a.id));
            assert!(!a.fabric_alias.is_empty());
        }
        assert!(get("filesync").is_some());
    }
}
