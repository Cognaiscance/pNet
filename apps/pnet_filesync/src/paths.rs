//! Relative path rules for the synced tree.

/// Max UTF-8 bytes in a relative path.
pub const MAX_PATH: usize = 512;

/// Normalize and reject unsafe relative paths.
///
/// Allowed: `notes/todo.txt`, `photo.jpg`. Rejected: absolute, `..`,
/// backslash, NUL/control, hidden components (`.git`), empty.
pub fn sanitize_rel(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > MAX_PATH {
        return None;
    }
    if raw.starts_with('/') || raw.starts_with('\\') {
        return None;
    }
    if raw.contains('\0') || raw.chars().any(|c| c.is_control()) {
        return None;
    }
    let unified = raw.replace('\\', "/");
    let mut out: Vec<&str> = Vec::new();
    for part in unified.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            return None;
        }
        if part.starts_with('.') {
            return None;
        }
        out.push(part);
    }
    if out.is_empty() {
        return None;
    }
    Some(out.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_nested_files() {
        assert_eq!(sanitize_rel("a/b.txt").as_deref(), Some("a/b.txt"));
        assert_eq!(sanitize_rel("photo.jpg").as_deref(), Some("photo.jpg"));
        assert_eq!(sanitize_rel("./x/y").as_deref(), Some("x/y"));
    }

    #[test]
    fn rejects_escapes_and_hidden() {
        assert!(sanitize_rel("../x").is_none());
        assert!(sanitize_rel("/etc/passwd").is_none());
        assert!(sanitize_rel("a/../b").is_none());
        assert!(sanitize_rel(".hidden").is_none());
        assert!(sanitize_rel("a/.git/x").is_none());
        assert!(sanitize_rel("").is_none());
        assert!(sanitize_rel("a\0b").is_none());
    }
}
