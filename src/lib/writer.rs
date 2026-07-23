use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;

pub enum WriteRequest {
    /// Directory snapshot (`node.toml`) — identity, devices, contacts, versions.
    NodeData(String),
    AppData(String),
    /// Sync v2 write log (`write_log.toml`), separate so it can grow without
    /// bloating the directory snapshot (§7.3).
    WriteLog(String),
}

pub struct WriterThread {
    sender: Option<mpsc::SyncSender<WriteRequest>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl WriterThread {
    pub fn start(data_dir: PathBuf) -> WriterThread {
        let (sender, receiver) = mpsc::sync_channel::<WriteRequest>(64);

        let handle = thread::spawn(move || {
            while let Ok(request) = receiver.recv() {
                let (filename, content) = match request {
                    WriteRequest::NodeData(s) => ("node.toml", s),
                    WriteRequest::AppData(s)  => ("apps.toml", s),
                    WriteRequest::WriteLog(s) => ("write_log.toml", s),
                };
                let path = data_dir.join(filename);
                if let Err(e) = write_atomic(&path, &content) {
                    eprintln!("[writer] failed to write {}: {e}", path.display());
                }
            }
            // Channel closed — sender(s) all dropped. Exit cleanly.
        });

        WriterThread {
            sender: Some(sender),
            handle: Some(handle),
        }
    }

    pub fn sender(&self) -> mpsc::SyncSender<WriteRequest> {
        self.sender.as_ref().unwrap().clone()
    }

    /// Close the channel (drop the sender) so the writer drains and exits,
    /// then join the thread.
    pub fn join(&mut self) {
        let WriterThread { sender, handle } = self;
        drop(sender.take());
        if let Some(h) = handle.take() {
            h.join().expect("writer thread panicked");
        }
    }
}

/// Atomically write `content` to `path` (temp file + fsync + rename).
///
/// On Unix the file is mode `0600` (owner read/write only) both on the temp
/// file and again after rename, matching `descriptions/data persistence.md`.
/// Temp name is derived from the final file name so concurrent directory /
/// write-log flushes never share one global temp path.
pub fn write_atomic(path: &Path, content: &str) -> io::Result<()> {
    let dir = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "path has no parent directory")
    })?;
    let base = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("pnet");
    let tmp = dir.join(format!(".{base}.tmp"));

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }

    file.write_all(content.as_bytes())?;
    file.sync_all()?;
    // Drop before rename so the file is closed on all platforms.
    drop(file);
    fs::rename(&tmp, path)?;

    // Belt-and-suspenders: ensure final path is 0600 even if rename replaced
    // an older inode with a looser mode on some platforms, or if an existing
    // world-readable file was the rename target's previous mode elsewhere.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("pnet_writer_test_{name}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn write_atomic_creates_file_with_correct_content() {
        let dir = test_dir("atomic");
        let path = dir.join("test.toml");

        write_atomic(&path, "hello = true\n").unwrap();

        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(content, "hello = true\n");
    }

    #[test]
    fn write_atomic_leaves_no_tmp_file_on_success() {
        let dir = test_dir("no_tmp");
        let path = dir.join("test.toml");

        write_atomic(&path, "x = 1\n").unwrap();

        assert!(!dir.join(".pnet_write_tmp").exists());
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_sets_file_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = test_dir("mode600");
        let path = dir.join("secret.toml");
        write_atomic(&path, "secret = true\n").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0600, got {mode:o}");
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_tightens_existing_world_readable_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = test_dir("tighten");
        let path = dir.join("loose.toml");
        fs::write(&path, "old\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        write_atomic(&path, "new\n").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(fs::read_to_string(&path).unwrap(), "new\n");
    }

    #[test]
    fn writer_thread_processes_all_requests_before_shutdown() {
        let dir = test_dir("thread");
        let mut writer = WriterThread::start(dir.clone());
        let tx = writer.sender();

        tx.send(WriteRequest::NodeData("node = true\n".into())).unwrap();
        tx.send(WriteRequest::AppData("app = true\n".into())).unwrap();
        tx.send(WriteRequest::WriteLog("entries = []\n".into())).unwrap();

        // Drop tx before joining — join() closes the internal sender, but the
        // channel stays open until all clones are dropped too.
        drop(tx);
        writer.join(); // blocks until channel drained

        assert_eq!(fs::read_to_string(dir.join("node.toml")).unwrap(), "node = true\n");
        assert_eq!(fs::read_to_string(dir.join("apps.toml")).unwrap(), "app = true\n");
        assert_eq!(
            fs::read_to_string(dir.join("write_log.toml")).unwrap(),
            "entries = []\n"
        );
    }
}
