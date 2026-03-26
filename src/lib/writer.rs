use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;

pub enum WriteRequest {
    NodeData(String),
    AppData(String),
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

fn write_atomic(path: &PathBuf, content: &str) -> io::Result<()> {
    (|| -> io::Result<()> {
        let dir = path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "path has no parent directory")
        })?;
        let tmp = dir.join(".pnet_write_tmp");

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
        fs::rename(&tmp, path)?;
        Ok(())
    })()
}
