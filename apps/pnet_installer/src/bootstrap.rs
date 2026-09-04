//! Phase 3: empty-machine bootstrap — install pNet + this agent from a local
//! binary directory, then optionally start them.
//!
//! Does **not** fetch packages from the network (phase 4). The user points at
//! a folder that already contains `pnet` and `pnet_installer` (unpacked dist,
//! or `target/debug` after `cargo build`).

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const BINS: &[&str] = &["pnet", "pnet_installer"];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opts {
    pub prefix: PathBuf,
    pub from: PathBuf,
    pub force: bool,
    pub start: bool,
    pub dry_run: bool,
    pub http_bind: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CopyKind {
    Copy,
    SkipExists,
    Overwrite,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    pub copies: Vec<(PathBuf, PathBuf, CopyKind)>,
    pub start_sh: PathBuf,
    pub record: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cmd {
    Run,
    Bootstrap(Opts),
    Help,
}

pub fn default_prefix() -> PathBuf {
    home_dir().join(".pnet")
}

fn home_dir() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

/// If `pnet` sits next to this binary, that directory is a valid `--from`.
pub fn infer_from(current_exe: &Path) -> Option<PathBuf> {
    let dir = current_exe.parent()?;
    if dir.join("pnet").is_file() && dir.join("pnet_installer").is_file() {
        Some(dir.to_path_buf())
    } else {
        None
    }
}

pub fn parse_args(args: &[String]) -> Result<Cmd, String> {
    let mut it = args.iter().skip(1);
    let Some(first) = it.next() else {
        return Ok(Cmd::Run);
    };
    match first.as_str() {
        "run" | "--run" => Ok(Cmd::Run),
        "help" | "--help" | "-h" => Ok(Cmd::Help),
        "bootstrap" => {
            let mut opts = Opts {
                prefix: default_prefix(),
                from: PathBuf::new(),
                force: false,
                start: true,
                dry_run: false,
                http_bind: "127.0.0.1".into(),
            };
            while let Some(a) = it.next() {
                match a.as_str() {
                    "--prefix" => {
                        opts.prefix = PathBuf::from(it.next().ok_or("--prefix needs a path")?);
                    }
                    "--from" => {
                        opts.from = PathBuf::from(it.next().ok_or("--from needs a path")?);
                    }
                    "--force" => opts.force = true,
                    "--no-start" => opts.start = false,
                    "--dry-run" => opts.dry_run = true,
                    "--http-bind" => {
                        opts.http_bind = it.next().ok_or("--http-bind needs an address")?.clone();
                    }
                    "--help" | "-h" => return Ok(Cmd::Help),
                    other => return Err(format!("unknown bootstrap flag: {other}")),
                }
            }
            Ok(Cmd::Bootstrap(opts))
        }
        other => Err(format!(
            "unknown command {other:?} (try: run | bootstrap | help)"
        )),
    }
}

pub fn help_text() -> &'static str {
    "pnet_installer — agent (run) or empty-machine bootstrap\n\
     \n\
     Commands:\n\
       run                  Long-running agent (default)\n\
       bootstrap            Install pNet + agent from local binaries, then start\n\
       help                 This text\n\
     \n\
     bootstrap flags:\n\
       --from DIR           Directory containing pnet and pnet_installer\n\
                            (default: directory of this executable, if both exist)\n\
       --prefix DIR         Install prefix (default: ~/.pnet)\n\
       --force              Overwrite existing binaries\n\
       --no-start           Copy and write start.sh only\n\
       --dry-run            Print plan, write nothing\n\
       --http-bind ADDR     PNET_HTTP_BIND for the started node (default 127.0.0.1)\n\
     \n\
     Phase 3 does not download packages. Signed catalog install is phase 4.\n"
}

pub fn resolve_from(opts: &mut Opts, current_exe: &Path) -> Result<(), String> {
    if opts.from.as_os_str().is_empty() {
        opts.from = infer_from(current_exe).ok_or_else(|| {
            "no --from DIR and pnet is not next to this binary\n\
             Unpack a dist folder (pnet + pnet_installer) and pass --from, or run from target/debug after cargo build."
                .to_string()
        })?;
    }
    Ok(())
}

pub fn plan(opts: &Opts) -> Result<Plan, String> {
    if !opts.from.is_dir() {
        return Err(format!("--from is not a directory: {}", opts.from.display()));
    }
    let bin_dir = opts.prefix.join("bin");
    let mut copies = Vec::new();
    for name in BINS {
        let src = opts.from.join(name);
        if !src.is_file() {
            return Err(format!("missing {} in {}", name, opts.from.display()));
        }
        let dest = bin_dir.join(name);
        let kind = if dest.is_file() {
            if opts.force {
                CopyKind::Overwrite
            } else {
                CopyKind::SkipExists
            }
        } else {
            CopyKind::Copy
        };
        copies.push((src, dest, kind));
    }
    Ok(Plan {
        copies,
        start_sh: opts.prefix.join("start.sh"),
        record: opts.prefix.join("bootstrap.json"),
    })
}

pub fn execute(opts: &Opts, plan: &Plan) -> Result<String, String> {
    let mut log = String::new();
    if opts.dry_run {
        log.push_str("dry-run (no writes)\n");
        for (src, dest, kind) in &plan.copies {
            log.push_str(&format!(
                "  {:?} {} -> {}\n",
                kind,
                src.display(),
                dest.display()
            ));
        }
        log.push_str(&format!("  write {}\n", plan.start_sh.display()));
        log.push_str(&format!("  write {}\n", plan.record.display()));
        return Ok(log);
    }

    fs::create_dir_all(opts.prefix.join("bin")).map_err(|e| e.to_string())?;
    fs::create_dir_all(opts.prefix.join("logs")).map_err(|e| e.to_string())?;
    fs::create_dir_all(opts.prefix.join("run")).map_err(|e| e.to_string())?;

    for (src, dest, kind) in &plan.copies {
        match kind {
            CopyKind::SkipExists => {
                log.push_str(&format!("keep {}\n", dest.display()));
            }
            CopyKind::Copy | CopyKind::Overwrite => {
                fs::copy(src, dest).map_err(|e| format!("copy {}: {e}", src.display()))?;
                chmod_755(dest)?;
                log.push_str(&format!("{:?} {}\n", kind, dest.display()));
            }
        }
    }

    let start = start_script(&opts.prefix, &opts.http_bind);
    fs::write(&plan.start_sh, start).map_err(|e| e.to_string())?;
    chmod_755(&plan.start_sh)?;
    log.push_str(&format!("wrote {}\n", plan.start_sh.display()));

    let rec = format!(
        "{{\n  \"installed_at\": {},\n  \"prefix\": {},\n  \"from\": {},\n  \"http_bind\": {}\n}}\n",
        unix_now(),
        json_str(&opts.prefix.to_string_lossy()),
        json_str(&opts.from.to_string_lossy()),
        json_str(&opts.http_bind),
    );
    fs::write(&plan.record, rec).map_err(|e| e.to_string())?;

    if opts.start {
        let status = Command::new(&plan.start_sh)
            .current_dir(&opts.prefix)
            .status()
            .map_err(|e| format!("start.sh: {e}"))?;
        if !status.success() {
            return Err(format!("start.sh exited {status}"));
        }
        log.push_str("started via start.sh\n");
    } else {
        log.push_str("not starting (--no-start); run start.sh when ready\n");
    }

    log.push_str(&format!(
        "Next: open http://{}:8777/setup to create a user or join with an invite.\n\
         Then Home → Installer for the catalog (still notify-only for other apps).\n",
        opts.http_bind
    ));
    Ok(log)
}

fn start_script(prefix: &Path, http_bind: &str) -> String {
    let p = prefix.display();
    format!(
        "#!/bin/sh\n\
         set -e\n\
         PREFIX=\"{p}\"\n\
         export PNET_HTTP_BIND={http_bind}\n\
         mkdir -p \"$PREFIX/logs\" \"$PREFIX/run\"\n\
         if [ ! -f \"$PREFIX/run/pnet.pid\" ] || ! kill -0 \"$(cat \"$PREFIX/run/pnet.pid\")\" 2>/dev/null; then\n\
           \"$PREFIX/bin/pnet\" >>\"$PREFIX/logs/pnet.log\" 2>&1 &\n\
           echo $! >\"$PREFIX/run/pnet.pid\"\n\
           sleep 1\n\
         fi\n\
         if [ ! -f \"$PREFIX/run/installer.pid\" ] || ! kill -0 \"$(cat \"$PREFIX/run/installer.pid\")\" 2>/dev/null; then\n\
           \"$PREFIX/bin/pnet_installer\" run >>\"$PREFIX/logs/installer.log\" 2>&1 &\n\
           echo $! >\"$PREFIX/run/installer.pid\"\n\
         fi\n\
         echo \"pNet bootstrap started. Portal: http://{http_bind}:8777/setup\"\n"
    )
}

fn chmod_755(path: &Path) -> Result<(), String> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn json_str(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        let mut n = [0u8; 8];
        let _ = getrandom::getrandom(&mut n);
        let p = std::env::temp_dir().join(format!("pnet-boot-{:x}", u64::from_le_bytes(n)));
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn dummy_from() -> PathBuf {
        let d = tmp();
        fs::write(d.join("pnet"), b"#!/bin/sh\necho pnet\n").unwrap();
        fs::write(d.join("pnet_installer"), b"#!/bin/sh\necho inst\n").unwrap();
        chmod_755(&d.join("pnet")).unwrap();
        chmod_755(&d.join("pnet_installer")).unwrap();
        d
    }

    #[test]
    fn parse_run_default_and_bootstrap_flags() {
        assert_eq!(parse_args(&["pnet_installer".into()]).unwrap(), Cmd::Run);
        assert_eq!(
            parse_args(&["pnet_installer".into(), "run".into()]).unwrap(),
            Cmd::Run
        );
        match parse_args(&[
            "pnet_installer".into(),
            "bootstrap".into(),
            "--from".into(),
            "/dist".into(),
            "--prefix".into(),
            "/opt/pnet".into(),
            "--no-start".into(),
            "--dry-run".into(),
            "--force".into(),
        ])
        .unwrap()
        {
            Cmd::Bootstrap(o) => {
                assert_eq!(o.from, PathBuf::from("/dist"));
                assert_eq!(o.prefix, PathBuf::from("/opt/pnet"));
                assert!(!o.start);
                assert!(o.dry_run);
                assert!(o.force);
            }
            _ => panic!("expected bootstrap"),
        }
    }

    #[test]
    fn infer_from_requires_both_bins() {
        let d = dummy_from();
        let exe = d.join("pnet_installer");
        assert_eq!(infer_from(&exe), Some(d.clone()));
        fs::remove_file(d.join("pnet")).unwrap();
        assert!(infer_from(&exe).is_none());
    }

    #[test]
    fn plan_errors_on_missing_bin() {
        let d = tmp();
        fs::write(d.join("pnet"), b"x").unwrap();
        let o = Opts {
            prefix: tmp(),
            from: d,
            force: false,
            start: false,
            dry_run: true,
            http_bind: "127.0.0.1".into(),
        };
        assert!(plan(&o).unwrap_err().contains("missing pnet_installer"));
    }

    #[test]
    fn execute_copies_and_writes_start_without_launching() {
        let from = dummy_from();
        let prefix = tmp();
        let o = Opts {
            prefix: prefix.clone(),
            from,
            force: false,
            start: false,
            dry_run: false,
            http_bind: "127.0.0.1".into(),
        };
        let p = plan(&o).unwrap();
        let log = execute(&o, &p).unwrap();
        assert!(log.contains("not starting"));
        assert!(prefix.join("bin/pnet").is_file());
        assert!(prefix.join("bin/pnet_installer").is_file());
        let sh = fs::read_to_string(prefix.join("start.sh")).unwrap();
        assert!(sh.contains("PNET_HTTP_BIND=127.0.0.1"));
        assert!(sh.contains("pnet_installer\" run"));
        assert!(prefix.join("bootstrap.json").is_file());
        // second run without --force keeps existing
        let p2 = plan(&o).unwrap();
        assert!(p2.copies.iter().all(|c| c.2 == CopyKind::SkipExists));
    }

    #[test]
    fn dry_run_writes_nothing() {
        let from = dummy_from();
        let prefix = tmp();
        let o = Opts {
            prefix: prefix.clone(),
            from,
            force: false,
            start: true,
            dry_run: true,
            http_bind: "127.0.0.1".into(),
        };
        let p = plan(&o).unwrap();
        execute(&o, &p).unwrap();
        assert!(!prefix.join("bin/pnet").exists());
    }
}
