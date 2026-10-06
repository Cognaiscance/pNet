//! `pnet --version` is how the installer compares binaries. It must exit
//! before the node creates or reads `~/.pnet/data`.

use std::fs;
use std::process::Command;

fn home() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "pnet-version-flag-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(home: &std::path::Path, arg: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_pnet"))
        .arg(arg)
        .env("HOME", home)
        .env_remove("PNET_KEY_PASSPHRASE")
        .env_remove("PNET_GRADE")
        .output()
        .unwrap()
}

#[test]
fn version_flags_print_the_package_version_and_skip_the_data_dir() {
    let expected = format!("pnet {}\n", env!("CARGO_PKG_VERSION"));
    for arg in ["--version", "-V"] {
        let home = home();
        let out = run(&home, arg);
        assert!(out.status.success(), "{arg} status: {}", out.status);
        assert_eq!(String::from_utf8(out.stdout).unwrap(), expected);
        assert!(
            out.stderr.is_empty(),
            "{arg} stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            !home.join(".pnet").exists(),
            "{arg} created {}",
            home.join(".pnet").display()
        );
        let _ = fs::remove_dir_all(&home);
    }
}
