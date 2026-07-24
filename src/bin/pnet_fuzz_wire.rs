//! Mutational wire fuzzer for bootstrap / directory / change codecs (§8.2).
//!
//! Pure Rust — no libFuzzer/clang. Mutates seed corpora and pure-random
//! buffers; success is **no panic**.
//!
//! ```text
//! cargo run --release --bin pnet_fuzz_wire -- --iters 100000
//! cargo run --release --bin pnet_fuzz_wire -- --iters 50000 --seed 1
//! # Single input (AFL-style): feed a file or stdin to every parser
//! cargo run --release --bin pnet_fuzz_wire -- --once < crash.bin
//! ```

use std::env;
use std::io::{self, Read};
use std::process;

use pnet::fuzz::{fuzz_all_parsers, run_campaign, FuzzTarget};

fn usage() -> ! {
    eprintln!(
        "pnet_fuzz_wire — mutational fuzzer for pNet wire codecs

Usage:
  pnet_fuzz_wire [--iters N] [--seed S]   mutational campaign (default N=10000, S=1)
  pnet_fuzz_wire --once                   read one blob from stdin; parse with all codecs
  pnet_fuzz_wire --list                   list target names
  pnet_fuzz_wire --help

Targets: bootstrap_payload, public_state, contact_data, contact_payload, change_payload
"
    );
    process::exit(2);
}

fn main() {
    let mut iters: usize = 10_000;
    let mut seed: u64 = 1;
    let mut once = false;
    let mut args = env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--help" | "-h" => usage(),
            "--list" => {
                for t in FuzzTarget::ALL {
                    println!("{}", t.name());
                }
                return;
            }
            "--once" => once = true,
            "--iters" => {
                let v = args.next().unwrap_or_else(|| usage());
                iters = v.parse().unwrap_or_else(|_| {
                    eprintln!("bad --iters");
                    process::exit(2);
                });
            }
            "--seed" => {
                let v = args.next().unwrap_or_else(|| usage());
                seed = v.parse().unwrap_or_else(|_| {
                    eprintln!("bad --seed");
                    process::exit(2);
                });
            }
            other => {
                eprintln!("unknown arg: {other}");
                usage();
            }
        }
    }

    if once {
        let mut buf = Vec::new();
        io::stdin()
            .read_to_end(&mut buf)
            .expect("read stdin");
        fuzz_all_parsers(&buf);
        eprintln!(
            "pnet_fuzz_wire: once ok ({} bytes, {} targets)",
            buf.len(),
            FuzzTarget::ALL.len()
        );
        return;
    }

    eprintln!(
        "pnet_fuzz_wire: campaign iters_per_target={iters} seed={seed} targets={}",
        FuzzTarget::ALL.len()
    );
    let (inputs, ok) = run_campaign(iters, seed);
    eprintln!("pnet_fuzz_wire: done inputs={inputs} well_formed_accepts={ok}");
}
