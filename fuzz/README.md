# Wire fuzzing (§8.2)

Untrusted UDP/sync blobs must never panic the node. This tree documents how to
stress the pure parsers for:

| Target | Codec |
|--------|--------|
| `bootstrap_payload` | device bootstrap user blob |
| `public_state` | public directory snapshot |
| `contact_data` | cross-user contact directory slice |
| `contact_payload` | contact-card exchange |
| `change_payload` | write-log `Change` |

## Default: pure-Rust mutational fuzzer (no clang)

Works on any host with a Rust toolchain (this environment has no libFuzzer/clang):

```bash
# Short CI-style run (also covered by unit tests under pnet::fuzz)
cargo test -p pnet fuzz -- --nocapture

# Longer campaign
cargo run --release --bin pnet_fuzz_wire -- --iters 100000 --seed 1

# One blob through every parser (handy for crash minimization)
cargo run --release --bin pnet_fuzz_wire -- --once < some_input.bin
```

Entry points live in `pnet::fuzz` (`fuzz_parse`, `run_campaign`, seed corpus).

## Optional: cargo-fuzz / libFuzzer

If you have **clang** and `cargo-fuzz` installed:

```bash
cargo install cargo-fuzz
# From repo root — scaffold would look like:
#   fuzz/fuzz_targets/*.rs calling pnet::fuzz::fuzz_parse
# Parent workspace excludes this directory (see root Cargo.toml `exclude = ["fuzz"]`).
```

libFuzzer was not wired as the default because this CI host lacks clang; the
mutational binary covers the same parsers without a C toolchain.
