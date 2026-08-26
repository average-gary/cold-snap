//! One job: make cargo notice when `link.x` changes.
//!
//! The script itself is wired in by `-C link-arg=-Tfirmware/link.x` in the repo
//! root's `.cargo/config.toml`, but a `-C link-arg` is invisible to cargo's
//! fingerprint — cargo has no idea the file is an input. MEASURED: editing the
//! memory map and re-running `cargo build --release` silently reuses the old
//! image, including a map that violates the containment ASSERTs (both negative
//! tests passed the build until `src/main.rs` was touched). On a unit where a bad
//! map bricks permanently and DFU is impossible at RDP=2, "my fix didn't take"
//! must not be a reachable state.
fn main() {
    println!("cargo:rerun-if-changed=link.x");
}
