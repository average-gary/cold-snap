//! Fails the build by name, before `src/main.rs` compiles, when `../../frostsnap` is
//! missing, is not its own git checkout, or is not at (or ahead of) the commit in
//! `frostsnap.rev`. See `check-frostsnap-pin.sh` for the policy; README "Bumping the
//! frostsnap pin". Re-runs when the pinned crates' sources change, not only on a HEAD move.
//! A missing `../../frostsnap/frostsnap_coordinator` fails even earlier,
//! in cargo's own path resolution, which runs before any build script.
use std::{path::Path, process::Command};

fn main() {
    // Read at run time: `env!` would bake in the directory the script was first compiled in.
    let dir = std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR");
    let fs = Path::new(&dir).join("../../frostsnap");
    println!("cargo:rerun-if-changed=frostsnap.rev");
    println!("cargo:rerun-if-changed=check-frostsnap-pin.sh");
    for p in ["HEAD", "packed-refs", "refs/heads"] {
        println!("cargo:rerun-if-changed={}", fs.join(".git").join(p).display());
    }
    // The EDITED check must re-run when a pinned crate's source changes, not only when HEAD
    // moves: once any rerun-if-changed is printed, cargo re-runs this script only for the
    // listed paths (a directory is scanned recursively). The list is the script's own
    // `crates=` line, so the two cannot drift apart.
    let script = std::fs::read_to_string("check-frostsnap-pin.sh")
        .expect("FROSTSNAP PIN: could not read check-frostsnap-pin.sh");
    let crates = script
        .lines()
        .find_map(|l| l.strip_prefix("crates=\""))
        .and_then(|l| l.strip_suffix('"'))
        .expect("FROSTSNAP PIN: no `crates=\"...\"` line in check-frostsnap-pin.sh");
    for c in crates.split_whitespace() {
        println!("cargo:rerun-if-changed={}", fs.join(c).display());
    }
    let out = Command::new("sh")
        .arg("check-frostsnap-pin.sh")
        .arg(&fs)
        .output()
        .expect("FROSTSNAP PIN: could not run `sh check-frostsnap-pin.sh`");
    let text = String::from_utf8_lossy(&out.stdout);
    match out.status.code() {
        Some(0) => {}
        Some(3) => text.lines().for_each(|l| println!("cargo:warning={l}")),
        _ => {
            eprint!("{text}{}", String::from_utf8_lossy(&out.stderr));
            eprintln!("FROSTSNAP PIN: check {}; refusing to build hostcheck", out.status);
            std::process::exit(1);
        }
    }
}
