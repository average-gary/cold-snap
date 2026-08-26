//! `checkfw` — pre-flight: **would the Mk4 bootloader's `verify_firmware()`
//! accept this artifact?** Host-only example; nothing here reaches the ARM image
//! (`cargo build --release` builds lib and bin targets only, and `secp256k1` is a
//! DEV-dependency).
//!
//! ```text
//! cargo run --target aarch64-apple-darwin -p coldsnap_firmware \
//!         --example checkfw -- /path/to/coldsnap-dev.dfu
//! ```
//!
//! Exit codes: `0` accept · `1` refuse · `2` usage · `3` self-test failed (the
//! crypto path is broken and NOTHING was reported about the artifact).
//!
//! It exists so a bench session never ends in "it did not boot and we do not know
//! why". Every rule cites the line in `mk4-bootloader/` that enforces it, so a
//! failure is fixable from the message alone.
//!
//! Two things it deliberately does NOT do:
//!
//! * It does not reimplement the signed range. `coldsnap_firmware::firmware_digest`
//!   owns it (`firmware/src/lib.rs:615`, hashing `verify.c:80-89`'s two spans);
//!   this file only adds the OUTER SHA-256, because that function is single-hash
//!   by deliberate coordinator convention while `fw_check` is double
//!   (`verify.c:226`). Two implementations of the range would be two things to
//!   keep in sync, and if they ever disagreed this checker would be worthless.
//! * It does not claim completeness. Four rules are device state, not file
//!   content; they are printed as NOT CHECKED on every run, pass or fail.

use coldsnap_firmware::firmware_digest;
use coldsnap_hal::memmap;
use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};
use sha2::{Digest, Sha256};

const HDR_OFF: usize = memmap::FW_HEADER_OFFSET as usize; // 0x3f80
const HDR_END: usize = HDR_OFF + memmap::FW_HEADER_SIZE as usize; // 0x4000
const MAGIC: u32 = 0xCC00_1234; // sigheader.h:41
const MAX_LEN: u32 = 0x0020_0000 - 0x0002_0000; // FW_MAX_LENGTH_MK4, sigheader.h:53
const NUM_KNOWN_PUBKEYS: u32 = 6; // firmware-keys.h:5
/// `signit.py:302-306` re-aligns the Mk4/Mk5 body to the 4 K flash erase unit,
/// which `verify.c:106` ties to `psram_do_upgrade`'s page-erase stride. NOT
/// `memmap::FW_BODY_ALIGN` (512, the mk1-3 rule) — see finding in the report.
const MK4_ALIGN: u32 = 4096;

/// `approved_pubkeys[0]` verbatim (`mk4-bootloader/firmware-keys.h:10-11`), the
/// published dev key whose private half is `stm32/keys/00.pem`. Raw X||Y, so
/// `PublicKey::from_slice` needs an `0x04` prefix. Keys 1-5 are Coinkite's and
/// are not embedded: an artifact claiming one of those is UNVERIFIABLE here and
/// is refused rather than waved through.
const PUBKEY0: [u8; 64] = [
    0xb4, 0xcb, 0x41, 0x26, 0xf7, 0xe1, 0x6c, 0xf3, 0x8f, 0xf2, 0xb4, 0x71, 0x1d, 0xfb, 0x23, 0x01,
    0x0d, 0x76, 0xd6, 0x66, 0xa7, 0x8a, 0xa3, 0x6c, 0x9b, 0x53, 0xf9, 0xf6, 0x7b, 0x58, 0x18, 0x05,
    0x58, 0x0b, 0x3b, 0xe9, 0x31, 0xc4, 0x9f, 0xb8, 0x44, 0x04, 0x3c, 0x11, 0x96, 0x08, 0x0f, 0x47,
    0x81, 0x25, 0xed, 0x37, 0x7a, 0x23, 0x9e, 0x4a, 0xaf, 0xb7, 0x18, 0x38, 0xba, 0x38, 0x04, 0xda,
];

/// KNOWN-GOOD cross-check vector, measured from Coldcard's own released Mk4
/// 6.3.5X image (`coldcard-firmware/stm32/built/firmware-signed.bin`, itself
/// signed with `pubkey_num=0`). The reference tree is not vendored, so the
/// *numbers* are embedded instead of the file: `fw_check` is
/// `sha256(sha256(img[..0x3fc0] ++ img[0x4000..0xfa000]))` and `REF_SIG` is that
/// header's 64-byte `r||s`. Verifying these before looking at the artifact is the
/// fail-closed self-test — it is what makes a printed "ACCEPT" mean something.
/// Run the full-file version by hand (see the report) to validate the RANGE too.
const REF_FW_CHECK: [u8; 32] = [
    0x87, 0xd1, 0x6b, 0xf4, 0xf5, 0x74, 0x40, 0x3b, 0x69, 0xaf, 0xba, 0x11, 0xdd, 0x4a, 0xfe, 0x2b,
    0x18, 0x37, 0xd9, 0xe2, 0x8c, 0x56, 0x41, 0xe8, 0xe8, 0x41, 0x4f, 0x94, 0x28, 0x25, 0x1a, 0x2d,
];
const REF_SIG: [u8; 64] = [
    0x34, 0x48, 0xef, 0x0f, 0xc9, 0x03, 0xc8, 0x76, 0x91, 0xcb, 0xf1, 0x59, 0x31, 0x01, 0x19, 0x50,
    0x64, 0xf3, 0xff, 0x07, 0xe2, 0xe9, 0xb8, 0x6f, 0xe0, 0x84, 0xbc, 0xef, 0x8f, 0x20, 0x5d, 0xfe,
    0x5f, 0xa3, 0xf5, 0xca, 0x6a, 0x06, 0xaf, 0x6b, 0x73, 0x43, 0xb5, 0xda, 0xfd, 0x4d, 0x4f, 0xe4,
    0xfa, 0x52, 0x67, 0xf0, 0xdb, 0x88, 0xda, 0xdc, 0xad, 0x84, 0x54, 0x85, 0xfd, 0x65, 0xe8, 0xbd,
];
/// `n - s` for `REF_SIG`, i.e. the same signature in HIGH-S form. `uECC_verify`
/// (`verify.c:232`) accepts it; libsecp256k1 refuses it outright
/// (`secp256k1.h:544`, "only ECDSA signatures in lower-S form are accepted") and
/// `signit.py:354`'s `sign_digest` does not canonicalise S, so ~half of all
/// perfectly bootable images land here. That is why `normalize_s()` below is
/// load-bearing, and this vector is what keeps it honest.
const REF_SIG_HIGH_S: [u8; 32] = [
    0xa0, 0x5c, 0x0a, 0x35, 0x95, 0xf9, 0x50, 0x94, 0x8c, 0xbc, 0x4a, 0x25, 0x02, 0xb2, 0xb0, 0x19,
    0xc0, 0x5c, 0x74, 0xf5, 0xd3, 0xbf, 0xc5, 0x5f, 0x12, 0x4e, 0x0a, 0x06, 0xd2, 0xd0, 0x58, 0x84,
];

fn main() {
    let secp = Secp256k1::verification_only();
    if let Err(why) = selftest(&secp) {
        eprintln!("SELF-TEST FAILED: {why}\nNothing was checked. Do not trust any earlier run.");
        std::process::exit(3);
    }

    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: checkfw <firmware-signed.bin | coldsnap.dfu>");
        std::process::exit(2);
    };
    let raw = match std::fs::read(&path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("cannot read {path}: {e}");
            std::process::exit(2);
        }
    };

    println!("artifact: {path}  ({} B)", raw.len());
    println!("self-test: reference 6.3.5X vector verifies; high-S refused pre-normalize");
    let (image, note) = match locate_image(&raw) {
        Ok(v) => v,
        Err(why) => {
            println!("[FAIL] R0 container: {why}");
            verdict(1, 1);
        }
    };
    println!("source:   {note}");

    let rules = check(&secp, image);
    let failed = rules.iter().filter(|(ok, _)| !ok).count();
    // R1-R7 and R12 are verify_firmware()'s own, in its order. R8-R11 are the
    // installer's and the packer's; each cites where it really lives, because
    // claiming the bootloader enforces something it does not is the same class of
    // lie as claiming a signature is valid when it is not.
    println!("\nrules checkable from this file alone:");
    for (ok, txt) in &rules {
        println!("  [{}] {txt}", if *ok { "PASS" } else { "FAIL" });
    }
    unchecked();
    verdict(rules.len(), failed);
}

fn verdict(total: usize, failed: usize) -> ! {
    if failed == 0 {
        println!("\nRESULT: ACCEPT — {total}/{total} locally checkable rules pass.");
        println!("        4 rules above are UNCHECKED. This is not a boot guarantee.");
        std::process::exit(0);
    }
    println!("\nRESULT: REFUSE — {failed} of {total} rules failed. Read each citation:");
    println!("        R1-R7/R12 → the BOOT refuses (verify.c:320/332) → screen_corrupt");
    println!("        → psram_recover_firmware → while(1) sdcard_recovery().");
    println!("        R8-R11 → verify_header would pass, but the INSTALL is wrong");
    println!("        (4 K erase stride, burn length, or verify.c:256's downgrade gate).");
    std::process::exit(1);
}

/// Fail-closed check of the one thing that cannot be eyeballed: the ECDSA path.
fn selftest(secp: &Secp256k1<secp256k1::VerifyOnly>) -> Result<(), String> {
    let pk = pubkey(0).map_err(|e| format!("pubkey 0 rejected: {e}"))?;
    let msg = Message::from_digest(REF_FW_CHECK);
    let sig = Signature::from_compact(&REF_SIG).map_err(|e| format!("ref sig parse: {e}"))?;
    if secp.verify_ecdsa(&msg, &sig, &pk).is_err() {
        return Err("released 6.3.5X signature does not verify under key 0".into());
    }
    let mut flipped = REF_FW_CHECK;
    flipped[0] ^= 1;
    if secp
        .verify_ecdsa(&Message::from_digest(flipped), &sig, &pk)
        .is_ok()
    {
        return Err("a one-bit digest change still verified — the check is decorative".into());
    }
    let mut high = REF_SIG;
    high[32..].copy_from_slice(&REF_SIG_HIGH_S);
    let mut hsig = Signature::from_compact(&high).map_err(|e| format!("high-S parse: {e}"))?;
    if secp.verify_ecdsa(&msg, &hsig, &pk).is_ok() {
        return Err("high-S verified before normalize_s — vector is wrong".into());
    }
    hsig.normalize_s();
    if secp.verify_ecdsa(&msg, &hsig, &pk).is_err() {
        return Err("normalize_s did not rescue a high-S signature".into());
    }
    Ok(())
}

fn pubkey(num: u32) -> Result<PublicKey, String> {
    if num != 0 {
        return Err(format!(
            "cannot verify: only approved_pubkeys[0] is embedded here, and key \
             {num} is not (1-5 are Coinkite's, >= 6 does not exist — \
             firmware-keys.h:5,8). Refusing rather than waving it through"
        ));
    }
    let mut sec1 = [4u8; 65];
    sec1[1..].copy_from_slice(&PUBKEY0);
    PublicKey::from_slice(&sec1).map_err(|e| e.to_string())
}

/// The bytes that land at `FLASH_ISR_BASE`. Accepts a raw `signit.py` output or a
/// DfuSe file, walking it the way `mk4-bootloader/sdcard.c:156-205` does — so the
/// thing checked is the thing that ships. Every length here comes out of the file
/// and is therefore attacker-controlled: all arithmetic is checked.
fn locate_image(raw: &[u8]) -> Result<(&[u8], String), String> {
    if !raw.starts_with(b"DfuSe") {
        return Ok((
            raw,
            format!(
                "raw binary, assumed to be the image at {:#010x}",
                memmap::FLASH_ISR_BASE
            ),
        ));
    }
    // DfuSe prefix 11 B; target prefix 274 B ("Target" 6, alt 1, named 4,
    // name 255, size 4, nbElements 4); then nbElements × (addr u32, size u32, data).
    let n_elem = u32::from_le_bytes(
        raw.get(281..285)
            .ok_or("DfuSe file truncated inside target prefix")?
            .try_into()
            .unwrap(),
    );
    let mut at = 285usize;
    let mut seen = Vec::new();
    for _ in 0..n_elem {
        let hdr = raw
            .get(at..at + 8)
            .ok_or_else(|| format!("DfuSe element header at {at} runs past EOF"))?;
        let addr = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
        let size = u32::from_le_bytes(hdr[4..8].try_into().unwrap()) as usize;
        let body = at
            .checked_add(8)
            .and_then(|s| s.checked_add(size))
            .and_then(|e| raw.get(at + 8..e))
            .ok_or_else(|| format!("DfuSe element at {addr:#010x} claims {size} B, past EOF"))?;
        if addr == memmap::FLASH_ISR_BASE {
            return Ok((
                body,
                format!("DfuSe element {addr:#010x}, {size} B of {} in file", raw.len()),
            ));
        }
        seen.push(format!("{addr:#010x}"));
        at += 8 + size;
    }
    Err(format!(
        "no DfuSe element at {:#010x} (found: {}) — dfu.py -b 0x08020000:<bin>",
        memmap::FLASH_ISR_BASE,
        seen.join(", ")
    ))
}

fn check(secp: &Secp256k1<secp256k1::VerifyOnly>, image: &[u8]) -> Vec<(bool, String)> {
    let mut r = Vec::new();
    let mut rule = |id: &str, ok: bool, what: &str, expect: String, actual: String, cite: &str| {
        r.push((
            ok,
            format!("{id} {what}: expected {expect}, actual {actual}  [{cite}]"),
        ));
    };

    let Some(h) = image.get(HDR_OFF..HDR_END) else {
        rule(
            "R1",
            false,
            "header present",
            format!("image >= {HDR_END} B"),
            format!("{} B", image.len()),
            "verify.h:12",
        );
        return r;
    };
    let u32at = |o: usize| u32::from_le_bytes(h[o..o + 4].try_into().unwrap());
    let magic = u32at(0);
    let ts = &h[4..12];
    let ver = &h[12..20];
    let pubkey_num = u32at(20);
    let length = u32at(24);
    let printable: String = ver
        .iter()
        .take_while(|&&b| b != 0)
        .map(|&b| if b.is_ascii_graphic() { b as char } else { '?' })
        .collect();

    println!(
        "header:   @{HDR_OFF:#x} magic {magic:#010x} version {printable:?} ts {} \
         pubkey_num {pubkey_num} firmware_length {length} ({length:#x}) \
         install_flags {:#x} hw_compat {:#x}",
        hex(ts),
        u32at(28),
        u32at(32)
    );

    rule(
        "R1",
        magic == MAGIC,
        "magic_value",
        format!("{MAGIC:#010x}"),
        format!("{magic:#010x}"),
        "verify.c:212",
    );
    rule(
        "R2",
        ver[0] != 0xff,
        "version_string[0] (unprogrammed?)",
        "!= 0xff".into(),
        format!("{:#04x}", ver[0]),
        "verify.c:319",
    );
    rule(
        "R3",
        ver[0] != 0x00,
        "version_string[0] (empty?)",
        "!= 0x00".into(),
        format!("{:#04x}", ver[0]),
        "verify.c:213",
    );
    rule(
        "R4",
        ts[0] < 0x40,
        "timestamp[0] (BCD year)",
        "< 0x40".into(),
        format!("{:#04x}", ts[0]),
        "verify.c:214",
    );
    rule(
        "R5",
        length >= memmap::FW_MIN_BODY_LEN,
        "firmware_length floor",
        format!(">= {}", memmap::FW_MIN_BODY_LEN),
        length.to_string(),
        "verify.c:215",
    );
    rule(
        "R6",
        length < MAX_LEN,
        "firmware_length ceiling",
        format!("< {MAX_LEN} ({MAX_LEN:#x})"),
        format!("{length} ({length:#x})"),
        "verify.c:216",
    );
    rule(
        "R7",
        pubkey_num < NUM_KNOWN_PUBKEYS,
        "pubkey_num",
        format!("< {NUM_KNOWN_PUBKEYS}"),
        pubkey_num.to_string(),
        "verify.c:217",
    );
    // Not a verify_header() rule — the bootloader has NO alignment test
    // (verify.c:212-217) — but psram_do_upgrade page-erases as it writes, so a
    // non-4K length corrupts the tail of the install.
    rule(
        "R8",
        length % MK4_ALIGN == 0,
        "firmware_length alignment",
        format!("multiple of {MK4_ALIGN}"),
        format!("{length} % {MK4_ALIGN} = {}", length % MK4_ALIGN),
        "signit.py:305, verify.c:106",
    );
    // verify_firmware_in_ram ignores its own `len` and hashes firmware_length
    // bytes, while psram_do_upgrade burns `size` bytes. They must be equal or the
    // installer hashes PSRAM nobody loaded / burns past the signed range.
    rule(
        "R9",
        image.len() == length as usize,
        "element size vs firmware_length",
        format!("{length}"),
        format!("{}", image.len()),
        "verify.c:247+273, psram.c:310",
    );
    // Install path only (check_is_downgrade, reached from verify_firmware_in_ram
    // at verify.c:256), never at boot. signit's default "0.1a" is refused.
    let major_ok = ver[1] != b'.' || (ver[0] as char).to_digit(10).unwrap_or(0) >= 3;
    rule(
        "R10",
        major_ok,
        "version major (install-time downgrade gate)",
        ">= 3, or version[1] != '.'".into(),
        printable.clone(),
        "verify.c:171-172",
    );
    // signit.py:263 asserts len < 8; the bootloader only ever reads [0] and [1],
    // but a non-NUL-terminated string is a packer bug worth catching here.
    let nul = ver.iter().position(|&b| b == 0);
    rule(
        "R11",
        nul.is_some() && ver[nul.unwrap_or(0)..].iter().all(|&b| b == 0),
        "version_string NUL-padded",
        "len < 8, tail all zero".into(),
        hex(ver),
        "signit.py:263",
    );

    // The signature. `firmware_digest` owns the range; we add only the outer hash.
    match firmware_digest(image) {
        None => rule(
            "R12",
            false,
            "signature (range unusable)",
            "firmware_digest() -> Some".into(),
            format!(
                "None: one of length >= {} / length % {} == 0 / length <= {} failed",
                memmap::FW_MIN_BODY_LEN,
                memmap::FW_BODY_ALIGN,
                image.len()
            ),
            "firmware/src/lib.rs:615",
        ),
        Some(inner) => {
            let fw_check: [u8; 32] = Sha256::digest(inner.0).into();
            let ok = pubkey(pubkey_num).and_then(|pk| {
                let mut sig =
                    Signature::from_compact(&h[64..128]).map_err(|e| format!("sig parse: {e}"))?;
                // uECC has no low-S rule and signit.py does not canonicalise, so
                // normalize BEFORE verifying or half of all valid images would be
                // reported as forged.
                sig.normalize_s();
                secp.verify_ecdsa(&Message::from_digest(fw_check), &sig, &pk)
                    .map_err(|e| e.to_string())
            });
            rule(
                "R12",
                ok.is_ok(),
                "signature over double-SHA256(signed range)",
                format!("valid under approved_pubkeys[{pubkey_num}]"),
                match &ok {
                    Ok(()) => format!("valid (S normalized); fw_check {}", hex(&fw_check)),
                    Err(e) => format!("{e}; fw_check {}", hex(&fw_check)),
                },
                "verify.c:226+232",
            );
            if pubkey_num == 0 {
                println!(
                    "note:     pubkey_num 0 is the published dev key: expect a \
                     'WARN: Unsigned firmware' screen and a forced delay \
                     (verify.c:349) unless the red-light branch wins first (:344)."
                );
            }
        }
    }
    r
}

/// The rules that are NOT a function of this file. Printed on every run,
/// including a passing one: a checker that prints OK while silently skipping half
/// the rules converts an unknown into a false assurance, and the cost lands on a
/// bench.
fn unchecked() {
    println!("\nNOT CHECKED — device state, absent from this file:");
    for l in [
        "U1 world checksum / SE1 CHECKMAC of KEYNUM_firmware (verify.c:305,326,336).",
        "   Covers flash OUTSIDE the image (LFS2, OTP, bootloader), so no file can",
        "   satisfy it. A never-blessed image takes the 'WARN: Red light' branch",
        "   (verify.c:344-347): ~25 s delay under a RELEASE bootloader, then BOOTS.",
        "U2 OTP min-version floor (verify.c:143 get_min_version, :181). Install path",
        "   only, and it grows with every install already done on that unit.",
        "U3 RDP level (verify.c:340 flash_is_security_level2). Decides 'Factory boot'",
        "   vs red-light, and whether a failed verify can still reach enter_dfu.",
        "U4 That an install path exists at all: only pins.c:1276-1340, from logged-in",
        "   MicroPython, installs NEW firmware. sdcard_recovery cannot (sdcard.c:248",
        "   needs SE1 to already hold THIS image's world hash).",
    ] {
        println!("  {l}");
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
