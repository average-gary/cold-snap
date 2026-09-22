//! The checked Mk4 image contract: what makes a staged image **installable**, as
//! distinct from merely transferable.
//!
//! Two boundaries, and conflating them is the defect this module exists to
//! prevent:
//!
//! * **Transfer-stage validity** — `firmware::upgrade::Stager`'s rules. Word
//!   alignment, `memmap::FW_BODY_ALIGN` (512, `cli/signit.py:295`), the
//!   `[BURN_LEN_MIN, BURN_LEN_MAX]` window, exact `received == size`, and a digest
//!   recomputed from PSRAM read-back. Those say *the bytes we hold are the bytes
//!   that were announced*. They do NOT say the image could boot: the synthetic
//!   262,656-byte short-tail fixture that `hostcheck`'s M13 and `upgrade.rs`'s
//!   tests both use satisfies every one of them and is not a shippable image.
//! * **Installability** — this module. Everything that has to hold before a burn
//!   could be contemplated, over the staged bytes alone.
//!
//! # The rules here, and where each comes from
//!
//! | rule | source | who else enforces it |
//! |---|---|---|
//! | header readable at `memmap::FW_HEADER_OFFSET` | `sigheader.h:38-39` | `verify.h:12` |
//! | `magic_value == 0xCC00_1234` | `sigheader.h:41` | `verify.c:212`, `checkfw` R1 |
//! | `hw_compat` admits Mk4 | `sigheader.h:71` | MicroPython `shared/utils.py:401-417` **only** |
//! | header length agrees with the announced length | `psram::check_burn_len` | nothing upstream — see its docs |
//! | length in `[BURN_LEN_MIN, BURN_LEN_MAX]`, not truncated | `psram::staged_burn_len` | `verify.c:215-216`, `psram.c:310` |
//! | `length % 4096 == 0` | `cli/signit.py:305` | `checkfw` R8 |
//!
//! Two of those have **no counterpart in the bootloader at all**, which is stated
//! here rather than implied:
//!
//! * `hw_compat` is not tested anywhere in `mk4-bootloader/`
//!   (`grep hw_compat verify.c` = 0 hits; `sigheader.h:32,67-73` only declares it).
//!   The one enforcer in the reference tree is MicroPython's
//!   `shared/utils.py:401-417`, i.e. the **installer**, not the boot path. So on
//!   this device the installer boundary is the only applicable one and this module
//!   is it.
//! * 4 KiB alignment is not tested in `verify_header` either (`verify.c:212-217`
//!   has no alignment rule). It matters because `psram_do_upgrade` page-erases as
//!   it writes at the 4 K flash erase unit (`verify.c:106`), so a length that is
//!   512-aligned but not 4,096-aligned erases past the end of the image it just
//!   wrote. `signit.py:305` is what guarantees every real Mk4/Mk5 artifact is a
//!   multiple of 4,096.
//!
//! The two are coupled in the reference packer, and the coupling is the reason
//! both live in one function: `signit.py:297-306` takes the 4,096 branch **only**
//! when `hw_compat` names no Mk1-3 product. An image claiming Mk3 *and* Mk4
//! compatibility is deliberately padded to 512-but-not-4,096 by `signit.py:300`,
//! and such an image is refused here — correctly, because the Mk4 erase stride is
//! what it would be installed with.
//!
//! # What this is NOT
//!
//! Not authentication and not permission. The key-0 wrapper
//! (`firmware/examples/checkfw.rs`) is a FORMAT check whose private half is
//! published (`coldcard-firmware/stm32/keys/README.md`), the digest is an
//! integrity check on the transfer, and these rules are a shape check. None of
//! them is evidence about who sent the image or whether it is worth trusting;
//! there is no release allowlist, no manifest, no registry and no rollback
//! ratchet here, and nothing in this module writes anything.
//!
//! # Allocation and target
//!
//! Pure, `no_std`, allocation-free, `&[u8]` in and a `Result` out, no `self`. That
//! is what lets the SAME code be the device-side install boundary
//! (`firmware::upgrade::Stager::installable`) and a host-side pre-flight rule
//! (`checkfw` R8/R13) with no second implementation. `hostcheck` cannot call it —
//! one cargo graph will not hold `coldsnap_hal` and upstream
//! `frostsnap_coordinator` (`hostcheck/Cargo.toml`) — so that consumer is
//! cross-checked by the fixed golden vector in `golden/mk4-staging-vectors.txt`
//! instead.

use crate::memmap;
use crate::psram::{self, StageError};

/// `coldcardFirmwareHeader_t.magic_value` (`sigheader.h:41` `FW_HEADER_MAGIC`),
/// checked by the bootloader at `verify.c:212`. Field offset 0
/// (`sigheader.h:26`).
pub const FW_HEADER_MAGIC: u32 = 0xCC00_1234;

/// Byte offset of `hw_compat` within the 128-byte header.
///
/// The running sum of `coldcardFirmwareHeader_t` (`sigheader.h:26-32`):
/// `magic_value` 4 + `timestamp` 8 + `version_string` 8 + `pubkey_num` 4 +
/// `firmware_length` 4 + `install_flags` 4 = 32. Pinned against
/// `offsetof(coldcardFirmwareHeader_t, hw_compat)` by
/// `tools/check-reference-contracts.py`, so this is read from the reference rather
/// than counted by hand a second time.
pub const HW_COMPAT_FIELD_OFFSET: u32 = 32;

/// The `hw_compat` bit meaning "this release runs on an Mk4" (`sigheader.h:71`).
pub const MK_4_OK: u32 = 0x08;

/// Why a staged image is not installable. Every variant is a VALUE; nothing here
/// panics on attacker-supplied bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotInstallable {
    /// Nothing is staged and verified yet, so there is nothing to install.
    ///
    /// Produced by `Stager::installable` alone: staging must have reached
    /// `State::Staged` — i.e. the announced digest already matched a PSRAM
    /// read-back — before this module's rules mean anything.
    Unstaged,

    /// The staged window is not readable, or is too short to hold a header.
    Unreadable,

    /// `magic_value` is not [`FW_HEADER_MAGIC`]. Carries what was found.
    Magic(u32),

    /// `hw_compat` does not admit this hardware. Carries the field.
    WrongFamily(u32),

    /// The header's `firmware_length` is not the announced length, or is outside
    /// `[BURN_LEN_MIN, BURN_LEN_MAX]`, or is longer than what is staged.
    Length(StageError),

    /// `firmware_length` is not a multiple of [`memmap::FW_INSTALL_ALIGN`].
    /// Carries the length, so the message names the number that is wrong.
    Alignment(u32),
}

/// Does `hw_compat` admit an Mk4?
///
/// `hw_compat == 0` means "no constraint" and is accepted, which is the
/// reference's own reading: `shared/utils.py:401` only consults the bits
/// `if hw_compat != 0`. Being stricter than the installer we are replacing would
/// refuse images Coldcard's own updater installs.
#[must_use]
pub fn family_ok(hw_compat: u32) -> bool {
    hw_compat == 0 || hw_compat & MK_4_OK != 0
}

/// Would this staged image be installable on an Mk4? Returns the header's
/// `firmware_length`, which is the only length a burn may use.
///
/// `announced` is the length the transfer agreed on. It is compared against the
/// header's field by [`psram::check_burn_len`] — the decoupling guard that exists
/// because `verify_firmware_in_ram` signs `hdr->firmware_length` while
/// `psram_do_upgrade` erases a caller-supplied `len` (`verify.c:247`,
/// `psram.c:310`). This is that function's first non-test caller.
///
/// # Errors
///
/// In order, and the order picks the diagnosis rather than the outcome:
/// [`NotInstallable::Unreadable`], [`NotInstallable::Magic`],
/// [`NotInstallable::WrongFamily`], [`NotInstallable::Length`],
/// [`NotInstallable::Alignment`]. Format before length because a slice that is
/// not an Mk4 image at all should not be reported as a length disagreement.
pub fn check_installable(image: &[u8], announced: u32) -> Result<u32, NotInstallable> {
    let field = |off: u32| -> Option<u32> {
        let at = (memmap::FW_HEADER_OFFSET + off) as usize;
        let b: [u8; 4] = image.get(at..at + 4)?.try_into().ok()?;
        Some(u32::from_le_bytes(b))
    };
    let (Some(magic), Some(hw_compat)) = (field(0), field(HW_COMPAT_FIELD_OFFSET)) else {
        return Err(NotInstallable::Unreadable);
    };
    if magic != FW_HEADER_MAGIC {
        return Err(NotInstallable::Magic(magic));
    }
    if !family_ok(hw_compat) {
        return Err(NotInstallable::WrongFamily(hw_compat));
    }
    let length = psram::check_burn_len(image, announced).map_err(NotInstallable::Length)?;
    if length % memmap::FW_INSTALL_ALIGN != 0 {
        return Err(NotInstallable::Alignment(length));
    }
    Ok(length)
}

/// Compile-time invariants. E0080 beats a test for anything a const can say.
const _: () = {
    // The install rule is strictly TIGHTER than the staging rule, never a
    // different rule: 4,096 is a multiple of 512, so nothing that fails staging
    // could pass here and the two cannot disagree about a length in the middle.
    assert!(memmap::FW_INSTALL_ALIGN % memmap::FW_BODY_ALIGN == 0);
    assert!(memmap::FW_INSTALL_ALIGN > memmap::FW_BODY_ALIGN);
    // Why the 4,096 rule may be applied to the WHOLE-IMAGE length even though
    // `signit.py:305` aligns the BODY: the header and vector table ahead of the
    // body are themselves a whole number of 4,096-byte units
    // (`signit.py:315`: `firmware_length = FW_HEADER_OFFSET + FW_HEADER_SIZE +
    // body_len` = 16,384 + body_len), so the total is 4,096-aligned exactly when
    // the body is. Without this the check would be testing a different property
    // from the one signit guarantees.
    assert!((memmap::FW_HEADER_OFFSET + memmap::FW_HEADER_SIZE) % memmap::FW_INSTALL_ALIGN == 0);
    // Both fields read here lie inside the header, and inside the part of it the
    // signature covers (`verify.c:269` hashes up to `FW_HEADER_SIZE - 64`) — which
    // is what makes deriving anything from them defensible at all.
    assert!(HW_COMPAT_FIELD_OFFSET + 4 <= memmap::FW_HEADER_SIZE - 64);
    assert!(psram::FW_LENGTH_FIELD_OFFSET + 4 <= memmap::FW_HEADER_SIZE - 64);
    // The window's ceiling is itself an installable length (1,441,792 = 352 x
    // 4,096), so the alignment rule and the burn ceiling cannot contradict each
    // other at the top of the range.
    assert!(psram::BURN_LEN_MAX % memmap::FW_INSTALL_ALIGN == 0);
};

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec;
    use std::vec::Vec;

    /// 65 x 4,096 = 266,240: above the 262,144 floor and 4,096-aligned, i.e. the
    /// shape every real artifact has (`target/software-only/package/firmware-signed.bin`
    /// measured 397,312 = 97 x 4,096).
    const ALIGNED: u32 = 266_240;

    /// 64 x 4,096 + 512 = 262,656: the staging fixture. Clears the floor, is
    /// 512-aligned, is NOT 4,096-aligned. Transferable, not installable.
    const MISALIGNED: u32 = 262_656;

    /// An image whose header declares `declared`, with `magic` and `hw_compat` set.
    fn image(size: usize, declared: u32, magic: u32, hw_compat: u32) -> Vec<u8> {
        let mut v = vec![0u8; size];
        let off = memmap::FW_HEADER_OFFSET as usize;
        v[off..off + 4].copy_from_slice(&magic.to_le_bytes());
        let len_at = off + psram::FW_LENGTH_FIELD_OFFSET as usize;
        v[len_at..len_at + 4].copy_from_slice(&declared.to_le_bytes());
        let hw_at = off + HW_COMPAT_FIELD_OFFSET as usize;
        v[hw_at..hw_at + 4].copy_from_slice(&hw_compat.to_le_bytes());
        v
    }

    /// A well-formed Mk4 image at `size`, `hw_compat = 0x28` — the value measured
    /// in the real artifact (`MK_4_OK | MK_5_OK`).
    fn ok_image(size: u32) -> Vec<u8> {
        image(size as usize, size, FW_HEADER_MAGIC, 0x28)
    }

    /// The whole contract, one case per rule, each differing from the accepted
    /// case in exactly one field.
    #[test]
    fn every_rule_refuses_on_its_own_and_the_real_shape_passes() {
        assert_eq!(check_installable(&ok_image(ALIGNED), ALIGNED), Ok(ALIGNED));

        // The transfer fixture: staged, verified, and NOT installable. This is the
        // separation the whole module exists for.
        assert_eq!(
            check_installable(&ok_image(MISALIGNED), MISALIGNED),
            Err(NotInstallable::Alignment(MISALIGNED))
        );

        // Wrong image family: Mk5-only, and Mk1-3-only. Both are legal Coldcard
        // images and neither may install here.
        for hw in [0x20u32, 0x07] {
            assert_eq!(
                check_installable(&image(ALIGNED as usize, ALIGNED, FW_HEADER_MAGIC, hw), ALIGNED),
                Err(NotInstallable::WrongFamily(hw)),
                "hw_compat {hw:#x}"
            );
        }
        // `0` is "no constraint" per `shared/utils.py:401`, not "no product".
        assert_eq!(
            check_installable(&image(ALIGNED as usize, ALIGNED, FW_HEADER_MAGIC, 0), ALIGNED),
            Ok(ALIGNED)
        );

        // Not an Mk4 image at all.
        assert_eq!(
            check_installable(&image(ALIGNED as usize, ALIGNED, 0xdead_beef, 0x28), ALIGNED),
            Err(NotInstallable::Magic(0xdead_beef))
        );
        assert_eq!(
            check_installable(&ok_image(ALIGNED)[..4096], ALIGNED),
            Err(NotInstallable::Unreadable)
        );

        // The header's number is not the announced one.
        assert_eq!(
            check_installable(&ok_image(ALIGNED), ALIGNED + memmap::FW_INSTALL_ALIGN),
            Err(NotInstallable::Length(StageError::LengthMismatch))
        );
        // ... and the out-of-band forms, which `staged_burn_len` owns.
        let short = image(ALIGNED as usize, 4096, FW_HEADER_MAGIC, 0x28);
        assert_eq!(
            check_installable(&short, 4096),
            Err(NotInstallable::Length(StageError::TooSmall))
        );
        let over = image(ALIGNED as usize, u32::MAX, FW_HEADER_MAGIC, 0x28);
        assert_eq!(
            check_installable(&over, u32::MAX),
            Err(NotInstallable::Length(StageError::TooLarge))
        );
        let truncated = image(ALIGNED as usize, ALIGNED + 4096, FW_HEADER_MAGIC, 0x28);
        assert_eq!(
            check_installable(&truncated, ALIGNED + 4096),
            Err(NotInstallable::Length(StageError::Truncated))
        );
    }
}
