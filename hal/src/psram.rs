//! Bounds on a firmware-upgrade burn, and the one defect they exist to stop.
//!
//! Nothing here calls the callgate, stages an image, or receives a byte. Every
//! item is either **pure arithmetic** or an **accessor**, and the accessor's
//! production caller is `firmware/src/upgrade.rs` — **this read "an accessor with
//! no production caller, landed before any code exists that could reach it" until
//! 2026-09-17**, when phase 3 landed that caller. The reason the bounds were
//! landed early is unchanged: the failure they guard is not recoverable, because
//! it erases the share. What is still true, and it is the load-bearing half: no
//! callgate sub-call is bound, so bytes can reach PSRAM and nothing can burn them.
//!
//! # The defect, read from Coinkite's source
//!
//! `pin_firmware_upgrade` (`mk4-bootloader/pins.c:1277`) is reached as selector
//! 18 / `arg2 = 7` and takes `start` and `len` out of `args->secret`
//! (`pins.c:1294-1296`). Its only ceiling is
//!
//! ```text
//! if(len < 32768)      return EPIN_RANGE_ERR;   // pins.c:1298
//! if(len > 2<<20)      return EPIN_RANGE_ERR;   // pins.c:1299
//! if(start+len > PSRAM_SIZE) return EPIN_RANGE_ERR;
//! ```
//!
//! It then calls `verify_firmware_in_ram(data, len, world_check)`
//! (`pins.c:1306`) — and **that function never reads its `len` argument**. In
//! `mk4-bootloader/verify.c` the name `len` appears exactly once, in the
//! signature at `:247`; every length in the body is `hdr->firmware_length`
//! (`:269-274`, `:288`). VERIFIED by reading the whole function.
//!
//! What burns is the *other* number. After
//! `ae_encrypted_write(KEYNUM_firmware, ..)` and after the comment
//! `// -- point of no return --`, `pin_firmware_upgrade` calls
//! `psram_do_upgrade(data, len)`, whose loop is `for(uint32_t pos=0; pos < size;
//! pos += 8)` with `dest = FIRMWARE_START+pos` and a `flash_page_erase(dest)` on
//! every page boundary (`psram.c:308-345`). So the **signature check and the
//! erase length are decoupled**, and the bootloader is not a backstop for the
//! gap: by the time the burn starts the 608 write has happened and the code is
//! past its own no-return marker.
//!
//! [`memmap::FLASH_FS_BASE`] is `FIRMWARE_START + `[`BURN_LEN_MAX`]. The
//! bootloader's `2<<20` is **655,360 bytes past that**, which is the identity
//! record, the four nonce A/B slots and the share
//! ([`memmap::FS_IDENTITY_OFFSET`] onward). One wrong integer, once.
//!
//! # What is here
//!
//! [`staged_burn_len`] derives the burn length from the staged image's **own
//! header**, so no caller can name it, and [`check_burn_len`] refuses the case
//! the bootloader cannot see: a caller-supplied `len` that differs from the
//! header's `firmware_length`.
//!
//! Under those, the bytes: [`MappedPsram`] is the memory-mapped accessor, whose
//! [`check_write`] / [`check_read`] pair encodes the ONE asymmetry the silicon
//! has — aligned writes, unaligned reads — and [`fake::FakePsram`] is a host
//! double enforcing the same pair, so no host test can pass on an access the
//! device refuses. [`readback_selftest`] writes an address-derived pattern and
//! reads it back, allocation-free, over either.
//!
//! Modelled on [`crate::flash::check_bounds`] — same shape, same
//! `Result<_, enum>` refusal-not-panic rule (a panic on this path is a reset
//! loop on an RDP=2 unit, decision 6), same insistence that the arithmetic be
//! checked rather than wrapping.
//!
//! # What is deliberately NOT here
//!
//! * **No 4 K length alignment.** `signit.py:302-306` re-aligns the Mk4 body to
//!   4096 and `firmware/examples/checkfw.rs`'s `MK4_ALIGN` already refuses a
//!   non-multiple *before the artifact ever leaves the host*. A misaligned
//!   length cannot reach `FLASH_FS` — [`BURN_LEN_MAX`] holds either way — it can
//!   only corrupt the tail of the install, which is a brick and not a fund loss.
//!   Encoding 4096 a second time here would give that number a third home
//!   (`memmap::FW_BODY_ALIGN` is the mk1-3 512 and `firmware`'s
//!   `firmware_digest_alignment_bound_is_looser_than_mk4_requires` is a live
//!   tripwire on it), so this module states the ceiling and leaves the stride to
//!   the checker that already owns it.
//! * **No `offset` parameter.** See [`PSRAM_STAGE_OFFSET`].
//! * **No `arg2 = 7` binding and no PIN.** `arg2 = 7` stays
//!   [`crate::callgate::SubCallCost::Destructive`] and unbound. [`MappedPsram`]
//!   can move bytes into PSRAM and [`readback_selftest`] can prove the silicon
//!   kept them, but nothing in `hal` or in `firmware` **burns** either.
//!
//!   **This paragraph read "nothing in `hal` or in `firmware` calls either",
//!   with an `rg` recipe and an "ARM image unmoved at 379,648 B", until
//!   2026-09-17.** That went false the moment phase 3 landed: the production
//!   caller is now `firmware/src/upgrade.rs`, which owns a [`MappedPsram`], runs
//!   [`readback_selftest`] at admission and [`Psram::write`] per chunk. What is
//!   still true and is the load-bearing half: **no callgate sub-call is bound**,
//!   so bytes can reach PSRAM and nothing can burn them, and
//!   [`check_burn_len`] — the selector-18/7 gate — still has no caller outside this
//!   file's own `#[cfg(test)]` assertions, i.e. none in any build that can reach
//!   hardware.
//! * **No staging state machine, no receive path, no USB.** Writing bytes into
//!   PSRAM and deciding which bytes to write are separate jobs, and only the
//!   first is here. The second is `firmware/src/upgrade.rs`'s `Stager`, which
//!   reaches this module through [`Psram`], [`readback_selftest`],
//!   [`staged_burn_len`] and [`PSRAM_STAGE_OFFSET`] and through nothing else.

use crate::memmap;

/// Where `psram_do_upgrade` writes, i.e. the first flash byte a burn touches:
/// `FIRMWARE_START` (`mk4-bootloader/verify.h:9` =
/// `BL_FLASH_BASE + BL_FLASH_SIZE + BL_NVROM_SIZE` = `0x0802_0000`), which is
/// exactly [`memmap::FLASH_ISR_BASE`] and exactly
/// [`memmap::FLASH_ERASE_FLOOR`].
///
/// The burn is `dest = FIRMWARE_START+pos` for `pos` in `0..size`
/// (`psram.c:326`), so the destination range is
/// `[BURN_BASE, BURN_BASE + len)` and the whole fund-loss question is where
/// that range ends.
pub const BURN_BASE: u32 = memmap::FLASH_ISR_BASE;

/// **The ceiling: 1,441,792 bytes.** The largest burn that cannot reach
/// `FLASH_FS`.
///
/// It is the difference of exactly two constants —
/// [`memmap::FLASH_FS_BASE`] minus [`memmap::FLASH_ISR_BASE`] — and
/// equivalently the sum of the two regions a burn is *allowed* to overwrite,
/// [`memmap::FLASH_ISR_LEN`] + [`memmap::FLASH_TEXT_LEN`] (16 K + 1392 K). Both
/// forms are asserted below so neither can drift.
///
/// Tighter than everything upstream, which is the point:
///
/// | Bound | Value | Overshoot past `FLASH_FS_BASE` |
/// |---|---|---|
/// | this | 1,441,792 | 0 |
/// | `FW_MAX_LENGTH_MK4` (`sigheader.h:53`) | 1,966,080 | 524,288 — all of `FLASH_FS` |
/// | `pins.c:1299`'s `2<<20` | 2,097,152 | 655,360 |
///
/// `saturating_sub` and not `-`: `profile.release` sets
/// `overflow-checks = false`, and a wrapped `BURN_LEN_MAX` is a bypass of the
/// only thing standing between a bad integer and the share. Saturating to 0
/// fails closed — every length would be refused.
pub const BURN_LEN_MAX: u32 = memmap::FLASH_FS_BASE.saturating_sub(memmap::FLASH_ISR_BASE);

/// Floor, matching the bootloader's own refusal of a too-small image:
/// `verify_header` refuses `firmware_length < FW_MIN_LENGTH`
/// (`verify.c:215`; `sigheader.h:46` = 256 K) and `psram_do_upgrade` opens with
/// `ASSERT(size >= FW_MIN_LENGTH)` (`psram.c:310`).
///
/// [`memmap::FW_MIN_BODY_LEN`] is that same 256 K, already read from source, so
/// this is an alias and not a second copy.
///
/// **Note it is 8x TIGHTER than the callgate's own floor.** `pins.c:1298`
/// refuses only `len < 32768`, so a `len` between 32,768 and 262,143 passes the
/// gate, passes the signature check (which ignores `len`), gets past
/// `// -- point of no return --`, and then trips `psram_do_upgrade`'s `ASSERT`
/// — inside the bootloader, after the 608 write. Refusing here is the only
/// place that window can be closed from our side.
pub const BURN_LEN_MIN: u32 = memmap::FW_MIN_BODY_LEN;

/// Byte offset of `firmware_length` within the 128-byte signature header.
///
/// From the `coldcardFirmwareHeader_t` layout (`sigheader.h:25-31`):
/// `magic_value` 4 + `timestamp` 8 + `version_string` 8 + `pubkey_num` 4 = 24.
/// Little-endian `u32`, read out of `staged[FW_HEADER_OFFSET + 24 ..][..4]`.
///
/// `coldsnap_firmware`'s `firmware_digest` reads the same field with a bare
/// `header.get(24..28)`. This constant is the canonical home — `hal` is *below*
/// `firmware`, so the literal is the one that should go — but that file was not
/// this increment's to edit, so the duplication is REAL and is recorded here
/// rather than hidden: two places read one field offset, and only this one is
/// named. Switching `firmware_digest` to `memmap`-style reuse of this constant
/// is a one-line change for whoever next owns `firmware/src/lib.rs`.
///
/// The field sits in the part of the header the signature covers (the last 64
/// bytes are the signature itself and are excluded from the digest,
/// `verify.c:269`), asserted below. That is what makes deriving the burn length
/// from the header defensible at all: the header cannot be edited without
/// invalidating the signature the bootloader checks *before* the burn. It is
/// also precisely why a caller-supplied length is not defensible — nothing
/// signs that.
pub const FW_LENGTH_FIELD_OFFSET: u32 = 24;

/// PSRAM byte offset the staged image starts at. **Fixed at 0, and not a
/// parameter of anything here.**
///
/// `pin_firmware_upgrade` takes a `start` relative to `PSRAM_BASE`
/// (`pins.c:1294-1295`), so a `start` exists at the callgate. It does not need
/// to exist here. This device stages one image at a time and chooses where; it
/// has no vdisk and no SD card path, and Coldcard's own USB upgrade passes 0
/// (`shared/usb.py:842`, `shared/actions.py:271` — only `vdisk.py:218` passes
/// anything else). A `stage_range_ok(offset, len)` whose every caller passes 0
/// would hand a future caller a knob and hand a reviewer a bound that had never
/// been exercised.
///
/// What the fixed base buys, stated so it is not mistaken for a check that
/// fires: `psram_recover_firmware` refuses to re-run a torn burn unless
/// `h->start >= PSRAM_BASE && h->start < PSRAM_BASE + (PSRAM_SIZE/2)`
/// (`psram.c:263-264`) — and that recovery net is the only thing between an
/// interrupted burn and a brick, since RDP=2 means no DFU. At offset 0 that
/// rule is satisfied unconditionally. [`staged_burn_len`] still bounds the
/// staging *window* to PSRAM's lower half, which is the base-independent form
/// of the same rule and does fire.
pub const PSRAM_STAGE_OFFSET: u32 = 0;

/// **The staging window: 4,194,304 bytes**, PSRAM's lower half. The single home
/// of that number — [`staged_burn_len`] bounds its slice to it and
/// [`check_read`] bounds every accessor offset to it, so the window a length is
/// judged against and the window bytes can be written into cannot drift apart.
///
/// Three independent reasons it is the lower half and not all 8 MiB, and each is
/// read from Coinkite's source rather than chosen:
///
/// * `psram_recover_firmware` replays a torn burn only if
///   `h->start >= PSRAM_BASE && h->start < PSRAM_BASE + (PSRAM_SIZE/2)`
///   (`psram.c:263-264`). On RDP=2 that recovery net is the only thing between
///   an interrupted burn and a brick, so a staged image outside this half is one
///   the bootloader will not finish.
/// * `RECHDR_POS` is `PSRAM_BASE + PSRAM_SIZE - 2048` (`psram.c:32`) — the
///   recovery header itself. Bounding to the lower half makes it **unnameable**
///   through [`MappedPsram`], the same containment property
///   [`crate::flash::check_bounds`] gives `FLASH_TEXT`.
/// * MicroPython restricts itself identically: `PSRAMWrapper.length` is
///   `0x40_0000`, commented "4 meg (lower half)" (`shared/psram.py`).
///
/// `PSRAM_BASE + PSRAM_SIZE - 4` is written by `psram_setup`'s own
/// non-destructive word probe, and it is in the half this excludes — so nothing
/// here can collide with that probe either.
pub const PSRAM_STAGE_LEN: u32 = memmap::PSRAM_LEN / 2;

/// Why a staged image may not be burned. A value, never a panic — same rule as
/// [`crate::flash::FlashError`], and for the same reason: every reachable panic
/// on this device is a permanent brick (decision 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageError {
    /// The slice is too short to contain the 128-byte header at
    /// [`memmap::FW_HEADER_OFFSET`], so there is no `firmware_length` to read.
    /// Refused rather than defaulted: a zero length here would be a burn
    /// length.
    HeaderUnreadable,
    /// The staging window is not PSRAM's lower half. See
    /// [`PSRAM_STAGE_OFFSET`].
    NotInStagingWindow,
    /// `firmware_length` is below [`BURN_LEN_MIN`].
    TooSmall,
    /// **`firmware_length` would erase past [`memmap::FLASH_FS_BASE`]** — the
    /// identity record, the nonce slots, the share. See [`BURN_LEN_MAX`]. This
    /// is the variant this module exists for.
    TooLarge,
    /// `firmware_length` exceeds the bytes actually staged, so the burn would
    /// copy whatever follows the image in PSRAM into flash.
    Truncated,
    /// **The decoupling refusal.** The length a caller is about to hand the
    /// callgate is not the length the header declares, and the bootloader
    /// cannot tell: `verify_firmware_in_ram` signs `hdr->firmware_length` while
    /// `psram_do_upgrade` erases the caller's `len`.
    ///
    /// No real `pack-signed.py` artifact can produce this — that tool emits a
    /// 4 K-aligned `fw_len` and the packed size equals it — so the only way to
    /// exercise it is a hand-built header, which
    /// `the_decoupling_guard_fires_on_a_mismatch_and_not_on_a_match` does.
    LengthMismatch,
}

/// The burn length, **derived from the staged image's own header** and bounded
/// before it can be used as a length.
///
/// `staged` must be the staging window: the bytes at
/// `PSRAM_BASE + `[`PSRAM_STAGE_OFFSET`], laid out exactly as flash from
/// [`BURN_BASE`] — which is the same convention `coldsnap_firmware`'s
/// `firmware_digest` takes, and it reuses [`memmap::FW_HEADER_OFFSET`] /
/// [`memmap::FW_HEADER_SIZE`] / [`FW_LENGTH_FIELD_OFFSET`] rather than
/// re-deriving them.
///
/// # Errors
///
/// In this order, and the order is load-bearing: [`StageError::NotInStagingWindow`],
/// [`StageError::HeaderUnreadable`], [`StageError::TooSmall`],
/// [`StageError::TooLarge`], [`StageError::Truncated`]. The ceiling is checked
/// **before** the truncation test so that a `firmware_length` of `u32::MAX` is
/// reported as what it is rather than needing 4 GiB of PSRAM to disprove.
pub fn staged_burn_len(staged: &[u8]) -> Result<u32, StageError> {
    // The staging window itself, before anything is read out of it. Attacker- or
    // caller-controlled: `staged` is whatever slice was constructed over PSRAM,
    // and a slice that is not the window means the header parsed below is not
    // the header. Bounded to the LOWER HALF, which is the base-independent form
    // of `psram.c:263-264`'s rule on `h->start`, and it also keeps the window
    // clear of `RECHDR_POS` (`PSRAM_BASE + PSRAM_SIZE - 2048`, `psram.c:32`) —
    // the recovery header a torn burn is replayed from.
    //
    // Not `checked_add`: `PSRAM_STAGE_OFFSET` is 0 and a Rust slice is at most
    // `isize::MAX` bytes, so `0 + staged.len()` has no representable overflow
    // and a `None` arm here could never be reached. The `const _` block below is
    // what holds if the base ever moves off 0.
    if staged.len() > PSRAM_STAGE_LEN as usize {
        return Err(StageError::NotInStagingWindow);
    }

    let header_end = (memmap::FW_HEADER_OFFSET + memmap::FW_HEADER_SIZE) as usize;
    let field = (memmap::FW_HEADER_OFFSET + FW_LENGTH_FIELD_OFFSET) as usize;
    let bytes = staged
        .get(field..field + 4)
        .filter(|_| staged.len() >= header_end)
        .ok_or(StageError::HeaderUnreadable)?;
    let length = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);

    if length < BURN_LEN_MIN {
        return Err(StageError::TooSmall);
    }

    // THE FUND-LOSS CHECK, written as the property rather than as its
    // pre-subtracted form: the erase must not reach `FLASH_FS`.
    //
    // `checked_add` is load-bearing and this one CAN overflow. `BURN_BASE` is
    // `0x0802_0000`, so with `overflow-checks = false` a plain `+` on a
    // `firmware_length` of `u32::MAX` wraps to `0x0801_ffff`, which compares
    // BELOW `FLASH_FS_BASE` and returns `Ok(u32::MAX)` — a full-flash erase
    // waved through by the guard written to stop it. MEASURED, not reasoned:
    // see `the_ceiling_cannot_be_wrapped_past_flash_fs`.
    let burn_end = match BURN_BASE.checked_add(length) {
        Some(end) => end,
        None => return Err(StageError::TooLarge),
    };
    if burn_end > memmap::FLASH_FS_BASE {
        return Err(StageError::TooLarge);
    }

    // Now that `length` is known to be at most `BURN_LEN_MAX`, comparing it
    // against what is actually staged is cheap and cannot need a huge slice.
    if length as usize > staged.len() {
        return Err(StageError::Truncated);
    }

    Ok(length)
}

/// **The decoupling guard.** Returns the burn length only if the length a
/// caller is about to hand the callgate equals the one the header declares.
///
/// This is the refusal that has no counterpart in the bootloader.
/// `verify_firmware_in_ram` ignores its `len` and signs
/// `hdr->firmware_length`; `psram_do_upgrade` erases `len`. Any caller of
/// selector 18 / `arg2 = 7` must pass through here, and passing
/// [`staged_burn_len`]'s own result is the only way to satisfy it — which is the
/// intended shape: the length is derived, and this function proves the derived
/// one is the one that ships.
///
/// # Errors
///
/// Everything [`staged_burn_len`] returns, plus
/// [`StageError::LengthMismatch`].
pub fn check_burn_len(staged: &[u8], callgate_len: u32) -> Result<u32, StageError> {
    let length = staged_burn_len(staged)?;
    if callgate_len != length {
        return Err(StageError::LengthMismatch);
    }
    Ok(length)
}

/// Word size for a PSRAM **write**, 4 bytes.
///
/// `mk4-bootloader/psram.c`'s file header is the whole rule, quoted:
/// **"CAUTION: All writes must be word aligned. Unaligned read okay."**
///
/// MicroPython encodes the same asymmetry as executable asserts, and it is
/// stricter than "aligned start": `PSRAMWrapper.write_at` refuses `offset % 4`
/// **and** `ln % 4` (`shared/psram.py`), and its `write()` pads a runt tail up to
/// a word rather than storing it, while `read_at` asserts nothing at all. So the
/// rule enforced here is *a whole number of words at a word-aligned address* —
/// the stricter of the two readings of the C comment, because the only
/// executable enforcement anywhere in Coinkite's tree is the stricter one, and a
/// bound that is too tight refuses a legal write while a bound that is too loose
/// corrupts a word we did not name.
pub const WRITE_ALIGN: u32 = 4;

/// Chunk [`readback_selftest`] works in, and the **entire** memory it uses:
/// one `[u8; 64]` on the stack.
///
/// **Why the number matters.** The heap is a 65,536 B arena with 5,024 B spare
/// and a staged image is ~388 KiB, so a self-test that allocated could not run at
/// all. Allocation-freedom here is structural, not a promise: outside
/// `#[cfg(any(test, feature = "fake-flash"))]` this module names no `alloc` path
/// (`extern crate alloc` appears only inside the gated `fake` and `tests`
/// modules), the buffer is a fixed-size array, and the span is walked with an
/// index rather than collected. A multiple of [`WRITE_ALIGN`], asserted below, so
/// every full chunk is a legal write.
pub const SELFTEST_CHUNK: usize = 64;

/// Why a PSRAM access was refused, or what the read-back saw. A value, never a
/// panic — same rule as [`StageError`] and [`crate::flash::FlashError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsramError {
    /// A write whose offset or length is not a multiple of [`WRITE_ALIGN`].
    /// **Reads never produce this**, which is the asymmetry the silicon has.
    NotAligned,
    /// The access reaches past [`PSRAM_STAGE_LEN`], or `offset + len` does not
    /// fit in a `usize`.
    OutOfBounds,
    /// There is no memory-mapped PSRAM on this target. Returned by
    /// [`MappedPsram`] on a host build **after** the bounds and alignment checks
    /// have run, so the refusals stay host-testable while the dereference does
    /// not SIGSEGV the test runner — the same shape, and for the same reason, as
    /// [`crate::flash::FlashError::NotOnThisTarget`].
    NotOnThisTarget,
    /// [`readback_selftest`] read back a byte other than the one it wrote, at
    /// this offset from [`memmap::PSRAM_BASE`]. Carries the offset so a caller
    /// can tell a single stuck cell from a whole aliased span; a fieldless
    /// variant would make an `assert_eq!` on it much weaker.
    Mismatch {
        /// Offset of the first byte that differed.
        offset: u32,
    },
}

/// Bounds a **read**: range only, no alignment. Deliberately permissive about
/// alignment, because the hardware is.
///
/// "Unaligned read okay" (`psram.c`), and `PSRAMWrapper.read_at` asserts nothing
/// (`shared/psram.py`). A checker that refused an unaligned read would make
/// `fake::FakePsram` refuse a capability the device has, which hides a real
/// capability rather than a real hazard — the opposite failure from
/// [`check_write`]'s, and still a wrong double.
///
/// # Errors
///
/// [`PsramError::OutOfBounds`] if `offset + len` overflows or exceeds
/// [`PSRAM_STAGE_LEN`].
pub fn check_read(offset: u32, len: usize) -> Result<(), PsramError> {
    // Checked, never wrapping. `profile.release` sets `overflow-checks = false`,
    // so a plain `+` here wraps SILENTLY on the device and a huge `len` would
    // bring `end` back under the limit — turning the containment this function
    // provides into a bypass that can name `RECHDR_POS`. Same reasoning, same
    // shape, as `crate::flash::check_bounds`.
    let end = match (offset as usize).checked_add(len) {
        Some(e) => e,
        None => return Err(PsramError::OutOfBounds),
    };
    if end > PSRAM_STAGE_LEN as usize {
        return Err(PsramError::OutOfBounds);
    }
    Ok(())
}

/// Bounds a **write**: [`WRITE_ALIGN`] on both the offset and the length, then
/// the same range as [`check_read`].
///
/// This is the function that makes a host double honest. Both [`MappedPsram`] and
/// `fake::FakePsram` route every write through it, so the set of writes the
/// double accepts is *by construction* the set the accessor accepts — which is
/// the fix PLAN.md §8.1 defect 5 records for flash, where `FakeFlash` accepted a
/// re-program that is `PROGERR` on silicon and every test built on it was
/// testing a machine that does not exist.
///
/// # Errors
///
/// [`PsramError::NotAligned`] first, so a request that is both misaligned and
/// oversized reports the more specific fault (as [`crate::flash::check_bounds`]
/// does); then [`PsramError::OutOfBounds`].
pub fn check_write(offset: u32, len: usize) -> Result<(), PsramError> {
    if offset % WRITE_ALIGN != 0 || len % WRITE_ALIGN as usize != 0 {
        return Err(PsramError::NotAligned);
    }
    // The range rule is IDENTICAL for reads and writes — only alignment differs —
    // so it lives in one place. A second copy here is how the two windows drift.
    check_read(offset, len)
}

/// Word-aligned write and byte read over a PSRAM staging window, so that
/// [`readback_selftest`] is **the same code** on the device and on the host.
///
/// Exactly two implementors and both are load-bearing: [`MappedPsram`] is the
/// silicon, `fake::FakePsram` is the double. Offsets are relative to
/// [`memmap::PSRAM_BASE`] and bounded to [`PSRAM_STAGE_LEN`], which is what makes
/// `RECHDR_POS` unnameable through this trait.
pub trait Psram {
    /// Write `bytes` at `offset`.
    ///
    /// # Errors
    ///
    /// [`PsramError::NotAligned`] / [`PsramError::OutOfBounds`] per
    /// [`check_write`]; [`PsramError::NotOnThisTarget`] from [`MappedPsram`] off
    /// ARM.
    fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), PsramError>;

    /// Read `out.len()` bytes from `offset`. No alignment requirement.
    ///
    /// # Errors
    ///
    /// [`PsramError::OutOfBounds`] per [`check_read`];
    /// [`PsramError::NotOnThisTarget`] from [`MappedPsram`] off ARM.
    fn read(&mut self, offset: u32, out: &mut [u8]) -> Result<(), PsramError>;

    /// The first `len` bytes of the staging window, as one contiguous slice.
    ///
    /// `len` is bytes from [`PSRAM_STAGE_OFFSET`]. This exists so that
    /// `firmware::firmware_digest` — which wants one `&[u8]` and already bounds
    /// the header's length field three ways before using it
    /// (`firmware/src/lib.rs:3029-3034`; **this pin read `:2998-3003` until
    /// 2026-09-17** — it was authored against pre-edit numbering and never
    /// re-derived) — can be applied to a staged image with
    /// **no second implementation of the bootloader's signed range**. The
    /// duplication of the offset-24 length field is already recorded as REAL at
    /// the docs of [`FW_LENGTH_FIELD_OFFSET`]; a third home was refused here.
    ///
    /// The default body is a refusal, so an implementor with no contiguous window
    /// fails CLOSED: no view, no digest, no staged image. It must never be
    /// `Ok(&[])` — see [`Psram::write`]'s own note on why `Ok` must not be read
    /// as "bytes moved".
    ///
    /// `&self` and not `&mut self` deliberately: the borrow checker is then what
    /// stops a view being held across a [`Psram::write`], which is the whole
    /// aliasing argument for [`MappedPsram`]'s `from_raw_parts`.
    ///
    /// # Errors
    ///
    /// [`PsramError::OutOfBounds`] per [`check_read`];
    /// [`PsramError::NotOnThisTarget`] from [`MappedPsram`] off ARM and from this
    /// default body.
    fn view(&self, len: u32) -> Result<&[u8], PsramError> {
        let _ = len;
        Err(PsramError::NotOnThisTarget)
    }
}

/// The memory-mapped PSRAM at [`memmap::PSRAM_BASE`].
///
/// **Its production caller is `firmware/src/upgrade.rs`'s `Stager`, constructed at
/// `firmware/src/main.rs`'s boot step 6d — this read "No production caller." until
/// 2026-09-17.** Nothing burns what lands here: no callgate sub-call is bound, and
/// [`check_burn_len`] — the selector-18/7 gate — still has no caller outside this
/// file's own tests.
///
/// # Why no token
///
/// [`crate::flash::StmFlash`] is reachable only by consuming a singleton token,
/// because a second owner could manipulate `FLASH->CR` under the first or read a
/// page mid-erase. None of that exists here: PSRAM is plain memory behind
/// OCTOSPI1 in memory-mapped mode, with no control register to share, no unlock,
/// no erase and nothing persistent of ours in it — [`PSRAM_STAGE_LEN`] already
/// puts `RECHDR_POS` out of reach, and the worst two owners can do is overwrite
/// each other's staged image, which the signature check then refuses. A
/// take-once guard would be scaffolding around a hazard that is not there.
///
/// # Why it is already set up
///
/// The bootloader configures OCTOSPI1 and maps PSRAM before any firmware runs,
/// so there is no `init` here and nothing to get wrong. VERIFIED by reading it:
/// `psram_setup()` is called from `main.c:150` on the straight-line boot path,
/// **before** the `verify_firmware()` at `main.c:162` that gates the jump into
/// our image — so any boot that reaches this crate has already run it. Its last
/// configuration step is `HAL_OSPI_MemoryMapped(&qh, &mmap)` (`psram.c:208`), and
/// it ends with a non-destructive `__IO uint32_t` probe of
/// `PSRAM_BASE+PSRAM_SIZE-4` that would `LOCKUP_FOREVER` on a failure. MicroPython
/// agrees in one line: "already started and memory mapped by bootrom"
/// (`shared/psram.py`).
///
/// [`memmap::PSRAM_BASE`] = `0x9000_0000` and [`memmap::PSRAM_LEN`] = 8 MiB are
/// the `PSRAM_BASE` / `PSRAM_SIZE` of `mk4-bootloader/psram.h`, re-checked
/// against that header for this module and asserted in the `const` block below.
/// No derives, matching [`crate::flash::StmFlash`]: nothing clones, prints or
/// defaults a handle to a fixed address, and `MappedPsram` is the only way to
/// spell one.
pub struct MappedPsram;

impl Psram for MappedPsram {
    fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), PsramError> {
        // The silicon's rule, on EVERY target. Not inside the `cfg` below: a
        // refusal under a `cfg` fails open on the target where the `cfg` is off,
        // and this is the refusal that keeps an unaligned store off the bus.
        check_write(offset, bytes.len())?;
        if bytes.is_empty() {
            // A zero-length write is a legal no-op on both targets, and the only
            // case that returns `Ok` off ARM. `readback_selftest` refuses an
            // empty SPAN instead, because there a no-op is a vacuous pass.
            return Ok(());
        }

        // `return` is load-bearing: on this target the `cfg(target_arch = "arm")`
        // block below is deleted, so this block is the last statement in the
        // function -- but it is still a *statement*, and a bare `Err(..)` tail
        // there is a discarded `#[must_use]` value, not the return value.
        #[cfg(not(target_arch = "arm"))]
        #[allow(clippy::needless_return)]
        {
            // Dereferencing 0x9000_0000 here would SIGSEGV the test runner. The
            // checks above already ran, which is the host-testable part.
            return Err(PsramError::NotOnThisTarget);
        }

        #[cfg(target_arch = "arm")]
        {
            // `check_write` has proved `offset % 4 == 0`, `bytes.len() % 4 == 0`
            // and `offset + bytes.len() <= PSRAM_STAGE_LEN`, so every store below
            // is a word-aligned word inside PSRAM's lower half.
            let base = memmap::PSRAM_BASE as usize + offset as usize;
            for (w, word) in bytes.chunks_exact(WRITE_ALIGN as usize).enumerate() {
                // Little-endian assembly, so a word store reproduces byte for
                // byte what a byte-wise copy of `bytes` would have written; this
                // target is LE (thumbv7em-none-eabihf) and the bootloader's own
                // `__IO uint32_t` accesses assume the same.
                let value = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);

                // SAFETY: `PSRAM_BASE + offset + 4*w` is inside the 8 MiB the
                // bootloader memory-mapped at `psram.c:208` before this crate
                // ran, and is 4-byte-aligned by `check_write`, which is the ONE
                // rule `psram.c`'s header states for writes. `write_volatile`
                // because the store must reach the OCTOSPI bus rather than be
                // elided or reordered against the read-back that follows it in
                // `readback_selftest` -- eliding it is precisely what would make
                // that self-test pass on dead RAM. `chunks_exact` cannot yield a
                // short slice, so all four indexes are in range.
                unsafe { core::ptr::write_volatile((base + w * 4) as *mut u32, value) };
            }
            Ok(())
        }
    }

    fn read(&mut self, offset: u32, out: &mut [u8]) -> Result<(), PsramError> {
        // Range only. Refusing an unaligned read here would refuse something the
        // hardware permits (`psram.c`: "Unaligned read okay").
        check_read(offset, out.len())?;
        if out.is_empty() {
            return Ok(());
        }

        // `return` is load-bearing -- see `write`.
        #[cfg(not(target_arch = "arm"))]
        #[allow(clippy::needless_return)]
        {
            return Err(PsramError::NotOnThisTarget);
        }

        #[cfg(target_arch = "arm")]
        {
            let base = memmap::PSRAM_BASE as usize + offset as usize;
            for (i, byte) in out.iter_mut().enumerate() {
                // SAFETY: `PSRAM_BASE + offset + i` is inside the mapped window
                // by the bound just checked. Byte-wise `read_volatile` rather
                // than `copy_from_slice`: the read has no alignment requirement,
                // so forming an aligned `&[u8]` view is unnecessary, and the
                // loads must not be hoisted above the `write_volatile` of the
                // same address in `readback_selftest`.
                *byte = unsafe { core::ptr::read_volatile((base + i) as *const u8) };
            }
            Ok(())
        }
    }

    fn view(&self, len: u32) -> Result<&[u8], PsramError> {
        // OUTSIDE the `cfg` below, for the reason `write` states above: a refusal
        // under a `cfg` fails OPEN on the target where the `cfg` is off, and this
        // is the bound that keeps a view off the bootloader's recovery header.
        check_read(PSRAM_STAGE_OFFSET, len as usize)?;

        // `return` is load-bearing -- see `write`.
        #[cfg(not(target_arch = "arm"))]
        #[allow(clippy::needless_return)]
        {
            return Err(PsramError::NotOnThisTarget);
        }

        #[cfg(target_arch = "arm")]
        {
            // SAFETY: `PSRAM_BASE .. + PSRAM_STAGE_LEN` is inside the 8 MiB the
            // bootloader memory-mapped at `psram.c:208` before this crate ran, and
            // `PSRAM_STAGE_OFFSET + PSRAM_STAGE_LEN <= PSRAM_LEN` is const-asserted
            // in the block below. `len` passed `check_read`, so the slice ends
            // inside that window. `&self` and not `&mut self` means no `write` --
            // which takes `&mut self` -- can be live for as long as this slice is,
            // so it aliases no mutable access. Same pattern and the same argument
            // as the flash digest in `firmware/src/main.rs`'s step 8c.
            Ok(unsafe {
                core::slice::from_raw_parts(memmap::PSRAM_BASE as *const u8, len as usize)
            })
        }
    }
}

/// The byte [`readback_selftest`] expects at `offset`: an XOR fold of the whole
/// address.
///
/// A constant pattern would pass on a PSRAM whose upper address lines are stuck,
/// because offset `0x00_0000` and offset `0x10_0000` would expect the same value
/// — which is the aliasing failure a memory test exists to find, and nothing has
/// ever run one on this hardware: `psram.c` has `#undef INCL_SELFTEST` above the
/// `#ifdef INCL_SELFTEST` that guards `psram_memtest`, so both memtests are
/// compiled out of every shipped bootloader. All that survives there is the
/// single-word probe at the end of `psram_setup`.
///
/// ponytail: a byte-wide pattern CANNOT be injective over 4,194,304 offsets, and
/// the collisions are not obscure — `pattern_byte(0x101) == pattern_byte(0)`,
/// asserted in the tests so the ceiling is measured rather than assumed. So this
/// detects an aliased or dead *span* reliably and a single aliased *byte* only
/// with probability 255/256. If a real unit ever fails this, the upgrade is a
/// `u32` pattern compared word-wise, which is injective over the whole window;
/// it is not written now because there is no unit to run it on.
///
/// Three terms and not four: [`PSRAM_STAGE_LEN`] is `1 << 22`, so every offset
/// this module accepts fits in 22 bits and `offset >> 24` would be a term that is
/// **always zero** — a fold over a bit that cannot be set is decoration, and the
/// tests below pin the three shifts that are live.
const fn pattern_byte(offset: u32) -> u8 {
    (offset ^ (offset >> 8) ^ (offset >> 16)) as u8
}

/// Write an address-derived pattern over `len` bytes at `offset`, read it back
/// and compare. **Allocation-free** ([`SELFTEST_CHUNK`]), and it touches no
/// flash, no SE1 and no PIN attempt.
///
/// This is the primitive that proves byte-exactness on a real unit before
/// anything trusts PSRAM with a staged image. It is **destructive to the staging
/// window** by design — it must run before staging, never after.
///
/// # Errors
///
/// [`PsramError::OutOfBounds`] or [`PsramError::NotAligned`] for the WHOLE span,
/// checked before a single byte is written, so a partly-legal span cannot be
/// partly scribbled; whatever the underlying [`Psram`] returns; and
/// [`PsramError::Mismatch`] at the first byte that read back wrong.
///
/// An empty span is [`PsramError::OutOfBounds`]. `Ok(())` from this function has
/// to mean "at least one byte was written and read back correctly", or it is a
/// vacuous pass wearing a success value — and `readback_selftest(p, 0, 0)` would
/// otherwise be exactly that.
pub fn readback_selftest<P: Psram>(psram: &mut P, offset: u32, len: u32) -> Result<(), PsramError> {
    if len == 0 {
        return Err(PsramError::OutOfBounds);
    }
    // The WHOLE span, before any mutation: all-or-nothing, the same rule
    // `flash::fake::FakeFlash::write` follows. Without this the per-chunk check
    // inside `Psram::write` would still refuse the illegal tail -- but only after
    // the legal head had already been overwritten.
    check_write(offset, len as usize)?;

    let mut buf = [0u8; SELFTEST_CHUNK];
    let mut pos = 0u32;
    while pos < len {
        // `len - pos` cannot underflow inside a `pos < len` loop, and both are
        // bounded by `PSRAM_STAGE_LEN` by the check above, so `at` cannot wrap
        // even with `overflow-checks = false`.
        let n = core::cmp::min(SELFTEST_CHUNK as u32, len - pos) as usize;
        let at = offset + pos;

        for (i, byte) in buf[..n].iter_mut().enumerate() {
            *byte = pattern_byte(at.saturating_add(i as u32));
        }
        psram.write(at, &buf[..n])?;

        // POISON the buffer with the exact complement of what was just written,
        // so a `read` that returns `Ok` without storing anything mismatches at
        // EVERY byte instead of at none. The complement and not zero: `!b != b`
        // for every `u8`, whereas `pattern_byte(0)` IS zero, so a zero-filled
        // buffer would let a no-op read pass its first byte.
        for byte in buf[..n].iter_mut() {
            *byte = !*byte;
        }
        psram.read(at, &mut buf[..n])?;

        for (i, got) in buf[..n].iter().enumerate() {
            let abs = at.saturating_add(i as u32);
            if *got != pattern_byte(abs) {
                return Err(PsramError::Mismatch { offset: abs });
            }
        }

        // `n >= 1` whenever the loop body runs, so this always advances.
        pos += n as u32;
    }
    Ok(())
}

/// Cross-checks that cost nothing at runtime and are E0080 if the memory map
/// moves. Deliberately const, not a test: the release profile is a gate and a
/// const item is evaluated on every build of both profiles.
const _: () = {
    // The ceiling stated both ways: as the difference of the two constants it
    // is named for, and as the sum of the two regions a burn may overwrite.
    assert!(BURN_LEN_MAX == memmap::FLASH_ISR_LEN + memmap::FLASH_TEXT_LEN);
    assert!(BURN_BASE + BURN_LEN_MAX == memmap::FLASH_FS_BASE);
    // `saturating_sub` reaching 0 would refuse everything rather than allow
    // everything, but it would still be a silent regression.
    assert!(BURN_LEN_MAX > 0);
    // Tighter than both upstream bounds; if it ever is not, the burn can reach
    // the share and this whole module is decoration.
    assert!(BURN_LEN_MAX < 2 << 20); // pins.c:1299
    assert!(BURN_LEN_MAX < 0x0020_0000 - 0x0002_0000); // FW_MAX_LENGTH_MK4
    // A floor below the ceiling, and at least the bootloader's own.
    assert!(BURN_LEN_MIN < BURN_LEN_MAX);
    // The length field lies inside the header, and inside the 64 bytes of it
    // the signature covers (`verify.c:269` hashes up to `FW_HEADER_SIZE - 64`).
    assert!(FW_LENGTH_FIELD_OFFSET + 4 <= memmap::FW_HEADER_SIZE - 64);
    // The window `staged_burn_len` accepts holds any burn it can approve, and
    // sits in the half of PSRAM `psram_recover_firmware` will replay from.
    assert!(BURN_LEN_MAX <= PSRAM_STAGE_LEN);
    assert!(PSRAM_STAGE_OFFSET + PSRAM_STAGE_LEN <= memmap::PSRAM_LEN);
    // `psram.h`'s PSRAM_BASE / PSRAM_SIZE, re-read for this module.
    assert!(memmap::PSRAM_BASE == 0x9000_0000);
    assert!(memmap::PSRAM_LEN == 0x0080_0000);
    // The staging window is the LOWER HALF, i.e. `psram.c:263-264`'s
    // `PSRAM_BASE + (PSRAM_SIZE/2)` and `shared/psram.py`'s `length`.
    assert!(PSRAM_STAGE_LEN == 0x0040_0000);
    // ... and it therefore cannot name RECHDR_POS (`psram.c:32`) or the word
    // `psram_setup` probes at the very top of the chip.
    assert!(memmap::PSRAM_BASE + PSRAM_STAGE_LEN <= memmap::PSRAM_BASE + memmap::PSRAM_LEN - 2048);
    // Every full self-test chunk is a legal write; only then is the tail's
    // legality decided by `len` alone.
    assert!(SELFTEST_CHUNK % WRITE_ALIGN as usize == 0);
    assert!(SELFTEST_CHUNK > 0);
};

/// A RAM-backed [`Psram`] for host tests that is **strictly no more permissive
/// than the silicon**.
///
/// It exists for the reason `flash::fake::FakeFlash` exists, which PLAN.md §8.1
/// defect 5 records as an "invalid test double": the vendored fake accepted a
/// doubleword re-program that is `PROGERR` on real flash, so tests built on it
/// passed on an access the hardware refuses. The equivalent mistake here is a
/// double that accepts an **unaligned write** — the one thing `psram.c`'s header
/// forbids — and it would silently validate a staging path that corrupts words on
/// the device.
///
/// So `FakePsram` routes every write through the same [`check_write`]
/// [`MappedPsram`] uses, and every read through the same [`check_read`], and only
/// then applies its own (smaller) capacity bound. The two directions it must get
/// right are opposite in sign and both are pinned by name:
///
/// * an unaligned **write** is refused — `the_double_refuses_an_unaligned_write_like_the_silicon`;
/// * an unaligned **read** is permitted — `the_double_permits_an_unaligned_read_like_the_silicon`.
///
/// What it does NOT model: OCTOSPI timing, the ESP-PSRAM64H refresh window
/// (`psram.c` chose `ChipSelectBoundary = 0` because Errata 2.8.1 forbids the
/// register that would have enforced the chip's 8 µs `CS`-low maximum), bus
/// faults, and retention across a power cut. Nothing here is a substitute for
/// running [`readback_selftest`] on a unit.
///
/// Same gate as the flash fake, `#[cfg(any(test, feature = "fake-flash"))]`,
/// deliberately rather than a new `fake-psram` feature: the feature is the one
/// every gate command already passes (`--features fake-flash,test-seam`), so a new
/// one would be compiled by no gate and documented by no `cargo doc` run. The
/// `fake-flash` comment in `hal/Cargo.toml` still describes `FakeFlash` only and
/// is now incomplete — flagged rather than fixed, because that file was not this
/// increment's to edit.
#[cfg(any(test, feature = "fake-flash"))]
pub mod fake {
    use super::{check_read, check_write, Psram, PsramError, PSRAM_STAGE_OFFSET};

    extern crate alloc;
    use alloc::boxed::Box;
    use alloc::vec;

    /// `len` bytes of RAM behind the real [`Psram`] rules. See the module docs.
    pub struct FakePsram {
        cells: Box<[u8]>,
        corrupt_at: Option<u32>,
    }

    impl FakePsram {
        /// `len` zeroed bytes.
        ///
        /// Zeroed and not `0xff`: PSRAM is not flash, it has no erased state, and
        /// filling with `0xff` would suggest one. Zero also makes
        /// [`super::readback_selftest`]'s buffer poisoning meaningful to test —
        /// `pattern_byte(0)` is 0, so a fake that started at `0xff` could hide a
        /// read that never stored anything.
        ///
        /// # Panics
        ///
        /// If `len` is 0, or larger than `super::PSRAM_STAGE_LEN`. Both are test
        /// bugs rather than device conditions, and both are pinned by a
        /// `#[should_panic]` test — the second is the load-bearing one, because a
        /// fake bigger than the real window would accept offsets the device
        /// refuses, which is the exact thing this type exists not to do.
        ///
        /// There is deliberately **no** `len % WRITE_ALIGN` assert: a fake of 62
        /// bytes is not more permissive than the silicon, it just refuses the last
        /// word through its own capacity bound like any other short capacity, so
        /// the assert would have guarded nothing and been unfailable by
        /// construction. (`span` is private, so inline code and not an intra-doc
        /// link — a link to a private item is a rustdoc warning, and rustdoc at 0
        /// warnings is a gate.)
        #[must_use]
        pub fn new(len: usize) -> Self {
            assert!(len > 0, "a zero-length fake PSRAM cannot hold a span");
            assert!(
                len <= super::PSRAM_STAGE_LEN as usize,
                "a fake larger than the staging window would accept offsets the \
                 device refuses"
            );
            Self {
                cells: vec![0u8; len].into_boxed_slice(),
                corrupt_at: None,
            }
        }

        /// Flip one bit of the byte at `offset` after every write that covers it,
        /// so a read-back sees a value that was never written.
        ///
        /// **This is the one thing this fake does that the silicon should not**,
        /// and it is here because the alternative is worse: without it the
        /// `Err(Mismatch)` arm of [`super::readback_selftest`] is unreachable
        /// from any host test, and a read-back comparison that has never been
        /// observed to fail is the vacuous-assertion class. Same justification as
        /// `flash::fake::FakeFlash::scribble`, which bypasses every NOR rule for
        /// the same reason.
        ///
        /// An offset outside the fake is accepted and simply never fires; the
        /// tests that use this assert the exact `Mismatch { offset }`, so a
        /// silently-not-firing corruption cannot be mistaken for a pass.
        pub fn corrupt_writes_at(&mut self, offset: u32) {
            self.corrupt_at = Some(offset);
        }

        /// The backing bytes, for a test that needs to prove *where* a write
        /// landed — an off-by-one in a chunk loop is invisible to a read-back
        /// through the same wrong offset.
        #[must_use]
        pub fn cells(&self) -> &[u8] {
            &self.cells
        }

        /// Total bytes.
        #[must_use]
        pub fn len(&self) -> usize {
            self.cells.len()
        }

        /// Never true by construction ([`FakePsram::new`] refuses 0); present
        /// because clippy requires it alongside `len`.
        #[must_use]
        pub fn is_empty(&self) -> bool {
            self.cells.is_empty()
        }

        /// The fake's OWN capacity bound, applied after the silicon's rules.
        ///
        /// A test fake is smaller than 4 MiB, so checking only
        /// `super::PSRAM_STAGE_LEN` would index out of range and panic — and a
        /// panicking double is a test that fails for the wrong reason. Checking
        /// only this one would be the real hazard: it would accept an unaligned
        /// write.
        fn span(&self, offset: u32, len: usize) -> Result<(usize, usize), PsramError> {
            let start = offset as usize;
            match start.checked_add(len) {
                Some(end) if end <= self.cells.len() => Ok((start, end)),
                _ => Err(PsramError::OutOfBounds),
            }
        }
    }

    impl Psram for FakePsram {
        fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), PsramError> {
            // THE POINT OF THIS FAKE. The silicon's rule first, through the same
            // checker `MappedPsram::write` uses, so this double cannot accept a
            // write the device refuses.
            check_write(offset, bytes.len())?;
            let (start, end) = self.span(offset, bytes.len())?;
            // Both checks are complete before any mutation, so a refused write
            // leaves the cells untouched -- which is what lets a test assert that
            // `readback_selftest`'s up-front span check scribbled nothing.
            self.cells[start..end].copy_from_slice(bytes);

            if let Some(at) = self.corrupt_at {
                let at = at as usize;
                if (start..end).contains(&at) {
                    self.cells[at] ^= 1;
                }
            }
            Ok(())
        }

        fn read(&mut self, offset: u32, out: &mut [u8]) -> Result<(), PsramError> {
            // NO alignment check, on purpose: `psram.c` says "Unaligned read
            // okay" and `PSRAMWrapper.read_at` asserts nothing. A double that
            // refused one would hide a capability the device has.
            check_read(offset, out.len())?;
            let (start, end) = self.span(offset, out.len())?;
            out.copy_from_slice(&self.cells[start..end]);
            Ok(())
        }

        fn view(&self, len: u32) -> Result<&[u8], PsramError> {
            // The device's bound FIRST, through the same checker `MappedPsram::view`
            // uses. DOMINATED BY `FakePsram::new` AND NO TEST CAN SEE IT: `new`
            // panics above `PSRAM_STAGE_LEN`, so any `len` this refuses is one the
            // capacity below refuses too, and both answer `OutOfBounds`. MEASURED
            // 2026-09-17: deleting this line left all 316 hal tests GREEN, exit 0.
            //
            // Kept, and labelled rather than deleted, for the one reason that is not
            // circular: `new`'s cap and `new`'s own test are one edit apart -- writer
            // and reader move together, which is the exact failure UPGRADE-PLAN §7
            // records -- and if that cap is ever relaxed this line becomes the live
            // check. Do NOT read it as covered.
            check_read(PSRAM_STAGE_OFFSET, len as usize)?;
            // Then the fake's own capacity. `get` and not an index, because a
            // capacity overrun in a test is a refusal to report, not a panic to
            // debug -- and `OutOfBounds` is the same variant the silicon's bound
            // produces, so a caller cannot tell the two apart and cannot come to
            // depend on which one fired.
            self.cells.get(..len as usize).ok_or(PsramError::OutOfBounds)
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    /// A hand-built staged image: `len` bytes with a header at
    /// [`memmap::FW_HEADER_OFFSET`] whose `firmware_length` field says
    /// `declared`.
    ///
    /// **Hand-built and not `tools/pack-signed.py` output on purpose.** The real
    /// artifact is 397,312 B = 97 x 4096 with `fw_len` equal to its own size, so
    /// a fixture derived from it can only ever produce `declared ==
    /// staged.len()`. Under that fixture
    /// [`StageError::LengthMismatch`] would be unreachable and
    /// [`StageError::Truncated`] unreachable, and both refusals would read
    /// exactly like working ones. Every length below is therefore chosen, not
    /// observed.
    ///
    /// The real artifact was still run through both functions once, by a
    /// throwaway probe on 2026-09-17, because a guard nothing shippable passes is
    /// its own kind of broken: `target/pack/firmware-signed.bin` is 397,312 B,
    /// [`staged_burn_len`] returns `Ok(397312)`, `check_burn_len(.., 397_312)` is
    /// `Ok`, and `397_308`, `393_216`, `2 << 20` and `u32::MAX` are all
    /// `Err(LengthMismatch)`. Not kept as a test: `target/` is build output, so
    /// the file is absent on a clean checkout and the test would fail for a
    /// reason that has nothing to do with the bounds.
    fn staged(len: usize, declared: u32) -> Vec<u8> {
        let mut v = vec![0u8; len];
        let field = (memmap::FW_HEADER_OFFSET + FW_LENGTH_FIELD_OFFSET) as usize;
        if field + 4 <= v.len() {
            v[field..field + 4].copy_from_slice(&declared.to_le_bytes());
        }
        v
    }

    /// The number this module exists to enforce, in both of the forms the
    /// constant is documented as, plus the three-way comparison against
    /// upstream. If this test and `BURN_LEN_MAX` disagree, believe neither.
    #[test]
    fn the_burn_ceiling_is_the_gap_between_flash_isr_and_flash_fs() {
        assert_eq!(BURN_LEN_MAX, 1_441_792);
        assert_eq!(BURN_LEN_MAX, memmap::FLASH_FS_BASE - memmap::FLASH_ISR_BASE);
        assert_eq!(BURN_LEN_MAX, memmap::FLASH_ISR_LEN + memmap::FLASH_TEXT_LEN);
        assert_eq!(BURN_BASE, 0x0802_0000);
        assert_eq!(BURN_BASE + BURN_LEN_MAX, memmap::FLASH_FS_BASE);
        // Strictly tighter than the two upstream ceilings, and by how much.
        assert_eq!((2 << 20) - BURN_LEN_MAX, 655_360, "pins.c:1299 overshoot");
        assert_eq!(
            (0x0020_0000 - 0x0002_0000_u32) - BURN_LEN_MAX,
            memmap::FLASH_FS_LEN,
            "FW_MAX_LENGTH_MK4 overshoots by exactly all of FLASH_FS"
        );
        // The floor is the bootloader's own, and 8x tighter than the callgate's.
        assert_eq!(BURN_LEN_MIN, 262_144);
        assert_eq!(BURN_LEN_MIN, memmap::FW_MIN_BODY_LEN);
        // `assert_eq!` and not `assert!(a > b)`: clippy's
        // `assertions_on_constants` flags the latter as const-folded away, and the
        // exact ratio is the more useful record anyway.
        assert_eq!(
            BURN_LEN_MIN,
            8 * 32_768,
            "pins.c:1298's own floor is 32,768; this is exactly 8x tighter"
        );
    }

    /// The burn length comes out of the header, at the offset the
    /// `coldcardFirmwareHeader_t` layout puts it at — not from a caller, and not
    /// from the slice length.
    ///
    /// **The offset is a LITERAL here, deliberately.** Building the fixture from
    /// [`FW_LENGTH_FIELD_OFFSET`] — as [`staged`] does, which is fine for the
    /// legs that are not about the offset — makes the writer and the reader move
    /// together, and MEASURED: with the fixture keyed off the constant, changing
    /// it from 24 to 28 left this test GREEN. The rest of the header is filled
    /// with `0xff` so that *any* other read offset yields a length the ceiling
    /// refuses rather than one that happens to work.
    #[test]
    fn staged_burn_len_reads_firmware_length_from_the_header() {
        // 16,280 = FW_HEADER_OFFSET 16,256 + 24 (sigheader.h:25-31).
        const FIELD: usize = 16_280;
        assert_eq!(
            FIELD as u32,
            memmap::FW_HEADER_OFFSET + FW_LENGTH_FIELD_OFFSET,
            "the length field is at header offset 24, not 20 and not 28"
        );

        // `declared` deliberately differs from the slice length, so a function
        // that returned `staged.len()` instead would be caught too.
        let header_end = (memmap::FW_HEADER_OFFSET + memmap::FW_HEADER_SIZE) as usize;
        let mut image = vec![0u8; 400_000];
        image[memmap::FW_HEADER_OFFSET as usize..header_end].fill(0xff);
        image[FIELD..FIELD + 4].copy_from_slice(&300_000_u32.to_le_bytes());
        assert_eq!(staged_burn_len(&image), Ok(300_000));
    }

    /// The fund-loss refusal. One byte past the ceiling must be refused, and the
    /// ceiling itself accepted, so the bound is proved to be exactly where it is
    /// claimed rather than merely somewhere nearby.
    #[test]
    fn staged_burn_len_refuses_a_length_that_would_reach_flash_fs() {
        // Exactly at the ceiling: allowed. Needs a window that big, and the
        // window bound must therefore not be tighter than the ceiling.
        let ok = staged(BURN_LEN_MAX as usize, BURN_LEN_MAX);
        assert_eq!(staged_burn_len(&ok), Ok(BURN_LEN_MAX));

        // One byte past: the first byte of FLASH_FS is FS_IDENTITY_OFFSET.
        let over = staged(BURN_LEN_MAX as usize, BURN_LEN_MAX + 1);
        assert_eq!(staged_burn_len(&over), Err(StageError::TooLarge));

        // The two upstream ceilings, both of which reach the share.
        for bad in [
            (0x0020_0000 - 0x0002_0000_u32), // FW_MAX_LENGTH_MK4
            2 << 20,                         // pins.c:1299
        ] {
            let image = staged(BURN_LEN_MAX as usize, bad);
            assert_eq!(
                staged_burn_len(&image),
                Err(StageError::TooLarge),
                "a length the BOOTLOADER accepts must still be refused here"
            );
        }
    }

    /// `BURN_BASE + length` is checked, not wrapping. Under
    /// `overflow-checks = false` a plain `+` turns the largest possible
    /// `firmware_length` into an address *below* `FLASH_FS_BASE`, so the ceiling
    /// would wave through the worst case it exists for.
    #[test]
    fn the_ceiling_cannot_be_wrapped_past_flash_fs() {
        for bad in [u32::MAX, u32::MAX - 7, 0xffff_ffff - BURN_BASE + 1] {
            let image = staged(BURN_LEN_MAX as usize, bad);
            assert_eq!(
                staged_burn_len(&image),
                Err(StageError::TooLarge),
                "{bad:#x}: BURN_BASE + len wraps under overflow-checks = false"
            );
        }
        // The wrapped value a plain `+` would produce, spelled out, so the
        // arithmetic claim in the comment is checked and not just asserted.
        assert_eq!(BURN_BASE.wrapping_add(u32::MAX), memmap::FLASH_ISR_BASE - 1);
        assert!(BURN_BASE.wrapping_add(u32::MAX) < memmap::FLASH_FS_BASE);
    }

    /// The floor, and the window it closes: between `pins.c:1298`'s 32,768 and
    /// `FW_MIN_LENGTH`'s 262,144 the callgate accepts a length that
    /// `psram_do_upgrade`'s own `ASSERT` then rejects — after the point of no
    /// return.
    #[test]
    fn staged_burn_len_refuses_an_image_smaller_than_the_bootloader_will_burn() {
        for bad in [0, 1, 32_768, 100_000, BURN_LEN_MIN - 1] {
            let image = staged(BURN_LEN_MIN as usize, bad);
            assert_eq!(staged_burn_len(&image), Err(StageError::TooSmall), "{bad}");
        }
        let ok = staged(BURN_LEN_MIN as usize, BURN_LEN_MIN);
        assert_eq!(staged_burn_len(&ok), Ok(BURN_LEN_MIN));
    }

    /// A header claiming more than is staged would burn whatever follows the
    /// image in PSRAM. Refused, and reported as truncation rather than as
    /// oversize, because the two have different causes.
    #[test]
    fn staged_burn_len_refuses_a_header_claiming_more_than_is_staged() {
        // Declared is in range for the ceiling and the floor; only the slice is
        // short. 16,384 bytes is exactly the header end, the smallest window
        // whose header can be read at all.
        let short = staged(16_384, BURN_LEN_MIN);
        assert_eq!(staged_burn_len(&short), Err(StageError::Truncated));

        let one_short = staged(BURN_LEN_MIN as usize - 1, BURN_LEN_MIN);
        assert_eq!(staged_burn_len(&one_short), Err(StageError::Truncated));

        let exact = staged(BURN_LEN_MIN as usize, BURN_LEN_MIN);
        assert_eq!(staged_burn_len(&exact), Ok(BURN_LEN_MIN));
    }

    /// No header, no length — and no default. A slice shorter than
    /// `FW_HEADER_OFFSET + FW_HEADER_SIZE` cannot be burned at all.
    #[test]
    fn staged_burn_len_refuses_a_window_with_no_readable_header() {
        let field = (memmap::FW_HEADER_OFFSET + FW_LENGTH_FIELD_OFFSET) as usize;
        for n in [0, 1, field, field + 3, 16_383] {
            assert_eq!(
                staged_burn_len(&staged(n, BURN_LEN_MIN)),
                Err(StageError::HeaderUnreadable),
                "{n} bytes"
            );
        }
        // The header must be WHOLE, not merely long enough to reach offset 24:
        // `field + 4` is 16,284 and the header ends at 16,384.
        assert_eq!(field + 4, 16_284);
        assert_eq!(
            staged_burn_len(&staged(field + 4, BURN_LEN_MIN)),
            Err(StageError::HeaderUnreadable),
            "reaching the length field is not the same as holding the header"
        );
    }

    /// The staging window is bounded to PSRAM's lower half, which is the
    /// base-independent form of `psram.c:263-264`'s rule — the one the torn-burn
    /// recovery net depends on.
    #[test]
    fn staged_burn_len_refuses_a_window_outside_psrams_lower_half() {
        let half = (memmap::PSRAM_LEN / 2) as usize;
        assert_eq!(half, 4_194_304);
        let big = staged(half + 1, BURN_LEN_MIN);
        assert_eq!(staged_burn_len(&big), Err(StageError::NotInStagingWindow));
        // Refused BEFORE the header is parsed: an oversized window with a
        // perfectly good header is still not the staging window.
        let big_ok_header = staged(half + 1, BURN_LEN_MAX);
        assert_eq!(
            staged_burn_len(&big_ok_header),
            Err(StageError::NotInStagingWindow)
        );
        // And the bound is not tighter than the ceiling, or no maximal image
        // could ever be staged.
        assert!(BURN_LEN_MAX as usize <= half);
    }

    /// The sharpest leg, and the one no real artifact can reach: the length a
    /// caller would hand the callgate must equal the header's.
    ///
    /// `tools/pack-signed.py` emits 397,312 = 97 x 4096 with `fw_len` equal to
    /// the packed size, so driven by real output this would be a refusal that
    /// never fires. Both directions are proved here on hand-built fixtures.
    #[test]
    fn the_decoupling_guard_fires_on_a_mismatch_and_not_on_a_match() {
        let declared = 397_312;
        let image = staged(declared as usize, declared);

        // Matches: accepted, and returns the DERIVED length, not the argument.
        assert_eq!(check_burn_len(&image, declared), Ok(declared));

        // Every mismatch is refused, including the ones that are individually
        // in range and would sail through every other bound in this module.
        for bad in [
            declared - 1,
            declared + 1,
            declared - 4096,   // one 4 K erase page short
            declared + 4096,   // one page long -- 4 K of FLASH_TEXT tail erased
            BURN_LEN_MIN,      // in range, signed nothing
            BURN_LEN_MAX,      // the ceiling itself
            2 << 20,           // what pins.c would accept
            u32::MAX,
            0,
        ] {
            assert_eq!(
                check_burn_len(&image, bad),
                Err(StageError::LengthMismatch),
                "callgate len {bad} vs header {declared}"
            );
        }

        // The mismatch is judged against the HEADER, not the slice length. Same
        // slice, different declared value: now the value that matched is the one
        // refused, and vice versa.
        let relabelled = staged(declared as usize, declared - 4096);
        assert_eq!(
            check_burn_len(&relabelled, declared),
            Err(StageError::LengthMismatch)
        );
        assert_eq!(
            check_burn_len(&relabelled, declared - 4096),
            Ok(declared - 4096)
        );

        // And the bounds still run first: a mismatch is not a way past them.
        let over = staged(BURN_LEN_MAX as usize, BURN_LEN_MAX + 1);
        assert_eq!(check_burn_len(&over, 1), Err(StageError::TooLarge));
    }

    // ---- the accessor, the double and the read-back ------------------------

    use super::fake::FakePsram;

    /// A [`Psram`] whose `read` returns `Ok` **without storing anything**, so the
    /// buffer-poisoning step in [`readback_selftest`] has something to catch.
    ///
    /// It cannot be [`FakePsram`] and it must not be a knob on it: `FakePsram`
    /// reads with `copy_from_slice`, which cannot no-op, and adding a
    /// "lie about reads" switch to a type whose whole purpose is being NO MORE
    /// PERMISSIVE than the silicon is the wrong place for a liar. Kept private and
    /// `#[cfg(test)]`, so nothing outside this file can reach it.
    struct NonStoringPsram;

    impl Psram for NonStoringPsram {
        fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), PsramError> {
            check_write(offset, bytes.len())
        }
        fn read(&mut self, offset: u32, out: &mut [u8]) -> Result<(), PsramError> {
            check_read(offset, out.len())
        }
    }

    /// The one rule `mk4-bootloader/psram.c`'s header states, applied to the
    /// offset AND the length — the stricter reading, which is the one
    /// `PSRAMWrapper.write_at` enforces.
    #[test]
    fn write_alignment_is_the_rule_psram_c_states() {
        assert_eq!(WRITE_ALIGN, 4);
        // A word-aligned START is not enough: a runt length is refused too, which
        // is what `shared/psram.py`'s `assert ln % 4 == 0` says.
        assert_eq!(check_write(1, 4), Err(PsramError::NotAligned));
        assert_eq!(check_write(2, 4), Err(PsramError::NotAligned));
        assert_eq!(check_write(4, 1), Err(PsramError::NotAligned));
        assert_eq!(check_write(4, 6), Err(PsramError::NotAligned));
        // And the aligned forms are ACCEPTED, or "refuses everything" would read
        // exactly like "enforces alignment".
        assert_eq!(check_write(0, 4), Ok(()));
        assert_eq!(check_write(4, 8), Ok(()));
        assert_eq!(check_write(4, 0), Ok(()), "a zero-length write is a no-op");
        // Alignment BEFORE bounds, so a request that is both reports the more
        // specific fault -- same order as `crate::flash::check_bounds`.
        assert_eq!(
            check_write(PSRAM_STAGE_LEN + 1, 1),
            Err(PsramError::NotAligned)
        );
    }

    /// The other half of the asymmetry, and the half a wrong double gets wrong in
    /// the quiet direction: "Unaligned read okay" (`psram.c`), and
    /// `PSRAMWrapper.read_at` asserts nothing.
    ///
    /// Every pair below is asserted BOTH ways — `Ok` as a read, `NotAligned` as a
    /// write — because either check alone could be satisfied by a checker that
    /// ignored alignment entirely or by one that refused every unaligned access.
    #[test]
    fn check_read_requires_no_alignment_because_the_hardware_requires_none() {
        for (offset, len) in [(1u32, 1usize), (1, 3), (2, 2), (3, 2), (5, 7), (0, 1)] {
            assert_eq!(check_read(offset, len), Ok(()), "read {offset}+{len}");
            assert_eq!(
                check_write(offset, len),
                Err(PsramError::NotAligned),
                "the SAME access as a write must be refused: {offset}+{len}"
            );
        }
    }

    /// Both ends of the window, exactly, plus the wrap. The window is what makes
    /// `RECHDR_POS` unnameable, so an off-by-one at the top end is the one that
    /// matters: it is the recovery header a torn burn is replayed from.
    #[test]
    fn the_access_window_ends_exactly_at_psrams_lower_half() {
        assert_eq!(PSRAM_STAGE_LEN, 4_194_304);
        assert_eq!(PSRAM_STAGE_LEN, memmap::PSRAM_LEN / 2);
        assert_eq!(PSRAM_STAGE_LEN, 1 << 22, "22 bits, which is why pattern_byte folds three terms");

        // Top end: the last word is writable, one word past it is not.
        assert_eq!(check_write(PSRAM_STAGE_LEN - 4, 4), Ok(()));
        assert_eq!(check_write(PSRAM_STAGE_LEN, 4), Err(PsramError::OutOfBounds));
        assert_eq!(
            check_write(PSRAM_STAGE_LEN - 4, 8),
            Err(PsramError::OutOfBounds)
        );
        // The whole window in one access, and one word more.
        assert_eq!(check_write(0, PSRAM_STAGE_LEN as usize), Ok(()));
        assert_eq!(
            check_write(0, PSRAM_STAGE_LEN as usize + 4),
            Err(PsramError::OutOfBounds)
        );
        // Byte granularity on the read side, where alignment cannot round the
        // boundary off for us.
        assert_eq!(check_read(PSRAM_STAGE_LEN - 1, 1), Ok(()));
        assert_eq!(check_read(PSRAM_STAGE_LEN - 1, 2), Err(PsramError::OutOfBounds));
        assert_eq!(check_read(PSRAM_STAGE_LEN, 1), Err(PsramError::OutOfBounds));
        assert_eq!(check_read(PSRAM_STAGE_LEN, 0), Ok(()), "empty at the very end");

        // `checked_add`, not wrapping. Under `overflow-checks = false` a plain `+`
        // brings `end` back under the limit and an in-window offset is accepted
        // for an out-of-window range -- which is how `RECHDR_POS` gets named.
        assert_eq!(check_read(u32::MAX, usize::MAX), Err(PsramError::OutOfBounds));
        assert_eq!(check_write(4, usize::MAX - 3), Err(PsramError::OutOfBounds));

        // The containment claim itself: the top of the window is below the
        // recovery header at `PSRAM_BASE + PSRAM_SIZE - 2048` (`psram.c:32`).
        // `assert_eq!` on the GAP and not `assert!(a < b)`, which clippy's
        // `assertions_on_constants` correctly calls const-folded-away -- and the
        // exact clearance is the more useful record.
        assert_eq!(
            memmap::PSRAM_LEN - 2048 - PSRAM_STAGE_LEN,
            4_192_256,
            "clearance between the top of the staging window and RECHDR_POS"
        );
    }

    /// **The single most important test in this module.** A double that accepted
    /// an unaligned write would be more permissive than the silicon, and every
    /// test built on it would be testing a machine that does not exist — PLAN.md
    /// §8.1 defect 5 in a new shape.
    #[test]
    fn the_double_refuses_an_unaligned_write_like_the_silicon() {
        let mut psram = FakePsram::new(64);
        for (offset, len) in [(1u32, 4usize), (2, 4), (3, 4), (0, 1), (0, 2), (0, 3), (4, 5)] {
            let bytes = vec![0xa5u8; len];
            assert_eq!(
                psram.write(offset, &bytes),
                Err(PsramError::NotAligned),
                "{offset}+{len} is not a whole number of words at a word boundary"
            );
        }
        // Refused means UNTOUCHED. A double that refused *after* copying would
        // still be lying, just about a different thing.
        assert!(
            psram.cells().iter().all(|b| *b == 0),
            "a refused write must not have stored anything"
        );
        // And the aligned form of the same write lands, so the refusals above are
        // alignment and not blanket rejection.
        assert_eq!(psram.write(4, &[0xa5; 4]), Ok(()));
        assert_eq!(&psram.cells()[4..8], &[0xa5; 4]);
        assert_eq!(&psram.cells()[0..4], &[0; 4], "and only at the offset given");
    }

    /// The opposite error, in the direction that hides a real capability: the
    /// hardware permits an unaligned read, so a double that refused one would make
    /// a legal staging path look illegal.
    #[test]
    fn the_double_permits_an_unaligned_read_like_the_silicon() {
        let mut psram = FakePsram::new(64);
        psram.write(0, &[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();

        let mut three = [0u8; 3];
        assert_eq!(psram.read(1, &mut three), Ok(()));
        assert_eq!(three, [2, 3, 4], "an unaligned read returns the right bytes");

        // Straddling the word boundary, at an unaligned offset AND an unaligned
        // length -- the pair `check_write` refuses outright.
        let mut two = [0u8; 2];
        assert_eq!(psram.read(3, &mut two), Ok(()));
        assert_eq!(two, [4, 5]);
        assert_eq!(check_write(3, 2), Err(PsramError::NotAligned));

        let mut one = [0u8; 1];
        assert_eq!(psram.read(7, &mut one), Ok(()));
        assert_eq!(one, [8]);

        // The fake's OWN capacity boundary, at exactly `end == len`. MEASURED:
        // without these three lines, changing `FakePsram::span`'s `end <=
        // self.cells.len()` to `end <` left all 291 lib tests GREEN -- no access
        // anywhere reached the last byte of the fake, so a double that quietly
        // refused its own final word would have looked correct.
        assert_eq!(psram.read(63, &mut one), Ok(()));
        assert_eq!(one, [0], "the last byte of the fake is readable");
        assert_eq!(psram.write(60, &[9; 4]), Ok(()));
        assert_eq!(&psram.cells()[60..], &[9; 4], "the last word is writable");

        // Bounds still apply to reads; only alignment does not.
        let mut past = [0u8; 2];
        assert_eq!(psram.read(63, &mut past), Err(PsramError::OutOfBounds));
    }

    /// The ARM accessor's refusals run on the HOST too, which is the only reason
    /// they are testable at all: [`check_write`] / [`check_read`] are outside the
    /// `cfg(target_arch = "arm")` block, so a `cfg` cannot fail this open.
    ///
    /// The `NotOnThisTarget` legs are host truths and this test is only ever
    /// compiled for the host (`cargo test` never runs on thumbv7em).
    #[test]
    fn the_mapped_accessor_checks_the_access_before_it_reports_no_hardware() {
        let mut psram = MappedPsram;
        // Alignment and bounds first: these must NOT be masked by the missing
        // hardware, or moving the checks inside the `cfg` would go unnoticed.
        assert_eq!(psram.write(1, &[0; 4]), Err(PsramError::NotAligned));
        assert_eq!(psram.write(0, &[0; 3]), Err(PsramError::NotAligned));
        assert_eq!(
            psram.write(PSRAM_STAGE_LEN, &[0; 4]),
            Err(PsramError::OutOfBounds)
        );
        let mut two = [0u8; 2];
        assert_eq!(
            psram.read(PSRAM_STAGE_LEN - 1, &mut two),
            Err(PsramError::OutOfBounds)
        );

        // Only a LEGAL access gets as far as "there is no PSRAM here".
        assert_eq!(psram.write(0, &[0; 4]), Err(PsramError::NotOnThisTarget));
        assert_eq!(psram.read(1, &mut two), Err(PsramError::NotOnThisTarget));

        // The one case that is `Ok` off ARM: a zero-length access is a no-op on
        // both targets. `readback_selftest` refuses an empty SPAN instead.
        assert_eq!(psram.write(0, &[]), Ok(()));
        assert_eq!(psram.read(0, &mut []), Ok(()));
    }

    /// [`Psram::view`] shows nothing off ARM rather than something wrong, and its
    /// window bound runs BEFORE it reports missing hardware.
    ///
    /// The ordering is host-observable because the two refusals are different
    /// VARIANTS, which is the same trick
    /// `the_mapped_accessor_checks_the_access_before_it_reports_no_hardware` uses:
    /// move `check_read` inside the `cfg(target_arch = "arm")` block and the
    /// over-window leg below turns from `OutOfBounds` into `NotOnThisTarget`,
    /// which is a refusal that fails OPEN on ARM — a `from_raw_parts` reaching
    /// past PSRAM's lower half and over the bootloader's recovery header.
    ///
    /// MEASURED 2026-09-17: deleting that `check_read` from [`MappedPsram::view`]
    /// reddens this test at `left: Err(NotOnThisTarget)` / `right: Err(OutOfBounds)`
    /// (exit 101, 1 of 292 failed), and replacing [`Psram::view`]'s default body with
    /// `Ok(&[])` reddens the `NoView` leg at `left: Ok([])`.
    ///
    /// **THE FAKE'S LEGS PIN ITS OWN CAPACITY AND NOTHING MORE, and this doc claimed
    /// otherwise until 2026-09-17.** It said they pin the same ordering — "the
    /// DEVICE's window bound runs before the double's own capacity, so the double
    /// cannot show a window the silicon refuses" — and that claim is
    /// **unfalsifiable**, not merely untested. MEASURED: deleting `check_read` from
    /// `FakePsram::view` left all 316 hal tests GREEN, exit 0. It cannot do
    /// otherwise: `FakePsram::new` PANICS above [`PSRAM_STAGE_LEN`]
    /// (`a_fake_larger_than_the_staging_window_is_a_test_bug`), so
    /// `self.cells.len() <= PSRAM_STAGE_LEN` always, so any `len` that
    /// [`check_read`] refuses is a `len` the capacity refuses too — and both produce
    /// the same [`PsramError::OutOfBounds`] variant, deliberately, so no leg can
    /// ever tell which one fired. The property is real; it is enforced at
    /// CONSTRUCTION and not at access, and `new`'s own `#[should_panic]` test is its
    /// pin. See the label at that `check_read`'s call site for why the redundant
    /// line is kept anyway.
    #[test]
    fn the_view_off_arm_shows_nothing_rather_than_something_wrong() {
        let mapped = MappedPsram;
        // The window bound, not masked by the missing hardware.
        assert_eq!(
            mapped.view(PSRAM_STAGE_LEN + 4),
            Err(PsramError::OutOfBounds)
        );
        // Only a LEGAL length gets as far as "there is no PSRAM here". So a host
        // build stages nothing through `MappedPsram` — the trap this module's
        // `write` doc names, in the one place a `Stager` could have mistaken an
        // `Ok` for progress.
        assert_eq!(mapped.view(4), Err(PsramError::NotOnThisTarget));
        // And the exact end of the window is legal, so the bound is not off by one
        // in the tighter direction either.
        assert_eq!(
            mapped.view(PSRAM_STAGE_LEN),
            Err(PsramError::NotOnThisTarget)
        );

        // The double: its last addressable byte is IN the view.
        let mut fake = fake::FakePsram::new(64);
        assert_eq!(fake.write(60, &[7; 4]), Ok(()));
        assert_eq!(fake.view(64).map(|v| v[60..].to_vec()), Ok(vec![7; 4]));
        // One past its capacity is a refusal and not a panic.
        assert_eq!(fake.view(65), Err(PsramError::OutOfBounds));

        // The default body is a refusal, so an implementor that forgets `view`
        // cannot hand a caller a digest of nothing. Spelled with a type that
        // implements the other two methods and nothing else.
        struct NoView;
        impl Psram for NoView {
            fn write(&mut self, _offset: u32, _bytes: &[u8]) -> Result<(), PsramError> {
                Ok(())
            }
            fn read(&mut self, _offset: u32, _out: &mut [u8]) -> Result<(), PsramError> {
                Ok(())
            }
        }
        assert_eq!(NoView.view(4), Err(PsramError::NotOnThisTarget));
    }

    /// The pattern depends on every address bit the window has, so an aliased
    /// address line changes the expected byte. A constant pattern is the vacuous
    /// version of this whole self-test.
    #[test]
    fn pattern_byte_folds_the_whole_address_and_its_collisions_are_measured() {
        // Adjacent bytes and adjacent words differ.
        assert_ne!(pattern_byte(0), pattern_byte(1));
        assert_ne!(pattern_byte(0), pattern_byte(4));
        // Every address line above the low byte is live. 21 is the top line the
        // window has (`PSRAM_STAGE_LEN == 1 << 22`).
        for shift in [8u32, 16, 20, 21] {
            assert_ne!(
                pattern_byte(0),
                pattern_byte(1 << shift),
                "address line {shift} does not reach the pattern"
            );
        }
        // Bit 24 and above cannot be set by any accepted offset, which is why
        // there is no `>> 24` term: it would fold in a bit that is always zero.
        assert_eq!((PSRAM_STAGE_LEN - 1) >> 24, 0);
        // THE MEASURED CEILING, as an equality so it cannot rot into an
        // injectivity claim: a byte-wide pattern collides, and here is one.
        assert_eq!(pattern_byte(0), 0);
        assert_eq!(
            pattern_byte(0x101),
            pattern_byte(0),
            "a byte-wide pattern is not injective over 4 MiB; see the ponytail note"
        );
    }

    /// A round trip through the double, checked against the backing store rather
    /// than only through the same offsets it was written with — an off-by-one in
    /// the chunk loop is invisible to a read-back that repeats the error.
    #[test]
    fn readback_selftest_round_trips_a_span_and_writes_nothing_outside_it() {
        let mut psram = FakePsram::new(256);
        assert_eq!(readback_selftest(&mut psram, 64, 128), Ok(()));
        for (i, byte) in psram.cells().iter().enumerate() {
            let want = if (64..192).contains(&i) {
                pattern_byte(i as u32)
            } else {
                0
            };
            assert_eq!(*byte, want, "byte {i}");
        }
    }

    /// The loop advances. A corrupted byte in the LAST chunk of a four-chunk span
    /// is only reachable if every chunk is visited.
    #[test]
    fn readback_selftest_visits_every_chunk_of_a_multi_chunk_span() {
        const SPAN: u32 = 200;
        assert_eq!(SPAN as usize / SELFTEST_CHUNK, 3, "3 full chunks and an 8 B tail");
        assert_eq!(SPAN as usize % SELFTEST_CHUNK, 8);

        let mut psram = FakePsram::new(256);
        psram.corrupt_writes_at(197);
        assert_eq!(
            readback_selftest(&mut psram, 0, SPAN),
            Err(PsramError::Mismatch { offset: 197 }),
            "a fault in the tail chunk must be seen"
        );
        // The clean span is `Ok`, so the failure above is the corruption and not
        // the span size.
        let mut clean = FakePsram::new(256);
        assert_eq!(readback_selftest(&mut clean, 0, SPAN), Ok(()));
        assert_eq!(&clean.cells()[SPAN as usize..], &[0u8; 56]);
    }

    /// The read-back can see a ONE-BYTE difference, and reports its ABSOLUTE
    /// offset — not its index within the chunk, and not the start of the span.
    #[test]
    fn readback_selftest_reports_the_offset_of_a_single_corrupted_byte() {
        let mut psram = FakePsram::new(256);
        // Inside the span but not at its start, and not at a chunk boundary, so
        // reporting `offset`, `pos` or `i` instead of the sum all read wrong.
        psram.corrupt_writes_at(100);
        assert_eq!(
            readback_selftest(&mut psram, 64, 64),
            Err(PsramError::Mismatch { offset: 100 })
        );
        // A corruption OUTSIDE the span is not the self-test's business.
        let mut elsewhere = FakePsram::new(256);
        elsewhere.corrupt_writes_at(200);
        assert_eq!(readback_selftest(&mut elsewhere, 64, 64), Ok(()));
    }

    /// The buffer is poisoned with the complement before the read-back, so a
    /// `read` that returns `Ok` without storing anything is a mismatch at byte 0
    /// rather than a pass.
    ///
    /// Without the poison the buffer still holds what was written, and comparing
    /// it to the pattern succeeds no matter what the read did. `pattern_byte(0)`
    /// is 0, which is why zeroing the buffer would not do.
    #[test]
    fn readback_selftest_fails_when_a_read_stores_nothing() {
        assert_eq!(
            readback_selftest(&mut NonStoringPsram, 0, SELFTEST_CHUNK as u32),
            Err(PsramError::Mismatch { offset: 0 })
        );
        // And the writes it made were legal, so the failure is the read.
        assert_eq!(NonStoringPsram.write(0, &[0; 64]), Ok(()));
    }

    /// `Ok(())` must mean "at least one byte round-tripped". A zero-length span
    /// would otherwise return a success value having compared nothing — the
    /// vacuous pass this whole module is written against.
    #[test]
    fn readback_selftest_refuses_an_empty_span_rather_than_passing_vacuously() {
        let mut psram = FakePsram::new(64);
        assert_eq!(
            readback_selftest(&mut psram, 0, 0),
            Err(PsramError::OutOfBounds)
        );
        assert_eq!(
            readback_selftest(&mut psram, 64, 0),
            Err(PsramError::OutOfBounds),
            "refused before the offset is even bounded"
        );
        assert!(psram.cells().iter().all(|b| *b == 0));
        // The smallest span that CAN pass is one word.
        assert_eq!(readback_selftest(&mut psram, 0, 4), Ok(()));
    }

    /// The WHOLE span is bounded before the first byte is written, so an illegal
    /// span cannot scribble the part of itself that was legal.
    #[test]
    fn readback_selftest_refuses_a_bad_span_before_writing_anything() {
        // Past the window. The fake is 256 B, so without the up-front check the
        // first chunk would land and only a later chunk would be refused.
        let mut over = FakePsram::new(256);
        assert_eq!(
            readback_selftest(&mut over, 0, PSRAM_STAGE_LEN + 4),
            Err(PsramError::OutOfBounds)
        );
        assert!(
            over.cells().iter().all(|b| *b == 0),
            "nothing may be written before the span is bounded"
        );

        // Misaligned length. 130 = two full chunks plus a 2-byte tail, so without
        // the up-front check 128 bytes would be written and only the tail refused.
        let mut runt = FakePsram::new(256);
        assert_eq!(
            readback_selftest(&mut runt, 0, 130),
            Err(PsramError::NotAligned)
        );
        assert!(
            runt.cells().iter().all(|b| *b == 0),
            "nothing may be written before the span is aligned"
        );

        // Misaligned offset, same rule.
        let mut skew = FakePsram::new(256);
        assert_eq!(readback_selftest(&mut skew, 2, 64), Err(PsramError::NotAligned));
        assert!(skew.cells().iter().all(|b| *b == 0));
    }

    /// A fake bigger than the real window would accept offsets the device
    /// refuses. That is the whole failure mode this type exists not to have, so
    /// the constructor refuses it rather than documenting it.
    #[test]
    #[should_panic(expected = "would accept offsets the device refuses")]
    fn a_fake_larger_than_the_staging_window_is_a_test_bug() {
        // One byte past. The window itself must still be constructible, or the
        // refusal would be off by one -- proved by the `Ok` leg below, which runs
        // BEFORE the panic.
        let full = FakePsram::new(PSRAM_STAGE_LEN as usize);
        assert_eq!(full.len(), 4_194_304);
        let _ = FakePsram::new(PSRAM_STAGE_LEN as usize + 1);
    }

    /// A zero-length fake, so `FakePsram::is_empty`'s "never true by
    /// construction" is enforced rather than asserted in prose.
    #[test]
    #[should_panic(expected = "cannot hold a span")]
    fn a_zero_length_fake_is_a_test_bug() {
        let _ = FakePsram::new(0);
    }
}
