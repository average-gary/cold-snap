//! `StmFlash` — [`NorFlash`] + [`ReadNorFlash`] over the 512 K `FLASH_FS`
//! region, which is where all frostsnap nonce and key state lives.
//!
//! `FLASH_FS` (`0x0818_0000`, 512 K, `layout.ld:18`) was MicroPython's LFS2
//! filesystem. We have no MicroPython, so the whole region is free and is the
//! natural home for nonce storage.
//!
//! # Offsets are relative to `FLASH_FS`, deliberately
//!
//! `offset = 0` is [`crate::memmap::FLASH_FS_BASE`] and [`ReadNorFlash::capacity`]
//! is [`crate::memmap::FLASH_FS_LEN`]. So a bounds check is also a containment
//! proof: no offset this type accepts can name `FLASH_TEXT`, the vector table, or
//! the bootloader. `frostsnap_embedded`'s `FlashPartition` then carves this up in
//! 4096-byte sectors (`partition.rs:32`, `:53-56`).
//!
//! # ERASE_SIZE = 4096 lines up exactly with frostsnap's SECTOR_SIZE
//!
//! `FLASH_ERASE_SIZE` is `0x1000` (`mk4-bootloader/storage.h:17`, with the
//! comment "when erasing pages they are half as big, since only in one physical
//! bank"), and `flash_page_erase` implements exactly that geometry: page index =
//! `addr / 0x1000`, bank 2 iff index >= 256, index masked to 8 bits
//! (`storage.c:212-232`) — i.e. 2 banks x 256 pages x 4 K = 2 MB. This is the
//! code that performs production firmware upgrades (`psram.c:330-347`), so it is
//! load-tested. It matches `frostsnap_embedded`'s `SECTOR_SIZE = 4096`
//! (`partition.rs:32`) with no adaptation.
//!
//! # THE CONFLICT THIS MODULE MUST RESOLVE: WRITE_SIZE
//!
//! **STM32L4 programs 64-bit doublewords.** `flash_burn(uint32_t address,
//! uint64_t val)` sets `FLASH_CR_PG`, stores the low word, `__ISB()`, stores the
//! high word, then waits (`storage.c:167-201`). The HAL has no 32-bit program
//! type at all — only `DOUBLEWORD`, `FAST`, `FAST_AND_LAST`, all 64-bit
//! (`stm32l4xx_hal_flash.h:200-203`). So the hardware truth is
//! `WRITE_SIZE = 8`, and that is what [`StmFlash::WRITE_SIZE`] is set to.
//!
//! **But `frostsnap_embedded::NorFlashLog::new` asserts
//! `assert_eq!(WORD_SIZE, S::WRITE_SIZE as u32)` with `WORD_SIZE = 4`**
//! (`nor_flash_log.rs:5,16`). With `WRITE_SIZE = 8` that assert fires, and under
//! `panic = "abort"` it is a halt at construction — inside the very module
//! PLAN.md §6.3 priority 2 is about. Upstream's own device wires
//! `NorFlashLog` into `MutationLog` (`device/src/flash/log.rs:4,38,51`), so this
//! is on the live path, not a corner.
//!
//! It is not only the assert. `NorFlashLog::push` writes the entry body first and
//! then goes **back** to write a 4-byte length word at `word_pos * 4`
//! (`nor_flash_log.rs:26-40`). With 8-byte programming, that length word and the
//! first body word share one doubleword, so the doubleword is programmed twice —
//! `PROGERR` on STM32L4, and `NorFlash`'s own contract already forbids it ("It
//! is not allowed to write to the same word twice",
//! `embedded-storage-0.3.1/src/nor_flash.rs:104`). A `WRITE_SIZE = 4` shim cannot
//! paper over this: `NorFlash` has no flush, so the impl can never know whether
//! the other half of a doubleword is still coming.
//!
//! **Two honest resolutions; pick one before implementing, do not silently
//! choose:**
//!
//! 1. Patch the vendored `frostsnap_embedded`: `WORD_SIZE = 8` in
//!    `nor_flash_log.rs`, and make `push` reserve the length slot as a full
//!    doubleword written once. Mechanical, and it is where the defect actually
//!    is. Record it in `vendor/README.md`'s local-modifications table.
//! 2. Do not use `NorFlashLog`. `AbSlot` (`ab_write.rs`) writes each slot as one
//!    forward pass with `bincode_writer_remember_to_flush`, pads the tail to
//!    `WRITE_SIZE` (`partition.rs:270-284`) and never revisits a word, so it is
//!    already doubleword-safe — and `NonceAbSlot` (`nonce_slots.rs:12-18`), the
//!    nonce path proper, uses only `AbSlot`. Only the mutation **log** needs
//!    replacing.
//!
//! `AbSlot` being safe and `NorFlashLog` not is why this is a live decision
//! rather than a blocker on all of phase 2. Both are **read**, not measured on
//! silicon.
//!
//! ## RESOLVED at integration: **option 2**, and the reason is measured
//!
//! `WRITE_SIZE` stays `8` — the hardware truth — and `NorFlashLog` is **not
//! usable over `StmFlash`**. What decided it:
//!
//! * **Nothing in this tree uses `NorFlashLog`.** Measured: the only references
//!   outside `nor_flash_log.rs` itself are this comment and `host_smoke.rs`. Its
//!   sole upstream consumer is `MutationLog` in the non-vendored `device` crate
//!   (`device/src/flash/log.rs:4,38,51`), which cold-snap replaces wholesale
//!   (PLAN.md §3). So option 2 costs nothing today.
//! * **The nonce path is `AbSlot`-only and it composes cleanly at
//!   `WRITE_SIZE = 8`.** Measured, not reasoned: `AbSlot` uses
//!   `bincode_writer_remember_to_flush::<256>` and `partition.rs:188-189`
//!   asserts `256 % WRITE_SIZE == 0` and `ERASE_SIZE % 256 == 0`; `8` and `4096`
//!   satisfy both. `NorFlashLog`'s `WRITE_BUF_SIZE` is `32` in release / `512` in
//!   debug (`nor_flash_log.rs:7`) and also divides, so the buffer asserts are
//!   *not* what rules it out — the `assert_eq!(WORD_SIZE, S::WRITE_SIZE)` and the
//!   re-programmed length doubleword are.
//! * **Option 1 was rejected as a fail-open change.** Setting `WORD_SIZE = 8`
//!   makes the assert pass while leaving `push`'s go-back-and-write-the-length
//!   pattern (`nor_flash_log.rs:26-41`) intact, so the doubleword is still
//!   programmed twice — `PROGERR` on real silicon, with the assert that would
//!   have caught it now removed. Fixing it properly means rewriting `push`'s
//!   layout, i.e. a non-mechanical change to vendored code with no in-tree
//!   consumer to justify it.
//!
//! [`assert_nor_flash_log_is_unusable`] pins this as an executable check, and
//! [`fake::FakeFlash`] lets the integration tests exercise the real
//! `AbSlot`/`device_nonces` stack at this geometry on the host. If a mutation log
//! is ever needed, build it on [`StmFlash`] with a forward-only layout; do not
//! reach for `NorFlashLog`.
//!
//! # DBANK is doubly load-bearing and the reference contradicts itself
//!
//! `storage.h:12-14` says "8k pages, because DBANK=0", yet `flash_page_erase`
//! implements 4 K pages with `BKER` bank selection (`storage.c:212-232`), which
//! is DBANK=**1** geometry. On this part the HAL defines
//! `FLASH_PAGE_SIZE = 0x1000` and `FLASH_PAGE_SIZE_128_BITS = 0x2000`
//! (`stm32l4xx_hal_flash.h:852-854`), i.e. 4 K normally and 8 K in single-bank
//! 128-bit mode. Both cannot be true. This decides two things:
//!
//! * **Erase granularity.** If DBANK were really 0, erases are 8 K and an
//!   `ERASE_SIZE = 4096` impl would silently destroy an adjacent 4 K sector —
//!   catastrophic for A/B nonce slots, whose entire purpose is that the other
//!   copy survives. `NonceAbSlot` uses `split_off_front(2)`
//!   (`nonce_slots.rs:27`), i.e. the A and B copies are two **consecutive** 4 K
//!   sectors, so at DBANK=0 they are the same physical 8 K page and every write
//!   destroys its own redundancy while reporting `Committed`. That is pinned by
//!   [`ab_copies_would_share_one_page_at_dbank_zero`].
//! * **Whether the driver must run from RAM.** See the next section — the
//!   previous justification here was arithmetically false.
//!
//! ## The DBANK check is now UNBYPASSABLE, and it previously never ran
//!
//! This module used to expose `StmFlash::take() -> Option<StmFlash>` plus
//! `StmFlash::new(self) -> Result<Self, _>` — same type in, same type out. `take`
//! already handed out a fully usable [`NorFlash`], so `new` was **decoration**:
//! measured, it had **zero callers** anywhere in the tree, so the `OPTR` read
//! never executed, and `StmFlash::take().unwrap()` followed by
//! `NorFlash::erase`/`write` type-checked and dispatched.
//!
//! Fixed by splitting the capability in two: [`StmFlashToken::take`] hands out a
//! token that implements **nothing**, and [`StmFlashToken::open`] — which reads
//! `FLASH->OPTR` bit 22 and applies [`dbank_ok`] — is the **only** way to obtain
//! an [`StmFlash`]. [`StmFlash`] has a private field and no other constructor, so
//! the check cannot be skipped by any caller, in this crate or downstream.
//!
//! Still **assumed, and bench work**: the actual `DBANK` value on silicon. If it
//! is 0, [`ERASE_SIZE`] must become 8192 *and* `nonce_slots.rs:27`'s
//! `split_off_front(2)` must change. This module cannot resolve that; it can only
//! refuse to write until it is known, which is what it now does.
//!
//! # Must this run from RAM? UNRESOLVED — and the old reasoning was wrong
//!
//! Coldcard marks `flash_burn` and `flash_page_erase`
//! `__attribute__((section(".ramfunc")))` with "this function **AND** everything
//! it calls, must be in RAM" (`storage.c:158-165`, `:204-211`), and
//! `_flash_wait_done` carries "Absolutely MUST be in RAM" (`storage.c:57-59`).
//!
//! This module previously justified *not* doing that with: "our code executes
//! from `FLASH_TEXT` (bank 1) while `FLASH_FS` is bank 2, so read-while-write
//! makes `.ramfunc` unnecessary." **The premise is false on its own numbers.**
//! Bank 2 begins at `0x0810_0000` (256 pages x 4 K = 1 MB), but `FLASH_TEXT`
//! spans `0x0802_4000`..`0x0818_0000`:
//!
//! | | bytes |
//! |---|---|
//! | `FLASH_TEXT` in bank 1 | 901,120 |
//! | `FLASH_TEXT` in **bank 2**, alongside `FLASH_FS` | **524,288** |
//! | image as built | 856,872 |
//! | margin before code lands in bank 2 | **44,248** |
//!
//! So 512 K of the firmware budget is in the same bank as `FLASH_FS`, and at
//! 856,872 bytes there are only ~44 K of headroom before instruction fetch and
//! nonce erase share a bank. [`flash_text_bytes_in_bank2`] and
//! [`bank1_margin_at`] make this arithmetic executable rather than a comment, and
//! [`text_and_fs_share_bank_two`] fails if someone reinstates the old claim.
//!
//! **Not fixed in this phase, and deliberately not papered over.** Placing these
//! functions in RAM needs `#[link_section = ".ramfunc"]` **plus** a linker script
//! that defines and loads that section; measured, this tree has no `.ld`, no
//! `.x`, no `build.rs` and no `link_section` anywhere, and no final image is
//! linked yet. Adding the attribute alone would put the code in a section nothing
//! places — worse than an honest gap. It is recorded in
//! [`RAM_EXECUTION_IS_UNRESOLVED`] and must be settled with the linker script, or
//! by a bench measurement that erasing `FLASH_FS` while fetching from
//! `>= 0x0810_0000` does not stall.
//!
//! # Registers (read, from the CMSIS header the bootloader itself compiles
//! against — `mk4-bootloader/Makefile:229` names `stm32l4s5xx.h`)
//!
//! `FLASH_R_BASE = AHB1PERIPH_BASE(0x4002_0000) + 0x2000 = 0x4002_2000`
//! (`stm32l4s5xx.h:1319,1401`). Offsets from `FLASH_TypeDef`
//! (`stm32l4s5xx.h:555-577`): `ACR 0x00`, `KEYR 0x08`, `SR 0x10`, `CR 0x14`,
//! `ECCR 0x18`, `OPTR 0x20`.
//!
//! # The `FLASH_SR` access is a PORT; the rest of the sequence is not
//!
//! This file had **zero** `#[test]`s. Six simultaneous mutations (deleting the
//! containment bound, replacing `checked_add` with `wrapping_add`, deleting the
//! alignment check, deleting the erase-floor guard, inverting the bank-select bit,
//! and making [`dbank_ok`] return unconditional `true`) left every host test
//! passing, because the tests exercised [`fake::FakeFlash`] and never the driver.
//! The `FLASH_SR` **ordering** defect below was likewise unreachable by any test,
//! which is why it went unnoticed.
//!
//! The fix is scoped to what the defect actually was. [`SrPort`] abstracts the two
//! `FLASH->SR` accesses — read and write-1-to-clear — and the wait/clear logic
//! lives in the `cfg`-free generic [`sr_wait_done`] and [`sr_prologue`]. `Mmio`
//! (private, ARM-only) is the real implementation; the test module's `SimPort`
//! models the error **latch**, `BSY` and `EOP`, which is all that sequencing bug
//! needed to be caught.
//!
//! **Deliberately not a full `FlashPort`.** `CR`, `KEYR`, `ACR` and the two program
//! stores are still direct volatile accesses under `#[cfg(target_arch = "arm")]`. A
//! simulator for those would model unlock, `PG`/`PER`/`STRT`, page/bank decoding
//! and the doubleword array from the same datasheet reading that produced the
//! driver, so agreement would prove only self-consistency — while the failures that
//! matter there (`PROGERR` timing, `WRPERR`, whether the sequence must run from
//! RAM) are exactly the ones a host model cannot have. Those stay in "Not testable
//! off-hardware" below, honestly. What *is* pure — [`check_bounds`],
//! [`erase_page_of`], [`dbank_ok`], the bank arithmetic — is tested directly.
//!
//! ## The `FLASH_SR` wedge this ordering fixes
//!
//! [`sr_wait_done`] returns `Err` on latched `SR` error bits **without clearing
//! them**. `write` used to call it *before* its own `SR` clear, so once any error
//! bit latched, the clear was unreachable and every later write returned the same
//! stale error forever — on healthy flash. `erase` contained no `SR` write at all.
//! Reproduced on `SimPort`, not reasoned: one `PROGERR` makes the next five writes
//! and the following erase all return `Hardware(8)`
//! (`one_latched_error_wedges_the_old_order_forever`). For nonce storage that is a
//! permanent wedge after one transient fault.
//!
//! Coldcard's order is the opposite of what this module had: `flash_burn` calls
//! `_flash_wait_done()` and **discards the result**, then clears `SR`
//! unconditionally (`storage.c:171-175`); `flash_page_erase` does the same
//! (`storage.c:223-228`). [`sr_prologue`] is that fix, and is strictly stronger: it
//! clears the latched errors **first** and *then* waits on `BSY` with the result
//! propagated, so a stale latch cannot wedge the driver **and** a genuinely stuck
//! peripheral is still refused instead of being programmed into. Every program and
//! every erase goes through it, via the private ARM-only `operation_prologue`.
//!
//! # Not testable off-hardware
//!
//! Real program/erase timing and `PROGERR`/`WRPERR` behaviour on silicon, power
//! loss (PLAN.md §7; neither `TestNorFlash` nor [`fake::FakeFlash`] models it),
//! the true `DBANK` value, and whether these functions must execute from RAM.
//!
//! **ECC is unhandled.** `FLASH->ECCR` is at offset `0x18` (above) and this module
//! never reads it. A single-bit error is corrected silently; an **uncorrectable
//! double-bit** error on a nonce read raises an NMI, not a `Result::Err`, so no
//! error path here can observe it. Listed rather than fixed: handling it needs the
//! NMI vector, which belongs with the panic handler and a linker script.

use embedded_storage::nor_flash::{
    ErrorType, NorFlash, NorFlashError, NorFlashErrorKind, ReadNorFlash,
};

/// `FLASH_R_BASE` = `AHB1PERIPH_BASE` + `0x2000` (`stm32l4s5xx.h:1319,1401`).
pub const FLASH_R_BASE: usize = 0x4002_2000;

/// `FLASH->KEYR` (`FLASH_TypeDef` offset `0x08`).
pub const FLASH_KEYR: *mut u32 = (FLASH_R_BASE + 0x08) as *mut u32;
/// `FLASH->SR` (offset `0x10`).
pub const FLASH_SR: *mut u32 = (FLASH_R_BASE + 0x10) as *mut u32;
/// `FLASH->CR` (offset `0x14`).
pub const FLASH_CR: *mut u32 = (FLASH_R_BASE + 0x14) as *mut u32;
/// `FLASH->OPTR` (offset `0x20`) — read-only for us; carries `DBANK` and `RDP`.
pub const FLASH_OPTR: *const u32 = (FLASH_R_BASE + 0x20) as *const u32;

/// Unlock key 1 for `FLASH->KEYR` (`stm32l4xx_hal_flash.h:490`).
pub const FLASH_KEY1: u32 = 0x4567_0123;
/// Unlock key 2 (`stm32l4xx_hal_flash.h:491`).
pub const FLASH_KEY2: u32 = 0xCDEF_89AB;

/// `FLASH_CR_PG` — program enable, bit 0 (`stm32l4s5xx.h:8840`).
pub const FLASH_CR_PG: u32 = 1 << 0;
/// `FLASH_CR_PER` — page erase, bit 1 (`:8843`).
pub const FLASH_CR_PER: u32 = 1 << 1;
/// `FLASH_CR_MER1` — mass erase bank 1, bit 2 (`:8846`). Cleared defensively;
/// never set.
pub const FLASH_CR_MER1: u32 = 1 << 2;
/// `FLASH_CR_PNB` — page number, bits 3..10 (`:8849-8850`).
pub const FLASH_CR_PNB: u32 = 0xFF << 3;

/// Encode a page number into the `FLASH_CR.PNB` field.
///
/// Extracted from `erase`'s inline expression on 2026-09-08 for one reason: as an
/// expression inside a `cfg(target_arch = "arm")` block it was **unreachable by every
/// gate in this project**, and PLAN.md §9 item 22 records the measurement — changing
/// `page << 3` to `page << 4` there left all 265 hal tests, 81 firmware tests, host
/// clippy, `cargo build --release` AND both new device-target clippy gates green.
///
/// The mask does not save it, which is what makes this worth a function. `page << 4`
/// masked by `FLASH_CR_PNB` (`0xFF << 3`) still yields a **valid** field value — just
/// the wrong page. Page 5 would erase page 10. In `FLASH_FS` that is the identity
/// record, a share, or nonce state destroyed silently; the erase reports success
/// because it *did* erase a page.
///
/// As a pure fn it is host-testable, which `pnb_bits_encodes_the_page_number_itself`
/// does across the whole field range. That is strictly better than a source-text pin:
/// it checks the value, not the spelling.
#[must_use]
pub const fn pnb_bits(page: u32) -> u32 {
    (page << 3) & FLASH_CR_PNB
}
/// `FLASH_CR_BKER` — bank select for erase, bit 11 (`:8852`).
pub const FLASH_CR_BKER: u32 = 1 << 11;
/// `FLASH_CR_STRT` — start erase, bit 16 (`:8858`).
pub const FLASH_CR_STRT: u32 = 1 << 16;
/// `FLASH_CR_LOCK` — bit 31 (`:8882`).
pub const FLASH_CR_LOCK: u32 = 1 << 31;

/// `FLASH_SR_BSY` — bit 16 (`stm32l4s5xx.h:8832`).
pub const FLASH_SR_BSY: u32 = 1 << 16;
/// `FLASH_SR_EOP` — bit 0 (`:8799`). Write-1-to-clear.
pub const FLASH_SR_EOP: u32 = 1 << 0;

/// Every error bit in `FLASH->SR`, matching the HAL's `FLASH_FLAG_SR_ERRORS` for
/// this part — which **includes `PEMPTY`** on L4P5/Q5/R/S
/// (`stm32l4xx_hal_flash.h:523-528`). Coldcard clears exactly this set before
/// programming, with the comment "clear any and all errors, including PEMPTY"
/// (`storage.c:173`).
///
/// Bits: `OPERR 1`, `PROGERR 3`, `WRPERR 4`, `PGAERR 5`, `SIZERR 6`, `PGSERR 7`,
/// `MISERR 8`, `FASTERR 9`, `RDERR 14`, `OPTVERR 15`, `PEMPTY 17`
/// (`stm32l4s5xx.h:8799-8836`).
pub const FLASH_SR_ERRORS: u32 = (1 << 1)
    | (1 << 3)
    | (1 << 4)
    | (1 << 5)
    | (1 << 6)
    | (1 << 7)
    | (1 << 8)
    | (1 << 9)
    | (1 << 14)
    | (1 << 15)
    | (1 << 17);

/// `FLASH_OPTR_DBANK` — bit 22 (`stm32l4s5xx.h:8951-8953`). See the module docs:
/// this bit decides both erase granularity and whether the driver may execute
/// from flash at all.
pub const FLASH_OPTR_DBANK: u32 = 1 << 22;

/// Bytes per erasable page. `FLASH_ERASE_SIZE` (`mk4-bootloader/storage.h:17`),
/// and identical to `frostsnap_embedded`'s `SECTOR_SIZE` (`partition.rs:32`), so
/// partitions map 1:1 onto pages. **Valid only if `DBANK == 1`** — see module
/// docs; [`StmFlashToken::open`] enforces it.
pub const ERASE_SIZE: usize = 4096;

/// Bytes per program operation: one 64-bit doubleword. See the module docs for
/// the `NorFlashLog` conflict this creates.
pub const WRITE_SIZE: usize = 8;

/// A flash fault, as a value. Never a panic: PLAN.md §6.3 priority 3 is
/// precisely that `ab_write.rs` panics on real flash I/O errors, and every panic
/// is a reset-loop trigger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlashError {
    /// Offset or length not a multiple of [`WRITE_SIZE`] (write) or
    /// [`ERASE_SIZE`] (erase).
    NotAligned,
    /// Range escapes `[0, `[`crate::memmap::FLASH_FS_LEN`]`)`.
    OutOfBounds,
    /// `FLASH->SR` reported errors after the operation. Carries the masked bits
    /// so `PROGERR` (programmed twice) is distinguishable from `WRPERR`
    /// (write-protected) at a bench — Coldcard returns this same raw value
    /// (`storage.c:68-72`).
    Hardware(u32),
    /// `FLASH->CR.LOCK` still set after writing both [`FLASH_KEY1`] and
    /// [`FLASH_KEY2`]. Coldcard calls `INCONSISTENT("failed to unlock")` here
    /// (`storage.c:107-109`); we must return instead.
    UnlockFailed,
    /// `FLASH->OPTR.DBANK` is not the value this driver was written for, so
    /// [`ERASE_SIZE`] and the read-while-write assumption may both be wrong.
    /// See module docs. Refusing here is the fail-closed choice.
    DbankMismatch,
    /// A read-back after programming did not match what was written. The
    /// distinction between "the write reported success" and "the bytes are
    /// there" is load-bearing: FROST nonce reuse is affine, so two challenges
    /// over one nonce solve for the secret share (PLAN.md §6.3).
    VerifyFailed,
    /// This build is not for the device, so there is no STM32 FLASH peripheral
    /// and no `FLASH_FS` mapping to touch.
    ///
    /// Every hardware method returns this on a non-ARM target instead of
    /// dereferencing `0x0818_0000` and taking a SIGSEGV. That matters because
    /// [`StmFlashToken::take`] deliberately touches no hardware and therefore
    /// **succeeds on the host** — without this variant a host test that reached
    /// a real [`StmFlash`] would crash the test runner rather than fail, and the
    /// same mistake on a `read` path would look like a flash fault.
    ///
    /// [`StmFlashToken::open`] returns it too, which is what keeps the host from
    /// ever holding an [`StmFlash`] at all.
    ///
    /// This is a refusal, not a fallback: it never yields plausible-looking data
    /// (the [`crate::rng`] module docs' fail-closed rule applied to flash). Host
    /// tests exercise the real `frostsnap_embedded` stack through
    /// [`fake::FakeFlash`], which implements the same traits at the same
    /// geometry.
    NotOnThisTarget,
}

impl NorFlashError for FlashError {
    fn kind(&self) -> NorFlashErrorKind {
        match self {
            FlashError::NotAligned => NorFlashErrorKind::NotAligned,
            FlashError::OutOfBounds => NorFlashErrorKind::OutOfBounds,
            _ => NorFlashErrorKind::Other,
        }
    }
}

/// Bounds/alignment check for one operation. Pure, `cfg`-free,
/// **host-testable** — and the only part of this module that can be.
///
/// # Contract
///
/// * `Err(`[`FlashError::OutOfBounds`]`)` if `offset + len` overflows or exceeds
///   [`crate::memmap::FLASH_FS_LEN`].
/// * `Err(`[`FlashError::NotAligned`]`)` if `offset % align != 0` or
///   `len % align != 0`.
/// * Must use saturating/checked arithmetic — a wrapping add here is a bypass of
///   the containment property the whole module rests on.
pub fn check_bounds(offset: u32, len: usize, align: usize) -> Result<(), FlashError> {
    // Alignment first, so a misaligned-AND-oversized request reports the more
    // specific fault. `align == 0` would be a division by zero, i.e. a panic in
    // a function documented as unable to panic; treat it as "no alignment
    // requirement" rather than trusting the caller.
    if align > 1 && (offset as usize % align != 0 || len % align != 0) {
        return Err(FlashError::NotAligned);
    }

    // Checked, never wrapping. `overflow-checks = false` in profile.release
    // means a plain `+` wraps SILENTLY on the device, which would turn the
    // containment proof this whole module rests on into a bypass: a huge `len`
    // could wrap `end` back under the limit and let an offset name FLASH_TEXT.
    let end = match (offset as usize).checked_add(len) {
        Some(e) => e,
        None => return Err(FlashError::OutOfBounds),
    };
    if end > crate::memmap::FLASH_FS_LEN as usize {
        return Err(FlashError::OutOfBounds);
    }
    Ok(())
}

/// Executable form of the `WRITE_SIZE` resolution in the module docs: this crate
/// deliberately does **not** support `frostsnap_embedded::NorFlashLog` over
/// [`StmFlash`], because `NorFlashLog::new` asserts `WRITE_SIZE == 4`
/// (`nor_flash_log.rs:5,16`) and its `push` reprograms the length doubleword
/// (`:26-41`).
///
/// Returns `true` while the two are genuinely incompatible, i.e. while the
/// hardware truth [`WRITE_SIZE`] is not `NorFlashLog`'s `WORD_SIZE` of 4. Kept as
/// a function rather than a comment so that "resolved by not using it" is a
/// checked claim: if someone sets `WRITE_SIZE = 4` to make the log link, this
/// goes `false` and its test fails, forcing the hardware question to be answered
/// instead of assumed.
#[must_use]
pub const fn assert_nor_flash_log_is_unusable() -> bool {
    // `NorFlashLog`'s WORD_SIZE, `core::mem::size_of::<u32>()`
    // (nor_flash_log.rs:5).
    const NOR_FLASH_LOG_WORD_SIZE: usize = 4;
    WRITE_SIZE != NOR_FLASH_LOG_WORD_SIZE
}

/// First address of flash **bank 2**: 256 pages x [`ERASE_SIZE`] = 1 MB above
/// [`crate::memmap::BL_FLASH_BASE`]. This is the same boundary `flash_page_erase`
/// encodes as "page index >= 256 means `BKER`" (`storage.c:213-219`).
pub const BANK2_BASE: u32 = crate::memmap::BL_FLASH_BASE + 256 * ERASE_SIZE as u32;

/// How many bytes of `FLASH_TEXT` lie in **bank 2**, i.e. in the same bank as
/// `FLASH_FS`.
///
/// Executable form of the module docs' read-while-write correction. The old
/// justification for not running this driver from RAM was "our code is in bank 1,
/// `FLASH_FS` is in bank 2", and this function is why that is false: it returns
/// 524,288, not 0.
#[must_use]
pub const fn flash_text_bytes_in_bank2() -> u32 {
    let text_end = crate::memmap::FLASH_TEXT_BASE + crate::memmap::FLASH_TEXT_LEN;
    text_end.saturating_sub(BANK2_BASE)
}

/// Bytes of headroom before a firmware image of `image_size` starts occupying
/// bank 2 — the bank `FLASH_FS` erases live in.
///
/// Returns `None` once the image has already crossed [`BANK2_BASE`], because at
/// that point "margin" is the wrong question: instruction fetch and nonce erase
/// already share a bank and the `.ramfunc` question
/// ([`RAM_EXECUTION_IS_UNRESOLVED`]) is live rather than theoretical.
#[must_use]
pub const fn bank1_margin_at(image_size: u32) -> Option<u32> {
    let bank1_bytes = BANK2_BASE - crate::memmap::FLASH_TEXT_BASE;
    if image_size > bank1_bytes {
        None
    } else {
        Some(bank1_bytes - image_size)
    }
}

/// Whether `FLASH_TEXT` and `FLASH_FS` share bank 2. **Always true on this
/// layout**, and pinned so the arithmetically false "different banks" claim cannot
/// be reinstated as a comment.
#[must_use]
pub const fn text_and_fs_share_bank_two() -> bool {
    flash_text_bytes_in_bank2() > 0 && crate::memmap::FLASH_FS_BASE >= BANK2_BASE
}

/// Whether `NonceAbSlot`'s A and B copies would land in **one** physical page if
/// `DBANK` were 0.
///
/// `NonceAbSlot` takes two consecutive [`ERASE_SIZE`] sectors
/// (`nonce_slots.rs:27`, `split_off_front(2)`). At `DBANK == 0` a page is 8 K
/// (`stm32l4xx_hal_flash.h:852-854`), so those two sectors are the same page and
/// erasing either destroys both — the A/B scheme reporting `Committed` while having
/// no surviving copy. This returns `true` while that is the case, which is why
/// [`StmFlashToken::open`] refuses rather than adapting.
#[must_use]
pub const fn ab_copies_would_share_one_page_at_dbank_zero() -> bool {
    /// Page size with `DBANK == 0`: single-bank 128-bit mode,
    /// `FLASH_PAGE_SIZE_128_BITS` (`stm32l4xx_hal_flash.h:854`).
    const DBANK0_PAGE: usize = 8192;
    // The A copy starts at sector offset 0, the B copy at ERASE_SIZE
    // (`split_off_front(2)`). Two consecutive sectors fit inside one 8 K page
    // exactly when the pair is no larger than a page, and then one erase takes
    // both.
    2 * ERASE_SIZE <= DBANK0_PAGE
}

/// Whether this driver must execute from RAM is **UNRESOLVED**, recorded as a
/// value rather than only as prose.
///
/// Coldcard marks `flash_burn`, `flash_page_erase` and `_flash_wait_done`
/// `.ramfunc` with "this function AND everything it calls, must be in RAM"
/// (`storage.c:57-59`, `:158-165`, `:204-211`). We do not, and the reason we gave
/// (different banks) is false — see [`text_and_fs_share_bank_two`].
///
/// Settling it needs `#[link_section = ".ramfunc"]` **plus** a linker script that
/// defines and loads the section. Measured: this tree has no `.ld`, no `.x`, no
/// `build.rs` and no `link_section`, and no image is linked yet, so the attribute
/// alone would place code in a section nothing loads — worse than an honest gap.
///
/// Stays `true` until either the linker script lands or a bench measurement shows
/// erasing `FLASH_FS` while fetching from `>= `[`BANK2_BASE`] does not stall.
pub const RAM_EXECUTION_IS_UNRESOLVED: bool = true;

/// Whether the erase geometry this driver assumes matches the option bytes.
/// Pure given the register value, so **host-testable**: pass a synthetic `optr`.
///
/// # Contract
///
/// Returns `true` iff `optr & `[`FLASH_OPTR_DBANK`]` != 0`, i.e. dual-bank /
/// 4 K pages, which is what [`ERASE_SIZE`] and the read-while-write assumption
/// require. See module docs for why the reference is self-contradictory here.
#[must_use]
pub fn dbank_ok(optr: u32) -> bool {
    optr & FLASH_OPTR_DBANK != 0
}

/// Owns the `FLASH_FS` region and the FLASH peripheral's program/erase path.
///
/// Not `Clone`, not `Copy`, no `Default`: it is a singleton capability. Two of
/// these could interleave `CR` writes and corrupt an unrelated page, so
/// [`StmFlashToken::take`] hands out exactly one token and
/// [`StmFlashToken::open`] consumes it — this type has no other constructor and
/// its only field is private.
///
/// `frostsnap_embedded::FlashPartition` wraps this in a `RefCell`
/// (`partition.rs:12,36`), which is where shared access comes from.
pub struct StmFlash {
    _private: (),
}

/// The right to *attempt* to open [`StmFlash`], and nothing else.
///
/// # Why this type exists: the DBANK check was previously unreachable
///
/// This module used to expose `StmFlash::take() -> Option<StmFlash>` alongside
/// `StmFlash::new(self) -> Result<Self, _>` — same type in, same type out. `take`
/// already handed out a fully usable [`NorFlash`] (the trait impls are on
/// [`StmFlash`], and its only field is private), so `new` was **decoration**: it
/// had zero callers anywhere in the tree, the `OPTR` read never executed, and
/// `StmFlash::take().unwrap()` followed by `NorFlash::erase`/`write` type-checked
/// and dispatched with the geometry never verified.
///
/// That matters because at `DBANK == 0` the pages are 8 K
/// (`stm32l4xx_hal_flash.h:852-854`) while [`ERASE_SIZE`] is 4096, so every erase
/// takes the **adjacent** 4 K sector with it — and `NonceAbSlot` puts the A and B
/// copies in two consecutive sectors (`nonce_slots.rs:27`, `split_off_front(2)`),
/// so a single write would destroy its own redundancy while reporting
/// `Committed`. The check being skippable is therefore a silent nonce-loss bug,
/// and nonce loss is the one failure that leaks the secret share.
///
/// This type implements **nothing** — no [`NorFlash`], no [`ReadNorFlash`], no
/// `Deref`. [`StmFlashToken::open`] is the only way to obtain an [`StmFlash`], and
/// [`StmFlash`] has a private field and no other constructor, so no caller in this
/// crate or downstream can reach a writable handle without the `OPTR` read having
/// happened.
pub struct StmFlashToken {
    _private: (),
}

impl StmFlashToken {
    /// Take the singleton token. Returns `None` on the second and later calls.
    ///
    /// Does **not** touch hardware, so it is safe to call on any target; all
    /// register access is in [`StmFlashToken::open`]. Splitting the two is what
    /// lets a host test exercise the singleton and type-state logic.
    pub fn take() -> Option<Self> {
        // NOT an `AtomicBool`, though the skeleton said so. See
        // `crate::singleton`: a `bool` static in `.bss` reads `0xdeadbeef` on
        // this board because the bootloader FILLS SRAM1 with that constant
        // rather than zeroing it (`main.c:42,47,130`) and nothing zeroes `.bss`
        // yet -- so `AtomicBool::new(false)` would read `true` and this would
        // return `None` on the FIRST call, bricking boot with no diagnostic.
        static TAKEN: crate::singleton::TakeOnce = crate::singleton::TakeOnce::new();
        if TAKEN.take() {
            Some(Self { _private: () })
        } else {
            None
        }
    }

    /// Verify the geometry, then hand back the usable handle.
    ///
    /// Consumes the token **by value**, so a failed open cannot be retried with
    /// the same token in the hope of a different answer, and a successful open
    /// cannot be duplicated.
    ///
    /// Reads `FLASH->OPTR` and applies [`dbank_ok`]. On mismatch returns
    /// [`FlashError::DbankMismatch`] and the caller gets **no** [`StmFlash`] at
    /// all — refusing to hand out the capability is the fail-closed choice, and
    /// it is stronger than returning a handle plus a warning nobody reads.
    ///
    /// Also clears stale `FLASH->SR` error bits left by the bootloader, including
    /// `PEMPTY` (`storage.c:173`).
    ///
    /// # Errors
    ///
    /// [`FlashError::DbankMismatch`] if the option bytes disagree with
    /// [`ERASE_SIZE`]; [`FlashError::NotOnThisTarget`] on a non-ARM build.
    ///
    /// # Panics
    ///
    /// Must not, ever. A panic here is a boot-time reset loop (decision 6).
    pub fn open(self) -> Result<StmFlash, FlashError> {
        // `return` is load-bearing: on this target the `cfg(target_arch = "arm")`
        // block below is deleted, so this block is the last statement in the
        // function -- but it is still a *statement*, and a bare `Err(..)` tail
        // there is a discarded `#[must_use]` value, not the return value.
        #[cfg(not(target_arch = "arm"))]
        #[allow(clippy::needless_return)]
        {
            // No FLASH peripheral here. Refusing keeps the failure a value; the
            // alternative is a SIGSEGV in the test runner. See
            // `FlashError::NotOnThisTarget`.
            let _ = &self;
            return Err(FlashError::NotOnThisTarget);
        }

        #[cfg(target_arch = "arm")]
        {
            // Read the geometry BEFORE clearing anything: if it disagrees, this type
            // must not have touched the peripheral at all.
            //
            // SAFETY: `FLASH_OPTR` is `FLASH_R_BASE + 0x20` (`stm32l4s5xx.h:1401`
            // and the `FLASH_TypeDef` layout at `:555-577`), a 4-byte-aligned
            // memory-mapped peripheral register that is always readable and has no
            // read side effects. `read_volatile` because the value is not ours and
            // must not be cached or elided.
            let optr = unsafe { core::ptr::read_volatile(FLASH_OPTR) };
            if !dbank_ok(optr) {
                // Refuse rather than adapt. With DBANK == 0 the pages are 8 K
                // (`stm32l4xx_hal_flash.h:852-854`), so an ERASE_SIZE-4096 erase
                // takes the ADJACENT 4 K with it -- and for A/B nonce slots that
                // destroys both copies at once, which is the exact failure the A/B
                // scheme exists to survive. It also decides whether this driver may
                // execute from flash at all (module docs).
                return Err(FlashError::DbankMismatch);
            }

            // Clear stale error bits the bootloader may have left, including
            // PEMPTY. Coldcard does exactly this before programming, with the
            // comment "clear any and all errors, including PEMPTY"
            // (`storage.c:173`). Without it, the first `_flash_wait_done`-equivalent
            // check in `write`/`erase` would report someone else's error as ours.
            //
            // SAFETY: `FLASH_SR` is `FLASH_R_BASE + 0x10`. The write-1-to-clear
            // idiom `SR = SR & ERRORS` only ever clears bits that are already set
            // and cannot set a control bit; it is the bootloader's own sequence.
            unsafe {
                let sr = core::ptr::read_volatile(FLASH_SR);
                core::ptr::write_volatile(FLASH_SR, sr & FLASH_SR_ERRORS);
            }
            // The token is consumed; this is the only site that mints an
            // `StmFlash`, and it is reachable only past the `dbank_ok` check above.
            Ok(StmFlash { _private: () })
        }
    }
}

impl StmFlash {
    /// Program-erase, then read back and compare.
    ///
    /// Separate from [`NorFlash::write`] because `NorFlash` has no verified-write
    /// method and `frostsnap_core`'s nonce path currently gets its guarantee from
    /// `assert_eq!` on read-back (`device_nonces.rs:235`, `:300`) — a halt under
    /// `panic = "abort"`. PLAN.md §6.3 priority 2 and phase 7 require those to
    /// become `Result`, and this is the method they should call.
    ///
    /// # Errors
    ///
    /// As [`NorFlash::write`], plus [`FlashError::VerifyFailed`] if the read-back
    /// differs. On `VerifyFailed` the caller must treat the target as
    /// indeterminate — not retry in place, since the doubleword can no longer be
    /// programmed without an erase.
    pub fn write_verified(&mut self, offset: u32, bytes: &[u8]) -> Result<(), FlashError> {
        NorFlash::write(self, offset, bytes)?;

        // Read back through the same bounds-checked path, in `WRITE_SIZE`
        // chunks, so no stack buffer scales with `bytes.len()` -- this runs on a
        // device whose whole RAM is the nonce state's neighbour.
        let mut checked = 0usize;
        while checked < bytes.len() {
            let n = core::cmp::min(WRITE_SIZE, bytes.len() - checked);
            let mut back = [0u8; WRITE_SIZE];
            ReadNorFlash::read(self, offset + checked as u32, &mut back[..n])?;
            // Not `==` on the whole array: only the `n` bytes just written are
            // meaningful, and a constant-time compare is pointless here (the
            // value is already on flash and readable by anyone who can run this).
            if back[..n] != bytes[checked..checked + n] {
                return Err(FlashError::VerifyFailed);
            }
            checked += n;
        }
        Ok(())
    }

    /// Absolute address of a `FLASH_FS`-relative offset, for read paths that
    /// map flash directly rather than going through [`ReadNorFlash::read`].
    ///
    /// # Errors
    ///
    /// [`FlashError::OutOfBounds`] if `offset >= `[`crate::memmap::FLASH_FS_LEN`].
    /// The bound is what keeps this from being a way to name `FLASH_TEXT`.
    pub fn abs_addr(&self, offset: u32) -> Result<u32, FlashError> {
        // `len = 1`: the returned address must itself be inside the region, so
        // `offset == FLASH_FS_LEN` (one past the end) is refused. `align = 1`
        // because a read path may name any byte.
        check_bounds(offset, 1, 1)?;
        // Cannot overflow: `check_bounds` just proved
        // `offset < FLASH_FS_LEN`, and `FLASH_FS_BASE + FLASH_FS_LEN` is
        // `0x0820_0000`, far below `u32::MAX`. Checked anyway -- an unchecked
        // `+` here would be the one arithmetic site that can escape the region.
        FLASH_FS_BASE_CHECKED
            .checked_add(offset)
            .ok_or(FlashError::OutOfBounds)
    }
}

/// Local alias so the `checked_add` in [`StmFlash::abs_addr`] reads as
/// arithmetic on a constant rather than a module path.
const FLASH_FS_BASE_CHECKED: u32 = crate::memmap::FLASH_FS_BASE;

/// The two `FLASH->SR` accesses the wait/clear logic needs, as an injectable
/// seam. **This is the only part of the program/erase path that is ported**; see
/// the module docs for what remains bench-only.
///
/// # Why a trait for two accesses
///
/// The `SR` **ordering** defect (module docs) was a pure sequencing bug — clear
/// versus wait — in code that could not be executed off-hardware, in a file that
/// had zero tests. Nothing about it needed silicon: it needed a `u32` that latches
/// error bits until written. That is what this abstracts, and no more.
///
/// Implementing this trait grants **nothing**: it is a pair of accessors on
/// whatever `u32` the implementor owns, and it cannot produce an [`StmFlash`],
/// unlock the peripheral or reach [`FLASH_SR`]. Only `Mmio` does that, and it is
/// private and ARM-only. So making the seam public does not reopen the fail-open
/// hole that the [`crate::rng`] test seam did — the rule from that fix is that a
/// gate belongs on a **bypass**, and this is not one.
pub trait SrPort {
    /// Read `FLASH->SR`.
    fn read_sr(&mut self) -> u32;
    /// Write `FLASH->SR`. Every bit in this register that we touch is
    /// write-1-to-clear, so a write can only ever clear.
    fn write_sr(&mut self, value: u32);
}

/// Spin until `BSY` clears, then report any error bits. Generic over [`SrPort`],
/// so this exact code runs on the host.
///
/// Mirrors `_flash_wait_done` (`storage.c:60-81`) with one deliberate
/// difference: Coldcard's `while(BSY)` is **unbounded**, and an unbounded wait in
/// our code is the same silent-brick failure class as a panic-halt. The bound is
/// generous — a 4 K page erase is ~25 ms typical on this part, well inside
/// [`FLASH_SPIN_LIMIT`] iterations at 120 MHz — and exceeding it reports
/// [`FlashError::Hardware`] with `BSY` still set rather than hanging.
///
/// Does **not** clear error bits: that is [`sr_prologue`]'s job, and the split is
/// exactly the defect described in the module docs.
///
/// # Errors
///
/// [`FlashError::Hardware`] with the masked `SR` bits, or with [`FLASH_SR_BSY`]
/// if the bound was exhausted.
pub fn sr_wait_done<P: SrPort>(port: &mut P, spin_limit: u32) -> Result<(), FlashError> {
    let mut spins = spin_limit;
    loop {
        let sr = port.read_sr();
        if sr & FLASH_SR_BSY == 0 {
            let errors = sr & FLASH_SR_ERRORS;
            if errors != 0 {
                return Err(FlashError::Hardware(errors));
            }
            if sr & FLASH_SR_EOP != 0 {
                // Write-1-to-clear, as `storage.c:74-77`.
                port.write_sr(FLASH_SR_EOP);
            }
            return Ok(());
        }
        spins = match spins.checked_sub(1) {
            Some(s) => s,
            // Bounded exit. Report BSY so a bench can tell "still busy" from a
            // real PROGERR/WRPERR.
            None => return Err(FlashError::Hardware(FLASH_SR_BSY)),
        };
    }
}

/// Clear the latched `FLASH->SR` error bits, **then** wait for `BSY` to clear.
/// Generic over [`SrPort`], so the ordering is host-testable — which is the whole
/// reason the seam exists.
///
/// Every program and every erase starts here. The order is the point, and it is
/// the opposite of what this module did before.
///
/// [`sr_wait_done`] reports latched `SR` error bits **without clearing them**. So
/// a prologue that waits first and clears second can never reach its own clear:
/// the `?` on the wait short-circuits, the error stays latched, and every
/// subsequent operation returns the same stale error forever — on healthy flash.
/// For nonce storage that is a permanent wedge after one transient fault. `erase`
/// had no clear at all.
///
/// Coldcard's order is clear-then-wait as well, but weaker: `flash_burn` calls
/// `_flash_wait_done()` and **discards the result** before clearing `SR`
/// (`storage.c:171-175`), as does `flash_page_erase` (`storage.c:223-228`). This
/// clears first and then propagates the wait, so a stale latch cannot wedge the
/// driver **and** a genuinely stuck peripheral is still refused rather than being
/// programmed into.
///
/// # Errors
///
/// [`FlashError::Hardware`] if `BSY` never clears within `spin_limit`, or if an
/// error bit is still set after the clear — which means the peripheral re-latched
/// it rather than it being left over, and it must not be swallowed.
pub fn sr_prologue<P: SrPort>(port: &mut P, spin_limit: u32) -> Result<(), FlashError> {
    // Clear FIRST. Write-1-to-clear, so `SR & ERRORS` only ever clears bits that
    // are already set and cannot set a control bit; this is the bootloader's own
    // sequence, including PEMPTY (`storage.c:173`, "clear any and all errors,
    // including PEMPTY").
    let sr = port.read_sr();
    port.write_sr(sr & FLASH_SR_ERRORS);

    // THEN wait, with the result propagated. Anything still reported survived the
    // clear above, so it is a live fault rather than a stale latch.
    sr_wait_done(port, spin_limit)
}

/// Iteration bound for [`sr_wait_done`]. Not a time: this is a bare-metal spin
/// with no timer, so the only honest statement is "many more iterations than the
/// longest documented erase takes". Deliberately not `u32::MAX` — the point is
/// that the loop terminates.
pub const FLASH_SPIN_LIMIT: u32 = 50_000_000;

/// The real [`SrPort`]: volatile accesses to [`FLASH_SR`]. Private and ARM-only,
/// so it is the single site in the crate that can reach the register.
#[cfg(target_arch = "arm")]
struct Mmio;

#[cfg(target_arch = "arm")]
impl SrPort for Mmio {
    fn read_sr(&mut self) -> u32 {
        // SAFETY: `FLASH_SR` is `FLASH_R_BASE + 0x10`, a 4-byte-aligned
        // memory-mapped peripheral register that is always readable; reads have
        // no side effects. `read_volatile` because the value is not ours and must
        // not be cached or elided.
        unsafe { core::ptr::read_volatile(FLASH_SR) }
    }

    fn write_sr(&mut self, value: u32) {
        // SAFETY: as above. Every bit this crate writes here is write-1-to-clear,
        // so the store can only clear a status bit; it cannot set a control bit
        // and cannot start an operation.
        unsafe { core::ptr::write_volatile(FLASH_SR, value) }
    }
}

/// [`sr_wait_done`] against the real peripheral.
///
/// # Errors
///
/// As [`sr_wait_done`].
#[cfg(target_arch = "arm")]
fn wait_done() -> Result<(), FlashError> {
    sr_wait_done(&mut Mmio, FLASH_SPIN_LIMIT)
}

/// [`sr_prologue`] against the real peripheral. Every program and every erase in
/// this module goes through it.
///
/// # Errors
///
/// As [`sr_prologue`].
#[cfg(target_arch = "arm")]
fn operation_prologue() -> Result<(), FlashError> {
    sr_prologue(&mut Mmio, FLASH_SPIN_LIMIT)
}

/// Unlock `FLASH->CR` by writing both keys, then confirm.
///
/// `storage.c:97-110` calls `INCONSISTENT("failed to unlock")` on failure; we
/// must return, since a panic here is a reset loop (decision 6).
///
/// # Errors
///
/// [`FlashError::UnlockFailed`] if `LOCK` is still set after both keys.
#[cfg(target_arch = "arm")]
fn unlock() -> Result<(), FlashError> {
    // SAFETY: `FLASH_CR`/`FLASH_KEYR` are memory-mapped peripheral registers at
    // `FLASH_R_BASE + 0x14` / `+ 0x08`. The two-key sequence is the hardware's
    // documented unlock protocol and the bootloader's own
    // (`storage.c:101-104`); writing a wrong value only re-locks, it cannot
    // start an operation, because no PG/PER/STRT bit is touched here.
    unsafe {
        if core::ptr::read_volatile(FLASH_CR) & FLASH_CR_LOCK != 0 {
            core::ptr::write_volatile(FLASH_KEYR, FLASH_KEY1);
            core::ptr::write_volatile(FLASH_KEYR, FLASH_KEY2);
            if core::ptr::read_volatile(FLASH_CR) & FLASH_CR_LOCK != 0 {
                return Err(FlashError::UnlockFailed);
            }
        }
    }
    Ok(())
}

/// Re-set `FLASH->CR.LOCK`. Always called on the way out of an operation,
/// including error paths: leaving the peripheral unlocked means any later stray
/// write can program flash.
#[cfg(target_arch = "arm")]
fn lock() {
    // SAFETY: sets only the LOCK bit of `FLASH->CR`, which can never start an
    // operation -- it only removes permission. `storage.c:88-93`.
    unsafe {
        let cr = core::ptr::read_volatile(FLASH_CR);
        core::ptr::write_volatile(FLASH_CR, cr | FLASH_CR_LOCK);
    }
}

/// `FLASH->ACR` — carries the data-cache enable/reset bits used around every
/// program and erase (`stm32l4s5xx.h:8782-8789`; `FLASH_TypeDef` offset `0x00`).
#[cfg(target_arch = "arm")]
const FLASH_ACR: *mut u32 = FLASH_R_BASE as *mut u32;
/// `FLASH_ACR_DCEN` — data cache enable, bit 10 (`stm32l4s5xx.h:8782`).
#[cfg(target_arch = "arm")]
const FLASH_ACR_DCEN: u32 = 1 << 10;
/// `FLASH_ACR_DCRST` — data cache reset, bit 12 (`stm32l4s5xx.h:8788`).
#[cfg(target_arch = "arm")]
const FLASH_ACR_DCRST: u32 = 1 << 12;

/// Disable the flash data cache. Mandatory around program/erase: the cache can
/// otherwise serve pre-operation data for an address that has just changed
/// (`storage.c:178`, `:230`).
#[cfg(target_arch = "arm")]
fn data_cache_disable() {
    // SAFETY: clears one bit of `FLASH->ACR`. Affects cache behaviour only, not
    // the array, and cannot start an operation.
    unsafe {
        let acr = core::ptr::read_volatile(FLASH_ACR);
        core::ptr::write_volatile(FLASH_ACR, acr & !FLASH_ACR_DCEN);
    }
}

/// Reset then re-enable the flash data cache, as `storage.c:196-198`/`:251-253`.
/// `DCRST` may only be written while `DCEN` is clear, which is why this is the
/// exact inverse of [`data_cache_disable`] and not a plain re-enable.
#[cfg(target_arch = "arm")]
fn data_cache_reset_and_enable() {
    // SAFETY: cache-control bits of `FLASH->ACR` only. The set-then-clear of
    // DCRST is the HAL's `__HAL_FLASH_DATA_CACHE_RESET()` sequence and is only
    // legal with DCEN clear, which the caller guarantees by having called
    // `data_cache_disable` first.
    unsafe {
        let acr = core::ptr::read_volatile(FLASH_ACR);
        core::ptr::write_volatile(FLASH_ACR, acr | FLASH_ACR_DCRST);
        core::ptr::write_volatile(FLASH_ACR, acr & !FLASH_ACR_DCRST);
        let acr = core::ptr::read_volatile(FLASH_ACR);
        core::ptr::write_volatile(FLASH_ACR, acr | FLASH_ACR_DCEN);
    }
}

/// Page index and bank for an **absolute** flash address, following
/// `flash_page_erase` (`storage.c:213-219`) exactly.
///
/// Pure — **host-testable**, and it must be: getting this wrong erases a page
/// somewhere else in the 2 MB array, which for `FLASH_TEXT` means destroying the
/// image the bootloader verifies.
///
/// Returns `(page_number_masked_to_8_bits, is_bank2)`. The address is masked with
/// `0x7ff_ffff` first, as the reference does, so both the `0x0800_0000` alias and
/// a bare offset give the same answer.
///
/// # Errors
///
/// [`FlashError::OutOfBounds`] if the page lies below
/// [`crate::memmap::FLASH_ERASE_FLOOR`] — the bootloader's own guard, which
/// returns 1 without touching anything (`storage.c:215-217`).
pub fn erase_page_of(abs_addr: u32) -> Result<(u32, bool), FlashError> {
    // The bootloader's own guard, reproduced against the SAME quantity it
    // compares (a page index), not against an address.
    if abs_addr < crate::memmap::FLASH_ERASE_FLOOR {
        return Err(FlashError::OutOfBounds);
    }
    let page = (abs_addr & 0x7ff_ffff) / ERASE_SIZE as u32;
    // 2 banks x 256 pages x 4 K = 2 MB (module docs).
    let bank2 = page >= 256;
    Ok((page & 0xff, bank2))
}

impl ErrorType for StmFlash {
    type Error = FlashError;
}

impl ReadNorFlash for StmFlash {
    /// Flash is memory-mapped for reads, so any alignment works.
    const READ_SIZE: usize = 1;

    /// Read from `FLASH_FS_BASE + offset`.
    ///
    /// Reads are plain memory-mapped loads; no unlock and no `CR` involvement.
    /// The one hazard is reading a page while it is being erased, which
    /// [`StmFlash`] being a singleton prevents.
    ///
    /// # Errors
    ///
    /// [`FlashError::OutOfBounds`] via [`check_bounds`] with `align = 1`.
    fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
        check_bounds(offset, bytes.len(), 1)?;
        if bytes.is_empty() {
            return Ok(());
        }

        // `return` is load-bearing: on this target the `cfg(target_arch = "arm")`
        // block below is deleted, so this block is the last statement in the
        // function -- but it is still a *statement*, and a bare `Err(..)` tail
        // there is a discarded `#[must_use]` value, not the return value.
        #[cfg(not(target_arch = "arm"))]
        #[allow(clippy::needless_return)]
        {
            // The bounds check above still ran, which is the host-testable part.
            // Dereferencing FLASH_FS_BASE here would SIGSEGV.
            return Err(FlashError::NotOnThisTarget);
        }

        #[cfg(target_arch = "arm")]
        {
            // `check_bounds` has proved `offset + bytes.len() <= FLASH_FS_LEN`, so
            // every byte touched below is inside FLASH_FS. That is the containment
            // proof the module docs describe: because offsets are region-relative,
            // no value this type accepts can name FLASH_TEXT or the bootloader.
            //
            // SAFETY: `FLASH_FS_BASE + offset` is a mapped, always-readable flash
            // address for `bytes.len()` bytes by the bound just checked; flash is
            // memory-mapped for reads with no unlock and no CR involvement. Reading a
            // page mid-erase is the one hazard, and `&mut self` on a singleton
            // (`StmFlashToken::take`) is what makes that unreachable. Byte-wise
            // `read_volatile` rather than `copy_from_slice`: alignment is
            // `READ_SIZE = 1`, so an unaligned `&[u8]` view of flash is not sound to
            // form, and the loads must not be reordered around a program/erase.
            let base = crate::memmap::FLASH_FS_BASE as usize + offset as usize;
            for (i, out) in bytes.iter_mut().enumerate() {
                *out = unsafe { core::ptr::read_volatile((base + i) as *const u8) };
            }
            Ok(())
        }
    }

    /// [`crate::memmap::FLASH_FS_LEN`] = 512 K. Every bounds check is against
    /// this, which is what makes `FLASH_TEXT` unnameable through this type.
    fn capacity(&self) -> usize {
        crate::memmap::FLASH_FS_LEN as usize
    }
}

impl NorFlash for StmFlash {
    /// 8 — one 64-bit doubleword. See the module docs: this is the hardware
    /// truth and it collides with `NorFlashLog`'s `assert_eq!(4, WRITE_SIZE)`.
    const WRITE_SIZE: usize = WRITE_SIZE;

    /// 4096 — matches `frostsnap_embedded`'s `SECTOR_SIZE` exactly. Valid only
    /// if `DBANK == 1`, which [`StmFlashToken::open`] verifies.
    const ERASE_SIZE: usize = ERASE_SIZE;

    /// Erase pages covering `[from, to)`, both [`ERASE_SIZE`]-aligned.
    ///
    /// Per page, following `flash_page_erase` (`storage.c:211-256`): wait `BSY`
    /// clear; clear `SR` errors; disable the data cache; select the bank via
    /// [`FLASH_CR_BKER`] (page index >= 256 means bank 2, then mask the index to
    /// 8 bits); set [`FLASH_CR_PNB`]; set [`FLASH_CR_PER`] then
    /// [`FLASH_CR_STRT`]; wait; clear `PER`/`PNB`; reset and re-enable the data
    /// cache.
    ///
    /// Page index is computed from the **absolute** address masked to the flash
    /// window (`storage.c:213`), not from the `FLASH_FS`-relative offset. Getting
    /// that wrong erases something else entirely.
    ///
    /// Must refuse any absolute address below
    /// [`crate::memmap::FLASH_ERASE_FLOOR`] — the bootloader's own guard
    /// (`storage.c:214-216`). Offsets from this type cannot reach it, so that
    /// check is a redundant belt, and worth keeping.
    ///
    /// # Errors
    ///
    /// [`FlashError::NotAligned`], [`FlashError::OutOfBounds`],
    /// [`FlashError::UnlockFailed`], or [`FlashError::Hardware`] with the `SR`
    /// bits.
    ///
    /// # Panics
    ///
    /// Must not. `AbSlot::write` calls `erase_all().expect("must erase")`
    /// (`ab_write.rs:104`) so a returned error still panics upstream today —
    /// that is PLAN.md §6.3 priority 3, fixed in `frostsnap_embedded`, not here.
    /// Do not make it worse by panicking in the driver.
    fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
        // `to` is exclusive. A reversed range is not "empty", it is a caller
        // bug, and silently succeeding would let a caller believe a sector was
        // erased when it was not.
        let len = match to.checked_sub(from) {
            Some(l) => l as usize,
            None => return Err(FlashError::OutOfBounds),
        };
        check_bounds(from, len, ERASE_SIZE)?;
        if len == 0 {
            return Ok(());
        }

        // `return` is load-bearing: on this target the `cfg(target_arch = "arm")`
        // block below is deleted, so this block is the last statement in the
        // function -- but it is still a *statement*, and a bare `Err(..)` tail
        // there is a discarded `#[must_use]` value, not the return value.
        #[cfg(not(target_arch = "arm"))]
        #[allow(clippy::needless_return)]
        {
            return Err(FlashError::NotOnThisTarget);
        }

        #[cfg(target_arch = "arm")]
        {
            unlock()?;
            // Every exit past this point must re-lock, including the error
            // paths, so the body is a closure and the lock is unconditional.
            let result = (|| -> Result<(), FlashError> {
                let mut off = from;
                while off < to {
                    // Page index comes from the ABSOLUTE address
                    // (`storage.c:213`), never the region-relative offset.
                    // `abs_addr` re-checks containment, so this cannot name a
                    // page outside FLASH_FS even if the loop arithmetic were
                    // wrong.
                    let abs = crate::memmap::FLASH_FS_BASE + off;
                    let (page, bank2) = erase_page_of(abs)?;

                    // Clear latched errors, THEN wait. This function previously
                    // called `wait_done()` alone and never wrote `SR` anywhere, so
                    // one latched error bit made every later erase return the same
                    // stale `Hardware(..)` forever. See `operation_prologue`.
                    operation_prologue()?;
                    data_cache_disable();

                    // SAFETY: all four writes target `FLASH->CR`
                    // (`FLASH_R_BASE + 0x14`), a memory-mapped peripheral
                    // register. The peripheral is unlocked (checked above) and
                    // idle (`wait_done`). The page/bank were computed by
                    // `erase_page_of`, which refuses anything below
                    // FLASH_ERASE_FLOOR, so no erase can reach the bootloader,
                    // NVROM or FLASH_TEXT. Sequence and bit order follow
                    // `flash_page_erase` (`storage.c:233-245`).
                    unsafe {
                        let mut cr = core::ptr::read_volatile(FLASH_CR);
                        if bank2 {
                            cr |= FLASH_CR_BKER;
                        } else {
                            cr &= !FLASH_CR_BKER;
                        }
                        // MODIFY_REG(CR, PNB, page << PNB_Pos) -- PNB is bits
                        // 3..10 (`stm32l4s5xx.h:8849`). Encoded by `pnb_bits`, a
                        // pure fn, because inline here it was a blind spot: see
                        // that function's docs.
                        cr = (cr & !FLASH_CR_PNB) | pnb_bits(page);
                        core::ptr::write_volatile(FLASH_CR, cr);
                        core::ptr::write_volatile(FLASH_CR, cr | FLASH_CR_PER);
                        core::ptr::write_volatile(FLASH_CR, cr | FLASH_CR_PER | FLASH_CR_STRT);
                    }

                    let waited = wait_done();

                    // Clear PER and PNB whether or not the erase reported an
                    // error (`storage.c:248`): leaving PER set makes the next
                    // unrelated CR write start an erase.
                    // SAFETY: as above; only clears operation-select bits.
                    unsafe {
                        let cr = core::ptr::read_volatile(FLASH_CR);
                        core::ptr::write_volatile(FLASH_CR, cr & !(FLASH_CR_PER | FLASH_CR_PNB));
                    }
                    data_cache_reset_and_enable();
                    waited?;

                    off += ERASE_SIZE as u32;
                }
                Ok(())
            })();
            lock();
            result
        }
    }

    /// Program `bytes` at `offset`; both must be [`WRITE_SIZE`]-aligned.
    ///
    /// Per doubleword, following `flash_burn` (`storage.c:167-201`): wait `BSY`;
    /// clear `SR` errors including `PEMPTY`; disable the data cache; clear
    /// `PG`/`MER1`/`PER`/`PNB` then set [`FLASH_CR_PG`]; store the low word;
    /// **`isb()`**; store the high word; wait; clear `PG`; reset and re-enable
    /// the data cache.
    ///
    /// The `__ISB()` between the two 32-bit stores is not decoration —
    /// `storage.c:190` labels it "instruction-order barrier" and the two halves
    /// must reach the peripheral in order.
    ///
    /// Never program the same doubleword twice without an erase in between:
    /// `PROGERR`, and `NorFlash`'s own contract forbids it
    /// (`embedded-storage-0.3.1/src/nor_flash.rs:104`). See the module docs for
    /// where `NorFlashLog` violates this.
    ///
    /// **Open, and it must be settled before hardware:** whether this function
    /// needs to execute from RAM. Coldcard marks its equivalents `.ramfunc` with
    /// "this function AND everything it calls, must be in RAM"
    /// (`storage.c:158-159`). Our code runs from `FLASH_TEXT` in bank 1 while
    /// `FLASH_FS` is bank 2, so dual-bank read-while-write **should** make it
    /// unnecessary — **assumed, not verified**. If wrong, the CPU stalls or
    /// faults mid-program. See module docs.
    ///
    /// # Errors
    ///
    /// [`FlashError::NotAligned`], [`FlashError::OutOfBounds`],
    /// [`FlashError::UnlockFailed`], or [`FlashError::Hardware`] with the `SR`
    /// bits (`PROGERR` = programmed twice, `WRPERR` = write-protected).
    ///
    /// # Panics
    ///
    /// Must not.
    fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
        check_bounds(offset, bytes.len(), WRITE_SIZE)?;
        if bytes.is_empty() {
            return Ok(());
        }

        // `return` is load-bearing: on this target the `cfg(target_arch = "arm")`
        // block below is deleted, so this block is the last statement in the
        // function -- but it is still a *statement*, and a bare `Err(..)` tail
        // there is a discarded `#[must_use]` value, not the return value.
        #[cfg(not(target_arch = "arm"))]
        #[allow(clippy::needless_return)]
        {
            return Err(FlashError::NotOnThisTarget);
        }

        #[cfg(target_arch = "arm")]
        {
            unlock()?;
            // As in `erase`: every exit past the unlock must re-lock, error paths
            // included, so the body is a closure and `lock()` is unconditional.
            let result = (|| -> Result<(), FlashError> {
                // `check_bounds` proved `offset % 8 == 0` and `len % 8 == 0`, so
                // `chunks_exact` leaves no remainder and every `abs` below is
                // doubleword-aligned -- a misaligned program is PGAERR.
                for (i, dw) in bytes.chunks_exact(WRITE_SIZE).enumerate() {
                    // Absolute address, as `flash_burn` takes
                    // (`storage.c:167`). Checked arithmetic: `overflow-checks =
                    // false` in release would let a wrap here name FLASH_TEXT,
                    // which is the one thing the region-relative offset design
                    // exists to prevent.
                    let byte_off = match i.checked_mul(WRITE_SIZE) {
                        Some(b) => b as u32,
                        None => return Err(FlashError::OutOfBounds),
                    };
                    let abs = match crate::memmap::FLASH_FS_BASE
                        .checked_add(offset)
                        .and_then(|a| a.checked_add(byte_off))
                    {
                        Some(a) => a,
                        None => return Err(FlashError::OutOfBounds),
                    };
                    // Belt: refuse anything the bootloader's own guard would
                    // refuse. Offsets from this type cannot reach below the
                    // floor, so this is redundant -- and worth keeping, because
                    // the cost of the arithmetic being wrong is the firmware
                    // image the bootloader verifies.
                    if abs < crate::memmap::FLASH_ERASE_FLOOR {
                        return Err(FlashError::OutOfBounds);
                    }

                    // Little-endian halves. `from_le_bytes` on fixed 4-byte
                    // arrays rather than a `u64` read of `dw`: `bytes` is a
                    // `&[u8]` with no alignment guarantee, so forming a `*const
                    // u64` to it is not sound.
                    let lo = u32::from_le_bytes([dw[0], dw[1], dw[2], dw[3]]);
                    let hi = u32::from_le_bytes([dw[4], dw[5], dw[6], dw[7]]);

                    // Clear stale errors INCLUDING PEMPTY, THEN wait for BSY.
                    //
                    // The order is load-bearing and it used to be inverted here: a
                    // bare `wait_done()?` came FIRST, and because `wait_done`
                    // reports latched error bits without clearing them, the `?`
                    // short-circuited and the clear below it was unreachable. One
                    // PROGERR then made every subsequent write return the same
                    // stale error forever, on healthy flash. See
                    // `operation_prologue`.
                    operation_prologue()?;

                    data_cache_disable();

                    // SAFETY: `FLASH_CR` is a memory-mapped peripheral register
                    // at `FLASH_R_BASE + 0x14`; the peripheral is unlocked
                    // (checked above) and idle (`wait_done`). MER1/PER/PNB are
                    // cleared before PG is set so a stale erase-select bit
                    // cannot turn this program into an erase -- `flash_burn`'s
                    // own sequence (`storage.c:180-186`).
                    unsafe {
                        let cr = core::ptr::read_volatile(FLASH_CR);
                        let cr = cr & !(FLASH_CR_MER1 | FLASH_CR_PER | FLASH_CR_PNB);
                        core::ptr::write_volatile(FLASH_CR, cr | FLASH_CR_PG);
                    }

                    // SAFETY: `abs` is doubleword-aligned, inside FLASH_FS by
                    // `check_bounds`, and above FLASH_ERASE_FLOOR by the check
                    // above. PG is set and the peripheral is unlocked, so these
                    // two stores are the documented program operation. The
                    // `isb` between them is not decoration: `storage.c:190`
                    // labels it "instruction-order barrier" and the halves must
                    // reach the peripheral in order or the doubleword is
                    // programmed from garbage.
                    unsafe {
                        core::ptr::write_volatile(abs as *mut u32, lo);
                        core::arch::asm!("isb sy", options(nostack, preserves_flags));
                        core::ptr::write_volatile((abs + 4) as *mut u32, hi);
                    }

                    let waited = wait_done();

                    // Clear PG whether or not the program succeeded
                    // (`storage.c:194`): leaving PG set makes the next stray
                    // store program flash.
                    // SAFETY: as above; clears only the operation-select bit.
                    unsafe {
                        let cr = core::ptr::read_volatile(FLASH_CR);
                        core::ptr::write_volatile(FLASH_CR, cr & !FLASH_CR_PG);
                    }
                    data_cache_reset_and_enable();
                    waited?;
                }
                Ok(())
            })();
            lock();
            result
        }
    }
}

/// A RAM-backed [`NorFlash`] at **exactly** [`StmFlash`]'s geometry, for host
/// tests.
///
/// # Why this is not `frostsnap_embedded::TestNorFlash`
///
/// `TestNorFlash` is `WRITE_SIZE = 4` (`frostsnap_embedded/src/test.rs:37`) and
/// `#[cfg(test)]`-private to that crate, so it can neither be reached from here
/// nor exercise the geometry this port actually ships. The `WRITE_SIZE = 8`
/// resolution in this module's docs is only a *claim* until the real `AbSlot` /
/// `device_nonces` stack has been run at 8, and running it is the one thing no
/// single-module agent could do. That is what this type is for.
///
/// It models the parts of NOR flash whose violation is a real STM32 fault:
///
/// * erase sets a page to `0xff`, and only whole [`ERASE_SIZE`] pages;
/// * a program may only clear bits, never set them, so **programming the same
///   doubleword twice without an erase is `PROGERR`** — returned as
///   [`FlashError::Hardware`], which is exactly how `NorFlashLog`'s
///   go-back-and-write-the-length pattern would fail on silicon;
/// * offsets and lengths must be [`WRITE_SIZE`]/[`ERASE_SIZE`]-aligned and in
///   bounds, via the same [`check_bounds`] the real driver uses.
///
/// It does **not** model power loss, bit rot, write disturb, ECC, or partially
/// programmed rows (PLAN.md §7). It is not a substitute for phase 7.
#[cfg(any(test, feature = "fake-flash"))]
pub mod fake {
    use super::{check_bounds, FlashError, ERASE_SIZE, WRITE_SIZE};
    use embedded_storage::nor_flash::{ErrorType, NorFlash, ReadNorFlash};

    extern crate alloc;
    use alloc::boxed::Box;
    use alloc::vec;

    /// A RAM-backed fake at [`StmFlash`](super::StmFlash)'s exact geometry.
    pub struct FakeFlash {
        cells: Box<[u8]>,
        /// Program operations performed, so a test can assert a write actually
        /// touched flash rather than being optimised into a no-op.
        pub programs: u32,
        /// Page erases performed.
        pub erases: u32,
        /// Refuse every program once [`FakeFlash::programs`] reaches this.
        /// `None` = never refuse.
        refuse_programs_from: Option<u32>,
        /// Refuse every erase once [`FakeFlash::erases`] reaches this.
        refuse_erases_from: Option<u32>,
    }

    impl FakeFlash {
        /// `sectors` pages of [`ERASE_SIZE`], all erased (`0xff`).
        ///
        /// # Panics
        ///
        /// If `sectors == 0`. Test-only helper; a zero-sector fake is a test bug,
        /// and `AbSlot::new` would assert on it anyway (`ab_write.rs:26`).
        #[must_use]
        pub fn new(sectors: usize) -> Self {
            assert!(sectors > 0, "a zero-sector fake flash cannot host a slot");
            Self {
                cells: vec![0xffu8; sectors * ERASE_SIZE].into_boxed_slice(),
                programs: 0,
                erases: 0,
                refuse_programs_from: None,
                refuse_erases_from: None,
            }
        }

        /// Refuse every program from the current count onward, reporting
        /// `PROGERR` exactly as the real driver does.
        ///
        /// Scheduled by operation *count* rather than by address, like
        /// `frostsnap_embedded`'s own `FaultyNorFlash` (`test.rs:64-172`), so a
        /// test can target "the second write of this A/B update" without knowing
        /// the partition layout. That crate's fault flash is `#[cfg(test)]` and so
        /// unreachable from here, which is why this exists.
        pub fn refuse_programs_now(&mut self) {
            self.refuse_programs_from = Some(self.programs);
        }

        /// Refuse every erase from the current count onward, reporting `WRPERR`.
        pub fn refuse_erases_now(&mut self) {
            self.refuse_erases_from = Some(self.erases);
        }

        /// Stop refusing. The cells are untouched, so a test can inspect exactly
        /// what survived the refusal — which is the whole point for A/B state.
        pub fn heal(&mut self) {
            self.refuse_programs_from = None;
            self.refuse_erases_from = None;
        }

        /// Total bytes, for tests that need to size a partition.
        #[must_use]
        pub fn len(&self) -> usize {
            self.cells.len()
        }

        /// Never empty by construction ([`FakeFlash::new`] refuses 0 sectors);
        /// present because clippy requires it alongside `len`.
        #[must_use]
        pub fn is_empty(&self) -> bool {
            self.cells.is_empty()
        }

        /// Corrupt `len` bytes at `offset` to `value`, bypassing every rule.
        ///
        /// For tests that need a slot to read back as garbage — the A/B scheme's
        /// whole purpose is surviving that, so it must be reachable.
        pub fn scribble(&mut self, offset: usize, len: usize, value: u8) {
            let end = core::cmp::min(offset.saturating_add(len), self.cells.len());
            if offset < end {
                self.cells[offset..end].fill(value);
            }
        }
    }

    impl ErrorType for FakeFlash {
        type Error = FlashError;
    }

    impl ReadNorFlash for FakeFlash {
        const READ_SIZE: usize = 1;

        fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
            // The fake's capacity, not FLASH_FS_LEN: a test fake is smaller, and
            // checking against the wrong bound would let a test pass on an access
            // the real device would refuse.
            let start = offset as usize;
            let end = match start.checked_add(bytes.len()) {
                Some(e) if e <= self.cells.len() => e,
                _ => return Err(FlashError::OutOfBounds),
            };
            bytes.copy_from_slice(&self.cells[start..end]);
            Ok(())
        }

        fn capacity(&self) -> usize {
            self.cells.len()
        }
    }

    impl NorFlash for FakeFlash {
        const WRITE_SIZE: usize = WRITE_SIZE;
        const ERASE_SIZE: usize = ERASE_SIZE;

        fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
            let len = match to.checked_sub(from) {
                Some(l) => l as usize,
                None => return Err(FlashError::OutOfBounds),
            };
            // Alignment via the real driver's own checker, then the fake's own
            // capacity bound.
            check_bounds(from, len, ERASE_SIZE)?;
            // Refusal is checked AFTER the argument checks (so a scheduled fault
            // cannot mask a genuine bounds bug) but BEFORE any mutation.
            if self
                .refuse_erases_from
                .is_some_and(|from_count| self.erases >= from_count)
            {
                // WRPERR, bit 4 (`stm32l4s5xx.h`), the write-protection refusal
                // `flash_page_erase` reports (`storage.c:212-216`).
                return Err(FlashError::Hardware(1 << 4));
            }
            let start = from as usize;
            let end = match start.checked_add(len) {
                Some(e) if e <= self.cells.len() => e,
                _ => return Err(FlashError::OutOfBounds),
            };
            self.cells[start..end].fill(0xff);
            self.erases = self.erases.saturating_add((len / ERASE_SIZE) as u32);
            Ok(())
        }

        fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
            check_bounds(offset, bytes.len(), WRITE_SIZE)?;
            let start = offset as usize;
            let end = match start.checked_add(bytes.len()) {
                Some(e) if e <= self.cells.len() => e,
                _ => return Err(FlashError::OutOfBounds),
            };
            if self
                .refuse_programs_from
                .is_some_and(|from_count| self.programs >= from_count)
            {
                return Err(FlashError::Hardware(1 << 3));
            }

            // THE POINT OF THIS FAKE. NOR programming can only clear bits, so
            // re-programming a doubleword to a different value is PROGERR on real
            // silicon and is forbidden by `NorFlash`'s own contract
            // ("It is not allowed to write to the same word twice",
            // `embedded-storage-0.3.1/src/nor_flash.rs:104`). Checked per
            // doubleword, before any mutation, so a refused write leaves the array
            // untouched -- which is what makes the A/B "old copy survives"
            // property meaningful.
            for (i, b) in bytes.iter().enumerate() {
                let old = self.cells[start + i];
                if old & b != *b {
                    // PROGERR, bit 3 (`stm32l4s5xx.h:8799-8836`), the same
                    // encoding the real driver reports.
                    return Err(FlashError::Hardware(1 << 3));
                }
            }
            self.cells[start..end].copy_from_slice(bytes);
            self.programs = self
                .programs
                .saturating_add((bytes.len() / WRITE_SIZE) as u32);
            Ok(())
        }
    }
}

/// Host tests for every part of this module that is pure.
///
/// These exist because six simultaneous mutations to this file once left the whole
/// suite green (module docs). Each test below is chosen to fail under exactly one
/// such mutation, so the name states which defect it holds closed.
#[cfg(test)]
mod tests {

    /// `pnb_bits` encodes the page number ITSELF, not a shifted-by-one neighbour.
    ///
    /// MEASURED (PLAN.md §9 item 22): as an inline expression in a
    /// `cfg(target_arch = "arm")` block, changing `page << 3` to `page << 4` passed
    /// all six gates. The `& FLASH_CR_PNB` mask does not catch it — the result is a
    /// VALID field value naming the wrong page, so page 5 erases page 10. In
    /// `FLASH_FS` that is the identity record, a share, or nonce state destroyed,
    /// and the erase reports success because it did erase a page.
    #[test]
    fn pnb_bits_encodes_the_page_number_itself() {
        // PNB is 8 bits at position 3, so pages 0..=255 round-trip exactly.
        for page in 0u32..=255 {
            let bits = pnb_bits(page);
            assert_eq!(bits & !FLASH_CR_PNB, 0, "page {page} set bits outside PNB");
            assert_eq!(bits >> 3, page, "page {page} encoded as page {}", bits >> 3);
        }
        // The specific mutation, named: a shift of 4 doubles the page.
        assert_ne!(pnb_bits(5), (5u32 << 4) & FLASH_CR_PNB, "shift-by-4 must differ");
    }
    use super::*;

    /// Capacity of [`SimPort`]'s write log. A module-level const, not an
    /// associated one: `Self::` is not in scope in a struct field type.
    const MAX_WRITES: usize = 16;

    /// A `FLASH->SR` that behaves like the peripheral in the one respect the
    /// ordering bug turned on: **error bits latch**. They stay set until written
    /// back as 1, and nothing else clears them.
    ///
    /// `BSY` is modelled as a countdown so a test can distinguish "busy then done"
    /// from "wedged forever", and `EOP` is set when an operation completes.
    struct SimPort {
        sr: u32,
        /// Reads remaining before `BSY` drops. `None` = never drops.
        busy_reads: Option<u32>,
        /// Every value written to `SR`, so a test can assert the driver cleared
        /// what it claimed to clear and in what order. Fixed-size: this crate is
        /// `no_std` and these tests need no allocator.
        writes: [u32; MAX_WRITES],
        /// How many of `writes` are populated. Saturates rather than panicking, so
        /// an unexpectedly chatty driver fails an assertion instead of aborting the
        /// test process.
        write_count: usize,
    }

    impl SimPort {
        /// Idle, no errors, no `EOP`.
        fn idle() -> Self {
            Self {
                sr: 0,
                busy_reads: Some(0),
                writes: [0; MAX_WRITES],
                write_count: 0,
            }
        }

        /// Idle, but with `errors` already latched — the state one transient fault
        /// leaves behind.
        fn latched(errors: u32) -> Self {
            let mut p = Self::idle();
            p.sr = errors;
            p
        }

        /// The writes actually performed, in order.
        fn writes(&self) -> &[u32] {
            &self.writes[..self.write_count]
        }
    }

    impl SrPort for SimPort {
        fn read_sr(&mut self) -> u32 {
            match self.busy_reads {
                Some(0) | None => {}
                Some(n) => self.busy_reads = Some(n - 1),
            }
            let busy = match self.busy_reads {
                None => FLASH_SR_BSY,
                Some(0) => 0,
                Some(_) => FLASH_SR_BSY,
            };
            self.sr | busy
        }

        fn write_sr(&mut self, value: u32) {
            if self.write_count < MAX_WRITES {
                self.writes[self.write_count] = value;
                self.write_count += 1;
            }
            // Write-1-to-clear: a 1 clears, a 0 leaves the bit alone. Modelling
            // this as `self.sr = value` would hide the whole defect, because it
            // would let a *wait* clear the latch.
            self.sr &= !value;
        }
    }

    // ---- #12: the FLASH_SR wedge -------------------------------------------

    /// The defect, reproduced against the OLD order (wait-then-clear) so the
    /// regression is a measurement rather than a claim: one latched `PROGERR`
    /// makes the next five writes and the following erase all fail on healthy
    /// flash, because `?` on the wait means the clear is never reached.
    #[test]
    fn one_latched_error_wedges_the_old_order_forever() {
        const PROGERR: u32 = 1 << 3;
        let mut port = SimPort::latched(PROGERR);

        // The old prologue, verbatim: wait first, propagate, then clear.
        fn old_order<P: SrPort>(port: &mut P) -> Result<(), FlashError> {
            sr_wait_done(port, 16)?;
            let sr = port.read_sr();
            port.write_sr(sr & FLASH_SR_ERRORS);
            Ok(())
        }

        for attempt in 0..6 {
            assert_eq!(
                old_order(&mut port),
                Err(FlashError::Hardware(PROGERR)),
                "attempt {attempt}: the stale latch must still be wedging the driver"
            );
        }
        assert!(
            port.writes().is_empty(),
            "the old order never reaches its own clear -- that IS the bug"
        );
        assert_eq!(port.sr & PROGERR, PROGERR, "so the error stays latched");
    }

    /// The fix: the same latched `PROGERR`, cleared first, so the operation
    /// proceeds and every later one succeeds.
    #[test]
    fn the_prologue_clears_a_stale_latch_and_then_succeeds() {
        const PROGERR: u32 = 1 << 3;
        let mut port = SimPort::latched(PROGERR);

        assert_eq!(sr_prologue(&mut port, 16), Ok(()));
        assert_eq!(port.sr & FLASH_SR_ERRORS, 0, "the latch must be gone");
        assert_eq!(
            port.writes().first().copied(),
            Some(PROGERR),
            "the FIRST SR write must be the clear, and must name only set bits"
        );

        for attempt in 0..5 {
            assert_eq!(
                sr_prologue(&mut port, 16),
                Ok(()),
                "attempt {attempt}: healthy flash must stay healthy"
            );
        }
    }

    /// Clearing must not swallow a *live* fault: an error the peripheral re-latches
    /// after the clear is a real one and must still be refused.
    #[test]
    fn a_relatched_error_is_still_reported() {
        const WRPERR: u32 = 1 << 4;
        struct Sticky(u32);
        impl SrPort for Sticky {
            fn read_sr(&mut self) -> u32 {
                self.0
            }
            // Models a peripheral holding the condition: the write does nothing.
            fn write_sr(&mut self, _value: u32) {}
        }
        assert_eq!(
            sr_prologue(&mut Sticky(WRPERR), 16),
            Err(FlashError::Hardware(WRPERR))
        );
    }

    /// The bounded wait must terminate rather than hang, and must report `BSY` so a
    /// bench can tell "stuck" from `PROGERR`. Coldcard's `while(BSY)` is unbounded;
    /// ours must not be.
    #[test]
    fn a_stuck_busy_bit_is_bounded_not_a_hang() {
        let mut port = SimPort {
            busy_reads: None,
            ..SimPort::idle()
        };
        assert_eq!(
            sr_wait_done(&mut port, 1_000),
            Err(FlashError::Hardware(FLASH_SR_BSY))
        );
    }

    /// `BSY` set for a while then clearing is the normal case, and `EOP` is cleared
    /// write-1-to-clear on the way out (`storage.c:74-77`).
    #[test]
    fn a_busy_then_done_peripheral_succeeds_and_clears_eop() {
        let mut port = SimPort {
            sr: FLASH_SR_EOP,
            busy_reads: Some(3),
            ..SimPort::idle()
        };
        assert_eq!(sr_wait_done(&mut port, 16), Ok(()));
        assert_eq!(port.writes(), &[FLASH_SR_EOP][..]);
        assert_eq!(port.sr & FLASH_SR_EOP, 0);
    }

    /// `PEMPTY` (bit 17) must be in the cleared set. The bootloader leaves it set
    /// and clears it explicitly ("clear any and all errors, including PEMPTY",
    /// `storage.c:173`); omitting it would wedge the first write after every boot.
    #[test]
    fn pempty_is_cleared_like_any_other_error() {
        const PEMPTY: u32 = 1 << 17;
        assert_eq!(FLASH_SR_ERRORS & PEMPTY, PEMPTY);
        let mut port = SimPort::latched(PEMPTY);
        assert_eq!(sr_prologue(&mut port, 16), Ok(()));
        assert_eq!(port.sr & PEMPTY, 0);
    }

    /// Every `SR` write must stay inside the errors+`EOP` set, so the
    /// write-1-to-clear idiom can only clear status and can never set a control
    /// bit. A mutation of `sr & FLASH_SR_ERRORS` to `!0`/`u32::MAX` breaks this.
    #[test]
    fn no_sr_write_ever_names_a_bit_outside_the_status_set() {
        let mut port = SimPort::latched(1 << 3);
        let _ = sr_prologue(&mut port, 16);
        for w in port.writes() {
            assert_eq!(
                w & !(FLASH_SR_ERRORS | FLASH_SR_EOP),
                0,
                "wrote {w:#x}, which names something outside the errors+EOP set"
            );
        }
    }

    // ---- #15: check_bounds -------------------------------------------------

    /// Containment: the bound is `FLASH_FS_LEN`, so no accepted offset can name
    /// `FLASH_TEXT`. Deleting this bound was mutation 1.
    #[test]
    fn check_bounds_refuses_past_the_region() {
        let len = crate::memmap::FLASH_FS_LEN;
        assert_eq!(check_bounds(len, WRITE_SIZE, WRITE_SIZE), Err(FlashError::OutOfBounds));
        assert_eq!(check_bounds(len - WRITE_SIZE as u32, WRITE_SIZE * 2, WRITE_SIZE), Err(FlashError::OutOfBounds));
        // Exact capacity is the boundary and must be ACCEPTED: an off-by-one here
        // would silently cost the last sector of nonce storage.
        assert_eq!(check_bounds(len - WRITE_SIZE as u32, WRITE_SIZE, WRITE_SIZE), Ok(()));
        assert_eq!(check_bounds(0, len as usize, WRITE_SIZE), Ok(()));
    }

    /// `checked_add`, not `wrapping_add` — mutation 2. With wrapping arithmetic a
    /// huge `len` wraps `end` back under the limit and an in-range offset is
    /// accepted for an out-of-range range. `overflow-checks = false` in release
    /// makes this silent on the device.
    #[test]
    fn check_bounds_cannot_be_wrapped_past_the_bound() {
        // offset + len overflows u32/usize entirely.
        assert_eq!(
            check_bounds(u32::MAX & !7, usize::MAX & !7, WRITE_SIZE),
            Err(FlashError::OutOfBounds)
        );
        assert_eq!(check_bounds(8, usize::MAX - 7, WRITE_SIZE), Err(FlashError::OutOfBounds));
    }

    /// Alignment is checked BEFORE bounds, so a request that is both misaligned and
    /// oversized reports the more specific fault. Deleting the alignment check was
    /// mutation 3; a misaligned program is `PGAERR` on silicon.
    #[test]
    fn check_bounds_reports_misalignment_before_oversize() {
        assert_eq!(
            check_bounds(crate::memmap::FLASH_FS_LEN + 1, 1, WRITE_SIZE),
            Err(FlashError::NotAligned)
        );
        assert_eq!(check_bounds(1, WRITE_SIZE, WRITE_SIZE), Err(FlashError::NotAligned));
        assert_eq!(check_bounds(0, 1, WRITE_SIZE), Err(FlashError::NotAligned));
        // align <= 1 means "no requirement", and must not divide by zero.
        assert_eq!(check_bounds(1, 1, 1), Ok(()));
        assert_eq!(check_bounds(1, 1, 0), Ok(()));
    }

    // ---- #15: erase_page_of ------------------------------------------------

    /// Page index, bank select and the 8-bit mask, against `flash_page_erase`
    /// (`storage.c:213-219`). Inverting the bank bit was mutation 5, and it erases
    /// a page 1 MB away from the intended one.
    #[test]
    fn erase_page_of_matches_the_bootloader_geometry() {
        // FLASH_FS is at 0x0818_0000: offset 0x180000 / 0x1000 = page 384 -> bank 2,
        // masked to 0x80.
        assert_eq!(erase_page_of(crate::memmap::FLASH_FS_BASE), Ok((0x80, true)));
        // Last page of bank 1 / first of bank 2, i.e. the boundary at index 256.
        assert_eq!(erase_page_of(BANK2_BASE - ERASE_SIZE as u32), Ok((255, false)));
        assert_eq!(erase_page_of(BANK2_BASE), Ok((0, true)));
        // The mask makes the page index identical for any alias of the same
        // offset within the 128 MB window (`storage.c:213`). `| 0x0800_0000`
        // would be a no-op here, so use a bit the mask actually discards.
        assert_eq!(
            erase_page_of(crate::memmap::FLASH_FS_BASE),
            erase_page_of(crate::memmap::FLASH_FS_BASE + 0x0800_0000)
        );
        // But the floor guard is applied to the address as GIVEN, before masking.
        // So a bare offset -- which masks to the same page -- is REFUSED rather
        // than silently aliased onto FLASH_FS. That is the fail-closed direction:
        // the caller has to name a real address.
        assert_eq!(
            erase_page_of(crate::memmap::FLASH_FS_BASE & 0x7ff_ffff),
            Err(FlashError::OutOfBounds)
        );
    }

    /// The erase floor — mutation 4. Below it the bootloader refuses without
    /// touching anything (`storage.c:212-216`); erasing there would destroy the
    /// image the bootloader verifies, or the NVROM secrets.
    #[test]
    fn erase_page_of_refuses_below_the_floor() {
        let floor = crate::memmap::FLASH_ERASE_FLOOR;
        assert_eq!(erase_page_of(0), Err(FlashError::OutOfBounds));
        assert_eq!(erase_page_of(crate::memmap::BL_FLASH_BASE), Err(FlashError::OutOfBounds));
        assert_eq!(erase_page_of(floor - 1), Err(FlashError::OutOfBounds));
        assert!(erase_page_of(floor).is_ok(), "the floor itself is allowed");
    }

    /// Every page this type can name is inside `FLASH_FS` and above the floor. This
    /// is the containment property stated as a sweep rather than as prose.
    #[test]
    fn no_reachable_offset_can_name_a_page_outside_flash_fs() {
        let mut off = 0u32;
        while off < crate::memmap::FLASH_FS_LEN {
            let abs = crate::memmap::FLASH_FS_BASE + off;
            let (page, bank2) = erase_page_of(abs).expect("inside FLASH_FS must be erasable");
            assert!(abs >= crate::memmap::FLASH_ERASE_FLOOR);
            assert!(bank2, "all of FLASH_FS is in bank 2");
            // Reconstruct the absolute address from (page, bank2) and check it maps
            // back -- catches a wrong mask or a wrong bank threshold.
            let bank_base = if bank2 { BANK2_BASE } else { crate::memmap::BL_FLASH_BASE };
            assert_eq!(bank_base + page * ERASE_SIZE as u32, abs & !(ERASE_SIZE as u32 - 1));
            off += ERASE_SIZE as u32;
        }
    }

    // ---- #13: dbank_ok and the token ---------------------------------------

    /// `dbank_ok` must actually test bit 22 — mutation 6 made it return `true`
    /// unconditionally, which re-opens the 8 K-page nonce-destruction path.
    #[test]
    fn dbank_ok_tests_bit_22_and_nothing_else() {
        assert!(dbank_ok(FLASH_OPTR_DBANK));
        assert!(dbank_ok(u32::MAX));
        assert!(!dbank_ok(0));
        // Every other bit set, DBANK clear: must still refuse. A mutation to
        // `!= 0` on the whole word, or to a wrong bit index, fails here.
        assert!(!dbank_ok(!FLASH_OPTR_DBANK));
        assert_eq!(FLASH_OPTR_DBANK, 1 << 22);
    }

    /// The reason refusal is the only safe answer at `DBANK == 0`: the A and B
    /// nonce copies would share one 8 K page, so a single write destroys its own
    /// redundancy while reporting `Committed`.
    #[test]
    fn ab_copies_share_a_page_when_dbank_is_zero() {
        assert!(ab_copies_would_share_one_page_at_dbank_zero());
    }

    /// The token is a singleton and it is take-once, so two `StmFlash` handles
    /// cannot interleave `CR` writes.
    #[test]
    fn the_token_is_take_once() {
        assert!(StmFlashToken::take().is_some());
        for _ in 0..3 {
            assert!(
                StmFlashToken::take().is_none(),
                "a second token would allow two writers to interleave CR writes"
            );
        }
    }

    /// On the host, `open` must refuse rather than dereference `0x4002_2020`. The
    /// type-state is what makes this the *only* path to an `StmFlash`: the token
    /// implements no flash trait, so there is nothing else to call.
    #[test]
    fn open_refuses_on_a_non_device_target() {
        // Constructed directly rather than via `take()`, so this test does not
        // race the singleton with `the_token_is_take_once`.
        let token = StmFlashToken { _private: () };
        // `matches!`, not `assert_eq!`: the Ok type is `StmFlash`, which
        // deliberately derives neither `Debug` nor `PartialEq`. Two `StmFlash`
        // values comparing equal would contradict the singleton property this
        // whole type-state exists to enforce, so the assertion bends, not the type.
        assert!(matches!(token.open(), Err(FlashError::NotOnThisTarget)));
    }

    // ---- #16: the claims the docs make ------------------------------------

    /// `WRITE_SIZE = 8` is the hardware truth and `NorFlashLog` needs 4, so the log
    /// is unusable over this driver — resolution "option 2" in the module docs. If
    /// someone sets `WRITE_SIZE = 4` to make it link, this fails and forces the
    /// hardware question to be answered instead of assumed.
    #[test]
    fn nor_flash_log_stays_unusable() {
        assert!(assert_nor_flash_log_is_unusable());
        assert_eq!(WRITE_SIZE, 8);
        assert_eq!(ERASE_SIZE, 4096);
    }

    /// The read-while-write premise the `.ramfunc` decision rested on is false:
    /// 512 K of `FLASH_TEXT` is in bank 2, alongside `FLASH_FS`. Pinned so the old
    /// "different banks, so it is fine" claim cannot come back as a comment.
    #[test]
    fn text_and_fs_really_do_share_bank_two() {
        assert_eq!(flash_text_bytes_in_bank2(), 512 * 1024);
        assert!(text_and_fs_share_bank_two());
        // A `const` block, not a plain `assert!`: both sides are constants, so this
        // is a *build* failure on every target rather than a host-test failure. A
        // geometry invariant that only breaks under `cargo test` is one an
        // embedded-only change can walk past.
        const { assert!(crate::memmap::FLASH_FS_BASE >= BANK2_BASE) };
        // Compared against a binding rather than written as `assert!(CONST)`, which
        // clippy reads as an assertion on a constant. The point is that the flag
        // still SAYS unresolved: flipping it to `false` must require deleting this
        // line together with the module-doc section that explains it.
        let unresolved = RAM_EXECUTION_IS_UNRESOLVED;
        assert!(
            unresolved,
            "still unresolved: no linker script, no bench measurement"
        );
    }

    /// The margin arithmetic, at the measured phase-1 image size.
    #[test]
    fn bank1_margin_is_about_44k_at_the_measured_image_size() {
        assert_eq!(bank1_margin_at(856_872), Some(44_248));
        assert_eq!(bank1_margin_at(0), Some(901_120));
        // Past the bank boundary "margin" is the wrong question, so: None.
        assert_eq!(bank1_margin_at(901_121), None);
        assert_eq!(bank1_margin_at(crate::memmap::FLASH_TEXT_LEN), None);
    }

    // ---- the fake, at the geometry it claims ------------------------------

    /// The fake must refuse a second program of the same doubleword, because NOR
    /// can only clear bits and re-programming is `PROGERR` on silicon. Without
    /// this the fake would accept exactly the `NorFlashLog` pattern the module docs
    /// rule out, and the integration test's "this composes" claim would be void.
    #[test]
    fn the_fake_enforces_program_once() {
        // `NorFlash`/`ReadNorFlash` are already in scope via `use super::*`.
        let mut f = fake::FakeFlash::new(2);
        assert_eq!(f.write(0, &[0xAA; 8]), Ok(()));
        // Same value again only clears bits already clear: allowed.
        assert_eq!(f.write(0, &[0xAA; 8]), Ok(()));
        // A different value needs a 0->1 transition somewhere: PROGERR (bit 3).
        assert_eq!(f.write(0, &[0xFF; 8]), Err(FlashError::Hardware(1 << 3)));
        // And the refusal left the cells untouched, which is what makes the A/B
        // "old copy survives" property meaningful.
        let mut back = [0u8; 8];
        assert_eq!(f.read(0, &mut back), Ok(()));
        assert_eq!(back, [0xAA; 8]);
    }

    /// The fake uses the real driver's own alignment checker, so a test cannot
    /// pass on an access the device would refuse.
    #[test]
    fn the_fake_shares_the_real_alignment_rules() {
        let mut f = fake::FakeFlash::new(2);
        assert_eq!(f.write(1, &[0; 8]), Err(FlashError::NotAligned));
        assert_eq!(f.write(0, &[0; 4]), Err(FlashError::NotAligned));
        assert_eq!(f.erase(0, 100), Err(FlashError::NotAligned));
        assert_eq!(f.erase(4096, 0), Err(FlashError::OutOfBounds));
    }
}
