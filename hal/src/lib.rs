//! `coldsnap_hal` — the STM32L4S5 substrate for cold-snap (PLAN.md phase 2).
//!
//! This crate is the entire hardware surface of the project. Everything above it
//! (`frostsnap_core`, `frostsnap_embedded`) is portable and already compiles for
//! `thumbv7em-none-eabihf` unchanged; everything below it is Coinkite's PCROP
//! bootloader, which we call but never modify (DECISIONS.md decision 2).
//!
//! # Hardware, as verified
//!
//! STM32L4S5, Cortex-M4F @ 120 MHz, `thumbv7em-none-eabihf`, 2 MB flash. From
//! `coldcard-firmware/stm32/COLDCARD_MK4/layout.ld:10-22` (read):
//!
//! | Region       | Origin       | Length | Owner |
//! |--------------|--------------|--------|-------|
//! | `FLASH`      | `0x0800_0000` | 64 K   | PCROP bootloader — runs first, never field-upgradable |
//! | `FLASH_ISR`  | `0x0802_0000` | 16 K   | vectors |
//! | `FLASH_TEXT` | `0x0802_4000` | 1392 K | our firmware budget (59.2% used at phase 1) |
//! | `FLASH_FS`   | `0x0818_0000` | 512 K  | **was** MicroPython's LFS2. We have no MicroPython, so this is free and is where frostsnap nonce/key state lives — see [`flash`]. |
//! | `RAM`        | `0x2000_0000` | `0x9_e000` | SRAM1+2+3 contiguous; the top `0x2000` belongs to the bootloader |
//!
//! # Module map — one owner per file, no cross-editing
//!
//! Each module is implemented independently against the signatures published
//! here. No implementer needs to edit `lib.rs` or another module's file.
//!
//! | Module | Owns | Depends on |
//! |---|---|---|
//! | [`callgate`] | the `blx` into the PCROP bootloader, selector constants, the SRAM-buffer safety rule | nothing in-crate |
//! | [`comms`] | the frostsnap wire framing: the magic-byte handshake gate, the bounded frame reassembler, the [`comms::FRAME_LIMIT`] refusal on both directions | `frostsnap_comms` only |
//! | [`display`] | the 128×64 SSD1306 on SPI1: `CS`/`DC` via `BSRR`, the 1,024-byte full-frame blit, and the **zero-initialisation** decision the bootloader's `HAL_GPIO_LockPin` forces on us | [`singleton`] |
//! | [`flash`] | `StmFlash`: `NorFlash` + `ReadNorFlash` over `FLASH_FS`, reachable only by consuming a `StmFlashToken` (so the `DBANK` geometry check cannot be skipped), plus [`flash::fake`] for host tests | [`singleton`] |
//! | [`heap`] | **constants only, no code**: the measured heap budget, and why the region and the allocator are deferred to phase 5 | [`comms`] (the decode bound), `memmap` |
//! | [`keypad`] | the 4×3 membrane pad: cols `PB0`-`PB2` in, rows `PD8`-`PD11` open-drain out, the `mempad.py:19` decode table, the Tempest row shuffle, and the ghost-rejecting debounce that makes simultaneous keys a **refusal** | [`display`] (the `BSRR` half-word encoders), [`singleton`] |
//! | [`rng`] | the fail-closed 2-source `RngCore` and its checked constructor | [`callgate`] (SE1/SE2 legs), [`singleton`] |
//! | [`mod@panic`] | `#[panic_handler]`, `NVIC_SystemReset`, the RTC backup-register counters | [`callgate`] (late DFU fallback) |
//! | [`singleton`] | the one tagged take-once guard `flash`, `rng` and `usb` use | nothing in-crate |
//! | [`ui`] | the 1,024-byte `MONO_VLSB` framebuffer, the 8x8 glyph blitter and the eight PLAN.md §4.2 screens as **pure** composition + pagination — no registers, so every screen is host-renderable and host-assertable | nothing in-crate |
//! | [`usb`] | OTG_FS device mode + CDC-ACM: descriptors, control-request dispatch, FIFO plan, packet I/O | [`callgate`] (`with_irq_off`), [`singleton`] |
//!
//! `rng` is the only module with an in-crate dependency beyond `callgate` and
//! `singleton`, and `panic` uses only `callgate::raw` plus its own register
//! writes. [`usb`] moves bytes and knows nothing about what they mean; [`comms`]
//! knows what they mean and touches no register. That split is what makes the
//! framing testable on the host at all.
//!
//! ## Why `singleton` exists at all — an integration-time correction
//!
//! The published contract told `flash` and `rng` to guard their singletons with
//! an `AtomicBool`. That is **wrong on this board** and both modules would have
//! shipped the same brick: a `static` lives in `.bss`, the bootloader *fills*
//! SRAM1 with `0xdeadbeef` rather than zeroing it (`main.c:42,47,130`), and no
//! `.bss`-zeroing startup code exists in this repo yet. An uninitialised
//! `AtomicBool` therefore reads `true`, so the **first** `take()` returns `None`
//! and the firmware can obtain neither flash nor entropy. [`singleton::TakeOnce`]
//! is the shared tagged fix; see its module docs for the fail-safe direction.
//!
//! # Two properties this crate exists to guarantee
//!
//! **Fail closed on entropy** (PLAN.md §5.1). The §1 rationale for discarding
//! MicroPython is that libngu's `#ifdef` ladder *failed open* to glibc
//! `random()`. The requirement is enforced by types rather than by review:
//! [`rng::Entropy`] is only constructible from a [`rng::Sources`], which is only
//! constructible from the non-defaultable singleton source types.
//!
//! The `cfg` rule that follows from libngu is **directional**, and stating it as
//! "[`rng`] has no conditional compilation at all" — as this file used to — got it
//! backwards. A `cfg` on a **refusal** fails open and is forbidden: that is
//! precisely libngu's defect. A `cfg` on a **bypass** fails closed and is
//! mandatory. So [`rng::check_source`], the source legs and
//! [`rng::Entropy::boot`] carry no `cfg`, while the seam that skips them
//! (`mix_sources`, `Entropy::from_proven_seed`, `ProvenSeed::expose`) is gated
//! behind the non-default `test-seam` feature — it was unconditionally public, and
//! it compiled for the device.
//!
//! Note also that "all **three** sources" was itself false: SE1's nonce is fed 20
//! bytes of our own STM32 TRNG (`ae.c:1332`) so it is not independent, and
//! `se2_read_rng` returns a **static** page (`se2.c:1341-1343`) so SE2 is not an
//! entropy source at all. [`rng::ENTROPY_SOURCE_COUNT`] is 2, with SE2 reclassified
//! as fixed personalisation; see the [`rng`] docs.
//!
//! **Never halt on panic** (DECISIONS.md decision 6). Under
//! `panic = "abort"` with no unwinder every failed `assert!` is a permanent
//! halt, and on a locked (RDP=2) unit DFU is hardware-impossible
//! (`mk4-bootloader/main.c:256-258`). [`mod@panic`] therefore resets rather than
//! spinning, and bounds the reset loop with a reboot-survivable counter.
//!
//! # Host-testability, and its hard limit
//!
//! `cargo test --target aarch64-apple-darwin -p coldsnap_hal` must always work,
//! so the pure logic can be unit-tested. Two consequences are baked into the
//! module layout:
//!
//! * The `#[panic_handler]` is gated on `all(target_os = "none",
//!   feature = "panic-handler")`. `target_os` is `"none"` for
//!   `thumbv7em-none-eabihf` and `"macos"` for the host (both **measured** via
//!   `rustc --print cfg`), so on the host it simply does not exist and cannot
//!   collide with `std`'s.
//! * Anything containing ARM `asm!` cannot be compiled for the host at all —
//!   `asm!` naming `r0`-`r3` gives `error: invalid register 'r0'` on aarch64
//!   (measured by the entropy investigation). Such code lives behind
//!   `#[cfg(target_arch = "arm")]` in [`callgate`] and [`mod@panic`], with the
//!   *pure* parts (buffer validation, response parsing, counter arithmetic,
//!   entropy mixing) kept in separate `cfg`-free functions so the host can test
//!   them. Splitting the mixer out of the hardware sources this way is the
//!   entropy investigation's blocker 5, resolved in the skeleton rather than
//!   deferred.
//!
//! # What can never be tested off-hardware
//!
//! PLAN.md §7 and DECISIONS.md decision 5: the callgate in any form (it is PCROP
//! code outside any image we can emulate — Renode included), both secure
//! elements, the two-source TRNG health checks, panic→reset recovery, real
//! STM32 program/erase semantics, and — new in phase 3 — the OTG_FS register
//! sequences in [`usb`]: core reset, FIFO sizing, endpoint enable and the
//! host-driven enumeration that exercises them. A host model of those registers
//! would be built from the same datasheet reading as the driver, so agreement
//! would prove only self-consistency. Every such item is marked in its module
//! docs. [`comms`], by contrast, is testable in full: it is where the
//! coordinator-controlled bytes are, and none of it touches hardware.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

pub mod callgate;
pub mod comms;
pub mod display;
pub mod flash;
pub mod heap;
pub mod identity;
pub mod keypad;
pub mod panic;
pub mod rng;
pub mod singleton;
pub mod ui;
pub mod usb;

/// Memory-map constants read from
/// `coldcard-firmware/stm32/COLDCARD_MK4/layout.ld` and
/// `stm32/mk4-bootloader/Makefile`. Every value here is **read**, not assumed.
///
/// These live in `lib.rs` rather than in a module because [`flash`],
/// [`callgate`] and [`mod@panic`] all need some of them, and duplicating an address
/// across three files is how the three drift apart.
pub mod memmap {
    /// Base of the bootloader's flash region. First 64 K, PCROP-protected,
    /// runs first, never field-upgradable. `layout.ld:9` comment;
    /// `mk4-bootloader/Makefile:47` `BL_FLASH_BASE`.
    pub const BL_FLASH_BASE: u32 = 0x0800_0000;

    /// Length of the bootloader region proper: `0x1c000` = 112 K
    /// (`mk4-bootloader/Makefile:48` `BL_FLASH_SIZE`). Note this is NOT 64 K —
    /// the "first 64k" in `layout.ld:9`'s comment is the older Mk3 figure, and
    /// the 16 K `BL_NVROM_SIZE` (`Makefile:57`) sits above it. The
    /// firmware-facing consequence is only that erase below
    /// `(BL_FLASH_SIZE + BL_NVROM_SIZE)` is refused by the hardware's own write
    /// protection AND by `flash_page_erase` (`storage.c:213-216`).
    pub const BL_FLASH_SIZE: u32 = 0x0001_c000;

    /// Non-volatile ROM secrets area above the bootloader
    /// (`mk4-bootloader/Makefile:57` `BL_NVROM_SIZE`).
    pub const BL_NVROM_SIZE: u32 = 0x0000_4000;

    /// First byte of flash our own firmware is allowed to erase. Below this,
    /// `flash_page_erase` returns 1 without touching anything
    /// (`mk4-bootloader/storage.c:212-216`) and option-byte write protection
    /// covers it (`storage.c:563-564`). [`crate::flash`] must never issue an
    /// erase below this address.
    pub const FLASH_ERASE_FLOOR: u32 = BL_FLASH_BASE + BL_FLASH_SIZE + BL_NVROM_SIZE;

    /// `FLASH_TEXT` origin — our firmware image (`layout.ld:17`).
    pub const FLASH_TEXT_BASE: u32 = 0x0802_4000;
    /// `FLASH_TEXT` length, 1392 K = 1,425,408 B. This is the flash budget all
    /// of PLAN.md §2.2's percentages are against.
    pub const FLASH_TEXT_LEN: u32 = 1392 * 1024;

    /// `FLASH_FS` origin (`layout.ld:18`). Formerly MicroPython's LFS2
    /// filesystem; with no MicroPython this whole region is ours.
    pub const FLASH_FS_BASE: u32 = 0x0818_0000;
    /// `FLASH_FS` length, 512 K (`layout.ld:18`).
    pub const FLASH_FS_LEN: u32 = 512 * 1024;

    /// Where [`crate::identity`]'s 48-byte record lives, as an offset into
    /// `FLASH_FS` (which is the offset space [`crate::flash::StmFlash`]'s
    /// `NorFlash` impl works in).
    ///
    /// **This constant can never change once a unit ships.** Moving it orphans
    /// the device's identity exactly as regenerating the key would, and the
    /// device has no way to tell the two apart.
    pub const FS_IDENTITY_OFFSET: u32 = 0;
    /// Length of the identity region: 2 sectors, 8 K.
    ///
    /// One 48-byte record needs one sector. The second exists for the geometry
    /// hazard of PLAN.md §8.1: at `DBANK == 0` a flash page is 8192 bytes, so an
    /// erase aimed at sector 0 takes 8 K with it. Every region here is a multiple
    /// of 8 K and 8 K-aligned, so even that erase cannot reach the next region.
    /// (`StmFlashToken::open` refuses `DBANK == 0` outright; this is the belt.)
    pub const FS_IDENTITY_LEN: u32 = 8 * 1024;

    /// Where the frostsnap nonce A/B slots go. Not wired up yet — recorded here
    /// because identity's placement is only defensible relative to it, and
    /// because one `NonceAbSlot` costs exactly 2 sectors
    /// (`nonce_slots.rs:24-31`'s `split_off_front(2)`).
    pub const FS_NONCE_OFFSET: u32 = FS_IDENTITY_OFFSET + FS_IDENTITY_LEN;
    /// 4 nonce streams × 2 sectors = 32 K. The stream count matches
    /// `hal/examples/stub.rs:424`, the only place in the tree that picks one; it
    /// is a guess at max concurrent streams, and raising it later moves
    /// everything above it.
    pub const FS_NONCE_LEN: u32 = 32 * 1024;

    /// Where the keygen share record lives (`coldsnap_firmware::store`).
    ///
    /// **16 K, not 8, and the extra 8 K is the whole point.** `AbSlot::new`
    /// halves its partition (`ab_write.rs:31-35`), so 4 sectors give each copy
    /// exactly 2 sectors = one `DBANK == 0` page, and `Slot::try_write`'s
    /// `erase_all()` (`ab_write.rs:162`) then erases exactly that page. At 8 K an
    /// erase of copy A would take copy B with it if `DBANK` turns out to be 0 —
    /// the hazard `flash::ab_copies_would_share_one_page_at_dbank_zero` already
    /// pins for the nonce region — which would make the A/B redundancy of the one
    /// record on this device that has **no backup path** imaginary.
    ///
    /// Like [`FS_IDENTITY_OFFSET`], this cannot change once a unit ships: moving
    /// it orphans the share, and the share cannot be re-derived.
    pub const FS_SHARE_OFFSET: u32 = FS_NONCE_OFFSET + FS_NONCE_LEN;
    /// 4 sectors, 16 K: 2 per A/B copy. See [`FS_SHARE_OFFSET`].
    pub const FS_SHARE_LEN: u32 = 16 * 1024;

    /// Where the device name record goes. Reserved, not yet written: `SetName`
    /// (PLAN.md gap 3) is separate work, but the constant has to exist *now*
    /// because carving it out later would move the share region, and moving the
    /// share region orphans the share.
    ///
    /// A separate region from [`FS_SHARE_OFFSET`] on purpose: the loss
    /// consequences differ. A lost name is retyped; a lost share is gone. Sharing
    /// a region would let a rename erase a sector the share lives in.
    pub const FS_NAME_OFFSET: u32 = FS_SHARE_OFFSET + FS_SHARE_LEN;
    /// 4 sectors, 16 K, for the same A/B-page reason as [`FS_SHARE_LEN`].
    pub const FS_NAME_LEN: u32 = 16 * 1024;

    /// First `FLASH_FS` byte no region claims — 440 K of the 512 K still
    /// unclaimed. Deliberately not carved up until something needs it.
    pub const FS_FREE_OFFSET: u32 = FS_NAME_OFFSET + FS_NAME_LEN;

    /// SRAM1 base = start of the contiguous SRAM1+2+3 window (`layout.ld:21`).
    pub const SRAM_BASE: u32 = 0x2000_0000;

    /// One past the last byte of SRAM usable by our firmware, and the base of
    /// the bootloader's own 8 K (`mk4-bootloader/Makefile:61`
    /// `BL_SRAM_BASE = 0x2009e000`; `layout.ld:21` gives RAM length
    /// `0x9e000`).
    ///
    /// Load-bearing in two places. (1) `good_addr()` requires every callgate
    /// buffer to lie inside `[SRAM_BASE, BL_SRAM_BASE)` and to be writable —
    /// a `static` in flash returns `EPERM` (`dispatch.c:39-62`). (2) Nothing of
    /// ours may live at or above it: the callgate **wipes** that 8 K on entry
    /// before dispatching and again on exit (`startup.S:124-134,148-156`), and
    /// `reset_entry` calls the gate on every boot (`startup.S:90-95`). This is
    /// why the panic counter is in an RTC backup register and not in SRAM —
    /// PLAN.md §9.2's SRAM suggestion must be struck.
    pub const BL_SRAM_BASE: u32 = 0x2009_e000;

    /// `FLASH_ISR` origin: where the bootloader looks for our vector table
    /// (`layout.ld:16`; `mk4-bootloader/verify.h:9` `FIRMWARE_START`;
    /// `mk4-bootloader/Makefile:52` `MPY_FLASH_BASE`).
    ///
    /// **The handoff reads exactly two words from here** and nothing else
    /// (`mk4-bootloader/startup.S:102-112`): word 0 goes into `SP`, word 1 into
    /// `PC` via `bx lr` and **must have its LSB set** for Thumb. `r0` arrives as
    /// `1` and `LR` holds the entry address itself, so the entry must never
    /// return — its signature is `-> !`.
    pub const FLASH_ISR_BASE: u32 = 0x0802_0000;
    /// `FLASH_ISR` length, 16 K (`layout.ld:16`). Ends exactly at
    /// [`FLASH_TEXT_BASE`].
    pub const FLASH_ISR_LEN: u32 = 16 * 1024;

    /// Offset of the 128-byte signature header within the image, and therefore
    /// the ceiling on everything we may place in `FLASH_ISR`
    /// (`stm32/sigheader.h:38-39`; absolute address `0x0802_3f80` =
    /// `sigheader.h:82` `FLASH_HEADER_BASE_MK4`).
    ///
    /// The header is inserted **post-link** by `cli/signit.py`, not by a linker
    /// script, and `signit.py:292` asserts the vector-table blob is
    /// `<= FW_HEADER_OFFSET`. A linker script must reserve it, not emit it.
    pub const FW_HEADER_OFFSET: u32 = FLASH_ISR_LEN - FW_HEADER_SIZE;
    /// Size of that header (`sigheader.h:38`, asserted at `verify.c:314`).
    pub const FW_HEADER_SIZE: u32 = 128;

    /// Suggested initial `SP`, placed in word 0 of the vector table.
    ///
    /// This is **our free choice** — the bootloader takes whatever we put there
    /// (`startup.S:106-107`), so stack placement needs no negotiation. The value
    /// here is the top of usable SRAM. MicroPython used `0x2009_bff8` because it
    /// reserved an 8 K LFS2 cache below `_ram_end` (`layout.ld:37-40`); that
    /// cache was MicroPython's, not the bootloader's, so with no MicroPython the
    /// 8 K is reclaimable.
    ///
    /// A full-descending stack never writes *at* `SP`, so a value equal to
    /// [`BL_SRAM_BASE`] does not touch the bootloader's 8 K.
    pub const ESTACK_TOP: u32 = BL_SRAM_BASE;

    /// Minimum image body the signing tool and the bootloader will accept: the
    /// body must be `>= 256 K` (`sigheader.h:46` `FW_MIN_LENGTH`;
    /// `cli/signit.py:293`; enforced again at `verify.c:215`) and padded to a
    /// **512-byte** multiple (`signit.py:295`; `sigheader.h:19`).
    ///
    /// Recorded here because it bites early: a first stub image is far smaller
    /// than this and is rejected by `signit.py` before the device ever sees it.
    pub const FW_MIN_BODY_LEN: u32 = 256 * 1024;
    /// Required body alignment (`cli/signit.py:295`).
    pub const FW_BODY_ALIGN: u32 = 512;

    /// The bootloader's 12-byte `dfu_flag` (`mk4-bootloader/main.h:14`).
    ///
    /// **Nothing of ours may leave attacker-influenced bytes here.** It is read
    /// at `main.c:115` — *before* `wipe_all_sram()` at `main.c:130` — so bytes
    /// that survive an `NVIC_SystemReset` reach that comparison on the next boot.
    /// A match causes `enter_dfu()`, which at RDP=2 is `LOCKUP_FOREVER()`
    /// (`main.c:256-258`; `dispatch.c:150-165`). Since [`crate::panic`] resets on
    /// every panic, and a coordinator can influence heap contents, a heap or
    /// buffer placed across this address is a remote brick path.
    ///
    /// Distinct from [`BL_SRAM_BASE`]: that region is wiped *by* the callgate and
    /// so cannot hold our data; this one is *read* by the bootloader and so must
    /// not hold our data.
    pub const DFU_FLAG_ADDR: u32 = 0x2000_8000;
    /// Length of that flag (`main.h:14`, `dfu_flag_t`).
    pub const DFU_FLAG_LEN: u32 = 12;

    /// SRAM2's low alias (`stm32l4s5xx.h:1290`). The same physical memory as part
    /// of the contiguous window at [`SRAM_BASE`], reachable at a second address —
    /// so a containment check written against one range can be bypassed via the
    /// other. Recorded for whoever writes the next bounds check.
    pub const SRAM2_ALIAS_BASE: u32 = 0x1000_0000;

    /// External PSRAM: **8 MiB at `0x9000_0000`**, configured by the bootloader's
    /// `psram_setup()` (`mk4-bootloader/psram.h`; called `main.c:150`).
    ///
    /// Closes PLAN.md §9 item 5, which recorded the capacity as unverified from
    /// Coldcard source. It is in the source. Not used by this firmware.
    pub const PSRAM_BASE: u32 = 0x9000_0000;
    /// PSRAM length, 8 MiB (`mk4-bootloader/psram.h`).
    pub const PSRAM_LEN: u32 = 8 * 1024 * 1024;

    /// The image layout must be self-consistent, and these are cheap.
    const _: () = {
        assert!(FLASH_ISR_BASE + FLASH_ISR_LEN == FLASH_TEXT_BASE);
        assert!(FLASH_TEXT_BASE + FLASH_TEXT_LEN == FLASH_FS_BASE);
        assert!(FW_HEADER_OFFSET + FW_HEADER_SIZE == FLASH_ISR_LEN);
        assert!(ESTACK_TOP <= BL_SRAM_BASE);
        // The dfu_flag sits inside the SRAM window we allocate from, which is
        // exactly why it needs recording rather than assuming.
        assert!(DFU_FLAG_ADDR >= SRAM_BASE && DFU_FLAG_ADDR < BL_SRAM_BASE);
        // Every `FLASH_FS` region is a whole number of `DBANK == 0` pages, so no
        // erase of one region can reach another even at the wrong geometry.
        const DBANK0_PAGE: u32 = 8 * 1024;
        assert!(FS_IDENTITY_OFFSET % DBANK0_PAGE == 0);
        assert!(FS_IDENTITY_LEN % DBANK0_PAGE == 0);
        assert!(FS_NONCE_LEN % DBANK0_PAGE == 0);
        assert!(FS_SHARE_LEN % DBANK0_PAGE == 0);
        assert!(FS_NAME_LEN % DBANK0_PAGE == 0);
        // Stronger than page alignment, and the reason both regions are 16 K:
        // each A/B *copy* must itself be a whole number of `DBANK == 0` pages, or
        // erasing one copy reaches the other and the redundancy is fiction.
        assert!(FS_SHARE_LEN % (2 * DBANK0_PAGE) == 0);
        assert!(FS_NAME_LEN % (2 * DBANK0_PAGE) == 0);
        // No region overlaps its neighbour and everything fits.
        assert!(FS_SHARE_OFFSET == FS_NONCE_OFFSET + FS_NONCE_LEN);
        assert!(FS_NAME_OFFSET == FS_SHARE_OFFSET + FS_SHARE_LEN);
        assert!(FS_FREE_OFFSET <= FLASH_FS_LEN);
    };
}
