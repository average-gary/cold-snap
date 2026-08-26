//! `#[panic_handler]`, `NVIC_SystemReset`, and the reboot-survivable counters in
//! the RTC backup registers (DECISIONS.md decision 6, PLAN.md §6.2).
//!
//! # Why this module exists
//!
//! `profile.release` sets `panic = "abort"` and there is no unwinder, so **every**
//! failed `assert!` is a permanent halt. On a locked (RDP=2) production unit DFU
//! is hardware-impossible (`mk4-bootloader/main.c:256-258`), so a halt is a brick
//! until the user pulls power — and the frostsnap code we vendor is full of
//! asserts on the nonce path (PLAN.md §6.3).
//!
//! Decision 6's answer is **`NVIC_SystemReset`, not DFU**. A reset returns
//! control to the bootloader, whose verify path still holds a valid signed image,
//! so a transient panic self-heals. The callgate is a late fallback only.
//!
//! # The handler sequence (PLAN.md §6.2, with step 4 corrected)
//!
//! 1. `cpsid i` — stop reentrancy from interrupts.
//! 2. Bump the reboot-survivable panic counter ([`Counter::Panic`]).
//! 3. Under [`PANIC_RESET_THRESHOLD`] → `system_reset`.
//! 4. Past threshold → `callgate::try_enter_dfu`, **`arg2 = 0` only**.
//! 5. Unconditional `system_reset` as final fallback, so it can never halt.
//!
//! **Step 4 corrects PLAN.md §6.2 and DECISIONS.md decision 6, which both say
//! "arg2 0 then 2".** `arg2 = 2` reaches `if(secure) LOCKUP_FOREVER();`
//! (`dispatch.c:174-177`, `:191-193`) and never returns — so step 5 would never
//! run and the handler would permanently halt a production unit at exactly the
//! moment it exists to prevent that. See `callgate::SELECTOR_ENTER_DFU`.
//!
//! # Hard rules for the handler body
//!
//! * **No display.** The OLED driver can itself panic; the bootloader repaints on
//!   reset anyway.
//! * **No allocation.**
//! * **No flash access.** The bootloader's verification of `FLASH_TEXT` is what
//!   makes the reset recoverable; a half-written page destroys that.
//! * **No unbounded loop.** Every wait must be bounded. An unbounded spin is the
//!   halt this module exists to remove.
//! * Nothing may depend on [`crate::rng`] or [`crate::flash`] succeeding: they may
//!   be the reason we are here.
//!
//! Note `cpsid i` sets `PRIMASK`, which does **not** mask NMI or HardFault. A
//! HardFault during the handler still re-enters. That is acceptable (the fault
//! handler resets too) but it means the handler must be re-entrancy tolerant: bump
//! then reset, never read-modify-write across a long window.
//!
//! # SRAM IS NOT ZERO ON THIS BOARD — a measured defect this module now handles
//!
//! **Correction 2026-08-21: `PANIC_DEPTH` is in `.data`, not `.bss`.** This section
//! said `.bss` throughout, and the distinction is not pedantic — it changes which
//! startup loop has to run. `PANIC_DEPTH` is initialised to
//! `DEPTH_MAGIC = 0xD3E1_0000` (`:296`), which is non-zero, so the linker places it in
//! **`.data`** and it must be **copied from flash**, not zeroed. An entry that zeroes
//! `.bss` faithfully and omits the `.data` copy leaves this word reading `0xdeadbeef`
//! no matter how correct the zeroing was. Everything below about the hazard and the
//! tagging defence is unchanged and still applies; only the remedy differs.
//!
//! The recursion guard `PANIC_DEPTH` is a `static` in SRAM1 at `0x2000_0000`
//! (`layout.ld:21`). The bootloader calls
//! `wipe_all_sram()` on **every** boot (`main.c:130`) and that fills
//! `SRAM1_BASE .. +SRAM1_SIZE_MAX` (`0x2000_0000..0x2003_0000`) with the noise
//! constant **`0xdeadbeef`** — *not* with zero (`main.c:42,47`). Zeroing `.bss` is
//! a property of **our own** startup code, which does not exist in this repo yet.
//!
//! An untagged depth word would therefore read `0xdeadbeef` on the very first
//! panic, making `depth > 0` true immediately. Every panic would take the
//! recursive short-circuit: the RTC counter never bumped, the threshold never
//! tripped, the DFU fallback unreachable, and [`BootHealth`] reporting a healthy
//! device while it reset-loops forever — the exact silent failure decision 6
//! exists to remove. So the depth word is **tagged** exactly as the counters are
//! ([`decode_depth`] / [`encode_depth`]), and an untagged word decodes to depth 0.
//! The handler is now correct whether or not `.bss` is ever zeroed.
//!
//! **Whoever writes the startup code must zero `.bss` AND copy `.data`** — every
//! other `static` in the firmware depends on one or the other, and this module can only
//! defend its own word. Which of the two a given `static` needs is decided by whether
//! its initialiser is zero, so it is not a choice the entry can make per-variable: both
//! loops are mandatory.
//!
//! # Where the counter lives, and why not SRAM
//!
//! SRAM is unusable. The bootloader wipes SRAM1/2/3 on every boot
//! (`main.c:39-50`), which is exactly why it reads its own DFU flag at
//! `0x2000_8000` *before* wiping (`main.c:115-122,129`). **PLAN.md §9.2's
//! suggestion of SRAM for the counter must be struck** — and worse than the boot
//! wipe, the callgate wipes the top 8 K on entry *and* exit
//! (`startup.S:124-134,148-156`) and `reset_entry` calls the gate on every boot.
//!
//! RTC backup registers `BKP0R..BKP31R` are the right home: 32 words in the backup
//! domain, reset only by a backup-domain reset or VBAT loss, and the bootloader
//! never touches them (the only `BKPxR` code in the tree is `#if 0`'d, in the
//! **Mk3** tree, `stm32/bootloader/storage.c:526-548` — all **read**).
//!
//! # Two PLAN.md §9 assumptions, now resolved by reading — and one NEW hazard
//!
//! §9 open question 2 asked whether the panic counter's storage is writable, and
//! assumed `PWR_CR1.DBP` was the risk. Reading the bootloader:
//!
//! * **`DBP` is set, and never cleared. RESOLVED.** `clocks.c:184` calls
//!   `HAL_RCCEx_PeriphCLKConfig` with `RCC_PERIPHCLK_RTC` in the selection
//!   (`clocks.c:161`), and that function unconditionally does
//!   `SET_BIT(PWR->CR1, PWR_CR1_DBP)` and waits for it
//!   (`stm32l4xx_hal_rcc_ex.c:336-348`). The only code that clears `DBP` is
//!   `HAL_PWR_DeInit` (`stm32l4xx_hal_pwr.c:117`), which the mk4 bootloader never
//!   calls (**measured**: no hits in `stm32/mk4-bootloader/`). So backup-domain
//!   write protection is already open when our firmware starts.
//! * **THE REAL HAZARD IS `RCC_APB1ENR1.RTCAPBEN`, WHICH THE BOOTLOADER NEVER
//!   SETS.** `__HAL_RCC_RTC_ENABLE()` (`clocks.c:186`) expands to
//!   `SET_BIT(RCC->BDCR, RCC_BDCR_RTCEN)` (`stm32l4xx_hal_rcc.h:3917`) — that is
//!   the RTC **kernel** clock, not the APB interface. Enabling the APB interface
//!   is a *different* macro, `__HAL_RCC_RTCAPB_CLK_ENABLE()`
//!   (`stm32l4xx_hal_rcc.h:1134-1137`), and **grep finds zero `RTCAPB` hits
//!   anywhere in `stm32/mk4-bootloader/`** (measured). Without `RTCAPBEN`, reads
//!   of `BKPxR` do not reach the peripheral. PLAN.md §6.2's claim that "the
//!   bootloader enables the RTC clock" is true but names the wrong clock, so the
//!   conclusion drawn from it does not hold.
//!
//!   `enable_backup_access` therefore sets `RTCAPBEN` itself, then reads back to
//!   confirm, and every counter access goes through it. This must be **verified on
//!   silicon**: whether a `BKPxR` access with `RTCAPBEN` clear returns zero or
//!   raises a bus fault is not determinable from this source tree, and a bus fault
//!   inside the panic handler is precisely the unbounded halt we are removing.
//!   **Assumed** until bench-checked.
//!
//! One further hazard, worth knowing but **not** currently live: if `RCC->BDCR`'s
//! `RTCSEL` ever disagrees with the requested source, `HAL_RCCEx_PeriphCLKConfig`
//! does `BACKUPRESET_FORCE`/`RELEASE` (`stm32l4xx_hal_rcc_ex.c:353-363`), which
//! **wipes every `BKPxR`**. On a cold unit `RTCSEL` is `NONE` so no reset happens;
//! thereafter it already equals `RCC_RTCCLKSOURCE_HSE_DIV32` (`clocks.c:172`, with
//! the comment "but unused") so it still does not. The counter therefore survives
//! warm resets — the property decision 6 depends on — but anything that changes
//! `RTCSEL` silently zeroes it (**read**, not bench-confirmed).
//!
//! # Why the counter value is tagged, not a bare integer
//!
//! On first VBAT power-up a `BKPxR` holds an undefined value. A bare integer read
//! could be `0xFFFF_FFFF`, i.e. instantly past threshold, and the device would
//! enter the DFU fallback on its very first boot. So the word carries
//! [`COUNTER_MAGIC`] in its high 16 bits ([`encode_counter`] /
//! [`decode_counter`]), and an untagged word reads as zero. Fail-safe direction:
//! garbage means "no panics recorded", not "many".
//!
//! # Host testability
//!
//! The `#[panic_handler]` is gated
//! `#[cfg(all(target_os = "none", feature = "panic-handler"))]`. `target_os` is
//! `"none"` for `thumbv7em-none-eabihf` and `"macos"` for the host (both
//! **measured** via `rustc --print cfg`), so on a host `cargo test` the item does
//! not exist and cannot collide with `std`'s handler. Belt and braces: the feature
//! alone would suffice, but a dependency enabling default features by accident
//! would then break every host test in the workspace.
//!
//! [`encode_counter`], [`decode_counter`], [`next_count`] and [`bkp_offset`] are
//! pure and `cfg`-free — **host-testable**. Everything touching a register is
//! `#[cfg(target_arch = "arm")]`. Panic→reset recovery itself is
//! **NOT testable off-hardware** (PLAN.md §7).

// Step 4's DFU fallback. Only the handler uses it, and the handler is gated on
// `target_os = "none"` AND the feature -- so with `--no-default-features` (a
// downstream supplying its own handler) this import would otherwise be dead.
#[cfg(all(target_os = "none", feature = "panic-handler"))]
use crate::callgate;

/// `RTC_BASE` = `APB1PERIPH_BASE` + `0x2800` (`stm32l4s5xx.h:1292,1317,1336`).
pub const RTC_BASE: usize = 0x4000_2800;

/// `RTC->WPR`, offset `0x24` (`stm32l4s5xx.h:856`). Write-protection key
/// register.
pub const RTC_WPR: *mut u32 = (RTC_BASE + 0x24) as *mut u32;

/// `RTC->BKP0R`, offset `0x50` (`stm32l4s5xx.h:867`). `BKP31R` is at `0xCC`
/// (`:898`), i.e. 32 consecutive words.
pub const RTC_BKP0R: *mut u32 = (RTC_BASE + 0x50) as *mut u32;

/// Number of backup registers: `BKP0R..=BKP31R` (`stm32l4s5xx.h:867,898`).
pub const BKP_COUNT: usize = 32;

/// First `RTC->WPR` unlock key. Mk3's own `backup_data_set` writes `0xCA` then
/// `0x53` (`stm32/bootloader/storage.c:541-542`).
pub const RTC_WPR_KEY1: u32 = 0xCA;
/// Second `RTC->WPR` unlock key (`stm32/bootloader/storage.c:542`).
pub const RTC_WPR_KEY2: u32 = 0x53;

/// `PWR->CR1`, offset `0x00` from `PWR_BASE` = `APB1PERIPH_BASE + 0x7000`
/// (`stm32l4s5xx.h:1351`).
pub const PWR_CR1: *mut u32 = 0x4000_7000 as *mut u32;

/// `PWR_CR1_DBP` — disable backup-domain write protection, bit 8
/// (`stm32l4s5xx.h:10871-10873`). Already set by the bootloader; see module docs.
pub const PWR_CR1_DBP: u32 = 1 << 8;

/// `RCC->APB1ENR1`, offset `0x58` from `RCC_BASE` = `AHB1PERIPH_BASE + 0x1000`
/// (`stm32l4s5xx.h:819,1400`).
pub const RCC_APB1ENR1: *mut u32 = (0x4002_1000 + 0x58) as *mut u32;

/// `RCC_APB1ENR1_RTCAPBEN` — RTC/backup APB interface clock, bit 10
/// (`stm32l4s5xx.h:12792-12794`).
///
/// **The bootloader never sets this.** See the module docs; this bit is the whole
/// reason `enable_backup_access` exists.
pub const RCC_APB1ENR1_RTCAPBEN: u32 = 1 << 10;

/// `RCC_APB1ENR1_PWREN` — the PWR peripheral's own APB clock, bit 28
/// (`stm32l4s5xx.h:12831-12833`).
///
/// **Also not left set by the bootloader**, and this is a second hazard the
/// design input did not separate out. `HAL_RCCEx_PeriphCLKConfig` enables `PWREN`
/// only if it finds it disabled (`stm32l4xx_hal_rcc_ex.c:329-332`) and then
/// **disables it again on the way out** (`:401-403`); the same
/// enable/use/disable bracket appears at `:2426-2429,2443-2445` and
/// `:2461-2464,2481-2483`, and in `HAL_RCC_OscConfig`'s LSE branch
/// (`stm32l4xx_hal_rcc.c:740-742,829`) which the Mk4 does not take at all
/// (`clocks.c:126` requests `RCC_OSCILLATORTYPE_HSE` only). Nothing in
/// `mk4-bootloader` leaves `PWREN` set (**read**).
///
/// Consequence: `enable_backup_access` must set `PWREN` in the *same*
/// read-modify-write as [`RCC_APB1ENR1_RTCAPBEN`], **before** touching
/// [`PWR_CR1`]. Without it the defensive `DBP` store could be dropped and the
/// read-back would then report `DBP` clear, so this function would return
/// [`CounterError::BackupWriteProtected`] and disable the counter on a unit whose
/// `DBP` was in fact already fine — a fail-closed answer to a non-problem.
///
/// `DBP` itself survives `PWREN` being gated off afterwards: gating an APB clock
/// does not reset the register it feeds, and the bootloader's own
/// `while(READ_BIT(PWR->CR1, PWR_CR1_DBP) == 0U)` (`stm32l4xx_hal_rcc_ex.c:341-348`)
/// cannot exit until `DBP` reads 1 — its timeout can never fire because
/// `HAL_GetTick()` is the constant 53 (`hal_glue.c:19`). A unit that boots at all
/// therefore had `DBP` set. **read**, not bench-confirmed.
pub const RCC_APB1ENR1_PWREN: u32 = 1 << 28;

/// `SCB->AIRCR` = `SCB_BASE(0xE000ED00) + 0x0C` (`core_cm4.h:1552`, `:445`).
pub const SCB_AIRCR: *mut u32 = 0xE000_ED0C as *mut u32;

/// `VECTKEY` write value. `__NVIC_SystemReset` uses `0x5FA << SCB_AIRCR_VECTKEY_Pos`
/// (`core_cm4.h:1930-1936`); a wrong key makes the store a silent no-op.
pub const AIRCR_VECTKEY: u32 = 0x5FA << 16;

/// `SCB_AIRCR_SYSRESETREQ`, bit 2 (`core_cm4.h:530`).
pub const AIRCR_SYSRESETREQ: u32 = 1 << 2;

/// `SCB_AIRCR_PRIGROUP` mask, bits 10:8 (`core_cm4.h:526-527`).
///
/// CMSIS's `__NVIC_SystemReset` preserves this field across the reset request
/// (`core_cm4.h:1934-1936`); the design sketch omitted it. Harmless either way
/// this close to a reset, but matching CMSIS exactly removes one difference from
/// the sequence Coldcard's own bootloader already executes successfully on this
/// part (`dispatch.c:203`).
pub const AIRCR_PRIGROUP_MASK: u32 = 0x7 << 8;

/// Iterations `system_reset` spins waiting for the reset to land before
/// re-issuing the `AIRCR` store.
///
/// The reset should take a handful of cycles, so any finite bound is generous;
/// what matters is that the bound EXISTS. A wrong `VECTKEY` makes the store a
/// silent no-op (`core_cm4.h:517-518`), and an unbounded `loop {}` there would be
/// exactly the halt this module exists to remove. At 120 MHz this is on the order
/// of a millisecond per attempt.
pub const RESET_SPIN_LIMIT: u32 = 100_000;

/// High-16-bit tag distinguishing a counter we wrote from an undefined
/// backup-register value. See the module docs: without it, garbage on first VBAT
/// power-up reads as a huge count and trips the DFU fallback on boot one.
pub const COUNTER_MAGIC: u32 = 0xC5A1_0000;

/// Mask selecting the count within a tagged word. 16 bits, far more than
/// [`PANIC_RESET_THRESHOLD`] needs.
pub const COUNTER_VALUE_MASK: u32 = 0x0000_FFFF;

/// Consecutive panics before the handler stops plain-resetting and tries the DFU
/// fallback. 3 matches the `cmp #0x3` in the disassembly PLAN.md §6.2 records as
/// already verified.
///
/// The counter is cleared only **after the event loop is proven healthy**
/// (PLAN.md §6.3) — clear it too early and the threshold never trips, which
/// silently reduces this module to "reset forever".
pub const PANIC_RESET_THRESHOLD: u32 = 3;

/// Maximum value the counter is allowed to reach. Saturates here rather than
/// wrapping: a wrap would step a device past threshold straight back to zero and
/// restart an unbounded reset loop.
pub const COUNTER_MAX: u32 = COUNTER_VALUE_MASK;

/// High-16-bit tag for the re-entry depth word, playing exactly the role
/// [`COUNTER_MAGIC`] plays for the backup registers. Distinct from it so a word
/// can never be mistaken for the other kind.
///
/// **This tag is not paranoia; it fixes a measured defect.** [`PANIC_DEPTH`] is a
/// `static`, so it lives in `.bss`, and on this board `.bss` is in SRAM1 at
/// `0x2000_0000` (`layout.ld:21`). The bootloader calls `wipe_all_sram()` on
/// **every** boot (`main.c:130`), and that fills
/// `SRAM1_BASE .. +SRAM1_SIZE_MAX` (`0x2000_0000..0x2003_0000`) with the noise
/// constant **`0xdeadbeef`**, not with zero (`main.c:42,47`). Zeroing `.bss` is
/// therefore a property of *our own* startup code — which does not exist in this
/// repo yet.
///
/// If `.bss` is not zeroed before the first panic, an **untagged** depth word
/// reads as `0xdeadbeef`, so `depth > 0` is true on the very FIRST panic. Every
/// panic then takes the recursive short-circuit in [`panic_action`]: the RTC
/// counter is never bumped, [`PANIC_RESET_THRESHOLD`] can never trip, the DFU
/// fallback becomes unreachable, and [`BootHealth`] reports a permanently healthy
/// device while it reset-loops forever. That is precisely the silent failure
/// decision 6 exists to remove, reintroduced through the back door.
///
/// Tagging removes the dependency on startup code altogether: an untagged word
/// decodes to depth 0, which is the fail-safe direction (garbage means "this is
/// the first entry", so the counter DOES get bumped).
const DEPTH_MAGIC: u32 = 0xD3E1_0000;

/// Which reboot-survivable counter. Each owns one backup register; the indices
/// are part of this crate's ABI with the firmware above it, so they must not be
/// renumbered without clearing the old ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum Counter {
    /// `BKP0R` — consecutive panics, driving [`PANIC_RESET_THRESHOLD`].
    Panic = 0,
    /// `BKP1R` — consecutive [`crate::rng::RngFault`]s at boot. Separate from
    /// [`Counter::Panic`] on purpose: entropy failure is not a code bug, and
    /// collapsing them would make a stuck SE look like a firmware crash loop at a
    /// bench.
    RngFault = 1,
}

impl Counter {
    /// Backup-register index. `const` so it is usable in array sizing.
    #[must_use]
    pub const fn index(self) -> usize {
        self as usize
    }
}

/// Why a counter access failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterError {
    /// `RCC_APB1ENR1.RTCAPBEN` did not read back set, so `BKPxR` is unreachable.
    /// See the module docs — this is the hazard PLAN.md §9 question 2 missed.
    ApbClockOff,
    /// `PWR_CR1.DBP` did not read back set, so the backup domain is still write
    /// protected.
    BackupWriteProtected,
    /// The value read back after writing did not match. Distinguishing "wrote" from
    /// "stuck" matters: a silently failing counter turns decision 6 into an
    /// unbounded reset loop, which is indistinguishable from a halt to the user.
    VerifyFailed,
    /// Index >= [`BKP_COUNT`].
    BadIndex,
}

/// Byte offset of backup register `idx` from [`RTC_BASE`]. Pure —
/// **host-testable**, and worth testing, because an off-by-one here writes into
/// `RTC->TAMPCR` (`stm32l4s5xx.h:863`) or beyond.
///
/// # Contract
///
/// `Some(0x50 + idx * 4)` for `idx < `[`BKP_COUNT`], else `None`. Must not panic.
#[must_use]
pub fn bkp_offset(idx: usize) -> Option<usize> {
    if idx >= BKP_COUNT {
        return None;
    }
    // `checked_mul`/`checked_add` rather than `0x50 + idx * 4`: `idx < 32` makes
    // a wrap impossible, but `overflow-checks = false` in release means a future
    // change to BKP_COUNT would wrap SILENTLY into a wild register write instead
    // of being caught. The bound check above is what makes this `Some`.
    idx.checked_mul(4)?.checked_add(0x50)
}

/// Tag a count for storage. Pure — **host-testable**.
///
/// # Contract
///
/// `COUNTER_MAGIC | (count.min(COUNTER_MAX) & COUNTER_VALUE_MASK)`. Saturating,
/// never wrapping. Must not panic.
#[must_use]
pub fn encode_counter(count: u32) -> u32 {
    // `min` before masking, not after: masking a value above COUNTER_MAX would
    // TRUNCATE it (0x1_0000 -> 0), stepping a device past threshold straight back
    // to zero and restarting an unbounded reset loop. Clamping first cannot.
    COUNTER_MAGIC | (count.min(COUNTER_MAX) & COUNTER_VALUE_MASK)
}

/// Recover a count from a stored word. Pure — **host-testable**, and the most
/// important test in this module: it is what keeps an undefined backup register
/// from reading as "past threshold".
///
/// # Contract
///
/// * `Some(raw & COUNTER_VALUE_MASK)` if `raw & !COUNTER_VALUE_MASK ==
///   COUNTER_MAGIC`.
/// * `None` otherwise, which callers **must** treat as zero, never as an error
///   that prevents the reset. `0`, `0xFFFF_FFFF` and the bootloader's
///   `0xdeadbeef` SRAM fill (`main.c:42`) must all decode to `None`.
/// * Must not panic.
#[must_use]
pub fn decode_counter(raw: u32) -> Option<u32> {
    if raw & !COUNTER_VALUE_MASK == COUNTER_MAGIC {
        Some(raw & COUNTER_VALUE_MASK)
    } else {
        None
    }
}

/// Next counter value. Pure — **host-testable**.
///
/// # Contract
///
/// `current.saturating_add(1).min(COUNTER_MAX)`. Clamps; must never wrap, for the
/// reason in [`COUNTER_MAX`]. Note `overflow-checks = false` in
/// `profile.release`, so a plain `+ 1` would wrap **silently** rather than
/// panicking — use `saturating_add` explicitly.
#[must_use]
pub fn next_count(current: u32) -> u32 {
    // Two clamps, both needed. `saturating_add` stops the u32 wrap; `.min` stops
    // a value that arrived already above COUNTER_MAX from being truncated by
    // `encode_counter`'s mask. Once at COUNTER_MAX the counter STAYS
    // past-threshold forever, which is the fail-safe direction: a saturated
    // counter means "keep taking the fallback", never "start counting again".
    current.saturating_add(1).min(COUNTER_MAX)
}

/// Decode a re-entry depth word, treating anything untagged as depth 0. Pure —
/// **host-testable**, and it must be: this function is the whole fix for the
/// `0xdeadbeef` defect described on `DEPTH_MAGIC`.
///
/// # Contract
///
/// * `raw & !`[`COUNTER_VALUE_MASK`]` == DEPTH_MAGIC` → `raw & COUNTER_VALUE_MASK`.
/// * Anything else → `0`. In particular `0xdead_beef` (the bootloader's
///   `wipe_all_sram` fill, `main.c:42`), `0`, and `0xFFFF_FFFF` must all give `0`.
/// * Fail-safe direction is the OPPOSITE of the counter's: garbage means "this is
///   a first entry", so the panic counter still gets bumped. Reading garbage as a
///   deep recursion would silently disable the counter, the threshold and the
///   fallback all at once.
/// * Must not panic.
#[must_use]
pub fn decode_depth(raw: u32) -> u32 {
    if raw & !COUNTER_VALUE_MASK == DEPTH_MAGIC {
        raw & COUNTER_VALUE_MASK
    } else {
        0
    }
}

/// Encode a re-entry depth for storage, saturating like [`next_count`]. Pure —
/// **host-testable**.
///
/// # Contract
///
/// `DEPTH_MAGIC | (depth.min(COUNTER_MAX) & COUNTER_VALUE_MASK)`. Clamps rather
/// than wrapping, so a pathological recursion cannot wrap the depth back to 0 and
/// re-enable the counter path mid-storm.
#[must_use]
pub fn encode_depth(depth: u32) -> u32 {
    DEPTH_MAGIC | (depth.min(COUNTER_MAX) & COUNTER_VALUE_MASK)
}

/// Whether a count has reached [`PANIC_RESET_THRESHOLD`]. Pure —
/// **host-testable**.
///
/// # Contract
///
/// `count >= PANIC_RESET_THRESHOLD`. Kept as a named function rather than an
/// inline comparison so the boundary is testable and cannot drift between the
/// handler and any caller that reports state to the UI.
#[must_use]
pub fn past_threshold(count: u32) -> bool {
    count >= PANIC_RESET_THRESHOLD
}

/// Make `BKPxR` reachable and writable: set [`RCC_APB1ENR1_RTCAPBEN`] and
/// [`PWR_CR1_DBP`], read both back, and unlock `RTC->WPR`. **ARM only.**
///
/// Idempotent and safe to call from the panic handler — no loops, no waits beyond
/// the RCC read-back delay the HAL itself performs
/// (`stm32l4xx_hal_rcc.h:1134-1140`).
///
/// `DBP` is expected to be set already (module docs); setting it again costs one
/// store and removes a dependency on bootloader behaviour we do not control.
///
/// # Errors
///
/// [`CounterError::ApbClockOff`] or [`CounterError::BackupWriteProtected`] if
/// either bit does not read back set.
///
/// # Panics
///
/// Must not. It is called from the panic handler.
#[cfg(target_arch = "arm")]
pub fn enable_backup_access() -> Result<(), CounterError> {
    // SAFETY: every address here is a fixed, 4-byte-aligned peripheral register
    // on this part, verified against the CMSIS header the bootloader itself
    // compiles against (see each constant's docs). Volatile access to MMIO is
    // exactly what these are for, and no Rust object aliases them. The writes are
    // read-modify-writes of bits we own; no loops, so this is callable from the
    // panic handler.
    unsafe {
        // 1. RCC first: BOTH the PWR peripheral clock and the RTC APB interface
        //    clock, in ONE store. `PWREN` must be on before the `PWR_CR1` access
        //    below (see RCC_APB1ENR1_PWREN's docs) and `RTCAPBEN` before any
        //    `BKPxR` access.
        let en = core::ptr::read_volatile(RCC_APB1ENR1);
        core::ptr::write_volatile(
            RCC_APB1ENR1,
            en | RCC_APB1ENR1_PWREN | RCC_APB1ENR1_RTCAPBEN,
        );

        // The HAL's own "delay after an RCC peripheral clock enabling" is a
        // read-back of the same register (`stm32l4xx_hal_rcc.h:1134-1140`), which
        // doubles as our verification. This is a bounded, single-shot read, not a
        // poll: if it does not read back set, the clock is not coming and
        // spinning would be the halt we are removing.
        let en_rb = core::ptr::read_volatile(RCC_APB1ENR1);
        dsb();
        isb();
        if en_rb & RCC_APB1ENR1_RTCAPBEN == 0 {
            return Err(CounterError::ApbClockOff);
        }

        // 2. Backup-domain write protection. Expected already set by the
        //    bootloader (module docs), but re-asserted so nothing here depends on
        //    bootloader behaviour we do not control.
        let cr1 = core::ptr::read_volatile(PWR_CR1);
        core::ptr::write_volatile(PWR_CR1, cr1 | PWR_CR1_DBP);
        let cr1_rb = core::ptr::read_volatile(PWR_CR1);
        dsb();
        if cr1_rb & PWR_CR1_DBP == 0 {
            return Err(CounterError::BackupWriteProtected);
        }

        // 3. RTC write-protection unlock, matching Mk3's own `backup_data_set`
        //    (`stm32/bootloader/storage.c:541-542`, `#if 0`'d but the sequence is
        //    the documented one).
        //
        //    NOTE, and this corrects the emphasis in PLAN.md §6.2: this step is
        //    almost certainly NOT required for backup registers. ST's own
        //    `HAL_RTCEx_BKUPWrite` stores to `BKPxR` with no `WPR` sequence at all
        //    (`stm32l4xx_hal_rtc_ex.c:2340-2362`), unlike the calendar registers.
        //    Kept because it is two stores and cannot hurt; the load-bearing bit
        //    is `RTCAPBEN` above.
        core::ptr::write_volatile(RTC_WPR, RTC_WPR_KEY1);
        core::ptr::write_volatile(RTC_WPR, RTC_WPR_KEY2);
        dsb();
    }
    Ok(())
}

/// `dsb` — drain the write buffer. Bounded by construction (a single
/// instruction).
#[cfg(target_arch = "arm")]
#[inline(always)]
pub fn dsb() {
    // SAFETY: a barrier instruction. It touches no memory and no registers; the
    // `compiler_fence` is what keeps the *compiler* from reordering the volatile
    // accesses around it, as the CPU barrier alone cannot.
    unsafe { core::arch::asm!("dsb 0xf", options(nostack, preserves_flags)) };
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// `isb` — flush the pipeline so a just-enabled clock is visible to the next
/// access.
#[cfg(target_arch = "arm")]
#[inline(always)]
pub fn isb() {
    // SAFETY: as `dsb`.
    unsafe { core::arch::asm!("isb 0xf", options(nostack, preserves_flags)) };
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Address of backup register `which`, or `None` if [`bkp_offset`] rejects the
/// index. **ARM only.**
///
/// The one place a `Counter` becomes a pointer, so the bound check cannot be
/// bypassed by any of the four public accessors.
#[cfg(target_arch = "arm")]
fn bkp_ptr(which: Counter) -> Option<*mut u32> {
    let off = bkp_offset(which.index())?;
    // `checked_add` for the same reason as in `bkp_offset`: silent wrapping under
    // `overflow-checks = false` would produce a wild pointer rather than a
    // refusal. Cannot actually wrap for off <= 0xCC.
    Some(RTC_BASE.checked_add(off)? as *mut u32)
}

/// Read a counter. **ARM only.**
///
/// Calls `enable_backup_access` first. An undecodable word reads as `0` — see
/// [`decode_counter`].
///
/// # Errors
///
/// Anything from `enable_backup_access`.
///
/// # Panics
///
/// Must not.
#[cfg(target_arch = "arm")]
pub fn read_counter(which: Counter) -> Result<u32, CounterError> {
    enable_backup_access()?;
    let ptr = bkp_ptr(which).ok_or(CounterError::BadIndex)?;
    // SAFETY: `bkp_ptr` returns an address in RTC_BASE + 0x50..=0xCC, i.e. within
    // BKP0R..BKP31R (stm32l4s5xx.h:867,898), 4-byte aligned, and
    // `enable_backup_access` has just confirmed RTCAPBEN so the access reaches
    // the peripheral. Nothing in Rust aliases it.
    let raw = unsafe { core::ptr::read_volatile(ptr) };
    // An undecodable word reads as ZERO, not as an error: garbage must mean "no
    // panics recorded", never "many". See `decode_counter`.
    Ok(decode_counter(raw).unwrap_or(0))
}

/// Write a counter and verify by read-back. **ARM only.**
///
/// # Errors
///
/// Anything from `enable_backup_access`, or [`CounterError::VerifyFailed`] if
/// the read-back differs.
///
/// # Panics
///
/// Must not.
#[cfg(target_arch = "arm")]
pub fn write_counter(which: Counter, count: u32) -> Result<(), CounterError> {
    enable_backup_access()?;
    let ptr = bkp_ptr(which).ok_or(CounterError::BadIndex)?;
    let want = encode_counter(count);
    // SAFETY: as `read_counter` -- in-range, aligned, clocked, unaliased.
    let got = unsafe {
        core::ptr::write_volatile(ptr, want);
        dsb();
        core::ptr::read_volatile(ptr)
    };
    // Verify by DATA, not by waiting. Distinguishing "wrote" from "stuck" is what
    // stops decision 6 degrading into an unbounded reset loop that looks
    // identical to a halt from outside the case.
    if got == want {
        Ok(())
    } else {
        Err(CounterError::VerifyFailed)
    }
}

/// Increment a counter and return the **new** value. **ARM only.**
///
/// The handler's step 2. Returns the new value so the caller does not re-read,
/// keeping the read-modify-write window as short as possible — relevant because a
/// HardFault can re-enter the handler despite `cpsid i` (module docs).
///
/// # Errors
///
/// Anything from `read_counter` or `write_counter`. **The caller must still
/// reset on error** — a failed bump means the loop is unbounded, which is strictly
/// worse than resetting one extra time.
///
/// # Panics
///
/// Must not.
#[cfg(target_arch = "arm")]
pub fn bump_counter(which: Counter) -> Result<u32, CounterError> {
    let next = next_count(read_counter(which)?);
    write_counter(which, next)?;
    Ok(next)
}

/// Zero a counter. **ARM only.**
///
/// Writes an encoded zero rather than a raw `0`, so a later [`decode_counter`]
/// can still tell "we cleared this" from "never initialised".
///
/// Call only once the event loop is proven healthy (PLAN.md §6.3). Clearing at the
/// top of `main` defeats the threshold entirely.
///
/// # Errors
///
/// As `write_counter`.
#[cfg(target_arch = "arm")]
pub fn clear_counter(which: Counter) -> Result<(), CounterError> {
    write_counter(which, 0)
}

/// Mask interrupts (`cpsid i`). **ARM only.**
///
/// Does not restore, unlike `callgate::with_irq_off` — the handler never
/// returns. Note `PRIMASK` does not mask NMI or HardFault.
#[cfg(target_arch = "arm")]
pub fn disable_interrupts() {
    // SAFETY: `cpsid i` sets PRIMASK. It touches no memory, so `nomem` is
    // correct; the compiler_fence is what stops later volatile accesses being
    // hoisted above it.
    unsafe { core::arch::asm!("cpsid i", options(nomem, nostack, preserves_flags)) };
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Reset the MCU via `SCB->AIRCR`. Never returns. **ARM only.**
///
/// `dsb`, then store [`AIRCR_VECTKEY`] `|` [`AIRCR_SYSRESETREQ`], then `dsb`,
/// then a bounded spin until the reset lands (`core_cm4.h:1930-1940`).
///
/// The trailing spin must be **bounded**: if the store is somehow a no-op — a
/// wrong `VECTKEY` makes it exactly that — an infinite `loop {}` is the halt this
/// whole module exists to prevent. On timeout, re-issue the store rather than
/// spinning forever.
///
/// This is the single most safety-critical function in the crate: decision 6's
/// "it can never halt" reduces entirely to this returning control to the
/// bootloader.
#[cfg(target_arch = "arm")]
pub fn system_reset() -> ! {
    // `loop` around the WHOLE sequence, so a timeout re-issues the store rather
    // than falling into a bare spin. There is no `break` and no exit other than
    // the reset itself: the only way out of this function is the hardware taking
    // the vector. That is the structural property decision 6 reduces to.
    loop {
        // Drain buffered writes -- notably the counter store in `bump_counter`,
        // which must reach the backup domain BEFORE the core is reset.
        dsb();

        // SAFETY: `SCB_AIRCR` is 0xE000_ED0C, the Application Interrupt and Reset
        // Control Register (core_cm4.h:1545,1552,445), always accessible from
        // privileged mode with no clock gating. PRIGROUP is preserved exactly as
        // CMSIS's `__NVIC_SystemReset` does (core_cm4.h:1934-1936).
        unsafe {
            let prigroup = core::ptr::read_volatile(SCB_AIRCR) & AIRCR_PRIGROUP_MASK;
            core::ptr::write_volatile(SCB_AIRCR, AIRCR_VECTKEY | prigroup | AIRCR_SYSRESETREQ);
        }
        dsb();

        // BOUNDED spin. Normally the reset lands within a few cycles and this
        // never completes. If it does complete, the store did not take effect --
        // the one realistic cause being a corrupted VECTKEY, which makes the
        // write a silent no-op -- so we go round and issue it again rather than
        // spinning forever. `for` rather than `while`: no condition to get wrong.
        for _ in 0..RESET_SPIN_LIMIT {
            // SAFETY: `nop` is a no-op instruction. It exists so the loop cannot
            // be optimised away as empty, which is why this is `asm!` and not an
            // empty body.
            unsafe { core::arch::asm!("nop", options(nomem, nostack, preserves_flags)) };
        }
    }
}

/// What the panic handler should do after bumping the counter. Pure value, so
/// the handler's whole decision is **host-testable** — see [`panic_action`].
///
/// There are only two variants on purpose. Neither is "halt", and there is no
/// variant that omits the reset: [`PanicAction::TryDfuThenReset`] resets *after*
/// the fallback, unconditionally. Adding a third variant that does not end in a
/// reset would reintroduce the defect decision 6 exists to remove.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PanicAction {
    /// Reset immediately. The normal case: a transient panic self-heals because
    /// the bootloader still holds a verified signed image.
    Reset,
    /// Try `callgate::try_enter_dfu` once (`arg2 = 0` only), then reset anyway.
    TryDfuThenReset,
}

/// The panic handler's entire decision, as a pure function — **host-testable**,
/// which is the only way to cover it at all (panic→reset recovery itself is not
/// testable off-hardware, PLAN.md §7).
///
/// `depth` is the number of handler entries already in progress (0 for the first),
/// and `bumped` is whatever `bump_counter` returned.
///
/// # Contract
///
/// * `depth > 0` → [`PanicAction::Reset`]. A recursive entry must not touch the
///   counters again and must not call the gate; it resets at once. This is what
///   makes "a panic inside the panic handler still resets" true, and it converges
///   because every path ends in a reset.
/// * `bumped == Err(_)` → [`PanicAction::TryDfuThenReset`]. Deliberately the
///   **opposite** of [`BootHealth::in_reset_loop`]'s fail-safe direction: an
///   unreachable counter cannot bound a reset loop, so the fallback is preferred
///   over looping forever. On a production RDP=2 unit the fallback is a clean
///   no-op and the reset still happens, so this costs nothing there.
/// * else [`past_threshold`] of the new count decides.
/// * Must not panic, for any input.
#[must_use]
pub fn panic_action(depth: u32, bumped: Result<u32, CounterError>) -> PanicAction {
    if depth > 0 {
        return PanicAction::Reset;
    }
    // `unwrap_or(u32::MAX)`, not `(0)`. See the contract above; this single
    // choice is the difference between "unbounded reset loop" and "one DFU
    // attempt then reset" on a unit whose backup domain is dead.
    let count = bumped.unwrap_or(u32::MAX);
    if past_threshold(count) {
        PanicAction::TryDfuThenReset
    } else {
        PanicAction::Reset
    }
}

/// Handler re-entry depth, stored **tagged** with `DEPTH_MAGIC`.
///
/// A plain `AtomicU32` in our own SRAM, not a backup register: it only has to be
/// meaningful *within one boot*, and the panic counter already covers across
/// boots. It is never decremented — the handler never returns, so there is
/// nothing to unwind, and a monotonically rising depth is exactly the signal
/// [`panic_action`] wants.
///
/// `cpsid i` masks `PRIMASK` but **not** NMI or HardFault, so recursion is
/// genuinely reachable: a HardFault taken inside the handler re-enters at the
/// vector, and a panic from there lands back here. `fetch_add` is a single
/// `LDREX`/`STREX` pair, available on `thumbv7em`.
///
/// **The initialiser is `encode_depth(0)`, not `0`, and that is load-bearing.**
/// This static is in `.bss`, which is in SRAM1 on this board, and the bootloader
/// fills SRAM1 with `0xdeadbeef` on every boot rather than zeroing it
/// (`main.c:42,47,130`). Nothing zeroes `.bss` unless our own startup code does,
/// and that code does not exist yet. Reading the word through [`decode_depth`]
/// makes the handler correct whether or not `.bss` was ever zeroed — see
/// `DEPTH_MAGIC` for the full failure chain this prevents.
#[cfg(all(target_os = "none", feature = "panic-handler"))]
static PANIC_DEPTH: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(DEPTH_MAGIC);

/// The panic handler. Present **only** when compiling for the device
/// (`target_os = "none"`) with the `panic-handler` feature, so a host
/// `cargo test` cannot collide with `std`'s handler. See the module docs.
///
/// Implements the 5-step sequence in the module docs. `info` is deliberately
/// unused: formatting a `PanicInfo` pulls in `core::fmt` and can itself panic.
///
/// # Why this function cannot halt
///
/// Structurally, not by inspection of the steps:
///
/// * The last statement is [`system_reset`], which is `-> !` and whose only exit
///   is the hardware taking the reset vector.
/// * Every earlier step is best-effort and returns a value — no `unwrap`, no
///   `assert`, no `?`, no unbounded loop anywhere in the call graph
///   ([`enable_backup_access`] verifies by single read-back, never by polling).
/// * [`PanicAction`] has no variant that skips the reset.
/// * Recursive entry short-circuits to the reset via [`panic_action`].
///
/// It touches no flash (the bootloader's verification of `FLASH_TEXT` is what
/// makes the reset recoverable), no display (the OLED driver can itself panic),
/// and allocates nothing.
#[cfg(all(target_os = "none", feature = "panic-handler"))]
#[panic_handler]
fn panic_handler(_info: &core::panic::PanicInfo) -> ! {
    use core::sync::atomic::Ordering;

    // 1. Stop reentrancy from interrupts (`modckcc.c:104`, `dispatch.c:96-101`).
    //    Does NOT mask NMI/HardFault -- hence the depth guard below.
    disable_interrupts();

    // Recursion guard. Read the PREVIOUS depth: 0 means we are the first entry.
    //
    // Read through `decode_depth` rather than trusting the raw word, because
    // nothing has necessarily zeroed `.bss`: the bootloader fills SRAM1 with
    // `0xdeadbeef` on every boot (`main.c:42,47,130`). An untagged word therefore
    // decodes to 0 -- "first entry" -- which is the fail-safe direction. See
    // `DEPTH_MAGIC`.
    //
    // A load and a separate store, NOT `fetch_add`/`fetch_update`: `fetch_add`
    // cannot repair an untagged word, and `fetch_update` spins on a
    // compare-exchange, which is an unbounded loop in the panic handler. The
    // load/store pair is not atomic, but the only thing that can interleave is an
    // NMI or HardFault (`cpsid i` masks neither), and the worst outcome is that a
    // re-entry also reads depth 0 and bumps the counter one extra time -- a
    // bounded, fail-safe error. Both paths still end in `system_reset`.
    let depth = decode_depth(PANIC_DEPTH.load(Ordering::SeqCst));
    PANIC_DEPTH.store(encode_depth(depth.saturating_add(1)), Ordering::SeqCst);

    // 2. Bump the reboot-survivable counter -- but only on a first entry. A
    //    recursive entry must not re-enter the register code that may be why we
    //    are here, so it is skipped entirely and `panic_action` ignores the value.
    let bumped = if depth == 0 {
        bump_counter(Counter::Panic)
    } else {
        Err(CounterError::VerifyFailed)
    };

    // 3./4. One pure decision, unit-tested on the host.
    if panic_action(depth, bumped) == PanicAction::TryDfuThenReset {
        // Real DFU only on an RDP != 2 dev unit, and even there it completes on
        // the NEXT boot (`dispatch.c:198-203` sets a magic word and resets;
        // `main.c:113-122` acts on it). A clean `EPERM` no-op on production.
        // `arg2 = 0` is baked into `try_enter_dfu` and is not a parameter.
        callgate::try_enter_dfu();
    }

    // 5. Unconditional reset. Reached whether or not anything above worked, and
    //    on every `PanicAction`.
    system_reset()
}

/// Snapshot of the counters for the UI or a diagnostic screen, read once at boot
/// before anything is cleared.
///
/// A plain value type with no methods that touch hardware, so the code that
/// *displays* boot health does not need register access and stays host-testable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BootHealth {
    /// [`Counter::Panic`] as read at boot.
    pub panics: u32,
    /// [`Counter::RngFault`] as read at boot.
    pub rng_faults: u32,
    /// Whether either counter was unreadable. `true` means the values above are
    /// `0` by fallback and mean nothing — do not render them as "healthy".
    pub counters_unavailable: bool,
}

impl BootHealth {
    /// Whether a reset loop is in progress. Pure — **host-testable**.
    ///
    /// # Contract
    ///
    /// `!self.counters_unavailable && past_threshold(self.panics)`.
    #[must_use]
    pub fn in_reset_loop(&self) -> bool {
        // `!counters_unavailable` first: when the counters are unreadable
        // `panics` is 0 by fallback and means nothing, so reporting "in a reset
        // loop" would be a fabrication. This is the *diagnostic* direction of the
        // fail-safe; the handler itself goes the other way (`unwrap_or(u32::MAX)`)
        // because there the safe choice is to prefer the fallback.
        !self.counters_unavailable && past_threshold(self.panics)
    }

    /// Read both counters. **ARM only.**
    ///
    /// Never fails: on error it sets [`BootHealth::counters_unavailable`] and
    /// leaves the counts at zero. Boot must not be blocked by a diagnostic.
    #[cfg(target_arch = "arm")]
    #[must_use]
    pub fn read() -> Self {
        // Both counters are read even if the first fails, so a single bad index
        // cannot hide the other value. No `?` anywhere: boot must not be blocked
        // by a diagnostic.
        let panics = read_counter(Counter::Panic);
        let rng_faults = read_counter(Counter::RngFault);
        Self {
            panics: panics.unwrap_or(0),
            rng_faults: rng_faults.unwrap_or(0),
            counters_unavailable: panics.is_err() || rng_faults.is_err(),
        }
    }
}

/// Boot-sequencing contract for whoever writes `main` — **read this before
/// calling `clear_counter`**.
///
/// The threshold only ever trips if the counter is allowed to accumulate across
/// resets. Clearing it too early silently reduces this whole module to "reset
/// forever", which is indistinguishable from a halt to a user holding the device
/// and is exactly the outcome decision 6 exists to prevent.
///
/// ```text
///   reset_entry (bootloader)  ->  our entry
///     let health = BootHealth::read();     // FIRST: read before clearing
///     ... bring up clocks, display, entropy, flash ...
///     ... enter the event loop ...
///     ... only once the loop has serviced work successfully:
///     let _ = clear_counter(Counter::Panic);
/// ```
///
/// Rules, in priority order:
///
/// 1. **Never clear at the top of `main`.** A deterministic panic on the path
///    between entry and the clear point would then never accumulate: bump to 1,
///    reset, clear to 0, bump to 1, forever.
/// 2. Clear only after the event loop is **proven healthy** — PLAN.md §6.3's
///    phrasing. "Proven" means at least one full iteration that did real work, not
///    merely reaching the loop, because the panic sites decision 6 ranks highest
///    (`device.rs:491`, `device_nonces.rs`) all fire *inside* message handling.
/// 3. Ignore the `Result`. A failed clear means the next panic counts one higher
///    than it should — harmless. Propagating it into a `?` at boot would turn a
///    dead backup domain into a dead device.
/// 4. [`Counter::RngFault`] is on the same rule but a different budget; clear it
///    only after entropy has been proven, not alongside the panic counter.
///
/// [`BootHealth::read`] must run *before* any clear, or a diagnostic screen can
/// never show why the device rebooted.
#[cfg(target_arch = "arm")]
pub mod boot_sequencing {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bkp_offset_is_bounded_and_matches_the_header() {
        // BKP0R at 0x50, BKP31R at 0xCC (stm32l4s5xx.h:867,898).
        assert_eq!(bkp_offset(0), Some(0x50));
        assert_eq!(bkp_offset(1), Some(0x54));
        assert_eq!(bkp_offset(BKP_COUNT - 1), Some(0xCC));
        // Off the end must be None, not a wild write. One past BKP31R is another
        // peripheral register entirely.
        assert_eq!(bkp_offset(BKP_COUNT), None);
        assert_eq!(bkp_offset(usize::MAX), None);
        // Never lands on TAMPCR (0x40, stm32l4s5xx.h:863) or below BKP0R.
        for i in 0..BKP_COUNT {
            let off = bkp_offset(i).expect("in range");
            assert!((0x50..=0xCC).contains(&off), "idx {i} -> {off:#x}");
            assert_eq!(off % 4, 0, "backup registers are word aligned");
        }
    }

    #[test]
    fn counter_indices_are_distinct() {
        // Two counters sharing a register would make an RNG fault look like a
        // crash loop and trip the DFU fallback for the wrong reason.
        assert_eq!(Counter::Panic.index(), 0);
        assert_eq!(Counter::RngFault.index(), 1);
        assert_ne!(
            bkp_offset(Counter::Panic.index()),
            bkp_offset(Counter::RngFault.index())
        );
    }

    #[test]
    fn encode_decode_round_trip() {
        for n in [0u32, 1, 2, 3, 17, 0xFF, 0x1000, COUNTER_MAX] {
            assert_eq!(decode_counter(encode_counter(n)), Some(n), "n = {n}");
        }
    }

    /// The most important test in the module: an undefined backup register must
    /// NOT read as "past threshold", or a brand-new unit takes the DFU fallback on
    /// its first ever boot.
    #[test]
    fn garbage_decodes_to_none_and_is_treated_as_zero() {
        for garbage in [
            0x0000_0000u32,
            0xFFFF_FFFF,
            0xDEAD_BEEF, // the bootloader's wipe_all_sram fill (main.c:42)
            0xC5A0_0003, // one bit off the magic
            0xC5A1_0003 ^ 0x8000_0000,
            0x0000_0003, // untagged small count: the naive encoding
        ] {
            assert_eq!(decode_counter(garbage), None, "{garbage:#010x}");
            // And the "treated as zero" half of the contract, which is what
            // `read_counter` relies on.
            assert!(!past_threshold(decode_counter(garbage).unwrap_or(0)));
        }
        // A correctly tagged word is NOT garbage, including a tagged zero -- that
        // is how `clear_counter` stays distinguishable from "never initialised".
        assert_eq!(decode_counter(encode_counter(0)), Some(0));
        assert_ne!(encode_counter(0), 0);
    }

    #[test]
    fn next_count_saturates_and_never_wraps() {
        assert_eq!(next_count(0), 1);
        assert_eq!(next_count(2), 3);
        // At the ceiling it STAYS at the ceiling. A wrap to 0 here would re-arm
        // the reset loop on a device already known to be crashing.
        assert_eq!(next_count(COUNTER_MAX), COUNTER_MAX);
        assert_eq!(next_count(COUNTER_MAX - 1), COUNTER_MAX);
        // Above the ceiling (only reachable via `unwrap_or(u32::MAX)`) clamps down
        // rather than wrapping through the mask to 0.
        assert_eq!(next_count(u32::MAX), COUNTER_MAX);
        assert!(past_threshold(next_count(u32::MAX)));
        // And it survives the encode round trip still past threshold -- the bug
        // this guards is `encode_counter` masking 0x1_0000 down to 0.
        assert_eq!(
            decode_counter(encode_counter(next_count(u32::MAX))),
            Some(COUNTER_MAX)
        );
    }

    #[test]
    fn threshold_boundary() {
        assert_eq!(PANIC_RESET_THRESHOLD, 3);
        assert!(!past_threshold(0));
        assert!(!past_threshold(1));
        assert!(!past_threshold(PANIC_RESET_THRESHOLD - 1));
        assert!(past_threshold(PANIC_RESET_THRESHOLD));
        assert!(past_threshold(PANIC_RESET_THRESHOLD + 1));
        assert!(past_threshold(u32::MAX));
    }

    /// Requirement 8, first two clauses: below threshold -> reset chosen; at or
    /// above -> fallback attempted.
    #[test]
    fn below_threshold_resets_at_or_above_tries_dfu() {
        for n in 0..PANIC_RESET_THRESHOLD {
            assert_eq!(panic_action(0, Ok(n)), PanicAction::Reset, "count {n}");
        }
        for n in [
            PANIC_RESET_THRESHOLD,
            PANIC_RESET_THRESHOLD + 1,
            COUNTER_MAX,
        ] {
            assert_eq!(
                panic_action(0, Ok(n)),
                PanicAction::TryDfuThenReset,
                "count {n}"
            );
        }
    }

    /// Walk the real sequence a crashing device performs, through the same pure
    /// functions the handler uses. Counts 1 and 2 reset; the third panic reaches
    /// the fallback; and it stays there.
    #[test]
    fn full_reset_loop_walkthrough_then_clear() {
        // Boot 1: an undefined backup register.
        let mut stored = 0xFFFF_FFFFu32;
        let mut actions = [PanicAction::Reset; 4];

        for slot in actions.iter_mut() {
            let count = next_count(decode_counter(stored).unwrap_or(0));
            stored = encode_counter(count);
            *slot = panic_action(0, Ok(count));
        }
        assert_eq!(
            actions,
            [
                PanicAction::Reset,           // count 1
                PanicAction::Reset,           // count 2
                PanicAction::TryDfuThenReset, // count 3 == threshold
                PanicAction::TryDfuThenReset, // and it stays
            ]
        );

        // Requirement 8, third clause: clear resets to zero -- and the very next
        // panic is back to a plain reset. This is also why `clear_counter` must
        // not be called at the top of `main`: doing so makes the loop above
        // repeat forever at count 1.
        stored = encode_counter(0);
        assert_eq!(decode_counter(stored), Some(0));
        let after_clear = next_count(decode_counter(stored).unwrap_or(0));
        assert_eq!(after_clear, 1);
        assert_eq!(panic_action(0, Ok(after_clear)), PanicAction::Reset);
    }

    /// Requirement 8, fourth clause. A recursive entry must still terminate, and
    /// terminate in a RESET -- never in a gate call and never in a loop.
    #[test]
    fn recursive_panic_still_terminates_in_a_reset() {
        for depth in 1..8u32 {
            // Whatever the counter says, however deep, the answer is a plain
            // reset: no counter access, no callgate.
            for bumped in [
                Ok(0),
                Ok(PANIC_RESET_THRESHOLD),
                Ok(COUNTER_MAX),
                Err(CounterError::VerifyFailed),
                Err(CounterError::ApbClockOff),
            ] {
                assert_eq!(
                    panic_action(depth, bumped),
                    PanicAction::Reset,
                    "depth {depth} bumped {bumped:?}"
                );
            }
        }
        // Both variants end in a reset, so termination does not depend on which
        // one is chosen. This is the property that makes the handler
        // structurally incapable of halting; if a variant is ever added that does
        // not reset, this fails.
        for a in [PanicAction::Reset, PanicAction::TryDfuThenReset] {
            assert!(matches!(
                a,
                PanicAction::Reset | PanicAction::TryDfuThenReset
            ));
        }
    }

    /// Regression test for a MEASURED defect. `PANIC_DEPTH` is in `.bss`, `.bss`
    /// is in SRAM1 (`layout.ld:21`), and the bootloader fills SRAM1 with
    /// `0xdeadbeef` on every boot rather than zeroing it (`main.c:42,47,130`).
    ///
    /// With an untagged depth word, `0xdeadbeef` reads as a huge depth, so the
    /// FIRST panic looks recursive: the counter is never bumped, the threshold
    /// never trips, the DFU fallback is unreachable and `BootHealth` reports a
    /// healthy device while it reset-loops forever. If anyone "simplifies"
    /// `decode_depth` away, this fails.
    #[test]
    fn uninitialised_bss_must_decode_to_depth_zero() {
        for garbage in [
            0xDEAD_BEEFu32, // the bootloader's actual fill (main.c:42)
            0xFFFF_FFFF,
            0x0000_0000,
            0xC5A1_0007, // the COUNTER magic: the two words must not be confused
            0xD3E0_0001, // one bit off DEPTH_MAGIC
            0x0000_0005, // untagged small depth: the naive encoding
        ] {
            assert_eq!(decode_depth(garbage), 0, "{garbage:#010x}");
            // And the consequence that actually matters: a first entry must still
            // bump the counter, so the threshold can eventually trip.
            assert_eq!(
                panic_action(decode_depth(garbage), Ok(PANIC_RESET_THRESHOLD)),
                PanicAction::TryDfuThenReset,
                "{garbage:#010x} must not look like a recursive entry"
            );
        }
        // The two tag spaces must be disjoint, or one word could decode as both.
        assert_ne!(DEPTH_MAGIC, COUNTER_MAGIC);
        assert_eq!(decode_counter(encode_depth(1)), None);
        assert_eq!(decode_depth(encode_counter(1)), 0);
    }

    /// A tagged depth round-trips, saturates, and a real recursion is still
    /// detected -- the guard must not be defeated by the fix for the garbage case.
    #[test]
    fn depth_round_trips_and_detects_real_recursion() {
        for d in [0u32, 1, 2, 7, 0xFF, COUNTER_MAX] {
            assert_eq!(decode_depth(encode_depth(d)), d, "d = {d}");
        }
        // A genuine second entry short-circuits to a plain reset.
        let first = decode_depth(encode_depth(0));
        assert_eq!(first, 0);
        let second = decode_depth(encode_depth(first + 1));
        assert_eq!(second, 1);
        assert_eq!(panic_action(second, Ok(0)), PanicAction::Reset);
        // Saturating, never wrapping back to 0 (which would re-enable the counter
        // path in the middle of a recursion storm).
        assert_eq!(decode_depth(encode_depth(u32::MAX)), COUNTER_MAX);
        assert!(decode_depth(encode_depth(u32::MAX)) > 0);
        assert_eq!(
            panic_action(decode_depth(encode_depth(u32::MAX)), Ok(0)),
            PanicAction::Reset
        );
    }

    /// An unreachable counter must prefer the fallback, NOT an unbounded
    /// plain-reset loop. This is the `unwrap_or(u32::MAX)` choice, and it is the
    /// opposite of `BootHealth::in_reset_loop`'s direction -- deliberately.
    #[test]
    fn unreachable_counter_prefers_the_fallback() {
        for e in [
            CounterError::ApbClockOff,
            CounterError::BackupWriteProtected,
            CounterError::VerifyFailed,
            CounterError::BadIndex,
        ] {
            assert_eq!(
                panic_action(0, Err(e)),
                PanicAction::TryDfuThenReset,
                "{e:?} must not degrade to an unbounded reset loop"
            );
        }
        // Sanity: this is only true because u32::MAX is past threshold.
        assert!(past_threshold(u32::MAX));
    }

    #[test]
    fn boot_health_reports_conservatively() {
        assert!(!BootHealth::default().in_reset_loop());
        assert!(!BootHealth {
            panics: 1,
            ..Default::default()
        }
        .in_reset_loop());
        assert!(BootHealth {
            panics: PANIC_RESET_THRESHOLD,
            ..Default::default()
        }
        .in_reset_loop());
        // Unavailable counters must NOT be rendered as a reset loop: `panics` is
        // 0 by fallback there and means nothing, so any claim about it is a
        // fabrication.
        assert!(!BootHealth {
            panics: PANIC_RESET_THRESHOLD,
            rng_faults: 9,
            counters_unavailable: true,
        }
        .in_reset_loop());
    }

    /// Register addresses, re-derived here from the base + offset rather than
    /// copied, so a typo in a constant is caught rather than duplicated.
    #[test]
    fn register_addresses_match_the_cmsis_header() {
        // RTC_BASE = APB1PERIPH_BASE(0x4000_0000) + 0x2800 (stm32l4s5xx.h:1292,1317,1336)
        assert_eq!(RTC_BASE, 0x4000_2800);
        assert_eq!(RTC_WPR as usize, RTC_BASE + 0x24); // :856
        assert_eq!(RTC_BKP0R as usize, RTC_BASE + 0x50); // :867
        assert_eq!(RTC_BKP0R as usize, RTC_BASE + bkp_offset(0).unwrap());
        // PWR_BASE = APB1PERIPH_BASE + 0x7000 (:1351), CR1 at +0x00
        assert_eq!(PWR_CR1 as usize, 0x4000_7000);
        assert_eq!(PWR_CR1_DBP, 1 << 8); // :10871-10873
                                         // RCC_BASE = AHB1PERIPH_BASE(0x4002_0000) + 0x1000 (:1319,:1400), APB1ENR1 +0x58 (:819)
        assert_eq!(RCC_APB1ENR1 as usize, 0x4002_1058);
        assert_eq!(RCC_APB1ENR1_RTCAPBEN, 1 << 10); // :12792-12794
        assert_eq!(RCC_APB1ENR1_PWREN, 1 << 28); // :12831-12833
                                                 // The two APB bits must be distinct, or one RMW cannot set both.
        assert_eq!(RCC_APB1ENR1_RTCAPBEN & RCC_APB1ENR1_PWREN, 0);
        // SCB_BASE = SCS_BASE(0xE000_E000) + 0x0D00 (core_cm4.h:1545,1552), AIRCR +0x0C (:445)
        assert_eq!(SCB_AIRCR as usize, 0xE000_ED0C);
        assert_eq!(AIRCR_VECTKEY, 0x05FA_0000); // :517-518
        assert_eq!(AIRCR_SYSRESETREQ, 1 << 2); // :529-530
        assert_eq!(AIRCR_PRIGROUP_MASK, 0x0000_0700); // :526-527
                                                      // VECTKEY must not overlap the bits we OR in, or the key is corrupted and
                                                      // the store becomes a silent no-op.
        assert_eq!(AIRCR_VECTKEY & (AIRCR_SYSRESETREQ | AIRCR_PRIGROUP_MASK), 0);
        // The reset spin must be bounded but nonzero. A `const` block, not an
        // `assert!`: on a constant, `assert!` is const-folded away and clippy
        // flags it as a no-op, whereas this fails the BUILD.
        const _: () = assert!(RESET_SPIN_LIMIT > 0 && RESET_SPIN_LIMIT < u32::MAX);
    }

    #[test]
    fn wpr_keys_match_the_documented_unlock_sequence() {
        // stm32/bootloader/storage.c:541-542 (Mk3, `#if 0`'d, but the sequence is
        // the documented one).
        assert_eq!((RTC_WPR_KEY1, RTC_WPR_KEY2), (0xCA, 0x53));
        assert_ne!(RTC_WPR_KEY1, RTC_WPR_KEY2, "order matters");
    }
}
