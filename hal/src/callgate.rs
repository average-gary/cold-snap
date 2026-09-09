//! The Coldcard bootloader callgate — our only path to SE1, SE2, the PIN, rate
//! limiting, the brick counter, trick PINs and fast wipe (DECISIONS.md
//! decision 2).
//!
//! **NOT TESTABLE OFF-HARDWARE, AT ANY TIER.** The gate is PCROP-protected code
//! outside any image we can emulate; Renode cannot reach it and neither can host
//! tests (PLAN.md §7, DECISIONS.md decision 5). Only [`validate_buf`],
//! [`parse_rng_response`] and [`Errno`] are host-testable, which is exactly why
//! they are separate `cfg`-free functions.
//!
//! # ABI (read: `stm32/COLDCARD_MK4/modckcc.c:41-47,51-57,72-82`, bootloader side
//! `stm32/mk4-bootloader/startup.S:62-67,113-158`)
//!
//! * Entry is the **first word** of `bootloaderInfoTable_t` at
//!   [`BOOTLOADER_TABLE`]. Read at runtime, **never hardcode the target**.
//! * `r0` = selector, `r1` = buffer or NULL, `r2` = len, `r3` = arg2; return in
//!   `r0`; reached by `BLX`.
//! * `(dest & 0xff) == 0x05` because `callgate_entry0` is `.align 8` inside
//!   `.firewall_code` at +4 with the Thumb bit set. Coldcard `assert()`s this
//!   (`modckcc.c:57`); we **return an error instead**, because a panic here is a
//!   reset loop (decision 6).
//! * Callers must disable interrupts (`modckcc.c:104`; `dispatch.c:98`).
//! * **No caller-side firewall pre-arm is needed** — the gate does its own
//!   `__HAL_FIREWALL_PREARM_DISABLE()` on entry (`dispatch.c:102`) and re-arms at
//!   `fail:` on every exit path (`dispatch.c:697`). This closes part of PLAN.md
//!   §9 open question 3.
//!
//! # The register-clobber trap — do not copy Coldcard's asm
//!
//! `modckcc.c:64-65` says the gate trashes `r0-r4` **and** `r9`/`r10`, but its
//! own clobber list names only `r9`/`r10`. That is safe for Coldcard *only*
//! because the file is compiled `#pragma GCC optimize("O0")`
//! (`modckcc.c:30-32`), and its own comment admits "this doesn't work with
//! compiler optimizations enabled" (`modckcc.c:62`). At our `opt-level = "s"`,
//! the short clobber list was **measured** to leave live values in `r4`/`r5`
//! across the `blx`. Declare the full set:
//!
//! ```text
//! r4, r5, r8, r9, r10, r11, r12, lr   plus s0..s15
//! ```
//!
//! `r6`/`r7` are LLVM-reserved and cannot appear in a clobber list at all;
//! `clobber_abi("C")` *and* `clobber_abi("system")` both warn about reserved FP
//! registers D16-D31 on this hard-float target and must be avoided (all
//! measured — DECISIONS.md decision 2 plus the panic-handler investigation).
//! The `s0..s15` entries are required because the gate is C compiled
//! `-mfpu=fpv4-sp-d16 -mfloat-abi=hard` (`mk4-bootloader/Makefile:66`).
//!
//! # Side effects every caller must accept
//!
//! * **Every** selector runs `ae_reset_chip()` at `fail:` (`dispatch.c:684`),
//!   putting SE1 to sleep and discarding its volatile auth state, and
//!   flushes/resets both flash caches (`dispatch.c:685-696`).
//! * Selector 26 `arg2=1` runs `ae_setup()`, which reprograms **UART4 wholesale**
//!   (CR1, RTOR, CR2, CR3, `BRR=521` @120 MHz) on PA0 (`ae.c:343-396`); `arg2=2`
//!   runs `se2_setup()`, reconfiguring PB13/PB14 and I2C2 (`se2.c:1003-1032`).
//!   The bootloader's own comment is "mpy code will have to clean this up"
//!   (`ae.c:354`) and we have no MicroPython. cold-snap must own UART4/I2C2
//!   exclusively or restore them after each call — see the open item in
//!   [`SELECTOR_READ_RNG`].
//! * A secure-element authentication failure calls `fatal_mitm()`, which is
//!   `noreturn`: screen, `wipe_all_sram` under RELEASE, then `LOCKUP_FOREVER()`
//!   (`ae.c:707-709`, `se2.c:1337`, `main.c:204-217`, `basics.h:61`). **Control
//!   never comes back**, so no error return and no reset policy of ours can
//!   intercept it. Fail-closed is preserved by Coinkite's code; so is unbounded
//!   halt.

use crate::memmap;
use core::num::NonZeroU32;

/// `bootloaderInfoTable_t` (`modckcc.c:41-47`; `startup.S:62-67`). The **first
/// word** is the callgate entry. Read at runtime — never hardcode the entry.
pub const BOOTLOADER_TABLE: *const u32 = 0x0800_0040 as *const u32;

/// Low byte the gate entry must have: `.align 8` + 4 + Thumb bit
/// (`startup.S:113-122`). Coldcard asserts it at `modckcc.c:57`; we return
/// [`Errno::BAD_GATE`] instead.
pub const GATE_ENTRY_LOW_BYTE: u32 = 0x05;

/// Selector 2 — `enter_dfu` (`dispatch.c:150-203`).
///
/// **`arg2` MUST be 0.** This corrects DECISIONS.md decision 6 step 4 and
/// PLAN.md §6.2 step 4, both of which say "arg2 0 then 2":
///
/// * `arg2 = 0` at RDP=2 checks `flash_is_security_level2()` and returns
///   `EPERM`, bailing to `fail:` **which returns to the caller**
///   (`dispatch.c:158-165`, `:680-699`). A clean no-op on production.
/// * `arg2 = 2` reaches `if(secure) LOCKUP_FOREVER();` (`dispatch.c:174-177`,
///   `:191-193`) and **never returns**, so the panic handler's unconditional
///   final reset would never run — permanently halting a production unit at
///   exactly the moment the handler exists to prevent that. `arg2 = 3` is worse:
///   it forces `secure = true` (`dispatch.c:181`).
///
/// On an RDP≠2 dev unit `arg2 = 0` writes the `REBOOT_TO_DFU` magic to
/// `0x2000_8000` and resets (`dispatch.c:198-203`); the bootloader acts on it on
/// the **next** boot, before `wipe_all_sram` (`main.c:113-122,130`). So the DFU
/// fallback completes after a reset, not in line.
pub const SELECTOR_ENTER_DFU: u32 = 2;

/// Only legal `arg2` for [`SELECTOR_ENTER_DFU`]. See that constant's docs; any
/// other value can `LOCKUP_FOREVER`.
pub const ENTER_DFU_ARG2_SAFE: u32 = 0;

/// Selector 26 — read random bytes from a secure element
/// (`dispatch.c:578-602`). `arg2` is [`RngSource`].
///
/// Output convention: `buf[0]` = count of valid bytes, data at `buf[1..]`.
/// `REQUIRE_OUT(33)` (`dispatch.c:580`) means the buffer must be at least
/// [`RNG_BUF_LEN`] and must satisfy [`validate_buf`].
///
/// **Callable pre-login** — `case 26` contains no PIN check and no
/// `pinAttempt_t` cast, unlike cases 4 and 18 (`dispatch.c:344-377`, `:493-498`).
/// Coldcard itself calls it pre-login from `mk4.init0()` (`shared/mk4.py:39-49`,
/// called at `:52`, before `pa.setup()` in `main.py`).
///
/// **OPEN (needs a decision, not just a bench run):** whether calling this from
/// our event loop is safe given the UART4/I2C2 reprogramming and the
/// unconditional `ae_reset_chip()` — see the module docs. This bounds how often
/// [`crate::rng::Entropy::try_reseed`] may be called.
pub const SELECTOR_READ_RNG: u32 = 26;

/// Required buffer length for [`SELECTOR_READ_RNG`]: `REQUIRE_OUT(33)`
/// (`dispatch.c:580`) — 1 length byte + up to 32 data bytes.
pub const RNG_BUF_LEN: usize = 33;

/// Largest `len_in` the gate accepts; above this it returns `ERANGE`
/// (`dispatch.c:114-117`).
pub const MAX_GATE_LEN: u32 = 1024;

/// Which secure element to read entropy from ([`SELECTOR_READ_RNG`]'s `arg2`).
/// Any other value returns `ERANGE` (`dispatch.c:596-598`).
///
/// **The two lengths differ, and both sources are weaker than they look.**
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RngSource {
    /// SE1 / ATECC608B — yields **32** bytes (`dispatch.c:583-588`).
    ///
    /// Not a raw RNG read: the raw path is deliberately disabled
    /// (`ae_random()` is `#if 0`'d with "RISKY - Easy for Mitm to control
    /// value", `ae.c:671-689`). `ae_secure_random()` does a GenDig against the
    /// pairing secret, verifies the tempkey, and SHA256s it (`ae.c:699-714`) —
    /// and `ae_gendig_slot` feeds **20 bytes of our own STM32 TRNG** into
    /// `ae_pick_nonce` first (`ae.c:1332`). So this leg is already a hash that
    /// mixes the TRNG in: the three sources are **not independent** in the way
    /// PLAN.md §5.1 assumes.
    Se1 = 1,
    /// SE2 / DS28C36B — yields only **8** bytes (`dispatch.c:590-594`).
    /// `callgate.py:116`'s `source=2` default is therefore the weaker source.
    ///
    /// **BLOCKER, unresolved: this is probably not an RNG at all.**
    /// `se2_read_rng()` issues **no RNG command**. It reads page 28
    /// (`PGN_ROM_OPTIONS`) with `verify=true` and returns bytes `[4..12]` of that
    /// page (`se2.c:1341-1343`) — a static page, write-protected `PROT_APH`
    /// ("not planning to change", `se2.c:586`), and the same page read elsewhere
    /// for the ROM ID. The only in-tree justification is the word "RPS" in a
    /// comment at `se2.c:1339`, with no datasheet corroboration anywhere in the
    /// repo. If that field does not refresh per read, PLAN.md §5.1's
    /// three-source claim is two-source-plus-a-constant. Resolve by bench-reading
    /// twice and comparing, or from the DS28C36B datasheet, BEFORE trusting the
    /// claim. [`crate::rng`]'s per-source repeat check turns a silent weakness
    /// into a hard refusal — but a hard refusal at every boot is also a dead
    /// device, so if the field is static, SE2 must be reclassified as a fixed
    /// per-device personalisation input (still worth hashing in for device
    /// uniqueness, **not** counted as an entropy source).
    Se2 = 2,
}

impl RngSource {
    /// Bytes this source returns in `buf[0]`. SE1 = 32, SE2 = 8
    /// (`dispatch.c:588`, `:593`).
    ///
    /// Named `byte_count`, not `len`: this is a fixed per-source constant, not a
    /// collection length, and `len` without `is_empty` is a clippy lint.
    #[must_use]
    pub const fn byte_count(self) -> u8 {
        match self {
            RngSource::Se1 => 32,
            RngSource::Se2 => 8,
        }
    }

    /// `arg2` value to pass to [`SELECTOR_READ_RNG`].
    #[must_use]
    pub const fn arg2(self) -> u32 {
        self as u32
    }
}

/// A nonzero errno from the gate, or one of our own pre-call refusals.
///
/// Nonzero-by-construction so `Result<(), Errno>` is niche-optimised and "ok"
/// cannot be confused with an error code. The gate returns 0 on success
/// (`dispatch.c:699`); Coldcard's Python side asserts `not rv`
/// (`shared/callgate.py:119`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Errno(pub NonZeroU32);

impl Errno {
    /// The word at [`BOOTLOADER_TABLE`] did not have low byte
    /// [`GATE_ENTRY_LOW_BYTE`], so we refused to `blx` it. Our own code, not the
    /// gate's. Coldcard `assert()`s this case; we must not, because a panic here
    /// is a reset loop.
    pub const BAD_GATE: Errno = Errno(NonZeroU32::new(0xC500_0001).unwrap());
    /// [`validate_buf`] rejected the buffer before any call was made.
    pub const BAD_BUFFER: Errno = Errno(NonZeroU32::new(0xC500_0002).unwrap());
    /// The gate returned 0 but `buf[0]` was not the length this source promises.
    pub const SHORT_READ: Errno = Errno(NonZeroU32::new(0xC500_0003).unwrap());
    /// [`check_pin_subcall`] refused a [`SELECTOR_PIN`] `arg2` that is not
    /// [`SubCallCost::Free`]. Our own refusal; **no call was made**.
    pub const FORBIDDEN_SUBCALL: Errno = Errno(NonZeroU32::new(0xC500_0004).unwrap());
    /// [`PinAttempt::new`] was given more than [`MAX_PIN_LEN`] bytes. Our own
    /// refusal; no call was made.
    pub const BAD_PIN_LEN: Errno = Errno(NonZeroU32::new(0xC500_0005).unwrap());

    /// Build from the gate's raw `r0`. `Some` iff nonzero, so
    /// `match Errno::from_raw(rv) { None => success, Some(e) => .. }`.
    #[must_use]
    pub fn from_raw(rv: i32) -> Option<Self> {
        NonZeroU32::new(rv as u32).map(Errno)
    }

    /// The raw value, for logging.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }

    /// The same value read back as the signed `int` the C side returned. The
    /// `errno.h` codes are small positives; the PIN layer's own codes are small
    /// negatives (`pins.h:76-92`), which is why they must not be compared as
    /// `u32`.
    #[must_use]
    pub const fn signed(self) -> i32 {
        self.0.get() as i32
    }

    /// `EPIN_I_AM_BRICK` — the one gate error with a policy consequence:
    /// terminal, show-and-halt, and **never** retried. Coldcard's Python answers
    /// it with `enter_dfu(3)` (`pincodes.py:263-265`), which is
    /// hardware-impossible at RDP=2 (decision 6).
    #[must_use]
    pub const fn is_brick_report(self) -> bool {
        self.signed() == EPIN_I_AM_BRICK
    }
}

/// Why a buffer is unacceptable to the gate. Mirrors `good_addr()`
/// (`dispatch.c:39-62`) so the failure is a value here rather than an `EPERM`
/// after a pointless firewall transit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BufFault {
    /// Buffer is not entirely inside `[SRAM_BASE, BL_SRAM_BASE)`
    /// (`dispatch.c:48`). A `static` in flash lands here and would return
    /// `EPERM` (`dispatch.c:53-55`); a stack local is fine.
    NotInSram,
    /// Length is 0, or exceeds [`MAX_GATE_LEN`] (`dispatch.c:114-117`).
    BadLength,
    /// Length is below what the selector's `REQUIRE_OUT` demands.
    TooShortForSelector,
}

/// Validate a callgate buffer *before* calling, replicating `good_addr()`
/// (`dispatch.c:39-62`) plus the `len_in > 1024` check (`dispatch.c:114-117`).
///
/// `min_len` is the selector's `REQUIRE_OUT` (e.g. [`RNG_BUF_LEN`] for
/// [`SELECTOR_READ_RNG`]); pass 0 where the selector takes no buffer.
///
/// Pure, `cfg`-free and pointer-arithmetic only — **host-testable**, and it must
/// be, since it encodes the one rule whose violation is otherwise a silent
/// `EPERM`. This is the only part of the callgate contract that can be covered
/// off-hardware.
///
/// # Contract
///
/// Returns `Ok(())` iff `[ptr, ptr+len)` lies wholly within
/// `[`[`crate::memmap::SRAM_BASE`]`, `[`crate::memmap::BL_SRAM_BASE`]`)`,
/// `len` is in `1..=`[`MAX_GATE_LEN`], and `len >= min_len`. Must not panic and
/// must not dereference `ptr`.
pub fn validate_buf(ptr: *const u8, len: usize, min_len: usize) -> Result<(), BufFault> {
    // Length first: `good_addr` only range-checks when `minlen != 0`, but
    // `firewall_dispatch` rejects `len_in > 1024` unconditionally
    // (dispatch.c:114-117) before reaching any selector.
    if len == 0 || len > MAX_GATE_LEN as usize {
        return Err(BufFault::BadLength);
    }
    if len < min_len {
        return Err(BufFault::TooShortForSelector);
    }

    // Containment in [SRAM_BASE, BL_SRAM_BASE). `good_addr` (dispatch.c:48)
    // tests `x >= SRAM1_BASE && (x + len) <= BL_SRAM_BASE`, and on a 32-bit
    // target that sum CAN wrap -- which is precisely the check we must not
    // reproduce. `checked_add` makes a wrap a refusal instead. Note
    // `overflow-checks = false` in profile.release, so a plain `+` would wrap
    // SILENTLY on the device even though a debug host build panics; this
    // function is not allowed to do either.
    //
    // `ptr` is never dereferenced: this is address arithmetic only, which is
    // what keeps the function pure and host-testable. `as usize` on a pointer is
    // a provenance-losing cast, not a read.
    let start = ptr as usize;
    let end = match start.checked_add(len) {
        Some(e) => e,
        None => return Err(BufFault::NotInSram),
    };
    if start >= memmap::SRAM_BASE as usize && end <= memmap::BL_SRAM_BASE as usize {
        Ok(())
    } else {
        Err(BufFault::NotInSram)
    }
}

/// Parse a [`SELECTOR_READ_RNG`] response buffer into `out`.
///
/// `buf` is the 33-byte gate buffer: `buf[0]` = valid length, data at
/// `buf[1..]`. Checks `buf[0] == source.byte_count()`, that `out.len()` matches, and
/// rejects an all-zero or all-`0xff` payload.
///
/// Pure and **host-testable**. Coldcard's own path does none of this: it asserts
/// `rv == 0` then trusts the bytes (`shared/callgate.py:116-122`), and
/// `mk4.py:43-44` feeds them straight into `sha256d` with no health check.
///
/// # Contract
///
/// * `Err(`[`Errno::SHORT_READ`]`)` if `buf.len() < `[`RNG_BUF_LEN`], if
///   `buf[0] != source.byte_count()`, or if `out.len() != source.byte_count() as usize`.
/// * `Err(`[`Errno::SHORT_READ`]`)` if the payload is all-`0x00` or all-`0xff`
///   (degenerate).
/// * Otherwise copies `buf[1..1 + source.byte_count()]` into `out` and returns `Ok(())`.
/// * Must not panic on any input, including a shorter-than-expected `buf`.
pub fn parse_rng_response(source: RngSource, buf: &[u8], out: &mut [u8]) -> Result<(), Errno> {
    let want = source.byte_count() as usize;

    // Every length relationship is checked before any indexing, so no slice
    // operation below can panic. `buf.len() >= RNG_BUF_LEN` and
    // `want <= RNG_BUF_LEN - 1` together guarantee `1 + want <= buf.len()`.
    if buf.len() < RNG_BUF_LEN || out.len() != want {
        return Err(Errno::SHORT_READ);
    }
    // buf[0] is the gate's own count (dispatch.c:588, :593). Trusting it
    // blindly is what Coldcard does (callgate.py:116-122); we require it to be
    // exactly what this source promises.
    if usize::from(buf[0]) != want {
        return Err(Errno::SHORT_READ);
    }
    // `want` is 8 or 32, both < RNG_BUF_LEN, so this cannot fail -- but express
    // it as a checked slice rather than an index so a future source with a
    // larger byte_count cannot turn this into a panic.
    let payload = match buf.get(1..1 + want) {
        Some(p) => p,
        None => return Err(Errno::SHORT_READ),
    };

    // Degenerate-payload refusal. A stuck bus or an unpowered SE reads as all
    // 0x00 or all 0xff; either would otherwise be hashed into the seed as if it
    // were entropy. This is a *pre*-mixer gate, deliberately duplicated by
    // `crate::rng::check_source` -- both are cheap and the failure mode is
    // silent.
    if payload.iter().all(|&b| b == 0x00) || payload.iter().all(|&b| b == 0xff) {
        return Err(Errno::SHORT_READ);
    }

    out.copy_from_slice(payload);
    Ok(())
}

/// Run `f` with interrupts masked, restoring `PRIMASK` afterwards.
///
/// Required by the gate (`modckcc.c:104`; `dispatch.c:98`). On a non-ARM host
/// this is a plain call, so pure logic above it stays host-testable.
///
/// Note `cpsid i` sets `PRIMASK`, which does **not** mask NMI or HardFault; this
/// is not full non-reentrancy. Relevant to [`crate::panic`], not here.
pub fn with_irq_off<T>(f: impl FnOnce() -> T) -> T {
    #[cfg(target_arch = "arm")]
    {
        // Save-and-restore, not unconditional re-enable: this is called from
        // `read_rng` on the normal event-loop path, which may already be inside
        // another critical section. `cpsie i` there would silently widen it.
        // (`crate::panic::disable_interrupts` is the deliberate one-way variant.)
        let primask: u32;
        // SAFETY: `mrs`/`cpsid` touch no memory and only the PRIMASK special
        // register. `nomem` is correct because PRIMASK is not memory; the
        // compiler_fence below is what stops the read/write of `f`'s captured
        // state from being hoisted out of the critical section.
        unsafe {
            core::arch::asm!(
                "mrs {0}, PRIMASK",
                "cpsid i",
                out(reg) primask,
                options(nomem, nostack, preserves_flags),
            );
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

        let out = f();

        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        // PRIMASK bit 0 set == interrupts were ALREADY masked on entry, so
        // leave them masked. Restoring unconditionally would be a bug.
        if primask & 1 == 0 {
            // SAFETY: as above.
            unsafe {
                core::arch::asm!("cpsie i", options(nomem, nostack, preserves_flags));
            }
        }
        out
    }
    #[cfg(not(target_arch = "arm"))]
    {
        f()
    }
}

/// The raw `blx` into the gate. **ARM only.**
///
/// Reads the entry from [`BOOTLOADER_TABLE`], refuses unless its low byte is
/// [`GATE_ENTRY_LOW_BYTE`] (returning [`Errno::BAD_GATE`] rather than
/// asserting), then calls with the ABI in the module docs and the **full**
/// clobber set. Does not validate the buffer, does not mask interrupts, and does
/// not interpret the result — [`call`] is the safe wrapper that does all three.
///
/// # Safety
///
/// Caller must guarantee all of:
/// * interrupts are already masked (use [`with_irq_off`]);
/// * `buf` is either null, or writable for at least `len` bytes and accepted by
///   [`validate_buf`];
/// * `selector`/`arg2` are a pair that returns — notably **not**
///   [`SELECTOR_ENTER_DFU`] with any `arg2` other than
///   [`ENTER_DFU_ARG2_SAFE`], which can `LOCKUP_FOREVER`;
/// * the caller accepts the peripheral side effects in the module docs
///   (`ae_reset_chip`, UART4/I2C2 reprogramming, flash-cache reset).
///
/// # Returns
///
/// The gate's raw `r0`: 0 on success, else an errno. May not return at all if a
/// secure element raises `fatal_mitm()`.
#[cfg(target_arch = "arm")]
pub unsafe fn raw(selector: u32, buf: *mut u8, len: u32, arg2: u32) -> i32 {
    // Read the entry at runtime and REFUSE rather than assert. Coldcard's
    // `assert((dest & 0xff) == 0x05)` (modckcc.c:57) is a halt for us: under
    // `panic = "abort"` with no unwinder it never returns, and on an RDP=2 unit
    // that is a brick. This is the single most important difference between this
    // function and the C original.
    //
    // SAFETY: BOOTLOADER_TABLE is 0x0800_0040, inside the always-readable
    // bootloader flash region (memmap::BL_FLASH_BASE..+BL_FLASH_SIZE); the first
    // word is `bootloaderInfoTable_t::callgate_entry` (startup.S:62-67). It is
    // read-only and 4-byte aligned by construction (`.align 6`, startup.S:63).
    let dest = unsafe { core::ptr::read_volatile(BOOTLOADER_TABLE) };
    if dest & 0xff != GATE_ENTRY_LOW_BYTE {
        // Negative so it cannot be confused with a gate errno (all of which are
        // small positive `errno.h` values) and is nonzero for `Errno::from_raw`.
        return Errno::BAD_GATE.get() as i32;
    }

    let rv: i32;
    // SAFETY: (the asm block itself) `dest` was just verified to be the gate
    // entry with the Thumb bit set, so `blx` transfers to Thumb code at the one
    // legal firewall call-gate address. All caller obligations (masked
    // interrupts, buffer validity, a returning selector/arg2 pair) are this
    // function's documented `# Safety` contract.
    //
    // The clobber set is the FULL one, not Coldcard's `"r9","r10"`
    // (modckcc.c:64-65). Theirs is safe only because that file is
    // `#pragma GCC optimize("O0")` (modckcc.c:30-32) and its own comment admits
    // it "doesn't work with compiler optimizations enabled" (modckcc.c:62).
    //
    // `dest` is passed in r4 as `inout(..) => _` rather than `in(reg)`: r4 must
    // be declared clobbered, and a register cannot be both an `out("r4") _`
    // clobber and an input. Carrying the value in the clobbered register is the
    // idiom that satisfies both. With r0-r3 taken by the ABI, r4/r5/r8-r12/lr
    // clobbered and r6/r7 LLVM-reserved, there is in fact no free register left
    // for `in(reg)` to allocate.
    //
    // No `options(...)`: the default (may read and write memory, may touch the
    // stack) is required. The gate writes through `buf`, and `nomem`/`readonly`
    // would let those writes be optimised away.
    unsafe {
        core::arch::asm!(
            "blx r4",
            inout("r4") dest => _,
            inout("r0") selector => rv,
            inout("r1") buf => _,
            inout("r2") len => _,
            inout("r3") arg2 => _,
            // r6/r7 are LLVM-reserved on this target and cannot be named at
            // all; clobber_abi("C") and clobber_abi("system") both warn about
            // reserved D16-D31 on hard-float (both measured).
            out("r5") _,
            out("r8") _,
            out("r9") _,
            out("r10") _,
            out("r11") _,
            out("r12") _,
            out("lr") _,
            // The gate is C compiled -mfpu=fpv4-sp-d16 -mfloat-abi=hard
            // (mk4-bootloader/Makefile:66), so s0..s15 are call-clobbered there.
            out("s0") _, out("s1") _, out("s2") _, out("s3") _,
            out("s4") _, out("s5") _, out("s6") _, out("s7") _,
            out("s8") _, out("s9") _, out("s10") _, out("s11") _,
            out("s12") _, out("s13") _, out("s14") _, out("s15") _,
        );
    }
    rv
}

/// Safe-ish wrapper: [`validate_buf`], then [`with_irq_off`] around [`raw`],
/// then errno interpretation. **ARM only.**
///
/// This is what [`crate::rng`] and [`crate::panic`] call; neither should invoke
/// [`raw`] directly.
///
/// # Safety
///
/// Still `unsafe`: `buf` must be a real writable allocation for `len` bytes
/// (validation checks the address range, not provenance), and `selector`/`arg2`
/// must be a returning pair. See [`raw`].
///
/// # Errors
///
/// [`Errno::BAD_BUFFER`] if [`validate_buf`] refuses (no call is made),
/// [`Errno::BAD_GATE`] if the table word is malformed, otherwise the gate's own
/// errno.
#[cfg(target_arch = "arm")]
pub unsafe fn call(
    selector: u32,
    buf: *mut u8,
    len: u32,
    min_len: usize,
    arg2: u32,
) -> Result<(), Errno> {
    // A selector taking no buffer passes (NULL, 0, 0). `good_addr` skips its
    // range check entirely when `minlen == 0` (dispatch.c:44-47), so validating
    // a null/zero buffer here would refuse calls the gate accepts -- notably
    // SELECTOR_ENTER_DFU, the whole point of `try_enter_dfu`.
    if !(buf.is_null() && len == 0 && min_len == 0)
        && validate_buf(buf.cast_const(), len as usize, min_len).is_err()
    {
        return Err(Errno::BAD_BUFFER);
    }

    // SAFETY: `with_irq_off` establishes the masked-interrupts precondition
    // (modckcc.c:104, dispatch.c:98); the buffer precondition is either the
    // null/zero case or `validate_buf` above plus the caller's provenance
    // guarantee; the returning-pair precondition is forwarded to our caller by
    // this function's own `# Safety` section.
    let rv = with_irq_off(|| unsafe { raw(selector, buf, len, arg2) });

    match Errno::from_raw(rv) {
        None => Ok(()),
        Some(e) => Err(e),
    }
}

/// Read `source.byte_count()` bytes of secure-element entropy into `out`.
///
/// The whole [`SELECTOR_READ_RNG`] path: a **stack-local** 33-byte buffer (which
/// is what satisfies `good_addr()` — a `static` in flash returns `EPERM`),
/// [`call`], then [`parse_rng_response`]. **ARM only.**
///
/// This is the only callgate entry point [`crate::rng`] needs, so the SE legs
/// there contain no `asm!` and no raw pointers.
///
/// # Errors
///
/// Any [`Errno`] from [`call`], or [`Errno::SHORT_READ`] if the response is
/// short or degenerate. Note a real SE authentication fault does **not** arrive
/// here — it `LOCKUP_FOREVER`s inside the gate (module docs).
///
/// # Panics
///
/// Must not, for any `source`/`out` pair. If `out.len() != source.byte_count()` return
/// [`Errno::SHORT_READ`].
#[cfg(target_arch = "arm")]
pub fn read_rng(source: RngSource, out: &mut [u8]) -> Result<(), Errno> {
    if out.len() != source.byte_count() as usize {
        return Err(Errno::SHORT_READ);
    }

    // MUST be a stack local. `good_addr` requires `[SRAM_BASE, BL_SRAM_BASE)`
    // and rejects flash for a writable buffer with EPERM (dispatch.c:48-56), so
    // a `static mut` would fail -- and a `static` is also how you get an
    // aliasing bug in a re-entrant reseed. `mut` is required: the gate writes
    // through the pointer even though Rust cannot see it happen.
    let mut buf = [0u8; RNG_BUF_LEN];

    // SAFETY: `buf` is a live stack allocation of exactly RNG_BUF_LEN bytes,
    // uniquely borrowed here, and the stack is inside
    // [SRAM_BASE, BL_SRAM_BASE) so `validate_buf` inside `call` will accept it.
    // Selector 26 with arg2 in {1,2} returns (dispatch.c:578-602): the only
    // non-returning path is a genuine SE authentication failure, which
    // `fatal_mitm()`s inside the gate and is not interceptable by any code of
    // ours (module docs).
    unsafe {
        call(
            SELECTOR_READ_RNG,
            buf.as_mut_ptr(),
            RNG_BUF_LEN as u32,
            RNG_BUF_LEN,
            source.arg2(),
        )?;
    }

    let res = parse_rng_response(source, &buf, out);
    // Do not leave secure-element entropy in a dead stack frame. `write_volatile`
    // (not a plain assignment) because the compiler can and does delete stores
    // to a local that is never read again.
    //
    // SAFETY: `buf` is a live, properly aligned, uniquely owned local for this
    // whole statement; the write is in-bounds and of the same type.
    unsafe { core::ptr::write_volatile(&mut buf, [0u8; RNG_BUF_LEN]) };
    res
}

/// Attempt DFU via [`SELECTOR_ENTER_DFU`] with [`ENTER_DFU_ARG2_SAFE`].
/// **ARM only.**
///
/// A no-op returning `EPERM` on a production RDP=2 unit; on a dev unit it sets
/// the DFU flag and resets, completing on the next boot. Called only by
/// [`crate::panic`], only past the panic-count threshold, and its result is
/// deliberately ignored — an unconditional reset follows either way.
///
/// Never pass any other `arg2`: see [`SELECTOR_ENTER_DFU`].
#[cfg(target_arch = "arm")]
pub fn try_enter_dfu() {
    // SAFETY: no buffer (NULL/0/0, which `good_addr` skips checking when
    // `minlen == 0`, dispatch.c:44-47), and `SELECTOR_ENTER_DFU` with
    // `ENTER_DFU_ARG2_SAFE` is the one arg2 that RETURNS on a secure unit --
    // `EPERM` via `fail:` (dispatch.c:158-165, :680-699). Any other arg2 reaches
    // `LOCKUP_FOREVER()` (dispatch.c:191-193) and would strand the panic handler
    // before its unconditional reset. `ENTER_DFU_ARG2_SAFE` is a constant here,
    // not a parameter, precisely so no caller can get that wrong.
    let _ = unsafe {
        call(
            SELECTOR_ENTER_DFU,
            core::ptr::null_mut(),
            0,
            0,
            ENTER_DFU_ARG2_SAFE,
        )
    };
    // Result deliberately dropped: on a production unit this is always EPERM,
    // and the caller (`crate::panic`) resets unconditionally either way.
}

// ---------------------------------------------------------------------------
// The PIN surface (selector 18) and the two free counters (21/3 and 25).
//
// ONLY the sub-calls that cannot consume a PIN retry are bound here. See
// [`SubCallCost`] for the classification and [`pin_subcall_cost`] for the
// per-`arg2` enumeration that backs it.
// ---------------------------------------------------------------------------

/// Selector 18 — the whole PIN surface (`dispatch.c:341-386`). `arg2` selects one
/// of nine sub-calls that all share one 280-byte [`PinAttempt`] buffer
/// (`REQUIRE_OUT(PIN_ATTEMPT_SIZE_V2)`, `dispatch.c:343`).
///
/// **This is the most dangerous selector on the chip and the buffer does not
/// change between the safe and the fatal sub-calls** — only `arg2` does. One
/// sub-call ([`pin_subcall_cost`]'s `Counted` case) advances SE1's brick counter
/// on every wrong PIN and can reach `fast_brick()` through
/// `se2_handle_bad_pin()` (`pins.c:761`; `se2.c:874-909`); five more write slots,
/// install firmware or wipe the seed. That is why `arg2` is **never a parameter**
/// of any wrapper here, exactly as [`ENTER_DFU_ARG2_SAFE`] is not a parameter of
/// `try_enter_dfu`, and why [`check_pin_subcall`] stands between
/// [`PinAttempt`] and `call` (both ARM-only, hence the plain spans).
///
/// Bound: [`PIN_SUBCALL_SETUP`] only.
pub const SELECTOR_PIN: u32 = 18;

/// The only [`SELECTOR_PIN`] `arg2` this module binds: `pin_setup_attempt`
/// (`dispatch.c:347-349` -> `pins.c:531-592`).
///
/// Costs nothing. It reaches `warmup_ae` (SE1 slot 1), `get_last_success`
/// (slots 5, 6 and a mode-0 `ae_get_counter` read, `ae.c:1117-1119`) and
/// `pin_is_blank` (slot 3). Slots 1/3/5/6 are all `LimitedUse=0`
/// (`ae_config.h:60,66,72,75`); the chip's only `LimitedUse=1` slot is 4
/// (`ae_config.h:69`), reached solely from `pin_hash_attempt`'s `ae_mixin_key`
/// (`pins.c:157`), which this sub-call does not call.
///
/// **That freeness is read from source, not measured on silicon.** Bench step 1
/// is two of these calls with a `read_counter0` before, between and after; if
/// the counter moves, everything downstream of this constant is void.
pub const PIN_SUBCALL_SETUP: u32 = 0;

/// `sizeof(pinAttempt_t) == PIN_ATTEMPT_SIZE_V2 == 176 + 72 + 32`
/// (`pins.h:71-72`), which the bootloader `STATIC_ASSERT`s at `pins.c:533`.
pub const PIN_ATTEMPT_SIZE: usize = 280;

/// `MAX_PIN_LEN` (`pins.h:16`). The gate checks only the **upper** bound
/// (`pins.c:396`) against a *signed* `int`, so a negative `pin_len` passes
/// validation and reaches `memcpy(pin_copy, args->pin, pin_len)`
/// (`pins.c:549-551`) as a huge `size_t`. [`PinAttempt::new`] makes that
/// unrepresentable rather than merely clamping it — see its docs.
pub const MAX_PIN_LEN: usize = 32;

/// `PA_MAGIC_V2` (`pins.h:37`). `_validate_attempt` returns `EPIN_BAD_MAGIC`
/// for anything else (`pins.c:389-393`).
pub const PA_MAGIC_V2: u32 = 0x2eaf_6312;

/// `state_flags` bit: the struct carries a successful login (`pins.h:41`).
pub const PA_SUCCESSFUL: u32 = 0x01;
/// `state_flags` bit: the main PIN is **blank/unset** (`pins.h:42`).
///
/// A blank PIN yields none of the security property: the PIN digest is a value
/// anyone can compute, so anything gated on it is gated on nothing.
pub const PA_IS_BLANK: u32 = 0x02;
/// `state_flags` bit: the secret slot has never been written, or is wiped
/// (`pins.h:45`).
pub const PA_ZERO_SECRET: u32 = 0x10;

/// Selector 21 — OTP / downgrade protection (`dispatch.c:441-489`). `arg2` 2
/// permanently raises the minimum firmware version and is not bound.
pub const SELECTOR_OTP: u32 = 21;

/// [`SELECTOR_OTP`] `arg2` = 3: read SE1's raw monotonic `Counter[0]`
/// (`dispatch.c:476-483`). `REQUIRE_OUT(4)`, and the gate casts the buffer to
/// `uint32_t *`, so it must be 4-byte aligned.
pub const OTP_SUBCALL_READ_COUNTER0: u32 = 3;

/// `REQUIRE_OUT(4)` for [`OTP_SUBCALL_READ_COUNTER0`] (`dispatch.c:478`).
pub const COUNTER0_BUF_LEN: usize = 4;

/// Ceiling the bootloader documents for `Counter[0]`: "max is 0x1fffff"
/// (`dispatch.c:477`). Monotonic and never decremented — a successful login
/// re-arms attempts by moving the *match target* up (`pins.c:620-642`), so this
/// is a hard lifetime ceiling on the number of logins a unit can ever perform.
/// Not enforced here: reporting an implausible counter is more useful at the
/// bench than converting it into an error.
pub const COUNTER0_MAX: u32 = 0x001f_ffff;

/// Selector 25 — mcu key slot usage (`dispatch.c:565-577`). Ignores `arg2`.
pub const SELECTOR_MCU_KEY_USAGE: u32 = 25;

/// Buffer length for [`SELECTOR_MCU_KEY_USAGE`]: **12**, not the 8 the gate
/// itself demands.
///
/// `dispatch.c:568` says `REQUIRE_OUT(8)` but the body writes three 4-byte ints
/// at `buf_io+0`, `+4` and `+8` (`dispatch.c:570-574`) — the gate under-declares
/// its own output by 4 bytes. Coldcard never trips it because `callgate.py:112`
/// passes `bytearray(3*4)`. An 8-byte buffer here would take a 4-byte overwrite
/// past its end, inside a firewall transit with interrupts masked.
pub const MCU_KEY_USAGE_BUF_LEN: usize = 12;

/// What a [`SELECTOR_PIN`] sub-call costs if invoked. The classification is the
/// point of this type: it puts the danger in the **type**, not in a comment, so
/// adding a binding for a new `arg2` cannot be done without writing the word
/// `Counted` or `Destructive` into the diff — where review and
/// [`check_pin_subcall`] both see it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubCallCost {
    /// Touches no `LimitedUse` slot and writes nothing. Safe to call from
    /// firmware, repeatedly, at boot.
    Free,
    /// Consumes a PIN retry / advances SE1's brick counter, or is unreachable
    /// without a prior sub-call that does. **Not bound, and no agent has
    /// authority to bind it without a bench session on an expendable unit.**
    Counted,
    /// Writes a slot, sets a PIN, installs firmware, wipes or never returns.
    /// Permanent. Must not appear in this tree at all.
    Destructive,
    /// Not a `case` in `dispatch.c:346-383`; falls to `default: rv = ENOENT`
    /// and is inert.
    Absent,
}

/// Classify a [`SELECTOR_PIN`] `arg2`, from `dispatch.c:346-383` plus the
/// function each case reaches.
///
/// Pure, `cfg`-free and host-tested — the enumeration is the security-relevant
/// part, so it must not live in ARM-only code (PLAN.md §9 item 22).
#[must_use]
pub const fn pin_subcall_cost(arg2: u32) -> SubCallCost {
    match arg2 {
        // 0: pin_setup_attempt -- see PIN_SUBCALL_SETUP.
        0 => SubCallCost::Free,
        // 1: pin_delay is literally `return 0;` (pins.c:598-603). Free, but
        // pointless, so not bound: delays are handled by the chip on the 608.
        1 => SubCallCost::Free,
        // 2: the login attempt. `ae_mixin_key(KEYNUM_pin_attempt=4, ..)`
        // (pins.c:157) on the chip's only LimitedUse slot, and the wrong-PIN leg
        // calls se2_handle_bad_pin (pins.c:761) which can reach mcu_key_clear,
        // fast_brick() or NVIC_SystemReset (se2.c:874-909).
        2 => SubCallCost::Counted,
        // 3: pin_change -- ae_encrypted_write to PIN/secret slots, and consumes
        // one of only 256 mcu key slots (secrets.h:43-44).
        3 => SubCallCost::Destructive,
        // 4: pin_fetch_secret is read-only in itself, but requires a struct
        // bearing PA_SUCCESSFUL or it returns EPIN_WRONG_SUCCESS -- i.e. it is
        // unreachable without first spending a counter tick on case 2.
        4 => SubCallCost::Counted,
        // 5: pin_firmware_greenlight, ae_encrypted_write to KEYNUM_firmware
        // (pins.c:1222-1250). 6/8: pin_long_secret, the same function reads AND
        // writes depending on change_flags. 7: pin_firmware_upgrade, a one-way
        // install from PSRAM.
        5..=8 => SubCallCost::Destructive,
        _ => SubCallCost::Absent,
    }
}

/// Refuse any [`SELECTOR_PIN`] `arg2` that is not [`SubCallCost::Free`].
///
/// The choke point every selector-18 wrapper must pass through. It is a value
/// refusal, not an assertion: a panic inside the callgate path is a reset loop
/// on an RDP=2 unit, which is permanent (decision 6).
///
/// Pure and `cfg`-free on purpose. Only its *call site* is ARM-only, and the
/// source-reading guard test asserts that call site still exists — a refusal
/// that lives solely in a `cfg(target_arch = "arm")` block is invisible to every
/// gate in this project.
///
/// # Errors
///
/// [`Errno::FORBIDDEN_SUBCALL`] for every `arg2` whose [`pin_subcall_cost`] is
/// not `Free`, including the [`SubCallCost::Absent`] ones — an `arg2` we have no
/// binding for is a bug in our code, not a request to let the gate return
/// `ENOENT`.
pub fn check_pin_subcall(arg2: u32) -> Result<(), Errno> {
    match pin_subcall_cost(arg2) {
        SubCallCost::Free => Ok(()),
        _ => Err(Errno::FORBIDDEN_SUBCALL),
    }
}

/// Attempts we refuse to go below. A login attempt is only permitted while
/// `attempts_left` is **strictly greater** than this.
///
/// `MAX_TARGET_ATTEMPTS` is 13 (`pins.c:28`) and `attempts_left == 0` is
/// "we're a brick now" (`pins.c:483-491`). The floor exists so that a UI bug, a
/// stuck key or a reset loop cannot walk a unit to death: it costs two of
/// thirteen attempts and buys back the only irreversible mistake on this path.
pub const ATTEMPTS_LEFT_FLOOR: u32 = 2;

/// Whether a login attempt may be made at all, given `attempts_left` as reported
/// by [`PinAttempt::attempts_left`].
///
/// No subtraction anywhere, by design: `overflow-checks = false` in
/// `profile.release`, so a decrementing retry counter that panics in a host test
/// would silently **wrap** on the device — and a wrapped retry counter on a
/// brick-counter path is the exact catastrophe this floor exists to prevent.
/// Comparison only, so there is nothing to wrap.
///
/// Nothing calls this yet: no counted sub-call is bound. It is defined now
/// because the refusal must exist *before* the call that needs it, and because
/// whoever binds `arg2 = 2` must have no excuse to invent their own.
#[must_use]
pub const fn login_attempt_permitted(attempts_left: u32) -> bool {
    attempts_left > ATTEMPTS_LEFT_FLOOR
}

/// `pinAttempt_t` (`pins.h:96-116`) — the 280-byte buffer every
/// [`SELECTOR_PIN`] sub-call shares.
///
/// Held as **bytes**, not as a field-per-field `repr(C)` struct, for three
/// reasons: the layout can then have no padding to get wrong, the struct
/// round-trips between sub-calls verbatim (the gate signs bytes `[0,68)` plus
/// `cached_main_pin` under the pairing secret and a per-boot nonce,
/// `pins.c:356-361`, so any re-encoding of ours would invalidate the HMAC), and
/// no field access needs `unsafe`. `align(4)` is required because the gate casts
/// the buffer to `pinAttempt_t *` and reads `uint32_t` fields through it.
///
/// The offsets below are derived by summing `pins.h:96-116` and are checked
/// against the struct's own `176 + 72 + 32` arithmetic by
/// `pin_attempt_offsets_match_pins_h`.
///
/// Contains a PIN, so [`Drop`] wipes it volatilely. Not `Copy`/`Clone` for the
/// same reason.
#[repr(C, align(4))]
pub struct PinAttempt {
    raw: [u8; PIN_ATTEMPT_SIZE],
}

impl PinAttempt {
    /// `magic_value` (`pins.h:97`).
    pub const OFF_MAGIC: usize = 0;
    /// `pin[MAX_PIN_LEN]` (`pins.h:99`).
    pub const OFF_PIN: usize = 8;
    /// `pin_len` (`pins.h:100`).
    pub const OFF_PIN_LEN: usize = 40;
    /// `num_fails` (`pins.h:103`).
    pub const OFF_NUM_FAILS: usize = 52;
    /// `attempts_left` (`pins.h:104`).
    pub const OFF_ATTEMPTS_LEFT: usize = 56;
    /// `state_flags` (`pins.h:105`).
    pub const OFF_STATE_FLAGS: usize = 60;
    /// `hmac[32]` (`pins.h:107`) — the gate's signature over the fields above.
    pub const OFF_HMAC: usize = 68;
    /// `secret[AE_SECRET_LEN]` (`pins.h:115`). The literal `176` in
    /// `PIN_ATTEMPT_SIZE_V2` (`pins.h:71`) is this offset, which is what proves
    /// the preceding fields carry no padding.
    pub const OFF_SECRET: usize = 176;
    /// `cached_main_pin[32]` (`pins.h:117`), the last field.
    pub const OFF_CACHED_MAIN_PIN: usize = 248;

    /// A zeroed attempt struct carrying [`PA_MAGIC_V2`] and `pin`.
    ///
    /// `is_secondary` stays 0 (anything else is `EPIN_PRIMARY_ONLY`,
    /// `pins.c:541-545`) and `change_flags` stays 0, both by virtue of the buffer
    /// being zeroed.
    ///
    /// **`pin_len` is written from a `usize` bounded to `0..=`[`MAX_PIN_LEN`],
    /// so a negative `pin_len` is unrepresentable rather than clamped.** That is
    /// the whole reason this is the only constructor and there is no `set_pin`.
    ///
    /// An **empty** `pin` is accepted and is the right thing to pass for pure
    /// introspection (`attempts_left`, `num_fails`, [`PA_IS_BLANK`]): sub-call 0
    /// caches nothing when the PIN is not checked, and forcing a real PIN into a
    /// call that does not need one is worse than allowing zero. The `1..=32`
    /// lower bound belongs to the login sub-call, which is not bound here; the
    /// gate itself returns `EPIN_PIN_REQUIRED` for a zero-length login
    /// (`pins.h:85`).
    ///
    /// # Errors
    ///
    /// [`Errno::BAD_PIN_LEN`] if `pin.len() > `[`MAX_PIN_LEN`].
    pub fn new(pin: &[u8]) -> Result<Self, Errno> {
        if pin.len() > MAX_PIN_LEN {
            return Err(Errno::BAD_PIN_LEN);
        }
        let mut raw = [0u8; PIN_ATTEMPT_SIZE];
        raw[Self::OFF_MAGIC..Self::OFF_MAGIC + 4].copy_from_slice(&PA_MAGIC_V2.to_le_bytes());
        // `get_mut`, not indexing: this makes the write panic-free without
        // depending on the OFF_PIN + MAX_PIN_LEN <= PIN_ATTEMPT_SIZE relationship
        // staying true, and a panic on the callgate path is a reset loop at
        // RDP=2. The returned slice is exactly `pin.len()` long, so
        // `copy_from_slice` cannot mismatch either.
        raw.get_mut(Self::OFF_PIN..Self::OFF_PIN + pin.len())
            .ok_or(Errno::BAD_PIN_LEN)?
            .copy_from_slice(pin);
        // `pin.len()` is <= MAX_PIN_LEN == 32 here, so the cast is exact and
        // the stored word is always a small positive value. This is the line
        // that makes `pins.c:396`'s missing lower bound irrelevant to us.
        let len = pin.len() as u32;
        raw[Self::OFF_PIN_LEN..Self::OFF_PIN_LEN + 4].copy_from_slice(&len.to_le_bytes());
        Ok(Self { raw })
    }

    /// Read a little-endian `u32` field. Private: every legal offset already has
    /// a named accessor, and an arbitrary offset is how you read half of the
    /// HMAC and call it a counter.
    const fn word(&self, off: usize) -> u32 {
        // Indexed, not sliced, so this stays a `const fn`. Every `off` is one of
        // the associated constants above, all of which are <= 248 with 4 bytes
        // to spare in a 280-byte array, so no index can be out of range.
        u32::from_le_bytes([
            self.raw[off],
            self.raw[off + 1],
            self.raw[off + 2],
            self.raw[off + 3],
        ])
    }

    /// `magic_value` as the gate sees it. Should always be [`PA_MAGIC_V2`];
    /// worth checking after a call, because sub-call 0 rewrites it
    /// (`pins.c:558`).
    #[must_use]
    pub const fn magic(&self) -> u32 {
        self.word(Self::OFF_MAGIC)
    }

    /// `pin_len`, as the unsigned word we wrote. See [`PinAttempt::new`].
    #[must_use]
    pub const fn pin_len(&self) -> u32 {
        self.word(Self::OFF_PIN_LEN)
    }

    /// `num_fails` — `counter - lastgood`, computed **by the bootloader**
    /// (`pins.c:474-480`), or 99 if `lastgood > counter`.
    #[must_use]
    pub const fn num_fails(&self) -> u32 {
        self.word(Self::OFF_NUM_FAILS)
    }

    /// `attempts_left` — `match_count - counter`, computed **by the
    /// bootloader** (`pins.c:483-491`), and `0` means the unit is already a
    /// brick. Never recompute it from `read_counter0`: that subtraction is
    /// exactly the arithmetic that wraps in release.
    ///
    /// Feed it to [`login_attempt_permitted`], not to a decrementing counter.
    #[must_use]
    pub const fn attempts_left(&self) -> u32 {
        self.word(Self::OFF_ATTEMPTS_LEFT)
    }

    /// `state_flags` — test against [`PA_SUCCESSFUL`], [`PA_IS_BLANK`],
    /// [`PA_ZERO_SECRET`].
    #[must_use]
    pub const fn state_flags(&self) -> u32 {
        self.word(Self::OFF_STATE_FLAGS)
    }

    /// Pointer for the gate. Private, and ARM-only: handing a raw pointer to
    /// this buffer to anything but the one selector-18 wrapper is how an
    /// unauthorised `arg2` gets called, and off-ARM there is no gate to hand
    /// it to.
    #[cfg(target_arch = "arm")]
    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.raw.as_mut_ptr()
    }
}

impl Drop for PinAttempt {
    fn drop(&mut self) {
        // Volatile, not a plain assignment: the compiler deletes stores to a
        // local that is never read again, and this buffer holds a PIN plus (on
        // sub-calls we do not bind) 72 bytes of secret. Same reasoning as
        // `read_rng`'s buffer wipe.
        //
        // SAFETY: `self.raw` is a live, aligned, uniquely borrowed array for the
        // duration of `drop`, and the write is of the same type and size.
        unsafe { core::ptr::write_volatile(&mut self.raw, [0u8; PIN_ATTEMPT_SIZE]) };
    }
}

/// `mcu_key_usage` output (`dispatch.c:570-574`; `storage.c` slot pool).
///
/// The third irreversible resource on this unit, after RDP=2 and the SE1 brick
/// counter: there are only `NUM_MCU_KEYS = 0x2000/32 = 256` slots
/// (`secrets.h:43-44`), each `pin_change`-with-secret and each wipe burns one
/// one-way, and running out is `// no free slots. we are brick.` ->
/// `LOCKUP_FOREVER()` (`storage.c:712-718`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct McuKeyUsage {
    /// Slots still available (`buf_io+0`).
    pub avail: u32,
    /// Slots already burned (`buf_io+4`).
    pub consumed: u32,
    /// Total slots the pool ever had (`buf_io+8`), i.e. 256.
    pub total: u32,
}

/// Decode a [`SELECTOR_MCU_KEY_USAGE`] response.
///
/// The gate writes three `int`s in the order avail, consumed, total
/// (`dispatch.c:570-574`). Pure and host-tested, because a swapped pair here
/// reads as "plenty of slots left" on a unit that has almost none.
#[must_use]
pub const fn mcu_key_usage_from_words(words: [u32; 3]) -> McuKeyUsage {
    McuKeyUsage {
        avail: words[0],
        consumed: words[1],
        total: words[2],
    }
}

/// `pins.h:78`. Bad `magic_value`.
pub const EPIN_BAD_MAGIC: i32 = -102;
/// `pins.h:79`. A length field out of range.
pub const EPIN_RANGE_ERR: i32 = -103;
/// `pins.h:81`. `warmup_ae()` failed: the chip is bricked (`pins.c:748`).
/// Terminal — show and halt, never retry.
pub const EPIN_I_AM_BRICK: i32 = -105;
/// `pins.h:82`. Low-level SE failure. Coldcard's Python retries this
/// (`pincodes.py:102-106`); **we must not**, because on the login sub-call a
/// retry is a second counter tick from one keypress.
pub const EPIN_AE_FAIL: i32 = -106;
/// `pins.h:90`. `is_secondary` was set; the feature is gone (`pins.c:541-545`).
pub const EPIN_PRIMARY_ONLY: i32 = -114;

/// Fill `att` with the free attempt report: [`SELECTOR_PIN`] with
/// [`PIN_SUBCALL_SETUP`]. **ARM only.**
///
/// On success `att` carries `num_fails`, `attempts_left`, `state_flags` and the
/// gate's HMAC, and must be passed back verbatim to any later sub-call.
///
/// Called from nothing in this crate. Its only caller today is the bench
/// procedure; wiring it into `boot()` needs the UART4/I2C2 question in the
/// module docs answered first, because this sub-call runs `warmup_ae()` ->
/// `ae_setup()`.
///
/// # Errors
///
/// [`Errno::FORBIDDEN_SUBCALL`] if the sub-call constant has been changed to
/// anything not [`SubCallCost::Free`] (no call is made), any [`Errno`] from
/// [`call`], or a negative `EPIN_*` — notably [`EPIN_I_AM_BRICK`], which is
/// terminal.
#[cfg(target_arch = "arm")]
pub fn pin_setup_attempt(att: &mut PinAttempt) -> Result<(), Errno> {
    // The refusal, before the call. Cheap, and it is what stops a future
    // "just change the constant" edit from reaching the brick counter.
    check_pin_subcall(PIN_SUBCALL_SETUP)?;

    // SAFETY: `att.raw` is a live, 4-byte-aligned 280-byte allocation uniquely
    // borrowed for this call, which is what the gate's `(pinAttempt_t *)buf_io`
    // cast requires (dispatch.c:344); if it is on the stack `validate_buf`
    // inside `call` accepts it, and if it is not it refuses rather than
    // returning EPERM from the firewall. `PIN_SUBCALL_SETUP` is the sub-call
    // just checked to be Free, and `pin_setup_attempt` returns on every path
    // (pins.c:531-592) except a genuine SE authentication failure, which
    // `fatal_mitm()`s inside the gate and is not interceptable (module docs).
    unsafe {
        call(
            SELECTOR_PIN,
            att.as_mut_ptr(),
            PIN_ATTEMPT_SIZE as u32,
            PIN_ATTEMPT_SIZE,
            PIN_SUBCALL_SETUP,
        )
    }
}

/// Read SE1's raw monotonic `Counter[0]` ([`SELECTOR_OTP`] /
/// [`OTP_SUBCALL_READ_COUNTER0`]). **ARM only.**
///
/// Free, and the honest way to check whether anything we called ticked the brick
/// counter: read it, do the thing, read it again. Compare against
/// [`COUNTER0_MAX`].
///
/// Do **not** derive `attempts_left` from this — that is the bootloader's
/// subtraction against a `& ~31` match target (`pins.c:483-491`), and
/// reproducing it here would be an unchecked subtraction in release.
///
/// # Errors
///
/// `EIO` if `ae_get_counter` fails (`dispatch.c:481`), or any [`Errno`] from
/// [`call`].
#[cfg(target_arch = "arm")]
pub fn read_counter0() -> Result<u32, Errno> {
    // A `u32` local, not `[u8; 4]`: the gate casts the buffer to `uint32_t *`
    // (dispatch.c:481), so it must be 4-byte aligned, and a `u32` is aligned by
    // construction. Stack, not `static`: `good_addr` requires
    // [SRAM_BASE, BL_SRAM_BASE) and returns EPERM for flash (dispatch.c:48-56).
    let mut counter = 0u32;

    // SAFETY: `counter` is a live, aligned, uniquely borrowed 4-byte stack
    // allocation, which is exactly `REQUIRE_OUT(4)` (dispatch.c:478); selector
    // 21 arg2=3 only reads a counter and returns (dispatch.c:476-483).
    unsafe {
        call(
            SELECTOR_OTP,
            (&raw mut counter).cast::<u8>(),
            COUNTER0_BUF_LEN as u32,
            COUNTER0_BUF_LEN,
            OTP_SUBCALL_READ_COUNTER0,
        )?;
    }

    // No byte swap: `ae_get_counter` writes a native `uint32_t` and both sides
    // are little-endian ARM.
    Ok(counter)
}

/// Read the mcu key slot budget ([`SELECTOR_MCU_KEY_USAGE`]). **ARM only.**
///
/// Free. Worth reading before anything that could consume a slot, and worth
/// recording at the bench: the pool is 256 slots for the life of the unit and
/// exhausting it is a permanent `LOCKUP_FOREVER` (see [`McuKeyUsage`]).
///
/// # Errors
///
/// Any [`Errno`] from [`call`].
#[cfg(target_arch = "arm")]
pub fn read_mcu_key_usage() -> Result<McuKeyUsage, Errno> {
    // `[u32; 3]`, so the buffer is 4-byte aligned for the gate's three `int *`
    // casts (dispatch.c:570-574) and is 12 bytes -- MCU_KEY_USAGE_BUF_LEN, NOT
    // the gate's own under-declared REQUIRE_OUT(8).
    let mut words = [0u32; 3];

    // SAFETY: 12 live, aligned, uniquely borrowed stack bytes, which covers all
    // three ints the gate writes; selector 25 only reads the slot pool and
    // returns (dispatch.c:565-577) and ignores arg2, so 0 is as good as any.
    unsafe {
        call(
            SELECTOR_MCU_KEY_USAGE,
            words.as_mut_ptr().cast::<u8>(),
            MCU_KEY_USAGE_BUF_LEN as u32,
            MCU_KEY_USAGE_BUF_LEN,
            0,
        )?;
    }

    Ok(mcu_key_usage_from_words(words))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A buffer address inside `[SRAM_BASE, BL_SRAM_BASE)`. Never dereferenced —
    /// `validate_buf` is pure address arithmetic, which is exactly why it can be
    /// tested on the host at all.
    const IN_SRAM: *const u8 = memmap::SRAM_BASE as *const u8;

    #[test]
    fn source_byte_counts_and_arg2_match_dispatch_c() {
        // dispatch.c:583-588 (SE1 => 32) and :590-594 (SE2 => 8).
        assert_eq!(RngSource::Se1.byte_count(), 32);
        assert_eq!(RngSource::Se2.byte_count(), 8);
        // arg2 is the `case` label, not the byte count (dispatch.c:583, :590).
        assert_eq!(RngSource::Se1.arg2(), 1);
        assert_eq!(RngSource::Se2.arg2(), 2);
        // Both payloads must fit the 33-byte REQUIRE_OUT buffer with the length
        // byte at [0]; if a future source broke this, parse_rng_response would
        // start rejecting valid reads.
        for s in [RngSource::Se1, RngSource::Se2] {
            assert!((s.byte_count() as usize) < RNG_BUF_LEN);
        }
    }

    #[test]
    fn validate_buf_accepts_only_sram() {
        assert_eq!(validate_buf(IN_SRAM, RNG_BUF_LEN, RNG_BUF_LEN), Ok(()));

        // A `static` in flash: good_addr returns EPERM for a writable buffer
        // (dispatch.c:53-55). Refusing here saves a pointless firewall transit.
        assert_eq!(
            validate_buf(memmap::FLASH_TEXT_BASE as *const u8, 33, 33),
            Err(BufFault::NotInSram)
        );
        // Below SRAM.
        assert_eq!(
            validate_buf((memmap::SRAM_BASE - 1) as *const u8, 1, 0),
            Err(BufFault::NotInSram)
        );
        // At BL_SRAM_BASE: the gate wipes that 8K on entry AND exit
        // (startup.S:124-134,148-156), so a buffer there is destroyed by the very
        // call meant to fill it. `good_addr` uses `<=` so ending exactly at
        // BL_SRAM_BASE is legal, but starting there is not.
        assert_eq!(
            validate_buf(memmap::BL_SRAM_BASE as *const u8, 1, 0),
            Err(BufFault::NotInSram)
        );
        assert_eq!(
            validate_buf((memmap::BL_SRAM_BASE - 4) as *const u8, 4, 0),
            Ok(())
        );
        assert_eq!(
            validate_buf((memmap::BL_SRAM_BASE - 4) as *const u8, 5, 0),
            Err(BufFault::NotInSram)
        );
    }

    #[test]
    fn validate_buf_length_rules() {
        assert_eq!(validate_buf(IN_SRAM, 0, 0), Err(BufFault::BadLength));
        assert_eq!(
            validate_buf(IN_SRAM, MAX_GATE_LEN as usize, 0),
            Ok(()),
            "dispatch.c:114 rejects len_in > 1024, so 1024 itself is legal"
        );
        assert_eq!(
            validate_buf(IN_SRAM, MAX_GATE_LEN as usize + 1, 0),
            Err(BufFault::BadLength)
        );
        assert_eq!(
            validate_buf(IN_SRAM, 32, RNG_BUF_LEN),
            Err(BufFault::TooShortForSelector),
            "selector 26 does REQUIRE_OUT(33) (dispatch.c:580)"
        );
    }

    /// The wrap `good_addr` is vulnerable to and we are not: on a 32-bit target
    /// `x + len` can overflow, making a huge length look contained.
    #[test]
    fn validate_buf_does_not_wrap_on_huge_length() {
        assert_eq!(
            validate_buf(IN_SRAM, usize::MAX, 0),
            Err(BufFault::BadLength)
        );
        // A pointer at the very top of the address space with a LEGAL length:
        // `start + len` wraps to a small number, which under `good_addr`'s
        // unchecked `x + len <= BL_SRAM_BASE` would look contained. This case is
        // why `validate_buf` uses `checked_add` -- an earlier draft used plain
        // `+` and this assertion is what caught it (`overflow-checks = false` in
        // release means the device would have wrapped silently).
        assert_eq!(
            validate_buf(usize::MAX as *const u8, 2, 0),
            Err(BufFault::NotInSram)
        );
        assert_eq!(
            validate_buf((usize::MAX - 8) as *const u8, MAX_GATE_LEN as usize, 0),
            Err(BufFault::NotInSram)
        );
    }

    /// Build a well-formed selector-26 response for `source`.
    fn good_response(source: RngSource) -> [u8; RNG_BUF_LEN] {
        let mut buf = [0u8; RNG_BUF_LEN];
        buf[0] = source.byte_count();
        for (i, b) in buf[1..=source.byte_count() as usize].iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(1);
        }
        buf
    }

    #[test]
    fn parse_rng_response_happy_path() {
        for source in [RngSource::Se1, RngSource::Se2] {
            let buf = good_response(source);
            let mut out = [0u8; 32];
            let n = source.byte_count() as usize;
            assert_eq!(parse_rng_response(source, &buf, &mut out[..n]), Ok(()));
            assert_eq!(&out[..n], &buf[1..1 + n]);
            // Nothing past the requested length is touched.
            assert!(out[n..].iter().all(|&b| b == 0));
        }
    }

    #[test]
    fn parse_rng_response_rejects_wrong_lengths() {
        let buf = good_response(RngSource::Se1);

        // out too short / too long: SE1 promises exactly 32.
        assert_eq!(
            parse_rng_response(RngSource::Se1, &buf, &mut [0u8; 31]),
            Err(Errno::SHORT_READ)
        );
        assert_eq!(
            parse_rng_response(RngSource::Se1, &buf, &mut [0u8; 33]),
            Err(Errno::SHORT_READ)
        );

        // The SE2 count in an SE1 response: the gate wrote 32 at buf[0], so
        // asking for SE2's 8 must fail rather than silently truncate.
        assert_eq!(
            parse_rng_response(RngSource::Se2, &buf, &mut [0u8; 8]),
            Err(Errno::SHORT_READ)
        );

        // buf[0] lying about the count.
        let mut lying = buf;
        lying[0] = 8;
        assert_eq!(
            parse_rng_response(RngSource::Se1, &lying, &mut [0u8; 32]),
            Err(Errno::SHORT_READ)
        );
        lying[0] = 0xff;
        assert_eq!(
            parse_rng_response(RngSource::Se1, &lying, &mut [0u8; 32]),
            Err(Errno::SHORT_READ)
        );
    }

    /// A short `buf` must be an error, never a panic: `parse_rng_response` runs
    /// on the device where a panic is a reset loop.
    #[test]
    fn parse_rng_response_never_panics_on_short_buf() {
        // `#![no_std]` crate, so no `vec!`: sub-slice a fixed array instead.
        let full = [0xa5u8; RNG_BUF_LEN];
        for len in 0..RNG_BUF_LEN {
            let buf = &full[..len];
            for source in [RngSource::Se1, RngSource::Se2] {
                let mut out = [0u8; 32];
                let n = source.byte_count() as usize;
                assert_eq!(
                    parse_rng_response(source, buf, &mut out[..n]),
                    Err(Errno::SHORT_READ),
                    "buf len {len} source {source:?}"
                );
            }
        }
        // Empty out slice too.
        assert_eq!(
            parse_rng_response(RngSource::Se1, &[], &mut []),
            Err(Errno::SHORT_READ)
        );
    }

    /// The check Coldcard's own path omits: it asserts `rv == 0` then trusts the
    /// bytes (callgate.py:116-122) and `mk4.py:43-44` hashes them unexamined.
    #[test]
    fn parse_rng_response_rejects_degenerate_payloads() {
        for source in [RngSource::Se1, RngSource::Se2] {
            let n = source.byte_count() as usize;
            let mut out = [0u8; 32];
            for fill in [0x00u8, 0xff] {
                let mut buf = [fill; RNG_BUF_LEN];
                buf[0] = source.byte_count();
                assert_eq!(
                    parse_rng_response(source, &buf, &mut out[..n]),
                    Err(Errno::SHORT_READ),
                    "all-{fill:#02x} payload must be refused"
                );
            }
            // One differing byte is enough to pass the degenerate check -- this
            // is a stuck-bus detector, not an entropy estimator. `crate::rng`
            // does the real per-source health checks.
            let mut buf = [0x00u8; RNG_BUF_LEN];
            buf[0] = source.byte_count();
            buf[1] = 0x01;
            assert_eq!(parse_rng_response(source, &buf, &mut out[..n]), Ok(()));
        }
    }

    #[test]
    fn errno_round_trips_and_is_nonzero() {
        assert_eq!(Errno::from_raw(0), None, "0 is success (dispatch.c:699)");
        assert_eq!(Errno::from_raw(1).map(Errno::get), Some(1));
        // Negative rv (Coldcard's own `rv = -2` sentinel, modckcc.c:71) must not
        // be mistaken for success.
        assert_eq!(Errno::from_raw(-2).map(Errno::get), Some(0xFFFF_FFFE));
        for e in [
            Errno::BAD_GATE,
            Errno::BAD_BUFFER,
            Errno::SHORT_READ,
            Errno::FORBIDDEN_SUBCALL,
            Errno::BAD_PIN_LEN,
        ] {
            assert_ne!(e.get(), 0);
            // Our own codes are in a high private range so they cannot collide
            // with the gate's small positive errno.h values.
            assert_eq!(e.get() & 0xFFFF_0000, 0xC500_0000);
        }
        // Niche optimisation: NonZeroU32 makes Result<(), Errno> word-sized.
        assert_eq!(
            core::mem::size_of::<Result<(), Errno>>(),
            core::mem::size_of::<u32>()
        );
    }

    #[test]
    fn enter_dfu_arg2_is_pinned_to_zero() {
        // Guards the correction to DECISIONS.md decision 6 step 4 / PLAN.md
        // §6.2 step 4. arg2=2 reaches `if(secure) LOCKUP_FOREVER()`
        // (dispatch.c:174-177,191-193) and never returns; arg2=3 forces
        // secure=true (dispatch.c:181). If anyone "restores" the documented
        // "0 then 2", this fails.
        assert_eq!(ENTER_DFU_ARG2_SAFE, 0);
        assert_eq!(SELECTOR_ENTER_DFU, 2);
        assert_eq!(SELECTOR_READ_RNG, 26);
        assert_eq!(GATE_ENTRY_LOW_BYTE, 0x05);
        assert_eq!(BOOTLOADER_TABLE as usize, 0x0800_0040);
    }

    /// On the host `with_irq_off` must be a transparent call, or the pure logic
    /// above it would not be host-testable at all.
    #[test]
    fn with_irq_off_is_transparent_on_host() {
        let mut side_effect = 0;
        let out = with_irq_off(|| {
            side_effect += 1;
            7u32
        });
        assert_eq!((out, side_effect), (7, 1));
    }

    // -----------------------------------------------------------------------
    // PIN surface. Nothing below calls the gate: these cover the marshalling,
    // the classification and the refusals, all of which are `cfg`-free
    // precisely so they are covered at all (PLAN.md §9 item 22).
    //
    // Selector constants are asserted with the LITERAL FIRST -- `assert_eq!(18,
    // SELECTOR_PIN)` -- so this file never contains the text `SELECTOR_PIN`
    // followed by a comma outside the one real call site that
    // `no_counted_or_destructive_selector_is_reachable_from_this_module` counts.
    // -----------------------------------------------------------------------

    /// MUTATION TARGET: change any selector or arg2 constant and this fails.
    #[test]
    fn pin_and_counter_selectors_match_dispatch_c() {
        assert_eq!(18, SELECTOR_PIN, "dispatch.c:341");
        assert_eq!(0, PIN_SUBCALL_SETUP, "dispatch.c:347-349");
        assert_eq!(21, SELECTOR_OTP, "dispatch.c:441");
        assert_eq!(3, OTP_SUBCALL_READ_COUNTER0, "dispatch.c:476");
        assert_eq!(25, SELECTOR_MCU_KEY_USAGE, "dispatch.c:565");

        // REQUIRE_OUT values. 12 is deliberately NOT the gate's own
        // REQUIRE_OUT(8) (dispatch.c:568): the body writes three ints, at +0, +4
        // and +8 (dispatch.c:570-574).
        assert_eq!(280, PIN_ATTEMPT_SIZE, "pins.h:71-72, 176+72+32");
        assert_eq!(4, COUNTER0_BUF_LEN, "dispatch.c:478");
        assert_eq!(12, MCU_KEY_USAGE_BUF_LEN, "dispatch.c:570-574 write 3 ints");

        // Every buffer we pass must be acceptable to the gate's length check.
        for len in [PIN_ATTEMPT_SIZE, COUNTER0_BUF_LEN, MCU_KEY_USAGE_BUF_LEN] {
            assert_eq!(validate_buf(IN_SRAM, len, len), Ok(()), "len {len}");
            assert!(len as u32 <= MAX_GATE_LEN);
        }

        assert_eq!(0x2eaf_6312, PA_MAGIC_V2, "pins.h:37");
        assert_eq!(32, MAX_PIN_LEN, "pins.h:16");
        assert_eq!(0x001f_ffff, COUNTER0_MAX, "dispatch.c:477");
        // Flag bits, pins.h:41-45.
        assert_eq!((0x01, 0x02, 0x10), (PA_SUCCESSFUL, PA_IS_BLANK, PA_ZERO_SECRET));
    }

    /// The classification is the security property of this module. Enumerated
    /// against `dispatch.c:346-383` case by case, including the `default`.
    #[test]
    fn pin_subcall_cost_classifies_every_dispatch_case() {
        use SubCallCost::{Absent, Counted, Destructive, Free};

        assert_eq!(pin_subcall_cost(0), Free, "pin_setup_attempt");
        assert_eq!(pin_subcall_cost(1), Free, "pin_delay is `return 0;`");
        assert_eq!(pin_subcall_cost(2), Counted, "THE login attempt: slot 4");
        assert_eq!(pin_subcall_cost(3), Destructive, "pin_change");
        assert_eq!(pin_subcall_cost(4), Counted, "needs a prior counted login");
        for arg2 in [5u32, 6, 7, 8] {
            assert_eq!(pin_subcall_cost(arg2), Destructive, "arg2 {arg2}");
        }
        // dispatch.c:380-382 `default: rv = ENOENT`.
        for arg2 in [9u32, 10, 255, 0x8000_0000, u32::MAX] {
            assert_eq!(pin_subcall_cost(arg2), Absent, "arg2 {arg2}");
        }
    }

    /// The refusal itself: fail-closed for everything that is not `Free`,
    /// including sub-calls that do not exist.
    #[test]
    fn check_pin_subcall_refuses_everything_but_free() {
        assert_eq!(check_pin_subcall(PIN_SUBCALL_SETUP), Ok(()));
        assert_eq!(check_pin_subcall(1), Ok(()));
        for arg2 in [2u32, 3, 4, 5, 6, 7, 8, 9, u32::MAX] {
            assert_eq!(
                check_pin_subcall(arg2),
                Err(Errno::FORBIDDEN_SUBCALL),
                "arg2 {arg2} must be refused before any call is made"
            );
        }
        // Exhaustive over the whole arg2 space would be 2^32; the boundary plus
        // the enumerated cases above is the same coverage, since
        // `pin_subcall_cost` is a match on literals with one catch-all.
    }

    /// The ABI contract. `176` in `PIN_ATTEMPT_SIZE_V2` (pins.h:71) IS the
    /// `secret` offset, and that identity is what proves the preceding fields
    /// carry no padding on a 4-byte-`int` target.
    #[test]
    fn pin_attempt_offsets_match_pins_h() {
        assert_eq!(core::mem::size_of::<PinAttempt>(), 280);
        assert_eq!(core::mem::size_of::<PinAttempt>(), PIN_ATTEMPT_SIZE);
        assert_eq!(
            core::mem::align_of::<PinAttempt>(),
            4,
            "the gate casts the buffer to `pinAttempt_t *` and reads u32 fields"
        );

        // Summed field-by-field from pins.h:96-117.
        assert_eq!(PinAttempt::OFF_MAGIC, 0);
        assert_eq!(PinAttempt::OFF_PIN, 8);
        assert_eq!(PinAttempt::OFF_PIN_LEN, 40);
        assert_eq!(PinAttempt::OFF_NUM_FAILS, 52);
        assert_eq!(PinAttempt::OFF_ATTEMPTS_LEFT, 56);
        assert_eq!(PinAttempt::OFF_STATE_FLAGS, 60);
        assert_eq!(PinAttempt::OFF_HMAC, 68);
        assert_eq!(PinAttempt::OFF_SECRET, 176);
        assert_eq!(PinAttempt::OFF_CACHED_MAIN_PIN, 248);

        // The two independent derivations of the size must agree: 176 + 72 + 32.
        assert_eq!(PinAttempt::OFF_SECRET + 72 + 32, PIN_ATTEMPT_SIZE);
        assert_eq!(PinAttempt::OFF_CACHED_MAIN_PIN + 32, PIN_ATTEMPT_SIZE);
        assert_eq!(
            PinAttempt::OFF_SECRET,
            PinAttempt::OFF_CACHED_MAIN_PIN - 72
        );
        // No offset can read past the buffer.
        for off in [
            PinAttempt::OFF_MAGIC,
            PinAttempt::OFF_PIN_LEN,
            PinAttempt::OFF_NUM_FAILS,
            PinAttempt::OFF_ATTEMPTS_LEFT,
            PinAttempt::OFF_STATE_FLAGS,
        ] {
            assert!(off + 4 <= PIN_ATTEMPT_SIZE, "offset {off}");
        }
        // The PIN field abuts pin_len exactly: 8 + 32 == 40, no padding.
        assert_eq!(PinAttempt::OFF_PIN + MAX_PIN_LEN, PinAttempt::OFF_PIN_LEN);
    }

    /// `pin_len` is written from a bounded `usize`, so the negative value the
    /// gate would happily `memcpy` (pins.c:396 checks only the upper bound
    /// against a signed int, pins.c:549-551 then copies it) cannot be encoded.
    #[test]
    fn pin_len_is_bounded_to_max_and_never_negative() {
        for len in 0..=MAX_PIN_LEN {
            let pin = [b'1'; MAX_PIN_LEN];
            let att = PinAttempt::new(&pin[..len]).expect("<= MAX_PIN_LEN is legal");
            assert_eq!(att.magic(), PA_MAGIC_V2);
            assert_eq!(att.pin_len(), len as u32, "len {len}");
            // The signed reading the gate does must also be in range.
            assert!(att.pin_len() as i32 >= 0);
            assert!(att.pin_len() as i32 <= MAX_PIN_LEN as i32);
            assert_eq!(&att.raw[PinAttempt::OFF_PIN..][..len], &pin[..len]);
            // Nothing past the PIN is touched, so is_secondary and change_flags
            // stay 0 (EPIN_PRIMARY_ONLY / EPIN_RANGE_ERR otherwise).
            assert!(att.raw[PinAttempt::OFF_PIN + len..PinAttempt::OFF_PIN_LEN]
                .iter()
                .all(|&b| b == 0));
            assert!(att.raw[PinAttempt::OFF_PIN_LEN + 4..]
                .iter()
                .all(|&b| b == 0));
            assert_eq!((att.num_fails(), att.attempts_left(), att.state_flags()), (0, 0, 0));
        }
        // Refused, not truncated, not clamped.
        assert_eq!(
            PinAttempt::new(&[b'1'; MAX_PIN_LEN + 1]).err(),
            Some(Errno::BAD_PIN_LEN)
        );
        assert_eq!(PinAttempt::new(&[0u8; 1024]).err(), Some(Errno::BAD_PIN_LEN));
    }

    /// MUTATION TARGET: swap any two offsets in the readers and this fails.
    /// A swapped `num_fails`/`attempts_left` would report 13 attempts left on a
    /// unit with none.
    #[test]
    fn pin_attempt_readers_decode_the_right_little_endian_fields() {
        // Hand-built response: distinct values so a swap cannot pass.
        let mut raw = [0u8; PIN_ATTEMPT_SIZE];
        raw[PinAttempt::OFF_MAGIC..][..4].copy_from_slice(&PA_MAGIC_V2.to_le_bytes());
        raw[PinAttempt::OFF_PIN_LEN..][..4].copy_from_slice(&6u32.to_le_bytes());
        raw[PinAttempt::OFF_NUM_FAILS..][..4].copy_from_slice(&11u32.to_le_bytes());
        raw[PinAttempt::OFF_ATTEMPTS_LEFT..][..4].copy_from_slice(&13u32.to_le_bytes());
        raw[PinAttempt::OFF_STATE_FLAGS..][..4]
            .copy_from_slice(&(PA_SUCCESSFUL | PA_ZERO_SECRET).to_le_bytes());
        // Fill the HMAC and secret with 0xff: a reader straying into either
        // would report a huge value rather than the small one asserted below.
        raw[PinAttempt::OFF_HMAC..][..32].fill(0xff);
        raw[PinAttempt::OFF_SECRET..].fill(0xff);

        let att = PinAttempt { raw };
        assert_eq!(att.magic(), PA_MAGIC_V2);
        assert_eq!(att.pin_len(), 6);
        assert_eq!(att.num_fails(), 11);
        assert_eq!(att.attempts_left(), 13);
        assert_eq!(att.state_flags(), PA_SUCCESSFUL | PA_ZERO_SECRET);
        assert_eq!(att.state_flags() & PA_IS_BLANK, 0);
        assert_ne!(att.state_flags() & PA_ZERO_SECRET, 0);

        // Little-endian, not big: a byte-swapped decoder reads 13 as 0x0d000000.
        assert_eq!(att.attempts_left(), 13);
        assert!(att.attempts_left() < 0x1_0000);
    }

    /// MUTATION TARGET: swap two fields in `mcu_key_usage_from_words` and this
    /// fails. A swapped avail/consumed reads as "plenty of slots" on a unit that
    /// is nearly out, and running out is a permanent LOCKUP_FOREVER.
    #[test]
    fn mcu_key_usage_word_order_matches_dispatch_c() {
        // dispatch.c:570-574: avail at +0, consumed at +4, total at +8.
        let u = mcu_key_usage_from_words([7, 249, 256]);
        assert_eq!(u.avail, 7);
        assert_eq!(u.consumed, 249);
        assert_eq!(u.total, 256);
        // secrets.h:43-44 -- 0x2000/32. Sanity, not an assertion about silicon.
        assert_eq!(u.avail + u.consumed, u.total);
        assert_eq!(u.total, 0x2000 / 32);
    }

    /// MUTATION TARGET: mis-decode an error return. The PIN layer's codes are
    /// negative ints (pins.h:76-92) while `errno.h` codes are small positives;
    /// comparing the wrong signedness, or pointing `is_brick_report` at the
    /// wrong constant, fails here.
    #[test]
    fn pin_error_codes_decode_to_pins_h_values() {
        for want in [
            EPIN_BAD_MAGIC,
            EPIN_RANGE_ERR,
            EPIN_I_AM_BRICK,
            EPIN_AE_FAIL,
            EPIN_PRIMARY_ONLY,
        ] {
            let e = Errno::from_raw(want).expect("EPIN codes are all nonzero");
            assert_eq!(e.signed(), want, "round trip");
            // As a u32 they are huge, which is why nothing may compare them
            // unsigned against a threshold.
            assert!(e.get() > 0xFFFF_0000, "{want} as u32 is {:#x}", e.get());
            assert_eq!(e.is_brick_report(), want == EPIN_I_AM_BRICK);
        }
        // The literal values, so a "tidy-up" of the constants fails.
        assert_eq!(
            (
                EPIN_BAD_MAGIC,
                EPIN_RANGE_ERR,
                EPIN_I_AM_BRICK,
                EPIN_AE_FAIL,
                EPIN_PRIMARY_ONLY
            ),
            (-102, -103, -105, -106, -114)
        );
        // A positive errno.h code is not a brick report, and neither is success
        // or one of our own refusals.
        for e in [1i32, 2, 13, 34] {
            let e = Errno::from_raw(e).expect("nonzero");
            assert!(!e.is_brick_report());
        }
        assert!(!Errno::BAD_GATE.is_brick_report());
        assert!(!Errno::FORBIDDEN_SUBCALL.is_brick_report());
        // Our private range cannot collide with an EPIN code.
        for ours in [Errno::FORBIDDEN_SUBCALL, Errno::BAD_PIN_LEN] {
            assert_ne!(ours.signed(), EPIN_I_AM_BRICK);
            assert_eq!(ours.get() & 0xFFFF_0000, 0xC500_0000);
        }
    }

    /// The floor that must be in place before any counted sub-call exists.
    /// Comparison only: `overflow-checks = false` in release, so a decrementing
    /// counter would wrap silently on the device.
    #[test]
    fn login_attempt_floor_refuses_the_last_attempts() {
        assert_eq!(ATTEMPTS_LEFT_FLOOR, 2);
        // 0 is "already a brick" (pins.c:488-490).
        assert!(!login_attempt_permitted(0));
        assert!(!login_attempt_permitted(1));
        assert!(!login_attempt_permitted(ATTEMPTS_LEFT_FLOOR));
        assert!(login_attempt_permitted(ATTEMPTS_LEFT_FLOOR + 1));
        // A healthy unit re-arms 13 (MAX_TARGET_ATTEMPTS, pins.c:28).
        assert!(login_attempt_permitted(13));
        // No arithmetic to wrap, at either extreme.
        assert!(login_attempt_permitted(u32::MAX));
    }

    /// Source-reading guard. The bindings above live partly inside
    /// `cfg(target_arch = "arm")`, which **no gate in this project compiles**
    /// (PLAN.md §9 item 22), so the only way to enforce "we bound nothing
    /// counted or destructive" is to read the file.
    ///
    /// Only the production half of the file is searched — the source is cut at
    /// the `cfg(test)` attribute — so the needles below cannot match this test's
    /// own text and self-trip.
    ///
    /// If you are here because this test failed: it is not in your way, it is
    /// the review. Binding a `Counted` or `Destructive` sub-call needs a bench
    /// session on an expendable unit and a decision, not an edit.
    #[test]
    fn no_counted_or_destructive_selector_is_reachable_from_this_module() {
        let src = include_str!("callgate.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("split always yields at least one part");
        assert!(
            src.contains("pub fn read_mcu_key_usage") && !src.contains("fn pin_error_codes"),
            "the cut must keep all production code and drop the test module"
        );

        // Exactly one selector-18 call site, and it passes the free sub-call.
        assert_eq!(
            src.matches("SELECTOR_PIN,").count(),
            1,
            "selector 18 must have exactly ONE call site in this file"
        );
        assert_eq!(
            src.matches("PIN_SUBCALL_SETUP,").count(),
            1,
            "the one selector-18 call site must pass the free sub-call"
        );

        // The refusal must still be invoked, not merely defined. Two hits:
        // the `pub fn` and the one call site inside the ARM wrapper.
        assert_eq!(
            src.matches("check_pin_subcall(").count(),
            2,
            "check_pin_subcall must be defined once and called once"
        );

        // Identifiers and magic values for things nothing here may ever call:
        // selector 23 (fast wipe, arg2 0xBeef), 24 (fast brick, arg2 0xDead --
        // destroys the pairing secret permanently), 19/1 and 19/100-102 (bag
        // number, flash lockdown), 21/2 (OTP highwater), 22 (trick PINs; the
        // gate wipes the mcu key before it even looks at arg2), 3 (never
        // returns), and selector 18's six unsafe sub-calls.
        for frag in [
            "0xDead",
            "0xDEAD",
            "0xBeef",
            "0xBEEF",
            "SELECTOR_TRICK",
            "SELECTOR_LOCKDOWN",
            "SELECTOR_LOGOUT",
            "SELECTOR_BAG",
            "SELECTOR_HIGHWATER",
            "PIN_SUBCALL_LOGIN",
            "PIN_SUBCALL_CHANGE",
            "PIN_SUBCALL_FETCH",
            "PIN_SUBCALL_GREENLIGHT",
            "PIN_SUBCALL_UPGRADE",
            "PIN_SUBCALL_LONG_SECRET",
        ] {
            assert!(
                !src.contains(frag),
                "forbidden token `{frag}` present in callgate.rs"
            );
        }

        // The PIN buffer must still be wiped on the way out: it holds a PIN.
        assert!(src.contains("impl Drop for PinAttempt"));
    }
}
