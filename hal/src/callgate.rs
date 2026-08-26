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
    // SAFETY (the asm block itself): `dest` was just verified to be the gate
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
        for e in [Errno::BAD_GATE, Errno::BAD_BUFFER, Errno::SHORT_READ] {
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
}
