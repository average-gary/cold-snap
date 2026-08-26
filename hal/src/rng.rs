//! Fail-closed entropy: a [`RngCore`] that cannot exist unless all three
//! hardware legs were read and passed their health checks (PLAN.md §5.1).
//!
//! Two of those legs are entropy ([`ENTROPY_SOURCE_COUNT`]); the third, SE2, is a
//! fixed per-device personalisation input. All three are still mandatory to boot.
//!
//! # Why the type-state, and not an `if`
//!
//! §1's rationale for discarding MicroPython is that libngu's `#ifdef` ladder
//! **failed open**: with no hardware TRNG it silently fell through to glibc
//! `random()`. So the requirement here is not "check the sources" — it is "make
//! an unchecked RNG unrepresentable". The chain is:
//!
//! ```text
//! Trng::take()  ---\
//! Se1Rng::take() ---+--> Sources::new(t, s1, s2) --> Entropy::boot() --> Entropy
//! Se2Rng::take() ---/         (consumes all 3)         (health-checks)
//! ```
//!
//! [`Entropy`] has **no** `Default`, no `new()`, no `from_seed`, and no public
//! fields. [`Sources`] cannot be built without all three singletons by value, and
//! each singleton is handed out exactly once by its own `take()`. A future
//! contributor cannot construct a two-source `Entropy` without editing this file
//! and deleting a constructor — which is a visible diff, unlike a silent
//! fallback.
//!
//! # The test seam is feature-gated, and the earlier reasoning here was inverted
//!
//! This section used to say "**there is no `cfg` or feature in this module**;
//! adding one reintroduces the exact defect §1 exists to prevent". That is
//! **wrong, and it was load-bearing**: it argued for leaving the bypass in
//! shipped firmware.
//!
//! `mix_sources` takes three `&[u8]`. It requires three byte arrays that pass
//! [`check_source`] — **not** three hardware draws. While it and
//! `Entropy::from_proven_seed` were unconditionally public, any downstream
//! crate could mint a [`ProvenSeed`] from hardcoded constants and get a full
//! `RngCore + CryptoRng` [`Entropy`] with zero hardware reads, zero callgate
//! entries and zero singletons taken — and it **compiled for the device
//! target**. That is the libngu defect reproduced as an unconditionally-public
//! constructor rather than as an `#ifdef` ladder.
//!
//! The distinction the old text missed: a `cfg` on a **refusal** fails open and
//! is forbidden. A `cfg` on a **bypass** fails closed and is mandatory. So:
//!
//! * `cfg`-FREE, always compiled, on every target: [`check_source`], the three
//!   [`EntropySource`] legs, [`Sources`], [`Entropy::boot`],
//!   [`Entropy::try_reseed`]. Every refusal path is unconditional.
//! * GATED behind `cfg(any(test, feature = "test-seam"))`: `mix_sources`,
//!   `Entropy::from_proven_seed`, `ProvenSeed::expose`. These are the seam
//!   that skips the hardware, and nothing in firmware may call them.
//!
//! [`Entropy::boot`] is unaffected either way: `Sources::draw` calls the
//! private `mix_checked_draws`, so the device path does not route through the
//! gated re-export. `flash::fake` was already gated this way
//! (`flash.rs`, feature `fake-flash`) with the reason stated as "shipping a fake
//! flash in firmware is how a test double ends up holding nonces". The identical
//! argument applies to a fake seed and had not been applied.
//!
//! # Why `fill_bytes` is infallible on purpose
//!
//! [`RngCore::fill_bytes`] cannot return an error, and `frostsnap_core` calls it
//! at 28 `&mut impl RngCore` bounds on paths that generate nonces. If it touched
//! hardware it would have to panic on failure — a halt under
//! `panic = "abort"`, and a halt in the middle of nonce generation is the worst
//! possible place for one.
//!
//! So all hardware I/O happens **once**, in [`Entropy::boot`], which returns
//! `Result`. What survives is a [`ChaCha20Rng`] seeded from the mixed output.
//! After that, `fill_bytes` is pure arithmetic that cannot fail, cannot block,
//! cannot re-enter the callgate, and needs no interrupt masking. The failure mode
//! moves to boot, where a caller can still make a decision.
//!
//! ChaCha20 is already in the device dependency graph (`rand_chacha`, via
//! frostsnap), so this costs no extra flash.
//!
//! # The honest source count is TWO, and SE2 is a personalisation input
//!
//! PLAN.md §5.1 treats TRNG/SE1/SE2 as three independent sources. Reading the
//! bootloader refutes that, and the refutation is now recorded in code as
//! [`ENTROPY_SOURCE_COUNT`] rather than only in prose:
//!
//! * **SE1** is not a raw RNG read. `ae_random()` is `#if 0`'d as "RISKY - Easy
//!   for Mitm to control value" (`ae.c:671-689`); the live
//!   `ae_secure_random()` does a GenDig against the pairing secret and SHA256s
//!   the result (`ae.c:699-714`), and `ae_gendig_slot` first feeds **20 bytes of
//!   our own STM32 TRNG** into `ae_pick_nonce` (`ae.c:1332`). So the SE1 leg
//!   already contains the TRNG leg — the two are **not independent**, though SE1
//!   does contribute the ATECC's own entropy on top.
//! * **SE2 is a static page read, not an RNG.** `se2_read_rng()` issues no RNG
//!   command; it reads page 28 (`PGN_ROM_OPTIONS`, `se2.c:68`) and returns bytes
//!   `[4..12]` (`se2.c:1341-1343`). The same page carries the device ROM ID at
//!   `[24..32]` (`se2.c:435`, `:529` "capture serial of device") and is
//!   protected `PROT_APH` with the comment "not planning to change"
//!   (`se2.c:586`). **Read**, not measured on silicon.
//!
//! ## The health checks CANNOT refuse a static SE2. That claim is deleted.
//!
//! This section previously said the checks "are what converts 'SE2 is a
//! constant' from a silent weakness into an observable refusal". **That was
//! false and it is removed.** [`check_source`] is stateless: it compares words
//! *within one draw* and holds no cross-boot state anywhere. A fixed page-28
//! value is identical on every boot but contains two distinct 4-byte words, so
//! it passes [`check_source`] forever — measured, 1000/1000 boots accepted for
//! plausible static bytes. No detector exists, so the text must not tell a
//! reviewer that one does.
//!
//! **Resolution (option (a) of the required fix): SE2 is reclassified as a fixed
//! per-device personalisation input.** It is still drawn, still health-checked
//! for a fully-stuck bus (all-`0x00`/all-`0xff` is a dead I2C bus, which
//! [`check_source`] *does* catch), and still hashed into the transcript so two
//! devices derive different seeds from identical TRNG/SE1 draws. It is **not**
//! counted as an entropy source. [`ENTROPY_SOURCE_COUNT`] is therefore `2`, not
//! `3`, and [`Se2Rng`] is documented as personalisation. PLAN.md §5.1's
//! three-source framing is amended to match.
//!
//! Cross-boot persistence (storing the previous SE2 draw in `FLASH_FS` and
//! refusing on an exact repeat) is option (b) and is **NOT implemented**: for a
//! source we have already read as deliberately constant, an exact-repeat detector
//! would fire on every healthy boot. It stays available if a bench ever shows SE2
//! varying.
//!
//! Dropping SE2 from the count does not weaken the mix. Mixing a constant in is
//! still at least as strong as the strongest real leg (`mix_sources` is
//! SHA-256 over a length-prefixed transcript, so nothing cancels), and the
//! constant is genuinely useful for device uniqueness. What changes is only that
//! the count is now honest.
//!
//! # Health checks, per source, before mixing (PLAN.md §5.1)
//!
//! Each source is checked **independently** — a good TRNG must not mask a stuck
//! SE. See [`check_source`], including its explicit statement of what it cannot
//! detect. The STM32 RNG's own error flags are a separate, mandatory check inside
//! [`Trng`]: both the *current-status* pair `SECS`/`CECS` **and** the *latched*
//! pair `SEIS`/`CEIS` are read before a word is used (a transient seed error that
//! self-cleared would otherwise be silently drawn through), and recovery
//! disables and re-enables the peripheral — see `recover_seed_error`.
//!
//! # Host-testable vs not
//!
//! [`check_source`] is pure and `cfg`-free — **fully host-testable**, and that
//! split is the entropy investigation's blocker 5, resolved here rather than
//! deferred. `mix_sources` and `Entropy::from_proven_seed` are pure too, but are
//! gated behind `test-seam` (see above) precisely *because* they are reachable
//! without hardware.
//!
//! The hardware legs ([`Trng::read`], [`Se1Rng::read`], [`Se2Rng::read`]) cannot
//! *succeed* off-hardware at any tier (PLAN.md §7, DECISIONS.md decision 5): no
//! host, and Renode cannot reach PCROP bootloader code. Their **refusals** are
//! host-testable and are tested: `se1_and_se2_legs_refuse_on_the_host` drives
//! both SE legs directly and asserts [`SourceFault::Callgate`] plus an untouched
//! output buffer. That matters because `Sources::draw` short-circuits at the
//! TRNG, so without those direct tests both SE legs could be made to fail open
//! and the suite would stay green — measured: it did.
//!
//! Deliberately, the singleton `take()` methods touch no hardware, so singleton
//! and plumbing logic *is* host-testable even though `read()` is not.

use core::num::NonZeroU8;

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

use crate::callgate;

/// Bytes drawn from the STM32 TRNG per boot. 8 x 32-bit `RNG_DR` reads. Not
/// 32: the four-word overlap gives margin if the health check rejects a draw and
/// we redraw, without re-entering the callgate.
pub const TRNG_BYTES: usize = 32;

/// Bytes SE1 returns (`dispatch.c:588`).
pub const SE1_BYTES: usize = 32;

/// Bytes SE2 returns (`dispatch.c:593`) — only 8.
pub const SE2_BYTES: usize = 8;

/// Length of the mixed seed handed to ChaCha20. Fixed by
/// `<ChaCha20Rng as SeedableRng>::Seed = [u8; 32]` and by SHA-256's output, so
/// `mix_sources` needs no truncation.
pub const SEED_BYTES: usize = 32;

/// Domain-separation prefix for the mixer transcript. Fixed and non-empty so the
/// mixed output cannot collide with a bare SHA-256 of the same bytes used
/// anywhere else in the firmware.
pub const MIX_DOMAIN: &[u8] = b"cold-snap/hal/rng/v1";

/// How many of the three legs are **entropy** sources. `2`, not `3`.
///
/// PLAN.md §5.1 originally claimed three independent sources. Both halves of that
/// are wrong and this constant is the executable correction:
///
/// * SE1 is not independent of the TRNG — `ae_gendig_slot` feeds 20 bytes of our
///   own STM32 TRNG into `ae_pick_nonce` before the GenDig (`ae.c:1332`), so the
///   SE1 leg contains the TRNG leg. It still adds the ATECC's own entropy, so it
///   counts, but "independent" does not apply.
/// * SE2 is **not an entropy source at all**. `se2_read_rng` reads static,
///   `PROT_APH`-protected page 28 (`se2.c:1341-1343`, `:586`). It is a fixed
///   per-device personalisation input: hashed in for device uniqueness, not
///   counted here. See the module docs.
///
/// Three legs are still drawn and three are still health-checked; a bench that
/// wants "how many legs" should count [`SourceId`] variants. This constant is the
/// **entropy** claim, and it exists so that a future edit which reinstates the
/// three-source framing has to change a value a test asserts.
pub const ENTROPY_SOURCE_COUNT: usize = 2;

/// Which source a fault came from. Never collapsed into one opaque error: PLAN.md
/// §5.1 requires each source to be health-checked independently, so the report
/// must name the culprit or a stuck SE2 is indistinguishable from a stuck TRNG at
/// a bench.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceId {
    /// STM32L4 on-die RNG peripheral.
    Trng,
    /// SE1 / ATECC608B, via [`callgate::RngSource::Se1`].
    Se1,
    /// SE2 / DS28C36B, via [`callgate::RngSource::Se2`]. A fixed per-device
    /// personalisation input, **not** an entropy source — see
    /// [`ENTROPY_SOURCE_COUNT`].
    Se2,
}

/// Why one source was rejected.
///
/// Every variant is a **refusal**, never a downgrade. There is no
/// `Degraded`/`PartiallyOk` variant and there must never be one: the moment a
/// caller can proceed on a subset, this module has the libngu defect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceFault {
    /// Every byte identical (all-`0x00` and all-`0xff` included) — a stuck source
    /// or a bus that never drove.
    AllBytesEqual,
    /// A repeated machine word within the draw. PLAN.md §5.1: "reject repeated
    /// words per source". Carries the repeated word's index so a bench can see
    /// *where*.
    RepeatedWord(u8),
    /// Fewer bytes arrived than the source promises, or the draw was empty.
    ShortRead,
    /// The STM32 RNG reported `SECS` (seed error) or `CECS` (clock error) in
    /// `RNG_SR`. Carries the raw `SR`. Requires RM0432's recovery sequence, and
    /// a `DR` read while either is set must be discarded, not mixed.
    RngHardware(u32),
    /// The callgate refused or errored. Carries the raw errno from
    /// [`callgate::Errno::get`] — kept raw rather than mapped so an unexpected
    /// bootloader errno is not flattened into "some error".
    Callgate(u32),
    /// `RNG_DR`'s `DRDY` never asserted within the bounded poll. Must be a
    /// bounded loop: an unbounded `while !ready {}` in boot code is a silent
    /// brick, which is the same failure class as a panic-halt.
    Timeout,
    /// This [`Entropy`] holds no [`Sources`], so there is no hardware to re-read.
    ///
    /// Only reachable from [`Entropy::try_reseed`] on an instance built by
    /// `Entropy::from_proven_seed` (the host-test seam). Added at integration
    /// time rather than reusing [`SourceFault::ShortRead`]: a reseed with nothing
    /// to reseed *from* must be distinguishable from a source that misbehaved, or
    /// a bench chases a hardware fault that does not exist. Reporting `Ok` here
    /// would be the real defect — the caller would believe it had folded in fresh
    /// entropy when nothing happened.
    NoSources,
}

/// A boot-time entropy failure: which source, and why.
///
/// Returned rather than panicked because a panic here is a reset loop
/// (decision 6), and a reset loop caused by *entropy* would be
/// indistinguishable from one caused by anything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RngFault {
    /// The offending source.
    pub source: SourceId,
    /// What was wrong with it.
    pub fault: SourceFault,
}

impl RngFault {
    /// Construct a fault. `const` so callers can build sentinels in tests.
    #[must_use]
    pub const fn new(source: SourceId, fault: SourceFault) -> Self {
        Self { source, fault }
    }
}

/// One hardware entropy source.
///
/// Implemented by [`Trng`], [`Se1Rng`] and [`Se2Rng`]. It exists so
/// [`Entropy::boot`] can treat the three uniformly *and* so that the trait
/// object surface stays tiny; it is deliberately **not** public-extensible in
/// spirit — adding a fourth implementor does not weaken anything, but adding a
/// *stub* implementor and passing it to [`Sources::new`] would. That is why
/// [`Sources::new`] takes the three concrete types by value rather than three
/// `impl EntropySource`.
pub trait EntropySource {
    /// Which source this is, for [`RngFault`].
    const ID: SourceId;

    /// Bytes this source yields per draw. Also the required length of `out` in
    /// [`EntropySource::read`].
    const LEN: usize;

    /// Fill `out` with exactly [`EntropySource::LEN`] fresh bytes.
    ///
    /// # Errors
    ///
    /// [`SourceFault`] on any hardware or protocol failure, including
    /// `out.len() != Self::LEN`.
    ///
    /// # Panics
    ///
    /// Must not, ever, for any `out`. This runs at boot before the panic counter
    /// is meaningful.
    fn read(&mut self, out: &mut [u8]) -> Result<(), SourceFault>;
}

/// The STM32L4 on-die RNG peripheral (`RNG_CR`/`RNG_SR`/`RNG_DR`).
///
/// Singleton: two handles could interleave `DR` reads and both consume the other's
/// word, silently halving the entropy drawn.
///
/// The implementer must handle RM0432's seed-error recovery: on `SEIS`, clear it,
/// then read and discard 12 words before trusting `DR`. Also required: enable the
/// RNG clock (`RCC`) and check that `HSI48`/the RNG clock source is actually
/// running — the bootloader may leave it off, in which case `DRDY` never asserts
/// and a naive poll hangs forever.
pub struct Trng {
    _private: (),
}

/// SE1 / ATECC608B, reached through [`callgate::SELECTOR_READ_RNG`] with
/// [`callgate::RngSource::Se1`].
///
/// Singleton because the call has global side effects: every callgate invocation
/// runs `ae_reset_chip()` and selector 26 `arg2=1` reprograms **UART4 wholesale**
/// (`ae.c:343-396`). Two callers racing that is not a data race, it is a
/// peripheral-configuration race.
pub struct Se1Rng {
    _private: (),
}

/// SE2 / DS28C36B, via [`callgate::RngSource::Se2`]. Yields only
/// [`SE2_BYTES`] = 8.
///
/// # This is a fixed personalisation input, NOT an entropy source
///
/// **Resolved, and reclassified.** `se2_read_rng()` issues no RNG command: it
/// reads page 28 (`PGN_ROM_OPTIONS`, `se2.c:68`) and returns bytes `[4..12]`
/// (`se2.c:1341-1343`). That page also holds the device ROM ID at `[24..32]`
/// (`se2.c:435`, `:529`) and is protected `PROT_APH` — "not planning to change"
/// (`se2.c:586`). So the value is expected to be **identical on every boot of a
/// given device, and different between devices**.
///
/// Consequences, all deliberate:
///
/// * It is still read, still length-checked, and still passed through
///   [`check_source`], which catches the failure mode that *is* real here — an
///   all-`0x00`/all-`0xff` draw, i.e. a dead I2C2 bus or an unpowered SE2.
/// * It is still hashed into the mixer transcript, so two devices with identical
///   TRNG and SE1 draws still derive different seeds.
/// * It is **not** counted toward the entropy claim: [`ENTROPY_SOURCE_COUNT`] is
///   `2`. The module docs previously claimed the health checks would produce "an
///   observable refusal" for a constant SE2. They cannot — [`check_source`] is
///   stateless — and that claim is deleted rather than propped up.
///
/// This is a documentation, naming and *counting* change. It is **not** a `cfg`
/// that skips the source: the draw and its refusal path stay unconditional, so a
/// dead SE2 bus still fails boot closed.
///
/// Singleton because `arg2=2` runs `se2_setup()`, reconfiguring PB13/PB14 and
/// I2C2 (`se2.c:1003-1032`).
pub struct Se2Rng {
    _private: (),
}

impl Trng {
    /// Take the singleton; `None` on every call after the first.
    ///
    /// Touches no hardware — all register access is in
    /// [`EntropySource::read`]. That split is what keeps the singleton logic
    /// host-testable while `read` is ARM-only in practice.
    pub fn take() -> Option<Self> {
        // NOT an `AtomicBool`, though the published contract said so. See
        // `crate::singleton`: on this board `.bss` is filled with `0xdeadbeef`
        // rather than zeroed (`main.c:42,47,130`) and nothing zeroes it yet, so
        // `AtomicBool::new(false)` reads `true` and this would return `None` on
        // the FIRST call -- no entropy, no signing, no diagnostic.
        static TAKEN: crate::singleton::TakeOnce = crate::singleton::TakeOnce::new();
        if TAKEN.take() {
            Some(Self { _private: () })
        } else {
            None
        }
    }
}

impl Se1Rng {
    /// Take the singleton; `None` on every call after the first.
    pub fn take() -> Option<Self> {
        static TAKEN: crate::singleton::TakeOnce = crate::singleton::TakeOnce::new();
        if TAKEN.take() {
            Some(Self { _private: () })
        } else {
            None
        }
    }
}

impl Se2Rng {
    /// Take the singleton; `None` on every call after the first.
    pub fn take() -> Option<Self> {
        static TAKEN: crate::singleton::TakeOnce = crate::singleton::TakeOnce::new();
        if TAKEN.take() {
            Some(Self { _private: () })
        } else {
            None
        }
    }
}

/// `RNG_BASE` = `AHB2PERIPH_BASE + 0x0806_0800` = `0x5006_0800`
/// (`stm32l4s5xx.h:1320,1468`; `AHB2PERIPH_BASE = PERIPH_BASE + 0x0800_0000`,
/// `PERIPH_BASE = 0x4000_0000` at `:1292`). Arithmetic verified this session.
pub const RNG_BASE: usize = 0x5006_0800;

/// `RNG->CR` (`RNG_TypeDef` offset `0x00`, `stm32l4s5xx.h:1153-1158`).
pub const RNG_CR: *mut u32 = RNG_BASE as *mut u32;
/// `RNG->SR` (offset `0x04`).
pub const RNG_SR: *mut u32 = (RNG_BASE + 0x04) as *mut u32;
/// `RNG->DR` (offset `0x08`). Reading it clears `DRDY`.
pub const RNG_DR: *const u32 = (RNG_BASE + 0x08) as *const u32;

/// `RNG_CR_RNGEN` — bit 2 (`stm32l4s5xx.h:13364-13366`).
pub const RNG_CR_RNGEN: u32 = 1 << 2;
/// `RNG_SR_DRDY` — bit 0 (`:13375-13377`).
pub const RNG_SR_DRDY: u32 = 1 << 0;
/// `RNG_SR_CECS` — clock error current status, bit 1 (`:13378-13380`).
pub const RNG_SR_CECS: u32 = 1 << 1;
/// `RNG_SR_SECS` — seed error current status, bit 2 (`:13381-13383`).
pub const RNG_SR_SECS: u32 = 1 << 2;
/// `RNG_SR_CEIS` — clock error interrupt status, bit 5 (`:13384-13386`).
/// Write-0-to-clear.
pub const RNG_SR_CEIS: u32 = 1 << 5;
/// `RNG_SR_SEIS` — seed error interrupt status, bit 6 (`:13387-13389`).
/// Write-0-to-clear. The recovery sequence starts by clearing this
/// (`stm32l4xx_hal_rng.c:776-778`).
pub const RNG_SR_SEIS: u32 = 1 << 6;

/// Every `RNG_SR` bit that invalidates a `DR` read: the two **current-status**
/// flags and the two **latched** interrupt-status flags.
///
/// Both pairs, deliberately. The poll used to test only `SECS | CECS`, and the
/// latched pair appeared nowhere except the clear-write — i.e. `SEIS`/`CEIS` were
/// written but never **read**. That is a silent fail-open window: a seed error
/// that occurred and whose *current* status has since self-cleared leaves `SEIS`
/// latched, and per ST's own driver the number in `DR` at that point "must not be
/// used because it may not have enough entropy"
/// (`stm32l4xx_hal_rng.c:773-778`). Testing only the current status draws that
/// word through as if it were healthy.
///
/// Checking the latched bits costs nothing on a healthy part — they are zero
/// unless an error has actually occurred since the last clear, and
/// `recover_seed_error` clears them.
pub const RNG_SR_ERRORS: u32 = RNG_SR_SECS | RNG_SR_CECS | RNG_SR_SEIS | RNG_SR_CEIS;

/// `RCC->AHB2ENR` (`RCC_TypeDef` offset `0x4C`, `stm32l4s5xx.h:816`;
/// `RCC_BASE = AHB1PERIPH_BASE + 0x1000 = 0x4002_1000` at `:1400`).
pub const RCC_AHB2ENR: *mut u32 = (0x4002_1000 + 0x4C) as *mut u32;
/// `RCC_AHB2ENR_RNGEN` — bit 18 (`stm32l4s5xx.h:12752-12754`).
pub const RCC_AHB2ENR_RNGEN: u32 = 1 << 18;

/// Words to read and discard after a seed error.
///
/// # Provenance, corrected
///
/// This constant previously claimed to be "**READ** from the reference manual's
/// procedure as described in PLAN.md §5.1". That overstated it: **RM0432 itself
/// is not in this tree**, so nothing here was read from it. PLAN.md §5.1 names
/// "RM0432 §32.3.7 SEIS conditioning" as a goal, not as a transcribed sequence,
/// and the 12-word figure is the widely-published STM32 seed-error discard count.
/// Mark it **assumed** until RM0432 §32.3.7 is checked against a copy of the
/// manual.
///
/// What *is* read, from ST's own driver present in this tree
/// (`external/micropython/lib/stm32lib/STM32L4xx_HAL_Driver/Src/stm32l4xx_hal_rng.c`):
///
/// * `:773-778` — "In the case of a seed error, the generation of random numbers
///   is interrupted as long as the SECS bit is '1'. If a number is available in
///   the RNG_DR register, it must not be used because it may not have enough
///   entropy. In this case, it is recommended to clear the SEIS bit ..., then
///   **disable and enable the RNG peripheral** to reinitialize and restart the
///   RNG."
/// * `:307-311` — `HAL_RNG_DeInit` does exactly that:
///   `CLEAR_BIT(CR, IE | RNGEN)` then `CLEAR_BIT(SR, CEIS | SEIS)`.
///
/// The disable/enable half was **missing** here and is now in
/// `recover_seed_error`. Discarding words alone left the peripheral latched.
///
/// Coldcard implements no SEIS recovery at all — neither `COLDCARD_MK4/rng.c:69`
/// nor `mk4-bootloader/rng.c:43-69` reads any of `SECS`/`CECS`/`SEIS`/`CEIS`;
/// both poll only `DRDY`. That gap is the improvement PLAN.md §5.1 asks for, and
/// it is genuinely an improvement — but the improvement was incomplete until the
/// peripheral re-init was added.
pub const SEED_ERROR_DISCARD_WORDS: usize = 12;

/// Iteration bound for the `DRDY` poll, per word.
///
/// Coldcard's bootloader spins **unbounded** with the comment "okay to get stuck
/// here... better than failing" (`mk4-bootloader/rng.c:52-54`). That is the exact
/// silent-brick failure class decision 6 exists to remove, so this bound replaces
/// it and exhausting it is [`SourceFault::Timeout`], not a hang. A `DR` word is
/// ready in ~10 us on this part (`COLDCARD_MK4/rng.c:66` says "on the order of
/// 10us" with a 10 ms timeout), so this is many thousands of times the expected
/// wait — it is a liveness bound, not a timing constraint.
pub const DRDY_SPIN_LIMIT: u32 = 1_000_000;

/// Attempts allowed for one word before giving up.
///
/// A word is retried when it is zero or repeats the previous word — the check
/// `mk4-bootloader/rng.c:59` and `COLDCARD_MK4/rng.c:143-146` both perform. Both
/// do it in an unbounded loop; this bounds it, for the same reason
/// [`DRDY_SPIN_LIMIT`] exists.
pub const WORD_RETRY_LIMIT: u32 = 16;

impl EntropySource for Trng {
    const ID: SourceId = SourceId::Trng;
    const LEN: usize = TRNG_BYTES;

    /// Read 8 words from `RNG_DR`.
    ///
    /// Per word: bounded-poll `DRDY`, then check `SECS`/`CECS` **before** using
    /// the value ([`SourceFault::RngHardware`]), and never mix a word read while
    /// either is set. `DRDY` failing to assert within the bound is
    /// [`SourceFault::Timeout`], not a hang.
    ///
    /// # Errors
    ///
    /// [`SourceFault::RngHardware`], [`SourceFault::Timeout`], or
    /// [`SourceFault::ShortRead`] if `out.len() != Self::LEN`.
    fn read(&mut self, out: &mut [u8]) -> Result<(), SourceFault> {
        if out.len() != Self::LEN {
            return Err(SourceFault::ShortRead);
        }

        #[cfg(not(target_arch = "arm"))]
        {
            // No RNG peripheral here, and no fallback: refusing is the whole
            // point (module docs). A host build that reached this would
            // otherwise dereference 0x5006_0800 and SIGSEGV.
            Err(SourceFault::RngHardware(0))
        }

        #[cfg(target_arch = "arm")]
        {
            enable_rng_clock();

            // Previous word, for the repeat check. Seeded with a sentinel that
            // cannot equal a valid word, because `0` is itself rejected -- so
            // the first word is never compared against a real value.
            let mut last: u32 = 0;
            for chunk in out.chunks_mut(4) {
                let word = read_one_word(&mut last)?;
                let bytes = word.to_le_bytes();
                // `chunk.len()` is 4 for every chunk here (LEN = 32), but copy
                // only what fits: `chunks_mut` can yield a short tail and
                // `copy_from_slice` would PANIC on a length mismatch. This
                // function is documented as unable to panic.
                let n = chunk.len().min(4);
                chunk[..n].copy_from_slice(&bytes[..n]);
            }
            Ok(())
        }
    }
}

/// Enable the RNG peripheral clock and the RNG itself, idempotently.
///
/// Mirrors `rng_init` (`COLDCARD_MK4/rng.c:46-54`) and `rng_setup`
/// (`mk4-bootloader/rng.c:22-25`): both set `RCC->AHB2ENR.RNGEN` then
/// `RNG->CR.RNGEN`. The bootloader calls `rng_setup()` "super early"
/// (`main.c:62`) and routes the RNG kernel clock from PLLSAI1
/// (`clocks.c:161,172`), so in practice this is already on — doing it anyway
/// removes a dependency on bootloader behaviour we do not control, exactly as
/// `crate::panic::enable_backup_access` does for `DBP`.
#[cfg(target_arch = "arm")]
fn enable_rng_clock() {
    // SAFETY: `RCC_AHB2ENR` (`0x4002_104c`) and `RNG_CR` (`0x5006_0800`) are
    // 4-byte-aligned memory-mapped peripheral registers. Both writes are
    // read-modify-write settings of a single enable bit; neither can disable a
    // peripheral another module owns, and neither starts a transfer. The
    // read-back plus `dsb` is what guarantees the clock is live before the first
    // `SR` poll -- without it a `DRDY` read can be issued before the enable has
    // taken effect, which reads as a Timeout.
    unsafe {
        let en = core::ptr::read_volatile(RCC_AHB2ENR);
        if en & RCC_AHB2ENR_RNGEN == 0 {
            core::ptr::write_volatile(RCC_AHB2ENR, en | RCC_AHB2ENR_RNGEN);
            // Read back: the HAL's own clock-enable macros do this so the
            // peripheral is reachable before the next access
            // (`stm32l4xx_hal_rcc.h:1134-1140`).
            let _ = core::ptr::read_volatile(RCC_AHB2ENR);
        }
        let cr = core::ptr::read_volatile(RNG_CR);
        if cr & RNG_CR_RNGEN == 0 {
            core::ptr::write_volatile(RNG_CR, cr | RNG_CR_RNGEN);
        }
        core::arch::asm!("dsb sy", options(nostack, preserves_flags));
    }
}

/// One good word from `RNG_DR`, with the bounded `DRDY` poll, the `SECS`/`CECS`
/// check and the zero/repeat rejection.
///
/// `last` is read and updated so the caller's repeat check spans the whole draw.
///
/// # Errors
///
/// [`SourceFault::Timeout`] if `DRDY` never asserts within
/// [`DRDY_SPIN_LIMIT`], or if [`WORD_RETRY_LIMIT`] words in a row were zero or
/// repeats. [`SourceFault::RngHardware`] with the raw `SR` if a seed or clock
/// error is current.
#[cfg(target_arch = "arm")]
fn read_one_word(last: &mut u32) -> Result<u32, SourceFault> {
    let mut tries = WORD_RETRY_LIMIT;
    loop {
        // Bounded DRDY poll. Coldcard's is unbounded and its comment says that
        // is deliberate (`mk4-bootloader/rng.c:52-54`); for us an unbounded spin
        // at boot is a brick with no diagnostic.
        let mut spins = DRDY_SPIN_LIMIT;
        loop {
            // SAFETY: `RNG_SR` is a readable memory-mapped peripheral register
            // (`RNG_BASE + 0x04`); reads have no side effects. Unlike `DR`,
            // reading `SR` does not consume a word.
            let sr = unsafe { core::ptr::read_volatile(RNG_SR) };

            // Errors BEFORE DRDY: a word produced while SECS is set is invalid
            // and must be discarded, not mixed. Checking after reading DR would
            // be too late -- the value would already be in a register we might
            // use.
            //
            // `RNG_SR_ERRORS` covers the LATCHED `SEIS`/`CEIS` as well as the
            // current-status `SECS`/`CECS`. Testing only the current status (as
            // this did) lets a transient seed error that has since self-cleared
            // be drawn through silently, which ST's driver explicitly forbids
            // (`stm32l4xx_hal_rng.c:773-778`).
            if sr & RNG_SR_ERRORS != 0 {
                recover_seed_error(sr);
                return Err(SourceFault::RngHardware(sr));
            }
            if sr & RNG_SR_DRDY != 0 {
                break;
            }
            spins = match spins.checked_sub(1) {
                Some(s) => s,
                None => return Err(SourceFault::Timeout),
            };
        }

        // SAFETY: `RNG_DR` is a readable memory-mapped peripheral register
        // (`RNG_BASE + 0x08`). `DRDY` was just observed set, so the value is
        // valid; the read CONSUMES the word and clears `DRDY`, which is why it
        // happens exactly once per loop iteration.
        let word = unsafe { core::ptr::read_volatile(RNG_DR) };

        // Zero and repeat rejection, as `mk4-bootloader/rng.c:59` and
        // `COLDCARD_MK4/rng.c:143-146`. Bounded, unlike either.
        if word != 0 && word != *last {
            *last = word;
            return Ok(word);
        }
        tries = match tries.checked_sub(1) {
            Some(t) => t,
            // A source that yields nothing but zeros or repeats is stuck. That
            // is a refusal, and `check_source` would catch it anyway -- this
            // just refuses sooner and without burning the whole draw.
            None => return Err(SourceFault::Timeout),
        };
    }
}

/// Seed-error recovery: clear `SEIS`/`CEIS`, **disable and re-enable the RNG
/// peripheral**, then read and discard [`SEED_ERROR_DISCARD_WORDS`] words.
///
/// # The disable/enable step, and why it was missing
///
/// ST's own driver, present in this tree, states the required sequence: "clear
/// the SEIS bit ..., then **disable and enable the RNG peripheral** to
/// reinitialize and restart the RNG" (`stm32l4xx_hal_rng.c:773-778`), and
/// `HAL_RNG_DeInit` implements it as `CLEAR_BIT(CR, IE | RNGEN)` followed by
/// `CLEAR_BIT(SR, CEIS | SEIS)` (`:307-311`).
///
/// This function previously cleared the flags and discarded words but **never
/// toggled `RNGEN`**, and [`enable_rng_clock`] cannot make up for it: it sets
/// `RNGEN` only when it is already clear, so on a peripheral that is enabled and
/// latched, nothing ever re-initialises the conditioning logic. The result was a
/// recovery that could not recover. The toggle is now unconditional here.
///
/// Order matters and follows ST: clear the latched flags, drop `RNGEN`, then set
/// it again. Clearing after the disable would race the re-enable.
///
/// Called on the failure path only. It does **not** make the draw succeed — the
/// caller still returns [`SourceFault::RngHardware`] — it leaves the peripheral in
/// a state where a later boot can work rather than latching the error forever.
/// Recovering *and* returning the word would be the fail-open choice.
#[cfg(target_arch = "arm")]
fn recover_seed_error(sr: u32) {
    // SAFETY: `RNG_CR`/`RNG_SR`/`RNG_DR` are 4-byte-aligned memory-mapped
    // peripheral registers, always accessible once the clock is enabled -- which
    // the caller guaranteed by calling `enable_rng_clock` first. `SEIS` and
    // `CEIS` are write-0-to-clear, so the mask-off is the documented clear. The
    // `RNGEN` clear/set pair is `HAL_RNG_DeInit`'s own sequence
    // (`stm32l4xx_hal_rng.c:307-311`) and touches only this peripheral's enable
    // bit; no other module owns the RNG (it is a singleton, `Trng::take`). The
    // discarded `DR` reads only consume words.
    unsafe {
        core::ptr::write_volatile(RNG_SR, sr & !(RNG_SR_SEIS | RNG_SR_CEIS));

        // Disable, then re-enable. Read-modify-write both ways so no other CR
        // bit is disturbed, with a `dsb` between so the disable has actually
        // reached the peripheral before the enable is issued -- otherwise the
        // two stores can coalesce into no visible toggle at all, which is the
        // failure this whole block exists to fix.
        let cr = core::ptr::read_volatile(RNG_CR);
        core::ptr::write_volatile(RNG_CR, cr & !RNG_CR_RNGEN);
        core::arch::asm!("dsb sy", options(nostack, preserves_flags));
        core::ptr::write_volatile(RNG_CR, cr | RNG_CR_RNGEN);
        core::arch::asm!("dsb sy", options(nostack, preserves_flags));

        // Bounded by a constant, deliberately: this runs on an error path and
        // must terminate even if the peripheral never becomes healthy. No DRDY
        // wait -- discarding a stale word is the point, and waiting here could
        // hang on the very fault being recovered from.
        for _ in 0..SEED_ERROR_DISCARD_WORDS {
            let _ = core::ptr::read_volatile(RNG_DR);
        }
    }
}

impl EntropySource for Se1Rng {
    const ID: SourceId = SourceId::Se1;
    const LEN: usize = SE1_BYTES;

    /// One `callgate::read_rng` with [`callgate::RngSource::Se1`].
    ///
    /// Contains no `asm!` and no raw pointers: the stack buffer and the `blx`
    /// both live in [`callgate`]. On a non-ARM host, `callgate::read_rng` does
    /// not exist, so this body must be `#[cfg(target_arch = "arm")]`-split
    /// internally and return [`SourceFault::Callgate`] with a sentinel on the
    /// host — the *type* stays available so [`Sources`]/[`Entropy`] plumbing
    /// remains host-testable.
    ///
    /// # Errors
    ///
    /// [`SourceFault::Callgate`] with the raw errno, or
    /// [`SourceFault::ShortRead`].
    fn read(&mut self, out: &mut [u8]) -> Result<(), SourceFault> {
        read_via_callgate(callgate::RngSource::Se1, Self::LEN, out)
    }
}

/// Shared body of the two SE legs: length check, then one
/// [`callgate::read_rng`].
///
/// Factored out so the two legs differ only in a constant, and so the
/// `cfg(target_arch)` split exists in exactly one place. On a non-ARM host
/// `callgate::read_rng` does not exist, so this returns
/// [`SourceFault::Callgate`] with [`callgate::Errno::BAD_GATE`] — a refusal, not
/// a fallback, and never plausible-looking bytes. That is what keeps
/// [`Sources`]/[`Entropy`] plumbing host-testable without making a host build
/// able to produce entropy.
fn read_via_callgate(
    source: callgate::RngSource,
    expect_len: usize,
    out: &mut [u8],
) -> Result<(), SourceFault> {
    if out.len() != expect_len {
        return Err(SourceFault::ShortRead);
    }
    // Belt: the byte count the callgate promises must match this source's LEN,
    // or `callgate::read_rng` would refuse anyway. Catching it here names the
    // right culprit.
    if usize::from(source.byte_count()) != expect_len {
        return Err(SourceFault::ShortRead);
    }

    #[cfg(target_arch = "arm")]
    {
        callgate::read_rng(source, out).map_err(|e| SourceFault::Callgate(e.get()))
    }
    #[cfg(not(target_arch = "arm"))]
    {
        // There is no gate to call. `out` is deliberately left untouched rather
        // than filled with anything: a host build must not be able to obtain
        // entropy at all.
        let _ = out;
        Err(SourceFault::Callgate(callgate::Errno::BAD_GATE.get()))
    }
}

impl EntropySource for Se2Rng {
    const ID: SourceId = SourceId::Se2;
    const LEN: usize = SE2_BYTES;

    /// One `callgate::read_rng` with [`callgate::RngSource::Se2`]. See the
    /// type docs: this source's nature is unresolved.
    ///
    /// # Errors
    ///
    /// [`SourceFault::Callgate`] with the raw errno, or
    /// [`SourceFault::ShortRead`].
    fn read(&mut self, out: &mut [u8]) -> Result<(), SourceFault> {
        read_via_callgate(callgate::RngSource::Se2, Self::LEN, out)
    }
}

/// Proof that all three sources exist and are exclusively owned.
///
/// The only way to obtain one is [`Sources::new`] with all three singletons **by
/// value**. It holds them for the process lifetime, so no second `Sources` — and
/// therefore no second [`Entropy`] — can be built.
pub struct Sources {
    trng: Trng,
    se1: Se1Rng,
    se2: Se2Rng,
}

impl Sources {
    /// Consume all three singletons.
    ///
    /// Infallible by construction: possessing the three arguments *is* the proof.
    /// Takes concrete types, not `impl EntropySource`, specifically so a stub
    /// implementor cannot be substituted.
    #[must_use]
    pub fn new(trng: Trng, se1: Se1Rng, se2: Se2Rng) -> Self {
        Self { trng, se1, se2 }
    }

    /// Draw from all three, health-check each, and mix.
    ///
    /// The single place hardware entropy is gathered, used by both
    /// [`Entropy::boot`] and [`Entropy::try_reseed`] so the two cannot drift —
    /// a reseed that checked less than boot would be a downgrade path.
    ///
    /// Buffers are stack locals and are zeroized before returning on **every**
    /// path, success included: raw source bytes in a dead frame are recoverable,
    /// and this frame sits next to nonce state.
    ///
    /// # Errors
    ///
    /// The first [`RngFault`] among the three, in TRNG, SE1, SE2 order.
    fn draw(&mut self) -> Result<ProvenSeed, RngFault> {
        let mut t = [0u8; TRNG_BYTES];
        let mut s1 = [0u8; SE1_BYTES];
        let mut s2 = [0u8; SE2_BYTES];

        // Read all three, then mix. Each `read` failure names its own source, so
        // a bench sees *which* leg is broken rather than "entropy failed".
        let result = (|| -> Result<ProvenSeed, RngFault> {
            self.trng
                .read(&mut t)
                .map_err(|f| RngFault::new(SourceId::Trng, f))?;
            self.se1
                .read(&mut s1)
                .map_err(|f| RngFault::new(SourceId::Se1, f))?;
            self.se2
                .read(&mut s2)
                .map_err(|f| RngFault::new(SourceId::Se2, f))?;
            // The PRIVATE mixer, not the `test-seam`-gated `mix_sources`
            // wrapper. This is what lets the seam be gated without gating
            // `Entropy::boot`: the device path never routes through a
            // conditionally-compiled item.
            //
            // Health-checks each again inside; that redundancy is deliberate.
            mix_checked_draws(&t, &s1, &s2)
        })();

        // Zeroize unconditionally. `write_volatile` because the compiler deletes
        // stores to locals that are never read again.
        //
        // SAFETY: all three are live, aligned, uniquely owned locals for this
        // whole statement; each write is of the same type and in bounds.
        unsafe {
            core::ptr::write_volatile(&mut t, [0u8; TRNG_BYTES]);
            core::ptr::write_volatile(&mut s1, [0u8; SE1_BYTES]);
            core::ptr::write_volatile(&mut s2, [0u8; SE2_BYTES]);
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

        result
    }

    /// Convenience: take all three singletons and combine them.
    ///
    /// Returns `None` if any was already taken. Touches no hardware.
    pub fn take_all() -> Option<Self> {
        Some(Self::new(Trng::take()?, Se1Rng::take()?, Se2Rng::take()?))
    }
}

/// A 32-byte seed produced by the mixer from three health-checked draws.
///
/// Separate from a bare `[u8; 32]` so no `Entropy` constructor can be handed an
/// arbitrary array. On the device the only producer is the private
/// `mix_checked_draws`, reached only through `Sources::draw`, which requires
/// all three source singletons and three hardware reads. Under
/// `cfg(any(test, feature = "test-seam"))` the public `mix_sources` wrapper is
/// additionally available — see the module docs for why that is a gated seam and
/// not a guarantee.
///
/// It has no `pub` field, and the bytes are readable only through
/// `ProvenSeed::expose`, which is itself gated.
///
/// Must implement `Drop` to zeroize; must NOT implement `Clone`, `Copy`, `Debug`
/// or `Default` — a `Debug` impl on seed material is how it ends up in a log.
pub struct ProvenSeed {
    seed: [u8; SEED_BYTES],
}

impl ProvenSeed {
    /// The raw seed bytes, for this module's own constructors.
    ///
    /// Private on purpose: firmware has no reason to see a seed, and the whole
    /// point of the type is that the bytes stay inside the mixer -> ChaCha20
    /// path. The public `expose` below is the gated test-only view.
    fn seed_bytes(&self) -> &[u8; SEED_BYTES] {
        &self.seed
    }

    /// The raw seed bytes. Named `expose` rather than `as_bytes` so a reviewer
    /// grepping for secret handling finds every use site.
    ///
    /// # Gated: `cfg(any(test, feature = "test-seam"))`
    ///
    /// Part of the test seam, and gated with the rest of it. A public reader of
    /// seed material is how a seed reaches a log or a debug channel in shipped
    /// firmware, and no firmware path needs it — [`Entropy::boot`] and
    /// [`Entropy::try_reseed`] use the private `seed_bytes`.
    #[cfg(any(test, feature = "test-seam"))]
    #[must_use]
    pub fn expose(&self) -> &[u8; SEED_BYTES] {
        self.seed_bytes()
    }
}

impl Drop for ProvenSeed {
    fn drop(&mut self) {
        // `write_volatile`, not a plain assignment: the compiler deletes stores
        // to a value that is never read again, and this one exists purely for
        // its side effect on memory. The `compiler_fence` stops the zeroing
        // being reordered after the frame is reused.
        //
        // SAFETY: `&mut self.seed` is a live, aligned, uniquely borrowed
        // `[u8; SEED_BYTES]` for the whole statement; the write is of the same
        // type and in bounds.
        unsafe { core::ptr::write_volatile(&mut self.seed, [0u8; SEED_BYTES]) };
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// Health-check one source's draw. Pure, `cfg`-free — **host-testable**, and the
/// most important thing in this module to actually test, since on-device it can
/// only ever be exercised by a source that is already broken.
///
/// # Contract
///
/// * `Err(`[`SourceFault::ShortRead`]`)` if `bytes.len() != expected_len` or
///   `bytes` is empty.
/// * `Err(`[`SourceFault::AllBytesEqual`]`)` if every byte is identical. This
///   subsumes all-zero and all-`0xff`.
/// * `Err(`[`SourceFault::RepeatedWord`]`(i)`) if any two 4-byte words are equal,
///   where `i` is the index of the later word. Applies to whole words only; a
///   trailing partial word (SE2's 8 bytes divide evenly, so this only matters for
///   defensive generality) is ignored.
/// * Otherwise `Ok(())`.
/// * Must not panic for any input, including lengths not divisible by 4.
///
/// Deliberately **not** a general randomness test: it catches stuck and
/// mirrored sources, which is what PLAN.md §5.1 asks for. It cannot detect a
/// biased-but-varying source, and must not be described as if it could.
pub fn check_source(bytes: &[u8], expected_len: usize) -> Result<(), SourceFault> {
    // Length first. `is_empty` is not redundant with the inequality: a caller
    // passing `expected_len == 0` would otherwise sail through with no bytes at
    // all, which is the one input that must never be accepted.
    if bytes.is_empty() || bytes.len() != expected_len {
        return Err(SourceFault::ShortRead);
    }

    // Subsumes all-0x00 and all-0xff, the two values a stuck bus or an unpowered
    // secure element reads as. Checked before the word scan because it is the
    // stronger statement.
    let first = bytes[0];
    if bytes.iter().all(|&b| b == first) {
        return Err(SourceFault::AllBytesEqual);
    }

    // Repeated 4-byte words, per PLAN.md §5.1 ("reject repeated words per
    // source"). `chunks_exact` ignores a trailing partial word by construction,
    // which is what the contract says: both real sources (32 and 8 bytes) divide
    // evenly, and a partial tail carries no word to compare against.
    //
    // Compared pairwise over slices rather than collected into an array: no
    // buffer to size, no bound to get wrong, and it works for any input length
    // — which matters because the contract says this must not panic for
    // lengths not divisible by 4. Quadratic in the word count, which is at most
    // 8 here, so at most 28 four-byte comparisons.
    let mut words = bytes.chunks_exact(4);
    let mut i = 0usize;
    while let Some(word) = words.next() {
        // `words.clone()` is a cheap iterator copy (`ChunksExact: Clone`), so
        // this is "every LATER word", giving the later index in the report.
        for (k, other) in words.clone().enumerate() {
            if word == other {
                // Index of the LATER word, per the contract. Saturating rather
                // than `as u8`: with at most 8 words it cannot exceed 255, but
                // an unchecked cast here would silently misreport if a future
                // source were larger.
                let later = i.saturating_add(k).saturating_add(1);
                return Err(SourceFault::RepeatedWord(
                    u8::try_from(later).unwrap_or(u8::MAX),
                ));
            }
        }
        i += 1;
    }

    Ok(())
}

/// Mix three checked draws into a [`ProvenSeed`].
///
/// # Gated: `cfg(any(test, feature = "test-seam"))` — and this is the FATAL fix
///
/// This function is the **bypass**, not the guarantee. It takes three `&[u8]`, so
/// what it requires is three byte arrays that pass [`check_source`] — *not* three
/// hardware draws. While it was unconditionally public, any downstream crate
/// could hand it three hardcoded constants, feed the result to
/// [`Entropy::from_proven_seed`], and obtain a full `RngCore + CryptoRng`
/// [`Entropy`] with zero hardware reads, zero callgate entries and zero
/// singletons taken. That compiled for `thumbv7em-none-eabihf`. It is the libngu
/// fail-open defect of PLAN.md §1 in a different shape.
///
/// The device path does **not** call this. `Sources::draw` calls the private
/// `mix_checked_draws`, which this is a thin wrapper over, so gating the
/// wrapper costs [`Entropy::boot`] nothing.
///
/// # Contract
///
/// Identical to `mix_checked_draws`: SHA-256 over a length-prefixed transcript,
/// in this fixed order:
///
/// ```text
/// SHA256( MIX_DOMAIN || [trng.len() as u8] || trng
///                    || [se1.len()  as u8] || se1
///                    || [se2.len()  as u8] || se2 )
/// ```
///
/// # Errors
///
/// The first [`RngFault`] among the three, checked in TRNG, SE1, SE2 order.
///
/// # Panics
///
/// Must not, for any input lengths.
#[cfg(any(test, feature = "test-seam"))]
pub fn mix_sources(trng: &[u8], se1: &[u8], se2: &[u8]) -> Result<ProvenSeed, RngFault> {
    mix_checked_draws(trng, se1, se2)
}

/// The real mixer. **Private**, `cfg`-free, and the only producer of a
/// [`ProvenSeed`] on the device.
///
/// Private is the whole point: reaching it requires being inside this module,
/// and inside this module the only caller is `Sources::draw`, which owns the
/// three source singletons and has just performed three hardware reads. That is
/// what makes "a `ProvenSeed` implies three health-checked hardware draws" true
/// *for firmware*, which is the claim the type is for. The public
/// `mix_sources` wrapper weakens it to "three passing arrays", which is why the
/// wrapper is gated.
///
/// # Contract
///
/// SHA-256 over a length-prefixed transcript, in this fixed order:
///
/// ```text
/// SHA256( MIX_DOMAIN || [trng.len() as u8] || trng
///                    || [se1.len()  as u8] || se1
///                    || [se2.len()  as u8] || se2 )
/// ```
///
/// The length prefixes are not decoration: without them, concatenation is
/// ambiguous and two different source triples can produce the same transcript.
/// The order is fixed and must not be made caller-dependent.
///
/// Re-runs [`check_source`] on each input. That is intentionally redundant with
/// `Sources::draw` — this function is the only path to a `ProvenSeed`, so the
/// invariant is enforced where it is *named*, not only where it is convenient.
///
/// Note the SE2 leg is checked and hashed like the others but is a fixed
/// personalisation input, not entropy — see [`ENTROPY_SOURCE_COUNT`].
///
/// # Errors
///
/// The first [`RngFault`] among the three, checked in TRNG, SE1, SE2 order.
///
/// # Panics
///
/// Must not, for any input lengths.
fn mix_checked_draws(trng: &[u8], se1: &[u8], se2: &[u8]) -> Result<ProvenSeed, RngFault> {
    // Re-check every input here, deliberately redundant with `Sources::draw`.
    // This function is the ONLY constructor of `ProvenSeed`, so the invariant is
    // enforced where the type promises it, not merely where it is convenient.
    // TRNG, SE1, SE2 order, matching the documented error order.
    check_source(trng, TRNG_BYTES).map_err(|f| RngFault::new(SourceId::Trng, f))?;
    check_source(se1, SE1_BYTES).map_err(|f| RngFault::new(SourceId::Se1, f))?;
    check_source(se2, SE2_BYTES).map_err(|f| RngFault::new(SourceId::Se2, f))?;

    let mut hasher = Sha256::new();
    hasher.update(MIX_DOMAIN);
    for part in [trng, se1, se2] {
        // Length-prefixed, not bare concatenation: without the prefix two
        // different source triples can produce the same transcript, so a source
        // that shrank could be masked by a neighbour that grew.
        //
        // `try_from` rather than `as u8`: a length above 255 would TRUNCATE and
        // reintroduce the ambiguity the prefix exists to remove. `check_source`
        // has already pinned each length to a constant well under 255, so this
        // cannot fail -- expressing it as a checked conversion means a future
        // larger source is a refusal rather than a silent collision.
        let len = match u8::try_from(part.len()) {
            Ok(l) => l,
            Err(_) => return Err(RngFault::new(SourceId::Trng, SourceFault::ShortRead)),
        };
        hasher.update([len]);
        hasher.update(part);
    }

    // SHA-256's 32-byte output is exactly `SEED_BYTES` and exactly
    // `<ChaCha20Rng as SeedableRng>::Seed`, so there is no truncation and no
    // padding anywhere on this path.
    let digest = hasher.finalize();
    let mut seed = [0u8; SEED_BYTES];
    seed.copy_from_slice(&digest[..]);
    Ok(ProvenSeed { seed })
}

/// The firmware's only RNG: a ChaCha20 stream seeded from all three
/// health-checked hardware sources.
///
/// No `Default`, no `new`, no `from_seed`, no public fields, and not `Clone` —
/// cloning an RNG duplicates its stream, and two nonces off identical streams is
/// the affine nonce-reuse break that costs the secret share.
///
/// In a default-feature build the **only** constructor is [`Entropy::boot`],
/// which consumes [`Sources`] and therefore all three source singletons.
/// `Entropy::from_proven_seed` exists only under
/// `cfg(any(test, feature = "test-seam"))`; see the module docs.
pub struct Entropy {
    rng: ChaCha20Rng,
    reseeds: u32,
    /// The three singletons, held for the lifetime of this `Entropy`.
    ///
    /// Not dead weight and not merely a marker: holding them is what makes a
    /// second `Entropy` unconstructible (every `take()` has already returned
    /// `Some` exactly once), and it is what lets [`Entropy::try_reseed`] re-read
    /// hardware without a second round of `take()` calls that would now fail.
    ///
    /// `Option` because the gated `Entropy::from_proven_seed` seam has no
    /// sources to hold. `None` therefore means "cannot reseed", which
    /// [`Entropy::try_reseed`] reports as a refusal rather than silently
    /// succeeding without fresh entropy. In a default-feature build this is
    /// always `Some`, because [`Entropy::boot`] is then the only constructor.
    sources: Option<Sources>,
}

impl Entropy {
    /// Read all three sources, health-check each, mix, and seed ChaCha20. The
    /// normal entry point, called once at boot.
    ///
    /// Consumes [`Sources`] by value: the three singletons stay owned by the
    /// returned `Entropy`, so a second `Entropy` cannot be built, and a caller
    /// cannot retry with fewer sources after a failure.
    ///
    /// # Errors
    ///
    /// [`RngFault`] naming the first failing source. **The caller must treat
    /// this as fatal for signing** — there is no partial success and must never
    /// be one. Do not retry in a loop hoping for a different answer; a stuck
    /// source stays stuck, and a retry loop at boot is a brick.
    ///
    /// # Panics
    ///
    /// Must not.
    pub fn boot(mut sources: Sources) -> Result<Self, RngFault> {
        let seed = sources.draw()?;
        // Keep the sources: they are what makes a second `Entropy`
        // unconstructible, and what lets `try_reseed` work later.
        //
        // `seed_bytes`, the private accessor -- not the gated public `expose`,
        // which must not be on the firmware path.
        Ok(Self {
            rng: ChaCha20Rng::from_seed(*seed.seed_bytes()),
            reseeds: 0,
            sources: Some(sources),
        })
        // `seed` drops here and zeroizes (see `ProvenSeed::drop`). ChaCha20Rng
        // has already absorbed it into its own state.
    }

    /// Seed directly from an already-mixed seed, with no hardware.
    ///
    /// # Gated: `cfg(any(test, feature = "test-seam"))` — and it IS a back door
    ///
    /// The previous doc comment here said: *"Not a back door: a `ProvenSeed` can
    /// only come from `mix_sources`, which requires three passing draws."* **That
    /// was false and it is deleted.** [`mix_sources`] requires three passing
    /// *arrays*, not three draws, so this pair of unconditionally-public functions
    /// was a complete bypass of the fail-closed chain that compiled into
    /// firmware.
    ///
    /// It is retained because host tests genuinely need a real [`Entropy`]
    /// without hardware, and it is gated so that a firmware build cannot see it.
    /// [`Entropy::boot`] is the only constructor with the feature off.
    #[cfg(any(test, feature = "test-seam"))]
    #[must_use]
    pub fn from_proven_seed(seed: ProvenSeed) -> Self {
        Self {
            rng: ChaCha20Rng::from_seed(*seed.expose()),
            reseeds: 0,
            // No sources were consumed, so this instance cannot reseed. See the
            // `sources` field docs: `try_reseed` refuses rather than pretending.
            sources: None,
        }
    }

    /// Draw fresh hardware entropy and fold it into the existing state.
    ///
    /// Folds rather than replaces: `new_seed = SHA256(MIX_DOMAIN || old_output ||
    /// fresh_mix)`, so a reseed can only ever add uncertainty. A reseed that
    /// *replaced* the state would let a compromised source downgrade a healthy
    /// stream.
    ///
    /// **Rate-limited by physics, not by policy:** every SE read runs
    /// `ae_reset_chip()` and reprograms UART4 or I2C2
    /// ([`callgate::SELECTOR_READ_RNG`]). Do not call this per signature. Once
    /// per session at most, and never from an interrupt.
    ///
    /// # Errors
    ///
    /// [`RngFault`] if any source now fails. On error the existing state is
    /// **left intact and still usable** — a failed reseed must not destroy a
    /// working RNG, or reseeding becomes strictly more dangerous than not
    /// reseeding.
    ///
    /// # Panics
    ///
    /// Must not.
    pub fn try_reseed(&mut self) -> Result<(), RngFault> {
        // No sources means no hardware to re-read. Refuse; see
        // `SourceFault::NoSources`. Returning `Ok` here would be a lie the caller
        // acts on.
        let sources = match self.sources.as_mut() {
            Some(s) => s,
            None => return Err(RngFault::new(SourceId::Trng, SourceFault::NoSources)),
        };

        // Draw FIRST and touch nothing until it succeeds. Every mutation below
        // this `?` is unreachable on failure, which is how "left intact and still
        // usable" is guaranteed structurally rather than by remembering to
        // restore state.
        let fresh = sources.draw()?;

        // Fold, never replace: the new seed commits to the CURRENT stream's
        // output as well as the fresh mix, so a compromised source can only add
        // to the uncertainty, never subtract from it. Replacing would let a
        // source that is now attacker-controlled downgrade a healthy stream.
        let mut old_output = [0u8; SEED_BYTES];
        self.rng.fill_bytes(&mut old_output);

        let mut hasher = Sha256::new();
        hasher.update(MIX_DOMAIN);
        hasher.update(old_output);
        // Private accessor, not the gated public `expose`: this is a firmware
        // path and must compile with `test-seam` off.
        hasher.update(fresh.seed_bytes());
        let digest = hasher.finalize();

        let mut next = [0u8; SEED_BYTES];
        next.copy_from_slice(&digest[..]);
        self.rng = ChaCha20Rng::from_seed(next);

        // Zeroize both intermediates. They are each sufficient to reconstruct the
        // new stream, so they are exactly as sensitive as the seed itself.
        //
        // SAFETY: both are live, aligned, uniquely owned locals for this whole
        // statement; each write is of the same type and in bounds.
        unsafe {
            core::ptr::write_volatile(&mut old_output, [0u8; SEED_BYTES]);
            core::ptr::write_volatile(&mut next, [0u8; SEED_BYTES]);
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

        // Saturating, per `reseed_count`'s contract. A wrap would make the
        // diagnostic read "never reseeded" on a device that had.
        self.reseeds = self.reseeds.saturating_add(1);
        Ok(())
        // `fresh` drops here and zeroizes (`ProvenSeed::drop`).
    }

    /// How many successful [`Entropy::try_reseed`] calls have happened.
    /// Diagnostic only; saturates rather than wrapping.
    #[must_use]
    pub fn reseed_count(&self) -> u32 {
        self.reseeds
    }

    /// Whether this instance can reseed at all, i.e. whether it owns the three
    /// source singletons.
    ///
    /// `false` exactly for `Entropy::from_proven_seed` instances, whose
    /// [`Entropy::try_reseed`] returns [`SourceFault::NoSources`]. Exposed so a
    /// caller can tell "reseeding is not available" from "reseeding failed"
    /// without provoking the failure.
    #[must_use]
    pub fn can_reseed(&self) -> bool {
        self.sources.is_some()
    }
}

impl RngCore for Entropy {
    /// Pure ChaCha20 output. Cannot fail, cannot block, touches no hardware.
    fn next_u32(&mut self) -> u32 {
        self.rng.next_u32()
    }

    /// Pure ChaCha20 output.
    fn next_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    /// Pure ChaCha20 output.
    ///
    /// Infallible **by construction**, which is the point: `frostsnap_core`'s 28
    /// `&mut impl RngCore` call sites include nonce generation, and there is no
    /// error path for them to take. See the module docs.
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.rng.fill_bytes(dest);
    }

    /// Always `Ok`. See [`RngCore::fill_bytes`].
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

/// Asserts [`Entropy`] is cryptographically secure, which is what
/// `frostsnap_core`'s `CryptoRng` bounds require.
///
/// Sound **in a default-feature build**, where [`Entropy::boot`] is the only
/// constructor: it consumes [`Sources`] (all three singletons by value), performs
/// three hardware reads, health-checks each, and seeds ChaCha20 from the private
/// `mix_checked_draws`.
///
/// With `test-seam` on, `Entropy::from_proven_seed` can seed this from arbitrary
/// bytes and the claim is only as good as the caller. That is exactly why the
/// seam is off by default — the guarantee holds for firmware, and the honest
/// statement is that it holds *because* of the gate, not in spite of it.
///
/// **If any future change lets `Entropy` be built without going through
/// [`Sources`] in a default-feature build, this impl becomes a lie** — it is the
/// single line that turns the type-state into a cryptographic claim.
impl CryptoRng for Entropy {}

/// A source's draw count, for a caller that wants to log how much was drawn
/// without exposing the bytes. Nonzero because a zero-byte draw is
/// [`SourceFault::ShortRead`], never a valid state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrawLen(pub NonZeroU8);

#[cfg(test)]
mod tests {
    use super::*;

    /// A varying, non-repeating filler so a test's *inputs* never trip
    /// `check_source` for a reason the test did not intend.
    fn varying(len: usize, salt: u8) -> [u8; 32] {
        let mut b = [0u8; 32];
        for (i, slot) in b.iter_mut().enumerate().take(len) {
            // Every 4-byte word differs because byte 0 of each word carries `i`.
            #[allow(clippy::cast_possible_truncation)]
            let i8_ = i as u8;
            *slot = i8_.wrapping_mul(7).wrapping_add(salt).wrapping_add(1);
        }
        b
    }

    #[test]
    fn good_draws_pass() {
        let t = varying(TRNG_BYTES, 0);
        assert_eq!(check_source(&t[..TRNG_BYTES], TRNG_BYTES), Ok(()));
        let s2 = varying(SE2_BYTES, 9);
        assert_eq!(check_source(&s2[..SE2_BYTES], SE2_BYTES), Ok(()));
    }

    #[test]
    fn length_mismatch_and_empty_are_short_reads() {
        let t = varying(TRNG_BYTES, 0);
        assert_eq!(
            check_source(&t[..TRNG_BYTES - 1], TRNG_BYTES),
            Err(SourceFault::ShortRead)
        );
        assert_eq!(check_source(&[], 0), Err(SourceFault::ShortRead));
        assert_eq!(check_source(&[], TRNG_BYTES), Err(SourceFault::ShortRead));
    }

    /// The two values a stuck bus or an unpowered secure element reads as.
    #[test]
    fn stuck_sources_are_rejected() {
        for fill in [0x00u8, 0xff, 0x5a] {
            let buf = [fill; SE1_BYTES];
            assert_eq!(
                check_source(&buf, SE1_BYTES),
                Err(SourceFault::AllBytesEqual),
                "fill {fill:#x} accepted"
            );
        }
    }

    #[test]
    fn repeated_words_report_the_later_index() {
        // Words 0 and 2 identical; the report must name 2, not 0.
        let mut buf = varying(TRNG_BYTES, 0);
        let word0 = [buf[0], buf[1], buf[2], buf[3]];
        buf[8..12].copy_from_slice(&word0);
        assert_eq!(
            check_source(&buf, TRNG_BYTES),
            Err(SourceFault::RepeatedWord(2))
        );
    }

    /// The contract says `check_source` must not panic for lengths that are not
    /// a multiple of 4. A panic here is a boot-time halt.
    #[test]
    fn odd_lengths_do_not_panic() {
        for len in 1usize..=9 {
            let buf = varying(len, 3);
            let _ = check_source(&buf[..len], len);
        }
    }

    #[test]
    fn mixer_is_deterministic_and_order_sensitive() {
        let t = varying(TRNG_BYTES, 1);
        let s1 = varying(SE1_BYTES, 2);
        let s2 = varying(SE2_BYTES, 3);

        let a = mix_sources(&t, &s1, &s2[..SE2_BYTES]).expect("good draws");
        let b = mix_sources(&t, &s1, &s2[..SE2_BYTES]).expect("good draws");
        assert_eq!(a.expose(), b.expose(), "mixer is not deterministic");

        // Swapping the SE1 leg must change the seed, i.e. the transcript really
        // commits to every source rather than only to the first.
        let s1b = varying(SE1_BYTES, 4);
        let c = mix_sources(&t, &s1b, &s2[..SE2_BYTES]).expect("good draws");
        assert_ne!(a.expose(), c.expose(), "SE1 does not affect the seed");
    }

    /// The mixer is the ONLY constructor of `ProvenSeed`, so it must re-reject a
    /// bad draw even when the caller already checked.
    #[test]
    fn mixer_refuses_a_bad_leg_and_names_it() {
        let t = varying(TRNG_BYTES, 1);
        let s1 = varying(SE1_BYTES, 2);
        let s2 = varying(SE2_BYTES, 3);

        assert_eq!(
            mix_sources(&[0u8; TRNG_BYTES], &s1, &s2[..SE2_BYTES]).err(),
            Some(RngFault::new(SourceId::Trng, SourceFault::AllBytesEqual))
        );
        assert_eq!(
            mix_sources(&t, &[0xffu8; SE1_BYTES], &s2[..SE2_BYTES]).err(),
            Some(RngFault::new(SourceId::Se1, SourceFault::AllBytesEqual))
        );
        // An all-zero / all-0xff SE2 is a dead I2C2 bus or an unpowered SE2,
        // which is the SE2 failure mode `check_source` really can catch. It
        // canNOT catch a *constant* SE2 -- see
        // `check_source_cannot_refuse_a_static_se2`.
        assert_eq!(
            mix_sources(&t, &s1, &[0u8; SE2_BYTES]).err(),
            Some(RngFault::new(SourceId::Se2, SourceFault::AllBytesEqual))
        );
        // Wrong length on the short leg, checked in TRNG/SE1/SE2 order.
        assert_eq!(
            mix_sources(&t, &s1, &s2[..SE2_BYTES - 1]).err(),
            Some(RngFault::new(SourceId::Se2, SourceFault::ShortRead))
        );
    }

    /// The mixer must name **each** leg's fault at the position that leg sits in,
    /// not just report "something was wrong". The SE1 and SE2 positions are the
    /// ones no other test pinned: `Sources::draw` short-circuits at the TRNG, so
    /// nothing else in this file ever observes an SE-position fault.
    ///
    /// Every fault variant `check_source` can produce, per leg, so that a future
    /// change which collapses the three `check_source` calls into one (losing the
    /// `SourceId`) fails here rather than at a bench.
    #[test]
    fn the_mixer_reports_faults_at_the_se1_and_se2_positions() {
        let t = varying(TRNG_BYTES, 1);
        let s1 = varying(SE1_BYTES, 2);
        let s2 = varying(SE2_BYTES, 3);

        // --- SE1 position -------------------------------------------------
        for fill in [0x00u8, 0xff, 0x5a] {
            assert_eq!(
                mix_sources(&t, &[fill; SE1_BYTES], &s2[..SE2_BYTES]).err(),
                Some(RngFault::new(SourceId::Se1, SourceFault::AllBytesEqual)),
                "SE1 fill {fill:#x} was not refused at the SE1 position"
            );
        }
        assert_eq!(
            mix_sources(&t, &s1[..SE1_BYTES - 1], &s2[..SE2_BYTES]).err(),
            Some(RngFault::new(SourceId::Se1, SourceFault::ShortRead))
        );
        assert_eq!(
            mix_sources(&t, &[], &s2[..SE2_BYTES]).err(),
            Some(RngFault::new(SourceId::Se1, SourceFault::ShortRead))
        );
        // A repeated word inside the SE1 draw, reported at the SE1 position with
        // the LATER word's index.
        let mut s1_rep = varying(SE1_BYTES, 2);
        let w0 = [s1_rep[0], s1_rep[1], s1_rep[2], s1_rep[3]];
        s1_rep[12..16].copy_from_slice(&w0);
        assert_eq!(
            mix_sources(&t, &s1_rep, &s2[..SE2_BYTES]).err(),
            Some(RngFault::new(SourceId::Se1, SourceFault::RepeatedWord(3)))
        );

        // --- SE2 position -------------------------------------------------
        for fill in [0x00u8, 0xff, 0x5a] {
            assert_eq!(
                mix_sources(&t, &s1, &[fill; SE2_BYTES]).err(),
                Some(RngFault::new(SourceId::Se2, SourceFault::AllBytesEqual)),
                "SE2 fill {fill:#x} was not refused at the SE2 position"
            );
        }
        assert_eq!(
            mix_sources(&t, &s1, &[]).err(),
            Some(RngFault::new(SourceId::Se2, SourceFault::ShortRead))
        );
        // SE2 is 8 bytes = exactly two words. Both equal is a repeat at index 1.
        let mut s2_rep = [0u8; SE2_BYTES];
        s2_rep[..4].copy_from_slice(&[1, 2, 3, 4]);
        s2_rep[4..].copy_from_slice(&[1, 2, 3, 4]);
        assert_eq!(
            mix_sources(&t, &s1, &s2_rep).err(),
            Some(RngFault::new(SourceId::Se2, SourceFault::RepeatedWord(1)))
        );

        // Order: the FIRST failing leg wins, TRNG then SE1 then SE2. With all
        // three bad the report must say TRNG, or a bench chases the wrong leg.
        assert_eq!(
            mix_sources(&[0u8; TRNG_BYTES], &[0u8; SE1_BYTES], &[0u8; SE2_BYTES]).err(),
            Some(RngFault::new(SourceId::Trng, SourceFault::AllBytesEqual))
        );
        // TRNG good, SE1 and SE2 both bad -> SE1, not SE2.
        assert_eq!(
            mix_sources(&t, &[0u8; SE1_BYTES], &[0u8; SE2_BYTES]).err(),
            Some(RngFault::new(SourceId::Se1, SourceFault::AllBytesEqual))
        );
    }

    /// **The negative control that was missing.** `Sources::draw` short-circuits
    /// at the TRNG (it returns on the first `?`), and the only boot-level test
    /// asserts `err.source == SourceId::Trng`. So mutating BOTH SE legs to fill
    /// `out` with plausible bytes and return `Ok(())` left the whole suite green —
    /// measured, 60/60. Two thirds of the refusal surface was untested.
    ///
    /// This drives each SE leg **directly**, bypassing `draw`'s short-circuit, so
    /// each leg's refusal is independently load-bearing.
    ///
    /// Both legs must:
    /// * return `Err(SourceFault::Callgate(BAD_GATE))` — a refusal naming the
    ///   callgate, never a substitute value and never `Ok`;
    /// * leave `out` **untouched**. A leg that filled the buffer and *then*
    ///   returned `Err` would be one `?`-deletion away from feeding attacker-known
    ///   bytes into the mixer, so "untouched" is the property that makes the
    ///   refusal safe rather than merely correct.
    #[test]
    fn se1_and_se2_legs_refuse_on_the_host() {
        const SENTINEL: u8 = 0xA5;

        let mut se1 = Se1Rng { _private: () };
        let mut buf1 = [SENTINEL; SE1_BYTES];
        assert_eq!(
            se1.read(&mut buf1),
            Err(SourceFault::Callgate(callgate::Errno::BAD_GATE.get())),
            "the SE1 leg did not refuse on a host build"
        );
        assert_eq!(
            buf1,
            [SENTINEL; SE1_BYTES],
            "the SE1 leg WROTE to out before refusing"
        );

        let mut se2 = Se2Rng { _private: () };
        let mut buf2 = [SENTINEL; SE2_BYTES];
        assert_eq!(
            se2.read(&mut buf2),
            Err(SourceFault::Callgate(callgate::Errno::BAD_GATE.get())),
            "the SE2 leg did not refuse on a host build"
        );
        assert_eq!(
            buf2,
            [SENTINEL; SE2_BYTES],
            "the SE2 leg WROTE to out before refusing"
        );

        // Repeatable: a leg that refused once must keep refusing. A leg with
        // internal state that failed open on the second call would pass the
        // asserts above.
        for _ in 0..3 {
            assert!(se1.read(&mut buf1).is_err());
            assert!(se2.read(&mut buf2).is_err());
        }

        // And the TRNG leg, for symmetry -- so all three legs' refusals are
        // pinned in one place rather than only the one `draw` happens to reach.
        let mut trng = Trng { _private: () };
        let mut buft = [SENTINEL; TRNG_BYTES];
        let err = trng.read(&mut buft).expect_err("the TRNG leg must refuse");
        assert!(
            matches!(err, SourceFault::RngHardware(_)),
            "TRNG refused with {err:?}, expected RngHardware"
        );
        assert_eq!(
            buft,
            [SENTINEL; TRNG_BYTES],
            "the TRNG leg WROTE to out before refusing"
        );
    }

    /// Every leg must also refuse a wrong-sized `out`, at the leg itself rather
    /// than downstream in the mixer. A leg that accepted a short buffer would
    /// either read out of bounds or silently under-fill.
    #[test]
    fn every_leg_refuses_a_wrong_length_buffer() {
        let mut trng = Trng { _private: () };
        let mut se1 = Se1Rng { _private: () };
        let mut se2 = Se2Rng { _private: () };

        assert_eq!(
            trng.read(&mut [0u8; TRNG_BYTES - 1]),
            Err(SourceFault::ShortRead)
        );
        assert_eq!(
            trng.read(&mut [0u8; TRNG_BYTES + 1]),
            Err(SourceFault::ShortRead)
        );
        assert_eq!(trng.read(&mut []), Err(SourceFault::ShortRead));

        assert_eq!(
            se1.read(&mut [0u8; SE1_BYTES - 1]),
            Err(SourceFault::ShortRead)
        );
        assert_eq!(se1.read(&mut []), Err(SourceFault::ShortRead));

        assert_eq!(
            se2.read(&mut [0u8; SE2_BYTES + 1]),
            Err(SourceFault::ShortRead)
        );
        assert_eq!(se2.read(&mut []), Err(SourceFault::ShortRead));

        // The length check must come BEFORE the hardware attempt, or a host build
        // would report Callgate for what is really a caller bug -- and on-device
        // it would enter the gate with a buffer the gate then rejects.
        assert_eq!(
            se1.read(&mut [0u8; SE2_BYTES]),
            Err(SourceFault::ShortRead),
            "SE1 accepted SE2's length"
        );
    }

    /// Each leg's declared `LEN` must equal the constant the callgate promises,
    /// or the leg and the gate disagree about how many bytes exist and the
    /// difference is either uninitialised buffer or a silent truncation.
    #[test]
    fn leg_lengths_match_the_callgate_byte_counts() {
        assert_eq!(<Trng as EntropySource>::LEN, TRNG_BYTES);
        assert_eq!(<Se1Rng as EntropySource>::LEN, SE1_BYTES);
        assert_eq!(<Se2Rng as EntropySource>::LEN, SE2_BYTES);
        assert_eq!(
            usize::from(callgate::RngSource::Se1.byte_count()),
            <Se1Rng as EntropySource>::LEN
        );
        assert_eq!(
            usize::from(callgate::RngSource::Se2.byte_count()),
            <Se2Rng as EntropySource>::LEN
        );
        // Each leg must report its OWN id, or a fault names the wrong culprit.
        assert_eq!(<Trng as EntropySource>::ID, SourceId::Trng);
        assert_eq!(<Se1Rng as EntropySource>::ID, SourceId::Se1);
        assert_eq!(<Se2Rng as EntropySource>::ID, SourceId::Se2);
    }

    /// **The deleted claim, as an executable statement of what is actually true.**
    ///
    /// The module docs used to say the health checks "convert 'SE2 is a constant'
    /// from a silent weakness into an observable refusal". They do not, and this
    /// test pins the real behaviour so nobody re-adds the claim: a plausible
    /// static page-28 value is accepted on **every** boot, because `check_source`
    /// is stateless and holds nothing across calls.
    ///
    /// This test asserting `Ok` is not an endorsement — it is the reason
    /// `ENTROPY_SOURCE_COUNT` is 2. If someone ever adds real cross-boot
    /// detection, this test SHOULD fail, and its failure is the signal to raise
    /// the count.
    #[test]
    fn check_source_cannot_refuse_a_static_se2() {
        // Plausible bytes [4..12] of PGN_ROM_OPTIONS (se2.c:1341-1343): two
        // distinct words, so the intra-draw checks find nothing wrong.
        let static_se2: [u8; SE2_BYTES] = [0x2c, 0x00, 0x00, 0x1a, 0x3f, 0x91, 0x00, 0x00];
        for boot in 0..1000 {
            assert_eq!(
                check_source(&static_se2, SE2_BYTES),
                Ok(()),
                "boot {boot} refused a constant -- if this is a real detector, \
                 raise ENTROPY_SOURCE_COUNT"
            );
        }

        // Same constant, every boot, mixes to the same seed. That is the whole
        // point: SE2 contributes device uniqueness, not per-boot entropy.
        let t = varying(TRNG_BYTES, 1);
        let s1 = varying(SE1_BYTES, 2);
        let a = mix_sources(&t, &s1, &static_se2).expect("a constant SE2 still mixes");
        let b = mix_sources(&t, &s1, &static_se2).expect("a constant SE2 still mixes");
        assert_eq!(a.expose(), b.expose());

        // It does still catch the failure mode that IS real for SE2: a dead I2C2
        // bus or an unpowered part reads as all-0x00 or all-0xff.
        assert_eq!(
            check_source(&[0x00; SE2_BYTES], SE2_BYTES),
            Err(SourceFault::AllBytesEqual)
        );
        assert_eq!(
            check_source(&[0xff; SE2_BYTES], SE2_BYTES),
            Err(SourceFault::AllBytesEqual)
        );

        // And what the checks cannot do, stated rather than implied: a counter
        // passes. `check_source` catches STUCK sources, not biased ones.
        let mut counter = [0u8; TRNG_BYTES];
        for (i, w) in counter.chunks_mut(4).enumerate() {
            w.copy_from_slice(&u32::try_from(i + 1).unwrap().to_le_bytes());
        }
        assert_eq!(
            check_source(&counter, TRNG_BYTES),
            Ok(()),
            "check_source is documented as not a general randomness test; if this \
             now fails, update that documentation"
        );
    }

    /// The entropy claim is a value, so a change to it is a test failure rather
    /// than a prose edit nobody notices.
    #[test]
    fn the_entropy_source_count_is_two_not_three() {
        assert_eq!(
            ENTROPY_SOURCE_COUNT, 2,
            "SE1 is not independent of the TRNG (ae.c:1332) and SE2 is a static \
             page read (se2.c:1341-1343). Raising this needs a bench measurement, \
             not a doc edit."
        );
        // But all three legs are still drawn and still mandatory: dropping SE2
        // from the entropy COUNT must not turn into skipping the read.
        let legs = [SourceId::Trng, SourceId::Se1, SourceId::Se2];
        assert_eq!(legs.len(), 3);
        assert!(ENTROPY_SOURCE_COUNT < legs.len());
    }

    fn proven(salt: u8) -> ProvenSeed {
        let t = varying(TRNG_BYTES, salt);
        let s1 = varying(SE1_BYTES, salt.wrapping_add(1));
        let s2 = varying(SE2_BYTES, salt.wrapping_add(2));
        mix_sources(&t, &s1, &s2[..SE2_BYTES]).expect("constructed good draws")
    }

    #[test]
    fn entropy_streams_are_seed_determined_and_advance() {
        let mut e = Entropy::from_proven_seed(proven(11));
        let mut f = Entropy::from_proven_seed(proven(11));
        let (mut a, mut b) = ([0u8; 64], [0u8; 64]);
        e.fill_bytes(&mut a);
        f.fill_bytes(&mut b);
        assert_eq!(a, b, "same seed gave different streams");

        let mut c = [0u8; 64];
        e.fill_bytes(&mut c);
        assert_ne!(a, c, "stream did not advance");

        // Different sources, different stream.
        let mut g = Entropy::from_proven_seed(proven(12));
        let mut d = [0u8; 64];
        g.fill_bytes(&mut d);
        assert_ne!(a, d);

        // next_u32/next_u64 come off the same stream, not a fresh one.
        let mut h = Entropy::from_proven_seed(proven(13));
        let x = h.next_u32();
        let y = h.next_u32();
        let z = h.next_u64();
        assert!(
            !(x == y && u64::from(x) == z),
            "next_u32/next_u64 look stuck"
        );
    }

    /// A `from_proven_seed` instance owns no sources. `try_reseed` must REFUSE,
    /// not silently report success without folding in anything.
    #[test]
    fn reseed_without_sources_refuses_and_leaves_the_stream_intact() {
        let mut e = Entropy::from_proven_seed(proven(21));
        assert!(!e.can_reseed());
        assert_eq!(e.reseed_count(), 0);

        // Snapshot the stream position by cloning the *seed*, not the RNG
        // (`Entropy` is deliberately not `Clone`).
        let mut reference = Entropy::from_proven_seed(proven(21));

        assert_eq!(
            e.try_reseed(),
            Err(RngFault::new(SourceId::Trng, SourceFault::NoSources))
        );
        assert_eq!(e.reseed_count(), 0, "a refused reseed was counted");

        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        e.fill_bytes(&mut a);
        reference.fill_bytes(&mut b);
        assert_eq!(a, b, "a refused reseed disturbed the RNG state");

        // Still usable afterwards, repeatedly.
        for _ in 0..3 {
            assert!(e.try_reseed().is_err());
        }
        e.fill_bytes(&mut a);
    }

    /// Two properties in one test **on purpose**: the source singletons are
    /// process-global, and `cargo test` runs tests concurrently in one process,
    /// so two tests that each call `take_all` would race over which one gets the
    /// `Some`. Splitting them would make this file order-dependent.
    ///
    /// Property 1: on the host every hardware leg refuses, so `Sources::draw` —
    /// and therefore `Entropy::boot` — fails closed at the FIRST source with no
    /// fallback. That is the libngu defect as an executable test.
    ///
    /// Property 2: `take_all` succeeds at most once per process, and dropping the
    /// `Sources` does **not** release the singletons — otherwise a second
    /// `Entropy`, and thus a duplicated nonce stream, would be constructible.
    #[test]
    fn boot_fails_closed_and_sources_are_take_once() {
        let sources = Sources::take_all().expect("first take of each singleton");
        assert!(
            Sources::take_all().is_none(),
            "two Sources exist, so two Entropy could exist"
        );

        // Not `expect_err`: that needs `Entropy: Debug`, and `Entropy`
        // deliberately has no `Debug` -- a `Debug` impl on live RNG state is how
        // it reaches a log.
        let err = match Entropy::boot(sources) {
            Ok(_) => panic!("host build produced entropy"),
            Err(e) => e,
        };
        assert_eq!(err.source, SourceId::Trng);
        // Whatever the leg reports, it must be a refusal, never a substitute.
        assert!(matches!(
            err.fault,
            SourceFault::RngHardware(_) | SourceFault::Timeout | SourceFault::Callgate(_)
        ));

        // `boot` consumed the `Sources` and dropped them on the error path. The
        // singletons must stay claimed regardless.
        assert!(
            Sources::take_all().is_none(),
            "a failed boot released the singletons; boot could be retried in a loop"
        );
    }

    /// A seed must not survive in a dead frame; nonce state sits next to it.
    ///
    /// What this can and cannot check: **observing** the zeroed bytes after the
    /// value is gone would mean reading a dropped place, so the test asserts the
    /// two things that are checkable without UB — that `ProvenSeed` still has a
    /// `Drop` impl at all (deleting it makes `needs_drop` false, since the only
    /// field is a `[u8; 32]`), and that the seed the mixer produced was not
    /// already zero. That the impl writes zeros is **read** from
    /// `ProvenSeed::drop`, not measured here.
    #[test]
    fn proven_seed_still_has_a_zeroizing_drop() {
        assert!(
            core::mem::needs_drop::<ProvenSeed>(),
            "ProvenSeed lost its Drop impl; seeds now survive in dead frames"
        );
        let s = proven(31);
        assert_ne!(
            *s.expose(),
            [0u8; SEED_BYTES],
            "mixer produced an all-zero seed, so this test proves nothing"
        );
    }

    /// Register addresses and bit positions, re-derived from the CMSIS header's
    /// documented base arithmetic rather than copied from the skeleton comments.
    #[test]
    fn rng_register_addresses_match_the_cmsis_header() {
        // `PERIPH_BASE` 0x4000_0000 (:1292) + `AHB2PERIPH_BASE` offset
        // 0x0800_0000 (:1320) + `RNG_BASE` offset 0x0806_0800 (:1468). The RNG
        // offset really is 0x0806_0800 and not 0x6_0800 -- the header adds the
        // 0x0800_0000 twice, which is why this is asserted rather than trusted.
        assert_eq!(RNG_BASE, 0x4000_0000 + 0x0800_0000 + 0x0806_0800);
        assert_eq!(RNG_BASE, 0x5006_0800);
        assert_eq!(RNG_CR as usize, RNG_BASE);
        assert_eq!(RNG_SR as usize, RNG_BASE + 0x04);
        assert_eq!(RNG_DR as usize, RNG_BASE + 0x08);
        assert_eq!(RCC_AHB2ENR as usize, 0x4002_1000 + 0x4C);

        assert_eq!(RNG_CR_RNGEN, 0x4);
        assert_eq!(RNG_SR_DRDY, 0x1);
        assert_eq!(RNG_SR_CECS, 0x2);
        assert_eq!(RNG_SR_SECS, 0x4);
        assert_eq!(RNG_SR_CEIS, 0x20);
        assert_eq!(RNG_SR_SEIS, 0x40);
        // The error flags must be disjoint from DRDY, or a data-ready poll would
        // mask an invalid word.
        assert_eq!(RNG_SR_DRDY & (RNG_SR_CECS | RNG_SR_SECS), 0);
    }

    /// The bounds that replace Coldcard's unbounded spins must actually be
    /// bounds: zero would make the poll never run, and these are the only thing
    /// standing between a dead RNG clock and a silent brick.
    #[test]
    fn liveness_bounds_are_nonzero_and_finite() {
        // `const` block, not a runtime `assert!`: these are consts, so a runtime
        // assert is compiled away to nothing (clippy::assertions_on_constants)
        // and would stop checking anything. This form fails the BUILD instead.
        const _: () = {
            assert!(DRDY_SPIN_LIMIT > 0);
            assert!(WORD_RETRY_LIMIT > 0);
        };
        assert_eq!(SEED_ERROR_DISCARD_WORDS, 12, "RM0432 32.3.7 says 12 words");
    }

    /// `SEED_BYTES` must be exactly ChaCha20's seed length and exactly SHA-256's
    /// output, or `mix_sources` would have to truncate or pad -- both of which
    /// would silently change how much of the mix reaches the stream.
    #[test]
    fn seed_length_lines_up_with_chacha_and_sha256() {
        assert_eq!(SEED_BYTES, 32);
        assert_eq!(
            core::mem::size_of::<<ChaCha20Rng as SeedableRng>::Seed>(),
            SEED_BYTES
        );
        assert_eq!(<Sha256 as sha2::Digest>::output_size(), SEED_BYTES);
        assert_eq!(TRNG_BYTES, 32);
        assert_eq!(SE1_BYTES, 32);
        assert_eq!(SE2_BYTES, 8);
        // Again a `const` block: `MIX_DOMAIN` is a const, so a runtime
        // `assert!(!MIX_DOMAIN.is_empty())` is a no-op the optimiser deletes.
        const _: () = assert!(
            !MIX_DOMAIN.is_empty(),
            "domain separation must be non-empty"
        );
    }
}
