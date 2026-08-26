//! One tagged take-once guard, shared by [`crate::flash`] and [`crate::rng`].
//!
//! # Why this is not an `AtomicBool`
//!
//! Both skeletons said "AtomicBool swap". A plain `AtomicBool::new(false)` is
//! **wrong on this board**, for exactly the reason [`crate::panic`]'s
//! `DEPTH_MAGIC` documents:
//!
//! A `static` lives in `.bss`. `.bss` on Mk4 is SRAM1 at `0x2000_0000`
//! (`layout.ld:21`). The bootloader calls `wipe_all_sram()` on **every** boot
//! (`main.c:130`) and that fills `SRAM1_BASE .. +SRAM1_SIZE_MAX` with the noise
//! constant `0xdeadbeef` — it does **not** zero it (`main.c:42,47`, both read
//! this session). Zeroing `.bss` is therefore a property of our own startup
//! code, and **that code does not exist in this repo yet**.
//!
//! So an uninitialised `AtomicBool` reads a nonzero byte, i.e. `true`. Every
//! `take()` returns `None` on the first call, `StmFlashToken::take()` and
//! `Sources::take_all()` both yield `None`, and the firmware cannot obtain flash
//! or entropy at all. That is a boot brick with no diagnostic — the same silent
//! failure class decision 6 exists to remove, and it would have been introduced
//! by two modules independently following the same skeleton hint.
//!
//! # The fix, and its fail-safe direction
//!
//! The word is tagged, like the RTC counters. Three cases:
//!
//! | Stored word | Meaning |
//! |---|---|
//! | [`AVAILABLE`] | never taken |
//! | [`TAKEN`] | already handed out |
//! | anything else | **uninitialised `.bss`** — treated as `AVAILABLE` |
//!
//! Garbage decoding to `AVAILABLE` is the correct direction and it is safe, not
//! merely convenient: garbage can only be present *before the first
//! [`TakeOnce::take`] of a boot*, because after that the word holds a tag this
//! module wrote. So the first caller is handed the singleton and immediately
//! stores [`TAKEN`]; every later caller sees [`TAKEN`] and gets `None`. The
//! exclusion property is preserved and the brick is gone.
//!
//! The opposite choice — garbage means taken — is the one that bricks, which is
//! why the tag values are asymmetric rather than a single bit.
//!
//! Pure and `cfg`-free, so this is **host-testable**, and it is tested both
//! directly and through each user's own `take()`.

use core::sync::atomic::{AtomicU32, Ordering};

/// Tag stored while the singleton has never been handed out.
///
/// Chosen so that neither `0x0000_0000`, `0xFFFF_FFFF` nor `0xDEAD_BEEF` (the
/// bootloader's SRAM fill, `main.c:42`) can be mistaken for it or for
/// [`TAKEN`]. Distinct from [`crate::panic`]'s `COUNTER_MAGIC` /
/// `DEPTH_MAGIC` tag spaces so a word can never be mistaken for a counter.
pub const AVAILABLE: u32 = 0x5A17_0001;

/// Tag stored once the singleton has been handed out.
pub const TAKEN: u32 = 0x5A17_0002;

/// Decode a raw guard word. Pure — **host-testable**.
///
/// # Contract
///
/// * `raw == `[`TAKEN`] → `true` (already taken).
/// * `raw == `[`AVAILABLE`] → `false`.
/// * anything else → `false`. In particular `0xDEAD_BEEF`, `0` and
///   `0xFFFF_FFFF` must all report "not taken", or the device cannot boot. See
///   the module docs for why that is safe.
/// * Must not panic.
#[must_use]
pub const fn is_taken(raw: u32) -> bool {
    raw == TAKEN
}

/// A take-once guard for a singleton capability.
///
/// Touches no hardware, so every user's `take()` stays host-testable even when
/// the capability it guards is ARM-only.
pub struct TakeOnce {
    word: AtomicU32,
}

impl TakeOnce {
    /// A fresh, untaken guard.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            word: AtomicU32::new(AVAILABLE),
        }
    }

    /// Claim the singleton. `true` for exactly one caller, `false` afterwards.
    ///
    /// Uses `compare_exchange` in a **bounded** loop of at most two attempts:
    /// once for the `AVAILABLE` tag and once for a garbage word. There is no
    /// `while` here on purpose — an unbounded CAS retry in boot code is the same
    /// silent-hang failure class as a panic-halt (`crate::rng`'s
    /// `SourceFault::Timeout` reasoning).
    pub fn take(&self) -> bool {
        // Attempt 1: the normal path, from the tag we wrote at compile time.
        if self
            .word
            .compare_exchange(AVAILABLE, TAKEN, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return true;
        }

        // Attempt 2: the uninitialised-`.bss` path. `compare_exchange` above
        // returned the observed word; if it is neither tag, `.bss` was never
        // zeroed and this is still a first take.
        let observed = self.word.load(Ordering::Acquire);
        if is_taken(observed) || observed == AVAILABLE {
            // A real second caller, or a race the first attempt lost.
            return false;
        }
        self.word
            .compare_exchange(observed, TAKEN, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Whether the singleton has already been handed out. Diagnostic only.
    #[must_use]
    pub fn is_claimed(&self) -> bool {
        is_taken(self.word.load(Ordering::Acquire))
    }
}

impl Default for TakeOnce {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tags must be distinguishable from every value the bootloader or an
    /// erased/blank word can leave behind. A collision here is a boot brick
    /// (`AVAILABLE` collision) or a double-take (`TAKEN` collision).
    #[test]
    fn tags_exclude_plausible_garbage() {
        for garbage in [0x0000_0000u32, 0xFFFF_FFFF, 0xDEAD_BEEF] {
            assert_ne!(garbage, AVAILABLE, "{garbage:#x} collides with AVAILABLE");
            assert_ne!(garbage, TAKEN, "{garbage:#x} collides with TAKEN");
            assert!(!is_taken(garbage), "{garbage:#x} must not read as taken");
        }
        assert!(is_taken(TAKEN));
        assert!(!is_taken(AVAILABLE));
    }

    /// The tag spaces must not overlap `crate::panic`'s counter tags, or a word
    /// could be decoded as the wrong kind of state.
    #[test]
    fn tag_space_is_disjoint_from_the_panic_counters() {
        use crate::panic::{decode_counter, decode_depth};
        for tag in [AVAILABLE, TAKEN] {
            assert_eq!(decode_counter(tag), None, "{tag:#x} decodes as a counter");
            assert_eq!(decode_depth(tag), 0, "{tag:#x} decodes as a nonzero depth");
        }
    }

    #[test]
    fn exactly_one_caller_wins() {
        let guard = TakeOnce::new();
        assert!(!guard.is_claimed());
        assert!(guard.take());
        assert!(guard.is_claimed());
        for _ in 0..8 {
            assert!(!guard.take(), "handed the singleton out twice");
        }
    }

    /// THE REGRESSION THIS MODULE EXISTS FOR. A guard whose word was never
    /// zeroed must still hand out the singleton exactly once. With the
    /// `AtomicBool::new(false)` the skeletons suggested, the first `take()` here
    /// returns `false` and the device cannot obtain flash or entropy.
    #[test]
    fn uninitialised_bss_still_yields_the_singleton_exactly_once() {
        for garbage in [0xDEAD_BEEFu32, 0x0000_0000, 0xFFFF_FFFF, 0x5A17_1234] {
            let guard = TakeOnce {
                word: AtomicU32::new(garbage),
            };
            assert!(
                guard.take(),
                "{garbage:#x} in .bss bricked the singleton (bootloader fill is 0xdeadbeef, main.c:42)"
            );
            assert!(guard.is_claimed());
            assert!(!guard.take(), "{garbage:#x} then handed it out twice");
        }
    }
}
