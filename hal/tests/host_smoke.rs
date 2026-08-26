//! Proves the host-test path works, so every implementer can add `#[test]`s
//! against their own module without first debugging the harness.
//!
//! Runs with `cargo test --target aarch64-apple-darwin -p coldsnap_hal`. The
//! device target is the default (`.cargo/config.toml` `build.target`), so
//! `--target` is mandatory here.
//!
//! The single most important thing this file asserts is implicit: it **links**.
//! If `coldsnap_hal`'s `#[panic_handler]` ever leaked onto the host target, this
//! binary would fail to link against `std`'s. That check is the point.
//!
//! Behavioural assertions belong in each module's own `#[cfg(test)] mod tests`
//! (44 of them as of integration), and cross-crate composition lives in
//! `integration_frostsnap_over_hal.rs`. Only target-shape invariants live here.

/// The gate that keeps the panic handler off the host. If this ever fails, the
/// `cfg` in `panic.rs` is wrong and every host test in the workspace breaks.
#[test]
fn host_target_is_not_bare_metal() {
    assert_ne!(
        std::env::consts::OS,
        "none",
        "host tests must not run on the device target"
    );
    assert!(!cfg!(target_os = "none"));
    assert!(!cfg!(target_arch = "arm"));
}

/// Constants are `cfg`-free and reachable from the host, so pure logic in
/// `flash`/`rng`/`panic` is testable off-hardware.
#[test]
fn memmap_and_geometry_constants_are_host_visible() {
    use coldsnap_hal::memmap;

    // FLASH_FS is the region `StmFlash` owns (layout.ld:18).
    assert_eq!(memmap::FLASH_FS_BASE, 0x0818_0000);
    assert_eq!(memmap::FLASH_FS_LEN, 512 * 1024);

    // Erase floor sits above the bootloader + NVROM (storage.c:212-216).
    assert_eq!(memmap::FLASH_ERASE_FLOOR, 0x0802_0000);

    // ERASE_SIZE must equal frostsnap_embedded's SECTOR_SIZE (partition.rs:32).
    assert_eq!(coldsnap_hal::flash::ERASE_SIZE, 4096);

    // The relational invariants below are all compile-time constant, so a
    // runtime `assert!` would be const-folded to a no-op (clippy
    // `assert_on_constants`). `const` blocks make a violation a BUILD FAILURE
    // instead -- which is what these deserve: each one is a memory-map error
    // that corrupts firmware or nonce state, not a test expectation.
    const _: () = {
        assert!(memmap::FLASH_ERASE_FLOOR < memmap::FLASH_TEXT_BASE);

        // FLASH_FS must not overlap the firmware image, or a nonce write
        // corrupts the code the bootloader verifies.
        assert!(memmap::FLASH_TEXT_BASE + memmap::FLASH_TEXT_LEN <= memmap::FLASH_FS_BASE);

        // Callgate buffers must be inside [SRAM_BASE, BL_SRAM_BASE)
        // (dispatch.c:48).
        assert!(memmap::SRAM_BASE < memmap::BL_SRAM_BASE);

        // ERASE_SIZE must divide the region evenly or the last partition is
        // short.
        assert!(memmap::FLASH_FS_LEN as usize % coldsnap_hal::flash::ERASE_SIZE == 0);
    };
}

/// Documents the live `WRITE_SIZE` conflict as an executable check rather than
/// only a comment. STM32L4 programs 64-bit doublewords (`storage.c:167`), but
/// `frostsnap_embedded::NorFlashLog::new` asserts `WRITE_SIZE == 4`
/// (`nor_flash_log.rs:5,16`). See `flash.rs`'s module docs: resolve by patching
/// the vendored log or by not using `NorFlashLog`.
///
/// If a future change makes `WRITE_SIZE` 4, this test fails and forces the
/// hardware question to be answered rather than silently assumed.
#[test]
fn write_size_is_a_doubleword_and_conflicts_with_nor_flash_log() {
    assert_eq!(coldsnap_hal::flash::WRITE_SIZE, 8);
    assert_ne!(
        coldsnap_hal::flash::WRITE_SIZE,
        4,
        "NorFlashLog's assert_eq!(WORD_SIZE, WRITE_SIZE) is unresolved -- see flash.rs docs"
    );
    // Whatever the resolution, ERASE_SIZE must stay a whole number of writes.
    assert_eq!(
        coldsnap_hal::flash::ERASE_SIZE % coldsnap_hal::flash::WRITE_SIZE,
        0
    );
}

/// Detects whether `T: Default`, without requiring it.
///
/// Autoref specialisation: given a `&&Probe<T>` receiver, method lookup tries
/// `&Probe<T>` (`HasDefault`, which needs `T: Default`) before deref-ing further
/// to `&&Probe<T>` (`NoDefault`), so the fallback is reached only when
/// `T: Default` does not hold. Both impls must be on reference receivers or the
/// unsatisfied bound is a hard error instead of a fallback. This is the only way
/// to assert the *absence* of an impl on stable.
mod default_probe {
    use core::marker::PhantomData;

    pub struct Probe<T>(pub PhantomData<T>);

    pub trait HasDefault {
        fn is_default(&self) -> bool;
    }
    impl<T: Default> HasDefault for &Probe<T> {
        fn is_default(&self) -> bool {
            true
        }
    }

    pub trait NoDefault {
        fn is_default(&self) -> bool;
    }
    impl<T> NoDefault for &&Probe<T> {
        fn is_default(&self) -> bool {
            false
        }
    }
}

/// The fail-closed chain must stay type-enforced. This asserts the *absence* of
/// a bypass: `Entropy` must not be `Default`, or it could be built without a
/// `ProvenSeed` from three health-checked sources — reinstating exactly the
/// libngu fail-open defect PLAN.md §1 rejects.
///
/// `CryptoRng` is implemented for `Entropy`, so a `Default` impl would make that
/// a cryptographic lie. If someone adds `#[derive(Default)]`, this test fails.
#[test]
fn entropy_is_not_default_constructible() {
    use core::marker::PhantomData;
    use default_probe::{HasDefault, NoDefault, Probe};

    // Self-check the probe: `u32` IS Default, so a true negative is meaningful.
    assert!(
        (&&Probe::<u32>(PhantomData)).is_default(),
        "probe is broken -- it reports Default types as non-Default"
    );

    assert!(
        !(&&Probe::<coldsnap_hal::rng::Entropy>(PhantomData)).is_default(),
        "Entropy must NOT implement Default: it would bypass ProvenSeed and \
         reinstate the fail-open defect PLAN.md 1 rejects"
    );
    // Same for the seed itself -- a Default ProvenSeed is an all-zero seed.
    assert!(!(&&Probe::<coldsnap_hal::rng::ProvenSeed>(PhantomData)).is_default());

    // Source byte counts, per dispatch.c:588 and :593. SE2 yields only 8.
    assert_eq!(coldsnap_hal::rng::SE1_BYTES, 32);
    assert_eq!(coldsnap_hal::rng::SE2_BYTES, 8);
    assert_eq!(coldsnap_hal::rng::SEED_BYTES, 32);
    assert!(
        !coldsnap_hal::rng::MIX_DOMAIN.is_empty(),
        "domain separation"
    );
}

/// The panic counter's tag must not collide with plausible garbage in an
/// uninitialised RTC backup register, or the device enters the DFU fallback on
/// its first ever boot. Pure constant arithmetic, so it is checkable now.
#[test]
fn counter_magic_excludes_plausible_garbage() {
    use coldsnap_hal::panic::{COUNTER_MAGIC, COUNTER_VALUE_MASK, PANIC_RESET_THRESHOLD};

    let tag = |raw: u32| raw & !COUNTER_VALUE_MASK;
    for garbage in [0x0000_0000u32, 0xFFFF_FFFF, 0xDEAD_BEEF] {
        assert_ne!(
            tag(garbage),
            COUNTER_MAGIC,
            "{garbage:#x} must decode as None"
        );
    }
    assert_eq!(tag(COUNTER_MAGIC), COUNTER_MAGIC);

    // Constant, so `const` rather than a folded-away runtime assert.
    const _: () = {
        // A zero threshold would trip the DFU fallback on boot one.
        assert!(PANIC_RESET_THRESHOLD > 0);
        // An unreachable threshold would make the handler reset forever.
        assert!(PANIC_RESET_THRESHOLD < COUNTER_VALUE_MASK);
        // The tag must not overlap the value field, or a high count corrupts it.
        assert!(COUNTER_MAGIC & COUNTER_VALUE_MASK == 0);
    };
}
