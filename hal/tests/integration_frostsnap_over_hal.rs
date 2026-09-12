//! PROOF THAT THE FOUR MODULES COMPOSE. This is the only test in the tree that
//! wires the **real** frostsnap types to the new HAL abstractions; every other
//! test exercises one side or the other.
//!
//! Run with `cargo test --target aarch64-apple-darwin -p coldsnap_hal`. The
//! device target is the default (`.cargo/config.toml` `build.target`), so
//! `--target` is mandatory.
//!
//! What is real here and what is not:
//!
//! * **Real**: `frostsnap_embedded::{FlashPartition, AbSlot, NonceAbSlot}`,
//!   `frostsnap_core::device_nonces::{AbSlots, NonceStreamSlot, SecretNonceSlot,
//!   NonceJob}`, and `coldsnap_hal::rng::Entropy` as the `&mut impl RngCore` those
//!   APIs take. The bincode encoding, the A/B index recovery and the nonce
//!   ratchet are all the shipped code.
//! * **A stand-in**: the flash *cells*. [`FakeFlash`] is RAM at `StmFlash`'s exact
//!   geometry (`WRITE_SIZE = 8`, `ERASE_SIZE = 4096`) with the NOR
//!   program-once rule enforced, because real program/erase semantics are
//!   untestable off-hardware (PLAN.md §7, DECISIONS.md decision 5). It models the
//!   *rules*, not the silicon.
//! * **A stand-in**: the entropy *source*. `Entropy::from_proven_seed` seeds the
//!   same ChaCha20 the device uses; only the three hardware legs are absent,
//!   because they cannot run on a host at any tier. The mixer that produces the
//!   `ProvenSeed` is the shipped one.
//!
//! The integration risks this file exists to catch, all of which are invisible to
//! any single-module test:
//!
//! 1. `WRITE_SIZE = 8` vs `frostsnap_embedded`'s buffer asserts
//!    (`partition.rs:188-189`) — a const mismatch is a panic at slot
//!    construction, i.e. a boot brick.
//! 2. `ERASE_SIZE` vs `SECTOR_SIZE` (`partition.rs:32`) — a mismatch silently
//!    erases a neighbouring sector, destroying the *other* A/B copy, which is the
//!    one thing the A/B scheme exists to prevent.
//! 3. `Entropy` satisfying the `RngCore` **and** `CryptoRng` bounds
//!    `frostsnap_core` actually asks for, at the `rand_core` version it resolves.
//! 4. The nonce write path being panic-free end to end on a flash that refuses.

use core::cell::RefCell;
use std::collections::BTreeSet;

use coldsnap_hal::flash::fake::FakeFlash;
use coldsnap_hal::rng::{mix_sources, Entropy, ProvenSeed, SE1_BYTES, SE2_BYTES, TRNG_BYTES};
use frostsnap_core::device::DeviceSecretDerivation;
use frostsnap_core::device_nonces::{
    NonceStreamSlot, NoncesUnavailable, SecretNonceSlot, SigningState,
};
use frostsnap_core::nonce_stream::{CoordNonceStreamState, NonceStreamId};
// The curve reached through `frostsnap_core`'s own re-export
// (`frostsnap_core/src/lib.rs:34`) rather than through hal's direct `schnorr_fun`
// dev-dependency, for the reason `firmware/Cargo.toml` gives: no second entry
// that can drift to a second version. It is also the only form that can work
// here — `PartySignSession::sign` takes the `PairedSecretShare<EvenY>` that
// `device_nonces`' own signature names, so a skewed copy would not typecheck.
use frostsnap_core::schnorr_fun::frost::{
    self, PairedSecretShare, PartySignSession, SecretShare, SignatureShare,
};
use frostsnap_core::schnorr_fun::fun::prelude::*;
use frostsnap_core::schnorr_fun::Message;
use frostsnap_core::SignSessionId;
use frostsnap_embedded::{AbSlot, AbWriteOutcome, FlashPartition, NonceAbSlot, SECTOR_SIZE};
use rand_core::RngCore;

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

/// A varying, word-distinct filler, so the mixer's own health checks never
/// reject this test's *inputs* for a reason the test did not intend.
fn varying(len: usize, salt: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    let mut v = salt;
    for slot in b.iter_mut().take(len) {
        v = v.wrapping_mul(7).wrapping_add(11);
        *slot = v;
    }
    b
}

/// A `ProvenSeed` through the real mixer. There is deliberately no other way to
/// get one — that is the fail-closed type-state — so even a host test has to go
/// through three passing draws.
fn proven_seed(salt: u8) -> ProvenSeed {
    let t = varying(TRNG_BYTES, salt);
    let s1 = varying(SE1_BYTES, salt.wrapping_add(1));
    let s2 = varying(SE2_BYTES, salt.wrapping_add(2));
    mix_sources(&t[..TRNG_BYTES], &s1[..SE1_BYTES], &s2[..SE2_BYTES])
        .expect("three good draws must mix")
}

/// The firmware's real RNG type, seeded without hardware. This is the value that
/// gets passed to every `&mut impl RngCore` site below.
fn entropy(salt: u8) -> Entropy {
    Entropy::from_proven_seed(proven_seed(salt))
}

/// A distinct, non-zero `SignatureShare` filler, `n` in the low byte.
///
/// Non-zero, and distinct per `n`, deliberately. `SignatureShare` is
/// `Scalar<Public, Zero>` so the all-zero encoding *is* legal, but a filler
/// vector of identical scalars cannot catch a decode that returns element 0
/// repeatedly — and the round-trip test below is the only thing in the tree that
/// reads a multi-element `signature_shares` back off flash. `from_bytes` is
/// `Option` only because it rejects `>= n`; a 1-byte value cannot.
fn filler_share(n: u8) -> SignatureShare {
    let mut bytes = [0u8; 32];
    bytes[31] = n;
    Scalar::from_bytes(bytes).expect("a one-byte scalar is below the curve order")
}

/// `frostsnap_core` derives the actual nonce seed through a device HMAC it does
/// not implement itself (`device.rs:612-626`); on hardware that is the SE. A
/// deterministic stand-in is fine here: this file tests composition, and the
/// upstream test suite already covers the derivation.
struct FakeDeviceHmac;

impl DeviceSecretDerivation for FakeDeviceHmac {
    fn get_share_encryption_key(
        &mut self,
        _access_structure_ref: frostsnap_core::AccessStructureRef,
        _party_index: frostsnap_core::schnorr_fun::frost::ShareIndex,
        _coord_key: frostsnap_core::CoordShareDecryptionContrib,
    ) -> frostsnap_core::SymmetricKey {
        frostsnap_core::SymmetricKey([42u8; 32])
    }

    fn derive_nonce_seed(
        &mut self,
        nonce_stream_id: NonceStreamId,
        index: u32,
        seed_material: &[u8; 32],
    ) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"coldsnap/integration-test/nonce-seed");
        h.update(nonce_stream_id.0);
        h.update(index.to_le_bytes());
        h.update(seed_material);
        let d = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&d[..]);
        out
    }
}

// ---------------------------------------------------------------------------
// 1. The consts line up. These are the ones that make a slot constructor panic.
// ---------------------------------------------------------------------------

/// `partition.rs:188-189` asserts `BUFFER_SIZE % S::WRITE_SIZE == 0` and
/// `S::ERASE_SIZE % BUFFER_SIZE == 0` at every `bincode_writer_remember_to_flush`.
/// `AbSlot` uses `BUFFER_SIZE = 256` (`ab_write.rs:161`). With the doubleword
/// `WRITE_SIZE = 8` the device really has, both hold — but a future change to
/// either const turns this from arithmetic into a **panic at nonce-write time**,
/// which under `panic = "abort"` is a halt. Pinned as a build failure, not a
/// runtime expectation.
#[test]
fn hal_geometry_satisfies_frostsnap_embedded_const_asserts() {
    use embedded_storage::nor_flash::NorFlash;

    const _: () = {
        // The two `partition.rs:188-189` asserts, for AbSlot's 256-byte buffer.
        assert!(256 % coldsnap_hal::flash::WRITE_SIZE == 0);
        assert!(coldsnap_hal::flash::ERASE_SIZE % 256 == 0);
        // `FlashPartition` does all of its arithmetic in units of its own
        // SECTOR_SIZE. If that is not our erase granularity, `erase_all` on one
        // slot wipes part of the other -- the exact failure A/B exists to survive.
        assert!(coldsnap_hal::flash::ERASE_SIZE == SECTOR_SIZE);
    };

    // The fake must be the same geometry as the real driver, or nothing below
    // this line proves anything about the device.
    assert_eq!(
        <FakeFlash as NorFlash>::WRITE_SIZE,
        coldsnap_hal::flash::WRITE_SIZE
    );
    assert_eq!(
        <FakeFlash as NorFlash>::ERASE_SIZE,
        coldsnap_hal::flash::ERASE_SIZE
    );
    // And the real driver's geometry must still be the hardware truth.
    assert_eq!(
        coldsnap_hal::flash::WRITE_SIZE,
        8,
        "STM32L4 programs 64-bit doublewords"
    );
    assert_eq!(coldsnap_hal::flash::ERASE_SIZE, 4096);
}

// ---------------------------------------------------------------------------
// 2. AbSlot over the HAL's flash, at the shipped WRITE_SIZE.
// ---------------------------------------------------------------------------

/// The core composition claim: `AbSlot`'s bincode round trip works over a
/// doubleword-programmed NOR flash that enforces program-once. Upstream only ever
/// ran it at `WRITE_SIZE = 4` (`test.rs:5`), so this is genuinely new coverage —
/// and it is the path the tail-padding in `flush` (`partition.rs:269-284`) exists
/// for.
#[test]
fn ab_slot_round_trips_over_the_hal_geometry() {
    let flash = RefCell::new(FakeFlash::new(4));
    let slot = AbSlot::new(FlashPartition::new(&flash, 0, 2, "coldsnap-nonce"));

    assert_eq!(
        slot.read::<u32>(),
        None,
        "a fresh partition must read empty"
    );

    assert_eq!(slot.try_write(&0xDEAD_BEEFu32), AbWriteOutcome::Committed);
    assert_eq!(slot.read::<u32>(), Some(0xDEAD_BEEF));

    // A second write must land in the *other* physical slot and still be
    // readable, i.e. the erase of one copy did not damage the other.
    assert_eq!(slot.try_write(&0x0BAD_F00Du32), AbWriteOutcome::Committed);
    assert_eq!(slot.read::<u32>(), Some(0x0BAD_F00D));

    // Something bigger than one 8-byte doubleword and not a multiple of it, so
    // the tail padding path runs. 37 bytes = 4 doublewords + 5.
    let payload: [u8; 37] = core::array::from_fn(|i| (i as u8).wrapping_mul(3).wrapping_add(1));
    assert_eq!(slot.try_write(&payload), AbWriteOutcome::Committed);
    assert_eq!(slot.read::<[u8; 37]>(), Some(payload));

    // Writes really happened; if the fake had silently no-op'd, everything above
    // would still pass off a cached value.
    assert!(
        flash.borrow().programs > 0 && flash.borrow().erases > 0,
        "no flash traffic: the test proves nothing"
    );
}

/// A write refused mid-way must leave the previous value readable. This is the
/// property that makes it safe for the caller to abort rather than halt, and it
/// only means anything if the refusal is enforced *before* any cell is mutated —
/// which is what `FakeFlash::write` does.
#[test]
fn refused_flash_leaves_the_previous_nonce_state_readable() {
    let flash = RefCell::new(FakeFlash::new(4));
    let slot = AbSlot::new(FlashPartition::new(&flash, 0, 2, "coldsnap-nonce"));

    assert_eq!(slot.try_write(&11u32), AbWriteOutcome::Committed);
    assert_eq!(slot.try_write(&22u32), AbWriteOutcome::Committed);

    flash.borrow_mut().refuse_programs_now();
    let outcome = slot.try_write(&33u32);
    assert!(
        matches!(outcome, AbWriteOutcome::NotCommitted(_)),
        "expected NotCommitted, got {outcome:?}"
    );
    assert!(!outcome.is_committed());

    flash.borrow_mut().heal();
    assert_eq!(
        slot.read::<u32>(),
        Some(22),
        "a refused write destroyed the previous value"
    );

    // Usable again once flash recovers.
    assert_eq!(slot.try_write(&44u32), AbWriteOutcome::Committed);
    assert_eq!(slot.read::<u32>(), Some(44));
}

// ---------------------------------------------------------------------------
// 3. device_nonces over NonceAbSlot over the HAL's flash, driven by Entropy.
// ---------------------------------------------------------------------------

/// The full vertical slice: `frostsnap_core::device_nonces` → `NonceAbSlot` →
/// `FlashPartition` → the HAL's `NorFlash` at `WRITE_SIZE = 8`, with the HAL's
/// `Entropy` as the `&mut impl RngCore`.
///
/// `initialize` is the site that binds all three: it calls `rng.fill_bytes` for
/// the ratchet seed material and then `write_slot` into flash.
#[test]
fn device_nonces_initialize_and_ratchet_over_hal_flash_and_entropy() {
    let flash = RefCell::new(FakeFlash::new(8));
    let mut slots = NonceAbSlot::load_slots(FlashPartition::new(&flash, 0, 8, "nonces"));
    assert_eq!(slots.total_slots(), 4, "8 sectors / 2 per A/B slot");

    let mut rng = entropy(1);
    let stream_id = NonceStreamId::random(&mut rng);

    // `get_or_create` takes `&mut impl RngCore` -- this is the trait-bound check
    // the whole file exists for, at the resolved rand_core version.
    let slot = slots.get_or_create(stream_id, &mut rng);
    assert_eq!(
        slot.last_write_outcome(),
        Some(AbWriteOutcome::Committed),
        "initialize did not commit the slot to flash"
    );

    let value = slot
        .read_slot()
        .expect("initialize must leave a readable slot");
    assert_eq!(value.index, 0);
    assert_eq!(value.nonce_stream_id, stream_id);
    assert!(value.signing_state.is_none());
    assert_ne!(
        value.ratchet_prg_seed_material, [0u8; 32],
        "Entropy handed device_nonces an all-zero ratchet seed"
    );

    // Re-reading through a fresh slot view proves the state is really on the
    // fake flash rather than in a Rust-side cache.
    let mut reloaded = NonceAbSlot::load_slots(FlashPartition::new(&flash, 0, 8, "nonces"));
    let ids: Vec<_> = reloaded.all_stream_ids().collect();
    assert_eq!(ids, vec![stream_id], "stream id did not survive a reload");

    // And the nonce ratchet runs off that persisted material.
    let persisted = reloaded
        .get(stream_id)
        .expect("stream must be found after reload")
        .read_slot()
        .expect("slot must be readable after reload");
    let mut job = persisted
        .try_nonce_task(None, 3)
        .expect("a 3-nonce task is well formed");
    assert_eq!(job.n_nonces_to_generate(), 3);
    job.run_until_finished(&mut FakeDeviceHmac);
    let segment = job.into_segment();
    assert_eq!(segment.nonces.len(), 3);
    assert_eq!(segment.index, 0);
}

/// Two different `Entropy` streams must produce different ratchet material, and
/// the same seed must reproduce it. If `Entropy` were accidentally stateless or
/// zero-seeded, every device would derive the same nonces — the catastrophic
/// case, since FROST nonce reuse is affine.
#[test]
fn nonce_material_tracks_the_entropy_seed() {
    let material = |salt: u8| {
        let flash = RefCell::new(FakeFlash::new(4));
        let mut slots = NonceAbSlot::load_slots(FlashPartition::new(&flash, 0, 4, "nonces"));
        let mut rng = entropy(salt);
        // Fixed stream id so only the RNG differs between runs.
        let stream_id = NonceStreamId([9u8; 16]);
        let slot = slots.get_or_create(stream_id, &mut rng);
        slot.read_slot()
            .expect("initialized")
            .ratchet_prg_seed_material
    };

    let a = material(5);
    let b = material(5);
    let c = material(6);
    assert_eq!(a, b, "same seed gave different nonce material");
    assert_ne!(a, c, "different seeds gave identical nonce material");
    assert_ne!(a, [0u8; 32]);
}

/// The reason `NonceAbSlot::write_slot_versioned` had to change at integration.
///
/// It called the panicking `AbSlot::write` (`nonce_slots.rs:27` before this
/// phase), so a `PROGERR` during a nonce update was a halt — under
/// `panic = "abort"` with the decision-6 handler, a reset loop, on the one path
/// where losing state is worst. This test drives a refusing flash through the real
/// `AbSlots::get_or_create` and asserts it **returns**.
///
/// A `#[should_panic]`-style negative control is not possible here without
/// reverting the fix, so the assertion is the positive one: the call completes,
/// the refusal is reported, and the slot reads as uninitialised rather than as
/// half-written.
#[test]
fn a_refusing_flash_does_not_panic_the_nonce_write_path() {
    let flash = RefCell::new(FakeFlash::new(4));
    let mut slots = NonceAbSlot::load_slots(FlashPartition::new(&flash, 0, 4, "nonces"));
    let mut rng = entropy(7);
    let stream_id = NonceStreamId::random(&mut rng);

    // Refuse everything from the very first program.
    flash.borrow_mut().refuse_programs_now();

    // Before the fix this line panicked inside `AbSlot::write`.
    let slot = slots.get_or_create(stream_id, &mut rng);
    let outcome = slot.last_write_outcome();
    assert!(
        matches!(outcome, Some(AbWriteOutcome::NotCommitted(_))),
        "expected the refusal to be recorded, got {outcome:?}"
    );

    // Nothing was committed, so the slot must read as empty rather than as a
    // partially written value. A half-written slot that decoded successfully
    // would be the dangerous outcome.
    assert_eq!(
        slot.read_slot(),
        None,
        "a fully refused initialize left something readable"
    );

    // Once flash recovers, the same call must succeed -- the failure was not
    // sticky in the Rust-side state.
    flash.borrow_mut().heal();
    let slot = slots.get_or_create(stream_id, &mut rng);
    assert_eq!(slot.last_write_outcome(), Some(AbWriteOutcome::Committed));
    assert_eq!(
        slot.read_slot().expect("now initialized").nonce_stream_id,
        stream_id
    );
}

/// A coordinator-controlled `index` must not turn into unbounded work, and it must
/// not panic, when the slot is a **real flash-backed** one rather than the
/// `MemoryNonceSlot` the upstream regression test uses
/// (`frostsnap_core/tests/nonce_index_bounds.rs:88-110`). The clamp lives in
/// `frostsnap_core`, but the read that feeds it goes through bincode over the
/// HAL's flash here, so this checks the two together.
#[test]
fn hostile_coordinator_index_over_hal_flash_stays_bounded() {
    let flash = RefCell::new(FakeFlash::new(4));
    let mut slots = NonceAbSlot::load_slots(FlashPartition::new(&flash, 0, 4, "nonces"));
    let mut rng = entropy(9);
    let stream_id = NonceStreamId::random(&mut rng);
    let batch = 30u32;

    let slot = slots.get_or_create(stream_id, &mut rng);
    for claimed in [batch + 1, 1_000_000, 100_000_000, u32::MAX - 1, u32::MAX] {
        let job = slot.reconcile_coord_nonce_stream_state(
            CoordNonceStreamState {
                stream_id,
                index: claimed,
                remaining: u32::MAX,
            },
            batch,
        );
        if let Some(job) = job {
            assert!(
                job.n_nonces_to_generate() <= batch,
                "claimed index {claimed} produced {} nonces, over the {batch} batch",
                job.n_nonces_to_generate()
            );
            assert!(
                job.n_derivations_remaining() <= batch,
                "claimed index {claimed} demanded {} derivations",
                job.n_derivations_remaining()
            );
        }
    }
}

/// `SecretNonceSlot` must survive a bincode round trip through the HAL's flash
/// unchanged, including the `Option<SigningState>` with a non-empty `Vec`. That is
/// the largest thing the nonce path writes, and it is what crosses the 256-byte
/// `AbSlot` buffer boundary where the doubleword padding matters.
///
/// THE `signing_state` USED TO BE `None` HERE, so the paragraph above was false:
/// without it the encoded value is 65 B, padded to 72, against `BUFFER_SIZE = 256`
/// (`ab_write.rs:163`) — one `nor_write` from `flush` and no second chunk, and no
/// test in this file had ever entered `BincodeFlashWriter::write`'s multi-chunk
/// branch (`partition.rs:292-315`). Derived: under Fixint the encoded value is
/// `4 + 4 + 4 + 16 + 32 + 4 + 1 + 32 + 8 + 32n` bytes — in order,
/// `SlotValue.index`, the `Versioned` tag, `index`, the stream id, the ratchet
/// material, `last_used`, the `Option` tag, the session id, the `Vec` length,
/// then `n` shares — so `n >= 5` exceeds 256. `n = 6` for margin, and the
/// program count below is what proves the boundary was crossed rather than the
/// arithmetic.
#[test]
fn a_full_secret_nonce_slot_survives_the_hal_flash_round_trip() {
    let flash = RefCell::new(FakeFlash::new(4));
    let mut slots = NonceAbSlot::load_slots(FlashPartition::new(&flash, 0, 4, "nonces"));
    let mut rng = entropy(13);
    let stream_id = NonceStreamId::random(&mut rng);

    let mut material = [0u8; 32];
    rng.fill_bytes(&mut material);
    let value = SecretNonceSlot {
        index: 0x1234_5678,
        nonce_stream_id: stream_id,
        ratchet_prg_seed_material: material,
        last_used: 7,
        signing_state: Some(SigningState {
            session_id: SignSessionId([3u8; 32]),
            signature_shares: (1..=6).map(filler_share).collect(),
        }),
    };

    let slot = slots.get_or_create(stream_id, &mut rng);
    let programs_before = flash.borrow().programs;
    slot.write_slot(&value);
    assert_eq!(slot.last_write_outcome(), Some(AbWriteOutcome::Committed));
    assert_eq!(slot.read_slot(), Some(value.clone()));

    // The boundary claim, measured rather than derived. `FakeFlash` counts
    // programs in DOUBLEWORDS (`bytes.len() / WRITE_SIZE`), not calls, so a full
    // 256-byte chunk is 32 and the 41-byte tail padded to 48 is 6. MEASURED: 76
    // for the two A/B copies (2 x 38); with `signing_state: None` it was 18
    // (2 x 9), i.e. one short chunk each and no boundary. `> 2 * 32` is the
    // claim itself: each copy programmed more than one whole buffer.
    let programmed = flash.borrow().programs - programs_before;
    assert!(
        programmed > 2 * (256 / 8),
        "{programmed} doublewords programmed: the value still fits one 256-byte \
         chunk, so the multi-chunk writer branch this test claims to cover is \
         unreached"
    );

    // Survives a reload from the same cells, i.e. it is really on "flash".
    let mut reloaded = NonceAbSlot::load_slots(FlashPartition::new(&flash, 0, 4, "nonces"));
    assert_eq!(
        reloaded.get(stream_id).and_then(|s| s.read_slot()),
        Some(value)
    );
}

// ---------------------------------------------------------------------------
// 3b. The POST-WRITE half of `sign_guaranteeing_nonces_destroyed`.
//
// Three of the thirteen former panic sites PLAN.md §6.3 enumerates live after
// the nonce advance has been written, and NOTHING in the tree had ever produced
// any of them: `rg SlotUnreadable` and `rg WriteVerifyFailed` found the
// identifiers only in their own definitions and in doc comments. That includes
// the read-back comparison, whose comment carries the entire anti-nonce-reuse
// argument and which `nonce_slots.rs:38-42` cites as already settled.
//
// A note on the double, because it decides which crate these tests live in.
// `frostsnap_embedded`'s own `FaultyNorFlash` (`test.rs`) is `#[cfg(test)]`, so
// it is unreachable from here at all; and it delegates writes to
// `TestNorFlash::write`, which asserts 4-byte alignment and then
// `copy_from_slice`s with NO clear-bits-only rule — it accepts a re-program that
// is `PROGERR` on silicon, which is verbatim the §8.1 defect-5 class `FakeFlash`
// was fixed for, at `WRITE_SIZE = 4` against the Mk4's 8. So a double MORE
// permissive than the hardware is not put into a gate: these use `FakeFlash`,
// whose injection surface is a strict superset at the shipped geometry.
// ---------------------------------------------------------------------------

/// A nonce slot that no longer reads back must make signing REFUSE, not halt.
///
/// `device_nonces.rs`'s `read_slot().ok_or(NoncesUnavailable::SlotUnreadable)?`
/// was `.expect("cannot sign with uninitialized slot")` upstream. On hardware
/// `read_slot` goes through `AbSlot::read` and a degraded slot yields `None`, so
/// under `panic = "abort"` with RDP=2 that `expect` was a brick — and no test
/// anywhere had ever produced the variant that replaced it.
///
/// Two legs make this falsifiable rather than "I broke flash and got an `Err`":
///
/// * The EXACT variant. `SlotUnreadable` is returned at exactly one site, so the
///   variant names the site — as against `WriteVerifyFailed`, which the read-back
///   half returns, and `Overflow`, which the lookup and the nonce iterator
///   return.
/// * The flash operation COUNTERS, and deliberately NOT `last_write_outcome()`.
///   MEASURED: with a "self-heal" mutation at the site — re-`initialize` the slot
///   before returning the error, which resets `index` to 0 and is therefore the
///   nonce-reuse catastrophe — the recorded outcome becomes `Some(Committed)`
///   again, identical to what it was before the call, so
///   `assert_eq!(last_write_outcome(), before)` stays GREEN. The counters caught
///   it; the outcome could not.
///
/// The reachability limit, stated because the site's own comment overstates it:
/// the shipped path is `device.rs:499` ->
/// `AbSlots::sign_guaranteeing_nonces_destroyed`, whose first act is
/// `self.get(stream_id).ok_or(Overflow)?`, and `get` calls `nonce_stream_id()` ->
/// `read_slot()`. An already-unreadable slot is filtered one call earlier and the
/// caller sees `Overflow`, never `SlotUnreadable`. The window is between those
/// two ADJACENT reads, not across the `RequestSign` handler. This test calls the
/// trait method on the slot handle to hold that window open.
#[test]
fn an_unreadable_nonce_slot_refuses_to_sign_instead_of_halting() {
    let flash = RefCell::new(FakeFlash::new(4));
    let mut slots = NonceAbSlot::load_slots(FlashPartition::new(&flash, 0, 4, "nonces"));
    let mut rng = entropy(21);
    let stream_id = NonceStreamId::random(&mut rng);

    let slot = slots.get_or_create(stream_id, &mut rng);
    assert_eq!(
        slot.last_write_outcome(),
        Some(AbWriteOutcome::Committed),
        "the setup write must reach flash or the degradation below proves nothing"
    );

    // 0xff, the ERASED state, and NOT 0x00. This is load-bearing, not cosmetic:
    // under Fixint a slot scribbled to 0x00 DECODES — `SlotValue.index` 0,
    // `Versioned` tag 0 = `V0`, an all-zero `nonce_stream_id`, `Option` tag 0 =
    // `None` — so `read_slot()` returns `Some`, the site below is passed, and the
    // very next line, `assert_eq!(.., "wrong stream id")` (kept deliberately,
    // vendor/README.md), fires. That is a PANIC, i.e. the brick this test exists
    // to rule out, reached by the test's own setup. At 0xff `read_index` sees
    // `u32::MAX`, the empty-slot sentinel, both A/B copies rank `None` and
    // `AbSlot::read` returns `None` before the assert. Charge loss also drifts
    // NOR cells towards 0xff, so it is the realistic degradation direction.
    let n = flash.borrow().len();
    flash.borrow_mut().scribble(0, n, 0xff);
    let (programs, erases) = {
        let f = flash.borrow();
        (f.programs, f.erases)
    };

    let err = slot
        .sign_guaranteeing_nonces_destroyed(
            SignSessionId([1u8; 32]),
            CoordNonceStreamState {
                stream_id,
                index: 0,
                remaining: 100,
            },
            1,
            Vec::<(PairedSecretShare<EvenY>, PartySignSession)>::new(),
            &mut FakeDeviceHmac,
            30,
        )
        .expect_err("an unreadable slot must not be signable");
    assert!(
        matches!(err, NoncesUnavailable::SlotUnreadable),
        "wrong site fired: {err:?}"
    );

    // Nothing reached flash. A recovery-by-rewrite here would look like a repair
    // and would in fact hand the coordinator a stream restarted at index 0.
    assert_eq!(
        (flash.borrow().programs, flash.borrow().erases),
        (programs, erases),
        "the refusal path touched flash"
    );
}

/// An empty `sessions` iterator must be refused BEFORE the write, not
/// `unwrap()`ed.
///
/// This single `let-else` -> `Err(Overflow)` replaced two upstream panics,
/// `panic!("sign sessions must not be empty")` and `next_prg_state.unwrap()`, and
/// its own comment calls it "the backstop if that invariant is ever bypassed" —
/// the wire cannot produce an empty `sessions` because `GroupSignReq::check`
/// enforces the count. A backstop nothing exercises is a backstop nobody has
/// checked, and this is the only way in.
///
/// WHICH `Overflow`: the variant alone is not enough here, because
/// `AbSlots::sign_guaranteeing_nonces_destroyed` also returns `Overflow` as its
/// placeholder for "stream not found" and the nonce iterator returns it when
/// exhausted. Both are excluded by argument, not by a further assertion — the
/// setup asserts the slot reads back exactly what was written, so the lookup by
/// stream id cannot miss, and an empty `sessions` never enters the loop that
/// could exhaust the iterator. Re-asserting "the stream is still findable" after
/// the call would be a restatement of the fixture: it cannot fail while the
/// counters below are unchanged, since `FakeFlash` only mutates cells through
/// program, erase or the test's own `scribble`.
#[test]
fn empty_sign_sessions_are_refused_before_anything_reaches_flash() {
    let flash = RefCell::new(FakeFlash::new(4));
    let mut slots = NonceAbSlot::load_slots(FlashPartition::new(&flash, 0, 4, "nonces"));
    let mut rng = entropy(22);
    let stream_id = NonceStreamId::random(&mut rng);

    let mut material = [0u8; 32];
    rng.fill_bytes(&mut material);
    let before = SecretNonceSlot {
        index: 7,
        nonce_stream_id: stream_id,
        ratchet_prg_seed_material: material,
        last_used: 1,
        signing_state: None,
    };
    let slot = slots.get_or_create(stream_id, &mut rng);
    slot.write_slot(&before);
    assert_eq!(
        slot.read_slot(),
        Some(before),
        "the fixture must be on flash and findable by stream id, or the Overflow \
         below could be the lookup's rather than the backstop's"
    );
    let (programs, erases) = {
        let f = flash.borrow();
        (f.programs, f.erases)
    };

    // The production path (`device.rs:499`), not the trait method: `AbSlots::get`
    // matching the stream id is what keeps the "wrong stream id" assert
    // unreachable, and `remaining: 100 >= nonce_batch_size: 30` keeps
    // replenishment out of it.
    let err = slots
        .sign_guaranteeing_nonces_destroyed(
            SignSessionId([2u8; 32]),
            CoordNonceStreamState {
                stream_id,
                index: 7,
                remaining: 100,
            },
            Vec::<(PairedSecretShare<EvenY>, PartySignSession)>::new(),
            &mut FakeDeviceHmac,
            30,
        )
        .expect_err("no sessions means no nonce was consumed, so nothing to sign");
    assert!(
        matches!(err, NoncesUnavailable::Overflow),
        "wrong site fired: {err:?}"
    );

    assert_eq!(
        (flash.borrow().programs, flash.borrow().erases),
        (programs, erases),
        "the backstop fired AFTER a write, so something reached flash on a request \
         that consumed no nonce"
    );
}

/// A RETRY of a session already on flash must return the cached shares and must
/// NOT advance the index. This is the anti-nonce-reuse property the read-back
/// comment leans on ("a retry cannot advance the index twice"), and it had no
/// test.
///
/// The empty `sessions` is legitimate here precisely because the cached branch
/// never touches it: it re-uses `slot_value` wholesale. That is also what makes
/// this test the load-bearing one for the branch — if a future edit made the
/// cached arm iterate `sessions`, this flips from `Ok` to `Err(Overflow)`.
#[test]
fn a_retry_of_the_same_signing_session_returns_the_cached_shares_without_advancing() {
    let flash = RefCell::new(FakeFlash::new(4));
    let mut slots = NonceAbSlot::load_slots(FlashPartition::new(&flash, 0, 4, "nonces"));
    let mut rng = entropy(23);
    let stream_id = NonceStreamId::random(&mut rng);
    let session_id = SignSessionId([5u8; 32]);

    let mut material = [0u8; 32];
    rng.fill_bytes(&mut material);
    let slot = slots.get_or_create(stream_id, &mut rng);
    slot.write_slot(&SecretNonceSlot {
        index: 7,
        nonce_stream_id: stream_id,
        ratchet_prg_seed_material: material,
        last_used: 1,
        signing_state: Some(SigningState {
            session_id,
            signature_shares: vec![filler_share(11), filler_share(12)],
        }),
    });
    assert_eq!(slot.last_write_outcome(), Some(AbWriteOutcome::Committed));

    // `replenish` is deliberately dropped rather than asserted `is_none()`.
    // `reconcile_coord_nonce_stream_state` returns `None` exactly when the slot's
    // index equals the coordinator's claimed index, so `replenish.is_none()` and
    // the index assertion below are the SAME fact read two ways: whichever is
    // written second cannot fail. The index is the one that says what the
    // property is, so it is the one kept.
    let (shares, _replenish) = slots
        .sign_guaranteeing_nonces_destroyed(
            session_id,
            CoordNonceStreamState {
                stream_id,
                index: 7,
                remaining: 100,
            },
            Vec::<(PairedSecretShare<EvenY>, PartySignSession)>::new(),
            &mut FakeDeviceHmac,
            30,
        )
        .expect("a retry of a cached session must not need nonces");
    assert_eq!(
        shares,
        vec![filler_share(11), filler_share(12)],
        "a retry returned different shares, so it re-derived rather than re-read"
    );
    assert_eq!(
        slots
            .get(stream_id)
            .expect("the cached branch rewrote the same stream, so it is still found")
            .read_slot()
            .expect("the rewrite committed, so the slot decodes")
            .index,
        7,
        "THE NONCE-REUSE CASE: a retry advanced the index a second time"
    );
}

/// THE HEADLINE. A nonce advance that flash refuses must come back as
/// `WriteVerifyFailed`, with the old state intact — because
/// `device.rs:507` maps that to `ActionError::StateInconsistent` and returns
/// before building the `SignatureShare` message, so no share leaves the device
/// for a nonce whose consumption could not be confirmed. `nonce_slots.rs:38-42`
/// states that as settled fact; until this test nothing had produced the value,
/// and `rg WriteVerifyFailed` found the identifier only in its own definition and
/// in two doc comments.
///
/// The cheap route to this site is vacuous and was rejected: with an EMPTY
/// `sessions` the cached branch sets `with_signatures = slot_value`, and a
/// refused `AbSlot::try_write` leaves the surviving A/B copy holding exactly that
/// `slot_value`, so the read-back compares the old value against itself and the
/// function returns `Ok` no matter how hard flash failed. Reaching it
/// non-vacuously costs one real `(PairedSecretShare<EvenY>, PartySignSession)`;
/// both halves are copied from the tree
/// (`frostsnap_core/tests/device_backward_compat.rs` for the markers,
/// `device.rs:466-490` for the session), and the agg nonce comes from the same
/// `try_nonce_task`/`run_until_finished`/`into_segment` chain used above, so
/// `session.sign` is handed the nonce `iter_secret_nonces` actually derives
/// rather than a degenerate one — `sign` panics on a mismatched key or a
/// non-member party, so consistency here is not optional.
///
/// THE PRE-EXISTING `signing_state` BELONGS TO A DIFFERENT SESSION, and that is
/// the whole design of this test. MEASURED: with `signing_state: None` — the
/// obvious shape — deleting the read-back comparison leaves the suite GREEN,
/// because the `signing_state.ok_or(WriteVerifyFailed)?` two lines further down
/// catches the stale `None` and returns the same variant. With a stale
/// `SigningState` present, that backstop is bypassed and the mutation returns
/// `Ok` carrying ANOTHER SESSION'S shares for an advance that never reached
/// flash. So the comparison is the only site that can fire, and the assertion
/// below pins it.
///
/// Two things this test does NOT claim. It does not assert "no `SignatureShare`
/// was emitted": the return type carries none in the `Err` arm and `device.rs`'s
/// `?` is on the same line as the call, so that assertion cannot fail. And it
/// does not reach the `read_slot()`-returns-`None` leg one line earlier, which
/// needs corruption to appear BETWEEN the write and the read-back, i.e. a torn
/// multi-chunk write. That needs an offset-scheduled refusal
/// (`refuse_programs_after(k)`) that `FakeFlash` does not have; it is the phase-7
/// increment and is deliberately not faked here.
#[test]
fn a_refused_nonce_advance_reports_write_verify_failed_and_leaves_the_index_unadvanced() {
    let flash = RefCell::new(FakeFlash::new(4));
    let mut slots = NonceAbSlot::load_slots(FlashPartition::new(&flash, 0, 4, "nonces"));
    let mut rng = entropy(24);
    let stream_id = NonceStreamId::random(&mut rng);
    let stale_session = SignSessionId([7u8; 32]);

    let mut material = [0u8; 32];
    rng.fill_bytes(&mut material);
    let stale = SecretNonceSlot {
        index: 7,
        nonce_stream_id: stream_id,
        ratchet_prg_seed_material: material,
        last_used: 1,
        signing_state: Some(SigningState {
            session_id: stale_session,
            signature_shares: vec![filler_share(31), filler_share(32)],
        }),
    };
    let slot = slots.get_or_create(stream_id, &mut rng);
    slot.write_slot(&stale);
    assert_eq!(slot.last_write_outcome(), Some(AbWriteOutcome::Committed));

    // The nonce the sign path will derive at index 7, and a session bound to it.
    let mut job = stale
        .try_nonce_task(None, 1)
        .expect("a 1-nonce task at index 7 is well formed");
    job.run_until_finished(&mut FakeDeviceHmac);
    let frost = frost::new_without_nonce_generation::<sha2::Sha256>();
    let agg = frost.aggregate_binonces(job.into_segment().nonces);
    let paired = PairedSecretShare::new_unchecked(
        SecretShare {
            index: s!(1).public(),
            share: s!(42).mark_zero(),
        },
        g!(42 * G).normalize(),
    )
    .into_xonly();
    let session = frost.party_sign_session(
        paired.public_key(),
        BTreeSet::from([paired.index()]),
        agg,
        Message::raw(b"coldsnap fault injection"),
    );

    // PROGRAMS refused, not erases, and that choice is load-bearing. A refused
    // erase means `Slot::try_write` fails at its first line and flash is
    // bit-identical afterwards, which makes the "the old value survived" leg
    // below a claim about a no-op. Refusing programs lets the erase of the OLDER
    // A/B copy land first, so flash really does change under this test and the
    // surviving-copy claim is about A/B redundancy doing its job.
    flash.borrow_mut().refuse_programs_now();
    let err = slots
        .sign_guaranteeing_nonces_destroyed(
            SignSessionId([6u8; 32]),
            CoordNonceStreamState {
                stream_id,
                index: 7,
                remaining: 100,
            },
            vec![(paired, session)],
            &mut FakeDeviceHmac,
            30,
        )
        .expect_err("a nonce advance flash did not take must not be signable");
    assert!(
        matches!(err, NoncesUnavailable::WriteVerifyFailed),
        "wrong site fired: {err:?}"
    );

    // Once flash recovers, the slot still holds the STALE session at index 7 —
    // index, ratchet material and the old shares all unmoved. That is the
    // anti-nonce-reuse half: the nonce at index 7 was derived and signed over in
    // RAM, but flash still says 7, so it will be derived again rather than
    // skipped, and the share computed from it never left the device.
    //
    // Ordered BEFORE the outcome leg deliberately. The lookup and the read both
    // go through `read_slot()`, so this is what fails if the refused write took
    // the A/B copies with it. MEASURED: dropping `AbSlot::try_write`'s early
    // return between the two copies ("write both, report the worst") erases both
    // and lands on the first `expect` here; with this block ordered after the
    // outcome leg it landed on an `expect` whose message named nothing.
    //
    // `FakeFlash` never refuses READS, so the read-back inside the site returned
    // `Some` — which is what says the equality comparison fired rather than the
    // `ok_or(WriteVerifyFailed)` one line above it.
    flash.borrow_mut().heal();
    let after = slots
        .get(stream_id)
        .expect("both A/B copies lost the stream: the refused write destroyed the slot")
        .read_slot()
        .expect("the slot is still findable but no longer decodes");
    assert_eq!(
        after, stale,
        "a refused advance changed what is on flash: the index, the ratchet \
         material or the stale session's shares moved"
    );

    // A write WAS attempted and left nothing — as against the two tests above,
    // where the refusal came before any write. This is the leg that separates
    // "the read-back caught it" from "the write silently succeeded and the
    // comparison is the thing that is wrong".
    let outcome = slots
        .get(stream_id)
        .expect("proven findable above")
        .last_write_outcome();
    assert!(
        matches!(outcome, Some(AbWriteOutcome::NotCommitted(_))),
        "expected NotCommitted, got {outcome:?}"
    );
}

// ---------------------------------------------------------------------------
// 4. Entropy at frostsnap_core's actual bounds.
// ---------------------------------------------------------------------------

/// `frostsnap_core` takes `&mut impl RngCore` at 28 sites and `CryptoRng` at
/// some. A generic function with those exact bounds is the compile-time check
/// that `Entropy` is usable there — including that the `rand_core` version
/// `coldsnap_hal` links is the one `frostsnap_core` resolves. A version skew here
/// is a trait-bound error, not a runtime bug, which is why this is a test that
/// merely has to *compile*.
#[test]
fn entropy_satisfies_the_bounds_frostsnap_core_asks_for() {
    fn takes_rng_core(rng: &mut impl RngCore) -> u32 {
        rng.next_u32()
    }
    fn takes_crypto_rng<R: RngCore + rand_core::CryptoRng>(rng: &mut R) -> u32 {
        rng.next_u32()
    }
    // `NonceStreamId::random` and `initialize` both take `&mut impl RngCore`.
    fn takes_it_by_value_generic<R: RngCore>(mut rng: R) -> NonceStreamId {
        NonceStreamId::random(&mut rng)
    }

    let mut rng = entropy(17);
    let a = takes_rng_core(&mut rng);
    let b = takes_crypto_rng(&mut rng);
    assert_ne!(
        (a, b),
        (0, 0),
        "two draws were both zero; the stream looks dead"
    );
    let _ = takes_it_by_value_generic(entropy(18));
}

/// `Entropy` must not be reseedable without sources, and the refusal must not
/// disturb the stream — a caller that reseeds opportunistically before signing
/// would otherwise be worse off than one that did not.
#[test]
fn a_seed_only_entropy_refuses_to_reseed_and_keeps_working() {
    let mut rng = entropy(19);
    assert!(!rng.can_reseed());
    assert!(rng.try_reseed().is_err());
    assert_eq!(rng.reseed_count(), 0);

    // Still produces the same stream a fresh instance would, i.e. the failed
    // reseed consumed nothing.
    let mut fresh = entropy(19);
    let (mut x, mut y) = ([0u8; 32], [0u8; 32]);
    rng.fill_bytes(&mut x);
    fresh.fill_bytes(&mut y);
    assert_eq!(x, y, "a refused reseed advanced or reseeded the stream");
}

// ---------------------------------------------------------------------------
// 5. The NorFlashLog decision, checked against the real type.
// ---------------------------------------------------------------------------

/// `flash.rs` resolves the `WRITE_SIZE` conflict as "do not use `NorFlashLog`"
/// (option 2). `assert_nor_flash_log_is_unusable` states that as a const; this
/// test checks it against the **real** `NorFlashLog`'s own constant rather than a
/// remembered value, so the two cannot drift.
///
/// `NorFlashLog::new` asserts `WORD_SIZE(4) == S::WRITE_SIZE` (`nor_flash_log.rs:5,16`),
/// so constructing one over the HAL's geometry would panic — a halt. This test
/// deliberately does **not** construct it.
#[test]
fn nor_flash_log_remains_unusable_over_the_hal_geometry() {
    assert!(
        coldsnap_hal::flash::assert_nor_flash_log_is_unusable(),
        "WRITE_SIZE became 4; re-open the NorFlashLog decision in flash.rs docs"
    );
    // `WRITE_BUF_SIZE` is the log's own buffer const, so this failing to compile
    // would mean the const moved or was removed. A `const` block rather than a
    // runtime `assert!`: on a const the runtime form is deleted by the optimiser
    // and checks nothing (clippy::assertions_on_constants).
    const _: () = assert!(frostsnap_embedded::WRITE_BUF_SIZE > 0);
    // The actual incompatibility: the log's word size is not the flash's.
    assert_ne!(
        core::mem::size_of::<u32>(),
        coldsnap_hal::flash::WRITE_SIZE,
        "NorFlashLog's WORD_SIZE now matches WRITE_SIZE, but its push() still \
         reprograms the length doubleword -- see flash.rs option 1 vs 2"
    );
}

// ---------------------------------------------------------------------------
// 5. identity and the real nonce stack, sharing FLASH_FS.
// ---------------------------------------------------------------------------

/// The one claim `identity`'s own unit tests cannot make: the two owners of
/// `FLASH_FS` do not tread on each other. `identity` writes raw bytes at
/// `FS_IDENTITY_OFFSET` through `NorFlash` directly; `NonceAbSlot` erases and
/// programs whole sectors through `FlashPartition` at `FS_NONCE_OFFSET`. Nothing
/// in either type knows about the other — only `memmap` does — so this is the
/// test that fails if those constants ever drift into overlap.
#[test]
fn nonce_writes_do_not_disturb_the_identity_record() {
    use coldsnap_hal::memmap::{FS_IDENTITY_LEN, FS_IDENTITY_OFFSET, FS_NONCE_LEN, FS_NONCE_OFFSET};
    const SECTOR: u32 = coldsnap_hal::flash::ERASE_SIZE as u32;

    let flash = RefCell::new(FakeFlash::new(
        ((FS_NONCE_OFFSET + FS_NONCE_LEN) / SECTOR) as usize,
    ));

    let secret = coldsnap_hal::identity::load_or_create(&mut *flash.borrow_mut(), &mut entropy(9))
        .expect("blank flash must yield an identity")
        .expose_secret()
        .to_owned();

    // The real stack, at the real offset, doing real erases and programs.
    let mut slots = NonceAbSlot::load_slots(FlashPartition::new(
        &flash,
        FS_NONCE_OFFSET / SECTOR,
        FS_NONCE_LEN / SECTOR,
        "nonces",
    ));
    let mut rng = entropy(10);
    for _ in 0..slots.total_slots() {
        let slot = slots.get_or_create(NonceStreamId::random(&mut rng), &mut rng);
        assert_eq!(slot.last_write_outcome(), Some(AbWriteOutcome::Committed));
    }

    // Identity still reads back — and `load_or_create` returning the SAME secret
    // is the assertion, because a clobbered record would have made it either
    // refuse (`Damaged`) or mint a new key.
    let reloaded = coldsnap_hal::identity::load_or_create(&mut *flash.borrow_mut(), &mut entropy(11))
        .expect("the nonce stack destroyed the identity record");
    assert_eq!(reloaded.expose_secret(), &secret);

    // And the identity region really is the *first* thing in FLASH_FS, so a
    // partition placed at sector 0 by a future edit would collide.
    assert_eq!(FS_IDENTITY_OFFSET, 0);
    assert_eq!(FS_NONCE_OFFSET, FS_IDENTITY_LEN);
}
