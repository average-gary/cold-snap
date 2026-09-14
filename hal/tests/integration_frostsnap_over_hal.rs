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
use frostsnap_core::{SignSessionId, Versioned};
use frostsnap_embedded::{
    AbSlot, AbWriteOutcome, FlashPartition, NonceAbSlot, ABWRITE_BINCODE_CONFIG, SECTOR_SIZE,
};
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

/// `AbSlot::try_write` erases and rewrites the **older** A/B copy first, so a
/// refusal can never destroy the copy holding the live value.
///
/// NOTHING enforced this. The order is expressed solely by which of `next_slot`
/// and `other_slot` appears first in `ab_write.rs`, its own comment ("Write the
/// *older* slot first") is unchecked prose, and MEASURED: swapping the two calls
/// left frostsnap_embedded (17), coldsnap_hal (288) and coldsnap_firmware (172) ALL
/// GREEN — **477** tests at the base commit, which is every test in the tree that
/// LINKS the function. `frostsnap_core` (63) is green under the swap too and it
/// means NOTHING: `frostsnap_core/Cargo.toml` declares no `frostsnap_embedded`
/// dependency, the arrow points the other way, so that gate never compiled
/// `try_write`. A gate with no view of a function is not a coverage measurement.
/// Every test that DOES see it reaches `try_write` from a state where both copies
/// are EQUAL, where the order cannot be observed at all.
///
/// One pin here covers ALL THREE in-tree consumers, because it is the same function
/// and no consumer adds a way for it to be wrong:
///
/// * the nonce path, `NonceAbSlot::write_slot_versioned` -> `AbSlot::try_write`,
///   reached on every `sign_ack` and every `OpenNonceStreams`. Losing both copies
///   loses the STREAM: `read_slot()` is `None`, so `AbSlots::get_or_create` takes
///   its `None => initialize(..)` arm, which draws FRESH `ratchet_prg_seed_material`
///   from the RNG and restarts at index 0. It fails CLOSED — the coordinator's
///   committed public nonces no longer match, and signing on the lost stream is
///   `NoncesUnavailable::Overflow` because `get` cannot find it — and there is NO
///   reuse, because a re-derived INDEX over new material is a different nonce. The
///   affine break belongs to the ROLLBACK case below, which this test never reaches.
/// * the share store, `ShareStore::persist_staged` in `firmware/src/store.rs`,
///   whose PRODUCTION module docs state this ordering as a premise of the record
///   format ("`AbSlot` writes the *older* copy first ... so an interrupted save
///   leaves the previous value live in the other copy") and whose own `ponytail:`
///   note closes the escape hatch ("`AbSlot` exposes no route to the intact older
///   copy, so the previous share becomes unreachable too"). Under the swap a torn
///   share save loses the ONLY COPY ON THE DEVICE, with no recovery install
///   (`mk4-bootloader/sdcard.c:248`) and no route to the intact older copy —
///   unspendable unless the holder had already taken the 25-word backup, which
///   `Session::recv_core` does admit (`DisplayBackup` plus the four restore-flow
///   messages). This is the worst of the three, and by a different mechanism from
///   the nonce path's.
/// * the name region, `NameStore::save` in `firmware/src/lib.rs`, also a plain
///   `frostsnap_embedded::AbSlot`. Cheapest of the three: a lost name reads back
///   `None`, the device announces `NeedName` and a human retypes it.
///
/// Steps (a)-(c) are swap-INVARIANT and cannot be what fails: they run from equal
/// copies, so the write lands on whichever slot and the read is `Some(33)` in
/// either orientation. Step (d) is the entire test.
/// `refused_flash_leaves_the_previous_nonce_state_readable` above also reaches the
/// asymmetric state, one live copy and one blank; what is unique HERE is that the
/// refusal is still ARMED for a FURTHER write from it, which is the only way the
/// erase order becomes observable.
///
/// WHAT IS NOT PINNED HERE, AND NOW IS, one test below: the ROLLBACK symptom. A
/// `CommittedSingleCopy` reached by a refused PROGRAM — the only kind this test can
/// build — leaves the loser copy BLANK, because `Slot::try_write` erases before it
/// writes, so under the swap BOTH copies are lost and `read` is `None`. A
/// `CommittedSingleCopy` from a refused ERASE instead leaves the loser holding the
/// OLD value at a SPENT index, and there the same one-line ordering error rolls the
/// index BACK rather than losing it — and THAT is the affine break: two challenges
/// over one nonce solve for the secret share, because the material is the same and
/// only the index was rewound.
///
/// This doc used to argue the gap away ("it falsifies the SAME mutation, so it buys a
/// second name for coverage that already exists"). The arithmetic was right and the
/// conclusion was wrong: `refuse_erases_after` plus
/// `a_further_refused_write_after_an_erase_refused_single_copy_does_not_roll_the_index_back`
/// now exist, both tests DO go red on this one swap, and the second one is kept
/// anyway because a fail-CLOSED total loss and a fail-OPEN index rewind are not the
/// same finding to whoever reads the failure. Do not re-collapse them.
#[test]
fn a_refused_write_after_a_single_copy_write_erases_the_older_copy_not_the_live_one() {
    let flash = RefCell::new(FakeFlash::new(4));
    let slot = AbSlot::new(FlashPartition::new(&flash, 0, 2, "coldsnap-nonce"));

    // (a), (b): two committed writes, so both copies hold the same value.
    assert_eq!(slot.try_write(&11u32), AbWriteOutcome::Committed);
    let programs_before = flash.borrow().programs;
    assert_eq!(slot.try_write(&22u32), AbWriteOutcome::Committed);
    // DERIVED from the write just measured, never hardcoded. A hardcoded
    // doubleword count rots silently into a refusal scheduled PAST the end of the
    // write, and then (c) asserts only that a successful write succeeded.
    let per_copy = (flash.borrow().programs - programs_before) / 2;
    assert!(
        per_copy > 0,
        "no programs measured, so the schedule below is blind"
    );

    // (c): refuse the SECOND copy's program. The first copy takes the new value;
    // the second is left BLANK by its own already-successful `erase_all`. Flash
    // is now asymmetric — exactly one copy is live — which is the state no other
    // test in the tree puts `try_write` in.
    let refuse_from = flash.borrow().programs + per_copy;
    flash.borrow_mut().refuse_programs_after(refuse_from);
    let outcome = slot.try_write(&33u32);
    assert!(
        matches!(outcome, AbWriteOutcome::CommittedSingleCopy(_)),
        "expected CommittedSingleCopy, got {outcome:?}"
    );
    assert_eq!(
        slot.read::<u32>(),
        Some(33),
        "the surviving copy is not live, so (d) below has nothing left to lose"
    );

    // (d): THE ASSERTION. Another write from the asymmetric state, still refused.
    let (erases, programs) = {
        let f = flash.borrow();
        (f.erases, f.programs)
    };
    let outcome = slot.try_write(&44u32);
    assert!(
        matches!(outcome, AbWriteOutcome::NotCommitted(_)),
        "expected NotCommitted, got {outcome:?}"
    );
    assert_eq!(
        slot.read::<u32>(),
        Some(33),
        "THE ORDERING IS WRONG: the refused write erased the LIVE copy, so both \
         copies are now blank. `AbSlot::read` takes the highest index with no \
         integrity check and no fallback, so there is no route back to the intact \
         one -- a re-derived nonce index, or on the share store the only share"
    );

    // ANTI-VACUITY, and the two legs differ. Neither count moves under the ORDERING
    // swap. A `FakeFlash` that STOPS counting is already caught by
    // `ab_slot_round_trips_over_the_hal_geometry`'s `programs > 0 && erases > 0` and by
    // `identity`'s over-flash test, and `erases + 1` is a local diagnostic those two
    // own as well. But a `FakeFlash` that COUNTS A REFUSED program is caught by
    // NOTHING ELSE — MEASURED, that fake left all 267 lib, 5 smoke and 16
    // pre-existing integration tests GREEN — so `programs` unchanged is the tree's
    // only pin on it. Do not delete it as redundant.
    assert_eq!(
        flash.borrow().erases,
        erases + 1,
        "no erase: nothing was attempted, so the read above proves nothing"
    );
    assert_eq!(
        flash.borrow().programs,
        programs,
        "a refused program still reached flash"
    );
}

/// One A/B copy's `(index, value)` read straight off its own sector, with `u32::MAX`
/// — the "slot is empty" sentinel (`ab_write.rs:151`, `:171`) — left VISIBLE instead
/// of mapped to `None`.
///
/// This is the only non-destructive PER-COPY read that exists. `AbSlot::read`
/// returns the CURRENT copy and drops the index, `current_slot_and_index` is
/// private, and `Slot`/`SlotValue` are private to `frostsnap_embedded`. The probe
/// pattern `a_torn_multi_chunk_write_makes_the_slot_unreadable_and_refuses_to_sign`
/// uses — a second `AbSlot` over the same sectors — cannot help here: `AbSlot::new`
/// asserts `n_sectors >= 2` (`ab_write.rs:26`), so it can only ever be aimed at a
/// PAIR, and a pair is exactly what hides which copy is which.
///
/// Decoding a `(u32, u32)` through the real `FlashPartition::bincode_reader` at the
/// real `ABWRITE_BINCODE_CONFIG` is byte-for-byte how `Slot::read` decodes
/// `SlotValue { index, value }`: same two fields, same order, fixint little-endian.
/// So a layout or config change surfaces here as a wrong number or a decode failure
/// rather than as a hand-rolled offset that has silently rotted.
fn ab_copy(flash: &RefCell<FakeFlash>, sector: u32) -> (u32, u32) {
    bincode::decode_from_reader::<(u32, u32), _, _>(
        FlashPartition::new(flash, sector, 1, "ab-copy-probe").bincode_reader(),
        ABWRITE_BINCODE_CONFIG,
    )
    .expect("eight bytes of a 4096-byte sector always decode as two fixint u32s")
}

/// THE ROLLBACK, which is a different security failure from the total loss the
/// ordering test above asserts. An ERASE-refused `CommittedSingleCopy` leaves the
/// loser copy holding the OLD value at the OLD index; a further refused write must
/// then still not rewind what the device reads back.
///
/// `a_refused_write_after_a_single_copy_write_erases_the_older_copy_not_the_live_one`
/// names this symptom as deliberately unpinned and calls it "a second name for
/// coverage that already exists". That note is right on the coverage arithmetic and
/// WRONG on the security question. Both tests do fail on the same one-line swap of
/// the two `Slot::try_write` calls in `AbSlot::try_write` — EXPECTED, stated here so
/// nobody reads the double failure as a surprise — but they assert different
/// consequences, and only one of the two is the affine break:
///
/// * The sibling's asymmetry comes from a refused PROGRAM, so its loser copy is
///   BLANK: `Slot::try_write` runs `self.flash.erase_all()?` as its FIRST statement,
///   and that erase had already succeeded. Under the swap a further refused write
///   loses BOTH copies, `read_slot()` is `None`, and `AbSlots::get_or_create` takes
///   its `None => initialize(..)` arm — FRESH `ratchet_prg_seed_material`, back at
///   index 0 — so the same index now yields a DIFFERENT nonce. Total loss, and it
///   fails CLOSED.
/// * The asymmetry HERE comes from a refused ERASE, so the loser copy still holds
///   the old value at the old index. Under the swap a further refused write erases
///   the LIVE copy and `current_slot_and_index` falls back to the SPENT index, under
///   the SAME ratchet material. Two challenges over one nonce solve for the secret
///   share. Nothing else in the tree reaches this state, and `refuse_erases_after`
///   did not exist before this test.
///
/// MEASURED, and it corrects the obvious way to write this: keeping the ERASE
/// refusal ARMED for step (c) leaves the swap GREEN. With every erase refused, the
/// further write's first-attempted slot fails its `erase_all` under either
/// orientation, no cell is mutated, and both orders read back identically — a
/// `NotCommitted` that proves only that a refusal refuses. The erase refusal has to
/// be HEALED and a PROGRAM refusal armed in its place, so the further write's erase
/// SUCCEEDS on whichever copy the order reaches first — destroying it — and only the
/// program fails. That asymmetry is the entire test.
///
/// Steps (a) and (b) are swap-INVARIANT by construction: every per-copy assertion is
/// over an unordered `BTreeSet`, so it holds whichever sector each copy lands in and
/// cannot smuggle in an assertion about the order it is meant to be the precondition
/// for.
#[test]
fn a_further_refused_write_after_an_erase_refused_single_copy_does_not_roll_the_index_back() {
    // An erased sector. Erase leaves 0xff and `u32::MAX` is the empty sentinel, so a
    // blank copy decodes to it in BOTH fields.
    const BLANK: (u32, u32) = (u32::MAX, u32::MAX);

    let flash = RefCell::new(FakeFlash::new(4));
    let slot = AbSlot::new(FlashPartition::new(&flash, 0, 2, "coldsnap-nonce"));

    // (a): two committed writes, so both copies are equal and the index has advanced.
    assert_eq!(slot.try_write(&11u32), AbWriteOutcome::Committed);
    let erases_before = flash.borrow().erases;
    assert_eq!(slot.try_write(&22u32), AbWriteOutcome::Committed);
    // DERIVED from the write just measured, never hardcoded, for the reason the
    // sibling gives: a stale constant schedules the fault PAST the end of the write,
    // and then (b) asserts only that a successful write succeeded.
    let per_copy_erases = (flash.borrow().erases - erases_before) / 2;
    assert!(
        per_copy_erases > 0,
        "no erases measured, so the schedule below is blind"
    );

    // (b): let the FIRST copy's erase through and refuse the SECOND's. Two borrows in
    // one expression is "already mutably borrowed" at RUNTIME, hence the `let`.
    let refuse_from = flash.borrow().erases + per_copy_erases;
    flash.borrow_mut().refuse_erases_after(refuse_from);
    let outcome = slot.try_write(&33u32);
    assert!(
        matches!(outcome, AbWriteOutcome::CommittedSingleCopy(_)),
        "expected CommittedSingleCopy, got {outcome:?}"
    );

    // THE PRECONDITION, and it is the whole discrimination from the sibling: BOTH
    // copies decode, at DIFFERENT indexes, the loser still holding the OLD value. The
    // program-scheduled route cannot produce this — its loser is BLANK — so asserting
    // only the `CommittedSingleCopy` variant would make this test a rename.
    assert_eq!(
        BTreeSet::from([ab_copy(&flash, 0), ab_copy(&flash, 1)]),
        BTreeSet::from([(1u32, 22u32), (2u32, 33u32)]),
        "not the rollback precondition: a copy is BLANK (u32::MAX in both fields) or \
         both sit at one index, and then (c) below has no spent index to rewind to"
    );
    // A refused erase must not be COUNTED, or every schedule derived from `erases` is
    // off by the number of refusals. Nothing else in the tree pins this.
    assert_eq!(
        flash.borrow().erases,
        refuse_from,
        "the refused erase was counted"
    );
    assert_eq!(
        slot.read::<u32>(),
        Some(33),
        "the surviving copy is not live, so (c) below has nothing left to lose"
    );

    // (c): THE ASSERTION. Heal the erase refusal — see the MEASURED note above,
    // leaving it armed makes the swap GREEN — and refuse PROGRAMS in its place, so
    // the further write's erase lands on whichever copy the order reaches first.
    flash.borrow_mut().heal();
    flash.borrow_mut().refuse_programs_now();
    let outcome = slot.try_write(&44u32);
    assert!(
        matches!(outcome, AbWriteOutcome::NotCommitted(_)),
        "expected NotCommitted, got {outcome:?}"
    );

    // ON THE INDEX AS WELL AS THE VALUE, and FIRST because it is the stronger of the
    // two forms: `AbSlot::read` drops the index, and the index is the security
    // property — a value assertion alone would pass a rewind that happened to carry
    // the same value. MEASURED as the assertion the swap trips: it reports
    // `{BLANK, (1, 22)}`, i.e. index 2 rewound to the SPENT 1.
    assert_eq!(
        BTreeSet::from([ab_copy(&flash, 0), ab_copy(&flash, 1)]),
        BTreeSet::from([BLANK, (2u32, 33u32)]),
        "ROLLBACK: the refused write erased the LIVE copy, so the newest index on \
         flash fell back to the SPENT one. On the nonce path that is a rewound index \
         over UNCHANGED `ratchet_prg_seed_material`, i.e. one nonce under two \
         challenges, which is the affine solve for the secret share"
    );
    // The same fact in the caller's terms. DOMINATED by the assertion above under the
    // ordering swap, and kept anyway for one reason that is not redundancy: it is the
    // only leg here that pins the SELECTION, i.e. that `current_slot_and_index` ranks
    // the blank copy's `None` below the live copy's `Some` rather than reading the
    // sector it just erased. MEASURED to fire alone on the selection mutation
    // `if b_index > a_index` -> `if a_index > b_index` — though at the (b) read above,
    // which reaches that comparison first. `refused_flash_leaves_the_previous_nonce_state_readable`
    // and the sibling's step (d) also pin the selection from a blank/live pair, so
    // deleting this line would lose no coverage, only the caller-facing name for it.
    assert_eq!(
        slot.read::<u32>(),
        Some(33),
        "the device would consume the rolled-back value"
    );
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

    // `replenish` IS asserted, and the reason it is worth saying so is that this
    // comment previously deleted the assertion on a FALSE argument. It claimed
    // `reconcile_coord_nonce_stream_state` "returns `None` exactly when the slot's index
    // equals the coordinator's claimed index", making the two the same fact — but that
    // function SHORT-CIRCUITS first: `if our_index > state.index || state.remaining <
    // nonce_batch_size { .. }` is tested BEFORE the `else if our_index == state.index {
    // return None }`. With `remaining: 5` against a batch of 30 it returns `Some(job)`
    // with the indices EQUAL, so the two facts merely coincide under THIS fixture's
    // `remaining: 100`. Caught by review, 2026-09-12.
    //
    // Kept AFTER the index assertion rather than before it, the same ordering trick used
    // at the refused-write block below: the index says what the property IS, and this
    // says the coordinator was told nothing needs replenishing. It is the only pin in the
    // tree on that `return None` arm — `nonce_index_bounds.rs` bounds the job size and
    // asserts nothing in its `None` leg.
    let (shares, replenish) = slots
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
    // And nothing was asked of the coordinator. See the note above the call for why this
    // is a SECOND fact and not a restatement of the index: with a `remaining` below the
    // batch size, `reconcile_coord_nonce_stream_state` returns `Some(job)` at an EQUAL
    // index, so this arm and the index arm are independently reachable.
    assert!(
        replenish.is_none(),
        "a retry of a cached session asked the coordinator to replenish, so \
         `reconcile_coord_nonce_stream_state`'s equal-index return was skipped"
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
/// multi-chunk write. That is now
/// `a_torn_multi_chunk_write_makes_the_slot_unreadable_and_refuses_to_sign`
/// below, via `FakeFlash::refuse_programs_after` — COUNT-scheduled in
/// DOUBLEWORDS, not offset-scheduled, so the fault lands on a 256-byte buffer
/// boundary rather than at an address.
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
    // AND THIS BLOCK IS WHAT NAMES THE SITE. `WriteVerifyFailed` has THREE producers —
    // the read-back's `ok_or`, the equality comparison, and the `signing_state` `ok_or`
    // below it — so the variant assertion alone does not say which fired. What excludes
    // the read-back's `ok_or` is the `expect` immediately below: had it fired, both A/B
    // copies would be blank, `AbSlots::get` would return `None`, and that `expect` would
    // have panicked instead. So reaching the comparison of `after` against `stale` is
    // what says the EQUALITY leg fired.
    //
    // This comment previously gave the reason as "`FakeFlash` never refuses READS, so the
    // read-back returned `Some`", which is an invalid inference and one the paragraph
    // directly above it disproves: `read_slot()` returns `None` whenever neither copy
    // DECODES, which has nothing to do with a refused read, and the both-copies-erased
    // mutation reaches exactly that with no read refused. Caught by review, 2026-09-12.
    // The distinction matters because believing the wrong reason is how the next test
    // written here drops this block and silently stops naming the site.
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

/// A nonce write TORN between its 256-byte chunk and its tail flush leaves the
/// newest A/B copy carrying a valid generation index over an undecodable body, and
/// signing must then REFUSE rather than trust it.
///
/// This is the third and last of §6.3's post-write panic sites, and the one the
/// test above says it cannot reach: `read_slot()` returning `None` *after* the
/// write. Three vendored facts compose into it, and none of them is
/// coincidental — `Slot::read_index` decodes only the leading `u32`, so a torn
/// copy still reports its NEW index and WINS `current_slot_and_index`;
/// `AbSlot::read` then decodes that one copy and has no fallback to the intact
/// older one; so `read_slot()` is `None` even though a perfectly good older copy
/// is sitting in the other sector.
///
/// The refusal must be scheduled INSIDE one logical write, which is what
/// `FakeFlash::refuse_programs_after` is for. `refuse_programs_now` cannot do it:
/// it stops the write before its first program and flash comes out unchanged.
///
/// THE CACHED ARM IS LOAD-BEARING, not a shortcut. `session_id` below matches the
/// one already on flash, so `sign_guaranteeing_nonces_destroyed` re-writes the
/// whole 297 B value verbatim — which the vendored comment explicitly sanctions
/// ("we may redundantly rewrite it but that's ok"). A FRESH sign would build a
/// value with one share per session, 137 B, a single chunk, and there is nothing
/// to tear.
///
/// WHICH of `WriteVerifyFailed`'s three producers fired is named by the probe's
/// `is_none()`, not by the variant: if the torn copy still decoded, the EQUALITY
/// leg would fire and return the identical variant. That assertion is load-bearing.
#[test]
fn a_torn_multi_chunk_write_makes_the_slot_unreadable_and_refuses_to_sign() {
    // One `BincodeFlashWriter` buffer, in the DOUBLEWORDS `FakeFlash` counts.
    // `Slot::try_write` uses `bincode_writer_remember_to_flush::<256>`.
    const CHUNK: u32 = 256 / coldsnap_hal::flash::WRITE_SIZE as u32;

    let flash = RefCell::new(FakeFlash::new(4));
    let mut slots = NonceAbSlot::load_slots(FlashPartition::new(&flash, 0, 4, "nonces"));
    let mut rng = entropy(25);
    let stream_id = NonceStreamId::random(&mut rng);
    let session_id = SignSessionId([8u8; 32]);

    let mut material = [0u8; 32];
    rng.fill_bytes(&mut material);
    // The 6-share / 297 B shape whose byte ledger
    // `a_full_secret_nonce_slot_survives_the_hal_flash_round_trip` derives above:
    // 105 fixed bytes + 32n, so the 41-byte tail past the first chunk is what the
    // refusal below cuts off.
    let big = SecretNonceSlot {
        index: 7,
        nonce_stream_id: stream_id,
        ratchet_prg_seed_material: material,
        last_used: 1,
        signing_state: Some(SigningState {
            session_id,
            signature_shares: (1..=6).map(filler_share).collect(),
        }),
    };

    let slot = slots.get_or_create(stream_id, &mut rng);
    let programs_before = flash.borrow().programs;
    slot.write_slot(&big);
    assert_eq!(slot.last_write_outcome(), Some(AbWriteOutcome::Committed));
    // DERIVED, not hardcoded, for the reason the ordering test above gives.
    let per_copy = (flash.borrow().programs - programs_before) / 2;
    assert!(
        per_copy > CHUNK,
        "{per_copy} doublewords per copy against a {CHUNK}-doubleword buffer: the \
         value fits ONE chunk, so the refusal below lands before the write instead \
         of inside it and nothing tears"
    );

    // `AbSlots::get` filters on `nonce_stream_id()` -> `read_slot()`, so once the
    // copy is torn the slot handle is UNREACHABLE, and `get_or_create` would
    // re-`initialize` straight over the evidence. A second `AbSlot` over the same
    // two sectors is the only non-destructive read. Asserted `Some` HERE, BEFORE
    // the fault, because a probe aimed at the wrong sectors reads `None`
    // unconditionally and would make the discrimination below vacuous.
    let probe = AbSlot::new(FlashPartition::new(&flash, 0, 2, "nonce-probe"));
    assert!(
        matches!(probe.read::<Versioned<SecretNonceSlot>>(), Some(Versioned::V0(ref v)) if *v == big),
        "the probe is not reading the slot under test, so its `is_none()` below \
         would say nothing"
    );

    // Between the first 256-byte chunk and the tail's flush.
    let refuse_from = flash.borrow().programs + CHUNK;
    flash.borrow_mut().refuse_programs_after(refuse_from);

    let err = slots
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
        .expect_err("a nonce advance torn part way into flash must not be signable");
    assert!(
        matches!(err, NoncesUnavailable::WriteVerifyFailed),
        "wrong site fired: {err:?}"
    );

    // THE LEG THIS TEST EXISTS FOR. The newest copy no longer decodes, so
    // `read_slot()` answered `None` and the read-back's `ok_or` is what returned
    // the variant above. Had the torn copy still decoded, the EQUALITY comparison
    // one line further down would have fired instead and returned the same
    // variant — which is why the assertion above cannot name the site on its own.
    //
    // Concretely why it does not decode: the torn tail reads back as 0xff, so
    // share 5 becomes ~2^72 (still a legal `Scalar`) and share 6 becomes
    // 32 x 0xff, above the group order, which `Scalar::from_bytes` rejects. If
    // that ever stops being true this assertion goes red loudly rather than the
    // test passing for the wrong reason.
    assert!(
        probe.read::<Versioned<SecretNonceSlot>>().is_none(),
        "the torn copy still DECODES, so the equality leg fired and the \
         read-back's `ok_or` is still unreached"
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
