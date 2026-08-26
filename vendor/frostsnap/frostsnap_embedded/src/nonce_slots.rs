use alloc::vec::Vec;
use embedded_storage::nor_flash::NorFlash;
use frostsnap_core::device_nonces::{AbSlots, NonceStreamSlot, SecretNonceSlot};
use frostsnap_core::Versioned;

use crate::{ab_write::AbSlot, AbWriteOutcome, FlashPartition};

#[derive(Clone, Debug)]
pub struct NonceAbSlot<'a, S> {
    slot: AbSlot<'a, S>,
    /// What the most recent [`NonceStreamSlot::write_slot_versioned`] actually
    /// left on flash, or `None` if this slot has not been written this boot.
    ///
    /// `NonceStreamSlot::write_slot_versioned` returns `()`, so there is nowhere
    /// to report a flash refusal to the caller. It is recorded here instead of
    /// being discarded: discarding it is how a `NotCommitted` looks identical to a
    /// success, and panicking on it (what this did before) is a reset loop under
    /// `panic = "abort"`.
    last_write: Option<AbWriteOutcome>,
}

impl<'a, S: NorFlash> NonceAbSlot<'a, S> {
    pub fn load_slots(mut partition: FlashPartition<'a, S>) -> AbSlots<Self> {
        let mut slots = Vec::with_capacity(partition.n_sectors() as usize / 2);
        while partition.n_sectors() >= 2 {
            slots.push(NonceAbSlot {
                slot: AbSlot::new(partition.split_off_front(2)),
                last_write: None,
            });
        }
        AbSlots::new(slots)
    }

    /// The outcome of the last write, for a caller that wants to notice a flash
    /// refusal at the point it happened rather than inferring it from a later
    /// read.
    ///
    /// Not required for safety: every path that *consumes* nonces
    /// (`device_nonces.rs:406-420`) re-reads the slot and compares, so a write
    /// that did not reach flash already becomes
    /// `NoncesUnavailable::WriteVerifyFailed` and no signature share is emitted.
    /// This accessor exists so `initialize`, which has no read-back, is not
    /// silent.
    pub fn last_write_outcome(&self) -> Option<AbWriteOutcome> {
        self.last_write
    }
}

impl<S: NorFlash> NonceStreamSlot for NonceAbSlot<'_, S> {
    fn read_slot_versioned(&mut self) -> Option<Versioned<SecretNonceSlot>> {
        self.slot.read()
    }

    /// Writes through [`AbSlot::try_write`], **not** the panicking
    /// [`AbSlot::write`] this used to call.
    ///
    /// This is the nonce path: `AbSlot::write` panics on both
    /// `CommittedSingleCopy` and `NotCommitted` (`ab_write.rs:100-110`), and on
    /// real STM32 flash a `PROGERR`/`WRPERR` is reachable, so the old form turned
    /// a recoverable flash fault into a halt — i.e. a reset loop — in the middle
    /// of a nonce update. Worse, `CommittedSingleCopy` means the advance **did**
    /// reach flash, so halting there loses the fact that the nonce was consumed.
    ///
    /// The outcome is recorded rather than dropped; see the `last_write` field.
    /// Read semantics are deliberately unchanged: after a `NotCommitted` the
    /// previous value is still what reads return, which is what lets
    /// `sign_guaranteeing_nonces_destroyed`'s read-back check
    /// (`device_nonces.rs:412-420`) detect the failure and abort *without*
    /// emitting a signature share.
    fn write_slot_versioned(&mut self, value: Versioned<&SecretNonceSlot>) {
        self.last_write = Some(self.slot.try_write(&value));
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test::{FaultyNorFlash, TestNorFlash};
    use core::cell::RefCell;
    use frostsnap_core::nonce_stream::NonceStreamId;
    use rand_core::RngCore;

    /// A deterministic counter RNG. Deliberately **not** `rand_chacha`: this
    /// crate does not depend on it, and adding a dev-dependency to a vendored
    /// manifest for three tests is a divergence to re-apply on every rebase.
    /// Nothing here tests randomness quality — the values only have to be
    /// non-constant so `initialize`'s ratchet material is distinguishable from a
    /// zeroed buffer.
    struct CountingRng(u64);

    impl RngCore for CountingRng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }

        fn next_u64(&mut self) -> u64 {
            // SplitMix64, so successive bytes are not obviously sequential.
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(8) {
                let bytes = self.next_u64().to_le_bytes();
                let n = chunk.len().min(8);
                chunk[..n].copy_from_slice(&bytes[..n]);
            }
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    fn slot_value(stream_id: NonceStreamId, index: u32) -> SecretNonceSlot {
        SecretNonceSlot {
            index,
            nonce_stream_id: stream_id,
            ratchet_prg_seed_material: [0x5au8; 32],
            last_used: 1,
            signing_state: None,
        }
    }

    #[test]
    fn write_and_read_round_trip() {
        let flash = RefCell::new(TestNorFlash::new());
        let mut slots = NonceAbSlot::load_slots(FlashPartition::new(&flash, 0, 4, "nonces"));
        let mut rng = CountingRng(3);
        let stream_id = NonceStreamId::random(&mut rng);

        let slot = slots.get_or_create(stream_id, &mut rng);
        assert_eq!(slot.last_write_outcome(), Some(AbWriteOutcome::Committed));
        let read = slot.read_slot().expect("initialize must be readable");
        assert_eq!(read.nonce_stream_id, stream_id);
        assert_eq!(read.index, 0);

        let updated = slot_value(stream_id, 9);
        slot.write_slot(&updated);
        assert_eq!(slot.last_write_outcome(), Some(AbWriteOutcome::Committed));
        assert_eq!(slot.read_slot(), Some(updated));
    }

    /// THE REGRESSION THIS TYPE'S CHANGE EXISTS FOR. `write_slot_versioned`
    /// previously called the panicking `AbSlot::write`, so a refused erase during
    /// a nonce update was a halt — under `panic = "abort"` a reset loop, on the
    /// path where losing state is worst. It must now return and report.
    #[test]
    fn a_refused_write_reports_instead_of_panicking() {
        let flash = RefCell::new(FaultyNorFlash::new());
        let mut slots = NonceAbSlot::load_slots(FlashPartition::new(&flash, 0, 4, "nonces"));
        let mut rng = CountingRng(4);
        let stream_id = NonceStreamId::random(&mut rng);

        let slot = slots.get_or_create(stream_id, &mut rng);
        assert_eq!(slot.last_write_outcome(), Some(AbWriteOutcome::Committed));
        let before = slot.read_slot().expect("initialized");

        flash.borrow_mut().fail_erase_after(0);
        // Before the fix this line panicked.
        slot.write_slot(&slot_value(stream_id, 42));
        let outcome = slot.last_write_outcome();
        assert!(
            matches!(outcome, Some(AbWriteOutcome::NotCommitted(_))),
            "expected NotCommitted, got {outcome:?}"
        );

        // And the previous value is still what reads return, which is what makes
        // `sign_guaranteeing_nonces_destroyed`'s read-back check catch it.
        flash.borrow_mut().heal();
        assert_eq!(slot.read_slot(), Some(before));
    }

    /// A fault landing between the two A/B copies means the advance **is** on
    /// flash. The outcome must say so, or a caller could treat a consumed nonce as
    /// unconsumed and reuse it — the affine break.
    #[test]
    fn a_single_copy_write_is_reported_as_committed() {
        let flash = RefCell::new(FaultyNorFlash::new());
        let mut slots = NonceAbSlot::load_slots(FlashPartition::new(&flash, 0, 4, "nonces"));
        let mut rng = CountingRng(5);
        let stream_id = NonceStreamId::random(&mut rng);

        let slot = slots.get_or_create(stream_id, &mut rng);
        // One erase per slot copy, so refusing the next-but-one erase lets the
        // first copy through and stops the second.
        let erases = flash.borrow().erase_count();
        flash.borrow_mut().fail_erase_after(erases + 1);

        let advanced = slot_value(stream_id, 77);
        slot.write_slot(&advanced);
        let outcome = slot.last_write_outcome();
        assert!(
            matches!(outcome, Some(AbWriteOutcome::CommittedSingleCopy(_))),
            "expected CommittedSingleCopy, got {outcome:?}"
        );
        assert!(outcome.expect("recorded").is_committed());

        flash.borrow_mut().heal();
        assert_eq!(
            slot.read_slot(),
            Some(advanced),
            "a single-copy write must still be the live value"
        );
    }
}
