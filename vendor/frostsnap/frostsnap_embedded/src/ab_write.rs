use crate::FlashPartition;
use embedded_storage::nor_flash::{NorFlash, NorFlashErrorKind};
pub const ABWRITE_BINCODE_CONFIG: bincode::config::Configuration<
    bincode::config::LittleEndian,
    bincode::config::Fixint,
    bincode::config::NoLimit,
> = bincode::config::standard().with_fixed_int_encoding();

/// Manages two writable sectors of persistent storage such that we make sure the state of the system we're managing is never lost.
/// The new state is first written, if that succeeds we finally write over the previous state.
#[derive(Clone, Debug)]
pub struct AbSlot<'a, S> {
    slots: [Slot<'a, S>; 2],
}

impl<'a, S: NorFlash> AbSlot<'a, S> {
    /// # Panics
    ///
    /// The two asserts below are construction-time invariants on a partition
    /// layout that is fixed at compile time by the caller (`nonce_slots.rs:14-16`
    /// only ever splits off exactly 2 sectors), not on any runtime or wire input.
    /// They are left as asserts deliberately: they cannot fire from coordinator
    /// data or a flash fault, and turning them into a `Result` would force every
    /// caller to handle an impossible case.
    pub fn new(mut partition: FlashPartition<'a, S>) -> Self {
        assert!(partition.n_sectors() >= 2);
        assert_eq!(
            partition.n_sectors() % 2,
            0,
            "ab-write partition sector size must be divisible by 2"
        );
        let slot_size = partition.n_sectors() / 2;
        let b_slot = Slot {
            flash: partition.split_off_end(slot_size),
        };
        let a_slot = Slot { flash: partition };

        Self {
            slots: [a_slot, b_slot],
        }
    }

    /// Writes `value` to both slots, reporting exactly what reached flash.
    ///
    /// Prefer this over [`AbSlot::write`] on real hardware: STM32 program/erase
    /// can fail (`PROGERR`/`WRPERR`), and `write` turns that into a panic — which
    /// under `panic = "abort"` is a halt, i.e. the worst possible outcome
    /// mid-nonce-update.
    ///
    /// The three outcomes must stay distinguishable. A bare
    /// `Result<(), NorFlashErrorKind>` cannot express
    /// [`AbWriteOutcome::CommittedSingleCopy`], and collapsing that into an error
    /// invites a caller to treat an *already committed* nonce advance as
    /// not-having-happened and reuse the nonce — FROST nonce reuse is affine, so
    /// two challenges over one nonce solve for the secret share.
    pub fn try_write<T>(&self, value: &T) -> AbWriteOutcome
    where
        T: bincode::Encode,
    {
        let (next_slot, next_index) = match self.current_slot_and_index() {
            Some((current_slot, current_index)) => {
                let next_slot = (current_slot + 1) % 2;
                // `u32::MAX` is the "slot is empty" sentinel (`:120`, `:151`), so
                // it can never be handed out as a real index. Saturating instead
                // of failing here would silently reuse an index.
                match current_index.checked_add(1) {
                    Some(next_index) if next_index != u32::MAX => (next_slot, next_index),
                    _ => return AbWriteOutcome::NotCommitted(NorFlashErrorKind::OutOfBounds),
                }
            }
            None => (0, 0),
        };

        let slot_value = SlotValue {
            index: next_index,
            value,
        };
        let other_slot = (next_slot + 1) % 2;

        // Write the *older* slot first (`next_slot` is `(current_slot + 1) % 2`).
        // Until this succeeds, `current_slot` still holds the previous value at
        // the previous index, so `current_slot_and_index` keeps selecting it and
        // nothing has been committed.
        if let Err(e) = self.slots[next_slot].try_write(slot_value) {
            return AbWriteOutcome::NotCommitted(e);
        }

        // Past this line `next_index` is the highest index on flash, so
        // `current_slot_and_index` selects what was just written: the new value
        // IS committed and readable even if the redundant second copy fails.
        if let Err(e) = self.slots[other_slot].try_write(slot_value) {
            return AbWriteOutcome::CommittedSingleCopy(e);
        }

        AbWriteOutcome::Committed
    }

    /// Panicking wrapper over [`AbSlot::try_write`], kept so upstream callers
    /// compile unchanged. New code on this port should call `try_write`.
    pub fn write<T>(&self, value: &T)
    where
        T: bincode::Encode,
    {
        match self.try_write(value) {
            AbWriteOutcome::Committed => {}
            AbWriteOutcome::CommittedSingleCopy(e) => {
                panic!("ab-write committed only one copy: {e:?}")
            }
            AbWriteOutcome::NotCommitted(e) => panic!("ab-write committed nothing: {e:?}"),
        }
    }

    pub fn read<T: bincode::Decode<()>>(&self) -> Option<T> {
        let current_slot = self.current_slot_and_index().map_or(0, |(slot, _)| slot);
        let slot_value = self.slots[current_slot].read();
        slot_value.map(|slot_value| slot_value.value)
    }

    /// Picks the slot holding the newest write and its index. Both the read and
    /// write paths rely on this single source of truth: keeping the selection
    /// logic in one place is what stops the two paths from disagreeing about
    /// which slot is current (a disagreement is how a nonce index gets reused).
    fn current_slot_and_index(&self) -> Option<(usize, u32)> {
        let a_index = self.slots[0].read_index();
        let b_index = self.slots[1].read_index();
        // `Option` ranks `None` below every `Some`, so an empty slot is older
        // than any written one — otherwise a crash mid-erase would make us
        // forget the index held in the surviving slot and reuse it.
        if b_index > a_index {
            Some((1, b_index?))
        } else {
            Some((0, a_index?))
        }
    }
}

#[derive(Clone, Debug)]
struct Slot<'a, S> {
    flash: FlashPartition<'a, S>,
}

impl<S: NorFlash> Slot<'_, S> {
    // TODO: justify no erorr type here
    pub fn read<T: bincode::Decode<()>>(&self) -> Option<SlotValue<T>> {
        let value = bincode::decode_from_reader::<SlotValue<T>, _, _>(
            self.flash.bincode_reader(),
            ABWRITE_BINCODE_CONFIG,
        )
        .ok()?;

        if value.index == u32::MAX {
            None
        } else {
            Some(value)
        }
    }

    pub fn try_write<T: bincode::Encode>(
        &self,
        value: SlotValue<T>,
    ) -> Result<(), NorFlashErrorKind> {
        self.flash.erase_all()?;
        let mut writer = self.flash.bincode_writer_remember_to_flush::<256>();
        // Encoding only fails via the writer's own `nor_write`, so this is the
        // same flash-error condition as the flush below. It must not use `?`
        // directly on the `EncodeError`: `BincodeFlashWriter`'s `Drop` asserts
        // `buf_index == 0` (`partition.rs:318-325`), so returning while the
        // writer still holds buffered bytes would panic in the destructor —
        // the error path would reintroduce the panic this conversion removes.
        // `flush` takes `self` by value and zeroes `buf_index` before it can
        // fail, so flushing unconditionally is what makes the drop safe.
        let encode_result =
            bincode::encode_into_writer(&value, &mut writer, ABWRITE_BINCODE_CONFIG);
        writer.flush()?;
        encode_result.map_err(|_| NorFlashErrorKind::Other)?;
        Ok(())
    }

    /// Panicking form, now used only by the tests that fabricate torn writes
    /// directly against one slot. `AbSlot::try_write` goes through `try_write`.
    #[cfg(test)]
    pub fn write<T: bincode::Encode>(&self, value: SlotValue<T>) {
        self.try_write(value).expect("ab-write slot write failed");
    }

    fn read_index(&self) -> Option<u32> {
        // A slot that cannot even be decoded is treated as empty rather than as
        // a panic. That is not merely safer, it is the ordering
        // `current_slot_and_index` (`:70-81`) already depends on: `None` ranks
        // below every `Some`, so an unreadable slot counts as older than any
        // written one and can never win the "newest index" comparison.
        let index = bincode::decode_from_reader::<u32, _, _>(
            self.flash.bincode_reader(),
            ABWRITE_BINCODE_CONFIG,
        )
        .ok()?;

        if index == u32::MAX {
            None
        } else {
            Some(index)
        }
    }
}

/// What an [`AbSlot::try_write`] actually left on flash.
///
/// These must not be collapsed into a bare `Result`: the caller's correct
/// recovery differs between "the new state is live" and "the new state is not",
/// and for nonce state guessing wrong in the optimistic direction reuses a
/// nonce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum AbWriteOutcome {
    /// Both slots hold the new value. The normal case.
    Committed,
    /// One slot holds the new value at the newest index and the redundant copy
    /// failed. The write **did** take effect — reads return the new value — but
    /// A/B redundancy is gone, so a further failure can no longer be recovered
    /// from. Callers must treat the new state as live (for nonces: as consumed)
    /// and should not retry the same logical write as if nothing happened.
    CommittedSingleCopy(NorFlashErrorKind),
    /// Nothing was committed: the previous value is still current and readable.
    /// Safe to fail the operation and leave state untouched.
    NotCommitted(NorFlashErrorKind),
}

impl AbWriteOutcome {
    /// True if the new value is what a subsequent [`AbSlot::read`] returns.
    pub fn is_committed(&self) -> bool {
        matches!(
            self,
            AbWriteOutcome::Committed | AbWriteOutcome::CommittedSingleCopy(_)
        )
    }

    pub fn err(&self) -> Option<NorFlashErrorKind> {
        match self {
            AbWriteOutcome::Committed => None,
            AbWriteOutcome::CommittedSingleCopy(e) | AbWriteOutcome::NotCommitted(e) => Some(*e),
        }
    }
}

#[derive(Clone, Copy, Debug, bincode::Encode, bincode::Decode)]
struct SlotValue<T> {
    // the Sector with the newest index is chosen
    index: u32,
    value: T,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test::{FaultyNorFlash, TestNorFlash};
    use core::cell::RefCell;

    /// The highest index actually committed to flash, or `None` if both slots
    /// are empty. `Option<u32>` orders `None` below every `Some`, so this is
    /// exactly the value the recovery logic is supposed to track.
    fn committed_index<S: NorFlash>(ab: &AbSlot<'_, S>) -> Option<u32> {
        ab.slots[0]
            .read_index()
            .into_iter()
            .chain(ab.slots[1].read_index())
            .max()
    }

    #[test]
    fn write_roundtrip_advances_index() {
        let flash = RefCell::new(TestNorFlash::new());
        let ab = AbSlot::new(FlashPartition::new(&flash, 0, 2, "ab-test"));

        ab.write(&100u32);
        assert_eq!(ab.read::<u32>(), Some(100));
        assert_eq!(committed_index(&ab), Some(0));

        ab.write(&200u32);
        assert_eq!(ab.read::<u32>(), Some(200));
        assert_eq!(committed_index(&ab), Some(1));
    }

    /// After an interrupted write the two slots end up at different indexes. A
    /// subsequent completed write must advance past the highest index ever
    /// committed and never reuse one — reusing an index here means reusing a
    /// nonce, which leaks the secret share. Run for both orientations so the
    /// test fails whichever slot the recovery logic is blind to.
    #[test]
    fn completed_write_after_torn_write_never_reuses_index() {
        for newer_slot in [0, 1] {
            let flash = RefCell::new(TestNorFlash::new());
            let ab = AbSlot::new(FlashPartition::new(&flash, 0, 2, "ab-test"));

            ab.write(&100u32);
            ab.write(&200u32);

            // Power loss part way through writing 300: only one slot got the
            // new value, leaving the slots at different indexes. `write()` must
            // consult *both* slots to discover the true newest index.
            ab.slots[newer_slot].write(SlotValue {
                index: 2,
                value: &300u32,
            });

            assert_eq!(committed_index(&ab), Some(2));
            assert_eq!(ab.read::<u32>(), Some(300));

            ab.write(&400u32);

            assert_eq!(ab.read::<u32>(), Some(400));
            assert!(
                committed_index(&ab) > Some(2),
                "completed write reused index 2 (torn write left slot {newer_slot} newer)"
            );
        }
    }

    /// A crash can land after a slot is erased but before it is rewritten,
    /// leaving it empty while the other slot still holds the committed value.
    /// Recovery must keep the surviving value and must not reset the index to
    /// 0: a reset would give the next write a lower index than the stale slot,
    /// so a later interrupted write could win with old data still in place.
    #[test]
    fn recovers_when_one_slot_is_empty() {
        for empty_slot in [0, 1] {
            let flash = RefCell::new(TestNorFlash::new());
            let ab = AbSlot::new(FlashPartition::new(&flash, 0, 2, "ab-test"));

            ab.write(&100u32);
            ab.write(&200u32);

            ab.slots[empty_slot].flash.erase_all().unwrap();

            assert_eq!(committed_index(&ab), Some(1));
            assert_eq!(ab.read::<u32>(), Some(200));

            ab.write(&300u32);

            assert_eq!(ab.read::<u32>(), Some(300));
            assert!(
                committed_index(&ab) > Some(1),
                "recovery from empty slot {empty_slot} reset the index instead of advancing it"
            );
        }
    }

    /// The failure the priority-3 conversion exists for: on real STM32 flash the
    /// very first erase can be refused, and `write()` used to turn that into a
    /// panic (halt, under `panic = "abort"`). `try_write` must instead report
    /// `NotCommitted` AND leave the previous value fully intact, because that is
    /// what makes it safe for the caller to abort without touching nonce state.
    #[test]
    fn erase_failure_on_first_slot_commits_nothing_and_preserves_old_value() {
        let flash = RefCell::new(FaultyNorFlash::new());
        let ab = AbSlot::new(FlashPartition::new(&flash, 0, 2, "ab-test"));

        assert_eq!(ab.try_write(&100u32), AbWriteOutcome::Committed);
        assert_eq!(ab.try_write(&200u32), AbWriteOutcome::Committed);

        // Refuse everything from here on.
        flash.borrow_mut().fail_erase_after(0);

        let outcome = ab.try_write(&300u32);
        assert!(
            matches!(outcome, AbWriteOutcome::NotCommitted(_)),
            "expected NotCommitted, got {outcome:?}"
        );
        assert!(!outcome.is_committed());

        // Nothing was disturbed: the old value is still the current one.
        flash.borrow_mut().heal();
        assert_eq!(ab.read::<u32>(), Some(200));
        assert_eq!(committed_index(&ab), Some(1));

        // And the slot is still usable once flash recovers, at a fresh index.
        assert_eq!(ab.try_write(&400u32), AbWriteOutcome::Committed);
        assert_eq!(ab.read::<u32>(), Some(400));
        assert!(committed_index(&ab) > Some(1));
    }

    /// `AbSlot::write` erases+writes twice, so a fault can land between the two
    /// copies. That is the case a bare `Result` cannot express: the new value is
    /// already live. The contract asserted here is what stops a caller treating a
    /// committed nonce advance as not-having-happened and reusing the nonce.
    #[test]
    fn fault_between_the_two_copies_reports_committed_and_the_new_value_is_live() {
        let flash = RefCell::new(FaultyNorFlash::new());
        let ab = AbSlot::new(FlashPartition::new(&flash, 0, 2, "ab-test"));

        assert_eq!(ab.try_write(&100u32), AbWriteOutcome::Committed);
        assert_eq!(ab.try_write(&200u32), AbWriteOutcome::Committed);

        // Let the first slot's erase+write through, then refuse the second
        // slot's erase. Erase count is 1 per slot write, so the next write does
        // erase #(n) for the first copy and #(n+1) for the second.
        let erases_so_far = flash.borrow().erase_count();
        flash.borrow_mut().fail_erase_after(erases_so_far + 1);

        let outcome = ab.try_write(&300u32);
        assert!(
            matches!(outcome, AbWriteOutcome::CommittedSingleCopy(_)),
            "expected CommittedSingleCopy, got {outcome:?}"
        );
        assert!(
            outcome.is_committed(),
            "a single-copy write IS committed; reporting otherwise is how a nonce gets reused"
        );

        // The whole point: the new value is what reads return.
        flash.borrow_mut().heal();
        assert_eq!(ab.read::<u32>(), Some(300));
        assert_eq!(committed_index(&ab), Some(2));

        // A later completed write must not reuse the committed index.
        assert_eq!(ab.try_write(&400u32), AbWriteOutcome::Committed);
        assert_eq!(ab.read::<u32>(), Some(400));
        assert!(
            committed_index(&ab) > Some(2),
            "reused the index committed by the single-copy write"
        );
    }

    /// A write refused *after* its erase succeeded leaves the target slot blank.
    /// Recovery must fall back to the surviving slot rather than reporting the
    /// slot as empty and restarting indexes at 0.
    #[test]
    fn write_failure_after_successful_erase_falls_back_to_surviving_slot() {
        let flash = RefCell::new(FaultyNorFlash::new());
        let ab = AbSlot::new(FlashPartition::new(&flash, 0, 2, "ab-test"));

        assert_eq!(ab.try_write(&100u32), AbWriteOutcome::Committed);
        assert_eq!(ab.try_write(&200u32), AbWriteOutcome::Committed);

        let writes_so_far = flash.borrow().write_count();
        flash.borrow_mut().fail_write_after(writes_so_far);

        let outcome = ab.try_write(&300u32);
        assert!(
            matches!(outcome, AbWriteOutcome::NotCommitted(_)),
            "expected NotCommitted, got {outcome:?}"
        );

        flash.borrow_mut().heal();
        // One slot is now blank, but 200 survives in the other.
        assert_eq!(ab.read::<u32>(), Some(200));
        assert_eq!(committed_index(&ab), Some(1));
    }

    /// `read_index` used to `.expect(..)` on a decode failure. Nothing in a
    /// 2-sector partition can actually produce that with `Fixint` u32 decoding,
    /// so this pins the *ordering* property the `.ok()?` conversion relies on
    /// instead: a blank slot ranks below a written one, in both orientations.
    #[test]
    fn unreadable_or_blank_slot_ranks_below_a_written_one() {
        for blank in [0, 1] {
            let flash = RefCell::new(TestNorFlash::new());
            let ab = AbSlot::new(FlashPartition::new(&flash, 0, 2, "ab-test"));

            ab.write(&100u32);
            ab.write(&200u32);
            ab.slots[blank].flash.erase_all().unwrap();

            assert_eq!(ab.slots[blank].read_index(), None);
            let (chosen, index) = ab.current_slot_and_index().unwrap();
            assert_ne!(chosen, blank, "selected the blank slot as newest");
            assert_eq!(index, 1);
            assert_eq!(ab.read::<u32>(), Some(200));
        }
    }

    /// `u32::MAX` is the empty-slot sentinel, so it must never be handed out as a
    /// real index. Previously this panicked; now it refuses without committing,
    /// and critically without corrupting the value already there.
    #[test]
    fn index_exhaustion_refuses_instead_of_panicking() {
        let flash = RefCell::new(TestNorFlash::new());
        let ab = AbSlot::new(FlashPartition::new(&flash, 0, 2, "ab-test"));

        ab.write(&100u32);
        // Force both slots to the last usable index.
        for slot in 0..2 {
            ab.slots[slot].write(SlotValue {
                index: u32::MAX - 2,
                value: &200u32,
            });
        }
        // One more write is still legal (u32::MAX - 1).
        assert_eq!(ab.try_write(&300u32), AbWriteOutcome::Committed);
        assert_eq!(committed_index(&ab), Some(u32::MAX - 1));

        // The next would need u32::MAX, the sentinel: refuse.
        let outcome = ab.try_write(&400u32);
        assert!(
            matches!(outcome, AbWriteOutcome::NotCommitted(_)),
            "expected NotCommitted at index exhaustion, got {outcome:?}"
        );
        // Old value intact, index unchanged.
        assert_eq!(ab.read::<u32>(), Some(300));
        assert_eq!(committed_index(&ab), Some(u32::MAX - 1));
    }
}
