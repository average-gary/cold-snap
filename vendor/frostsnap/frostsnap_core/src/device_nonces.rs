use crate::{
    device::DeviceSecretDerivation,
    nonce_stream::{CoordNonceStreamState, NonceStreamId, NonceStreamSegment},
    SignSessionId, Versioned,
};
use alloc::vec::Vec;
use chacha20::{
    cipher::{KeyIvInit, StreamCipher},
    ChaCha20,
};
use rand_core::RngCore;
use schnorr_fun::{
    binonce,
    frost::{NonceKeyPair, PairedSecretShare, PartySignSession, SignatureShare},
    fun::prelude::*,
};

/// How far ahead of our own index a coordinator may claim to be, expressed in
/// `nonce_batch_size` multiples.
///
/// Each skipped index costs a full ChaCha20 + EC nonce derivation, so this bounds
/// coordinator-triggered work. It must be well above any legitimate divergence:
/// the coordinator only ever advances by whole batches, and the device replenishes
/// a batch at a time (`reconcile_coord_nonce_stream_state`, `:220-234`), so being
/// more than a handful of batches ahead is not a state normal operation reaches.
/// With the default `NONCE_BATCH_SIZE` of 30 (`device.rs:32`) this is 1,920
/// derivations — trivially fast, while `u32::MAX` would be ~4.29e9.
pub const MAX_NONCE_SKIP_BATCHES: u32 = 64;

/// A job that generates nonces incrementally, can be polled for work
#[derive(Clone, Debug)]
pub struct NonceJob {
    pub stream_id: NonceStreamId,
    seed_material: RatchetSeedMaterial,
    index: u32,
    target_index: u32,
    nonces: Vec<binonce::Nonce>,
    skip_to: u32,
}

impl NonceJob {
    /// Do one unit of work - generate a single binonce
    pub fn do_work(&mut self, device_hmac: &mut impl DeviceSecretDerivation) -> bool {
        if self.index >= self.target_index {
            return true;
        }

        let current_index = self.index;

        // Derive actual nonce seed from material AND eFuse HMAC
        let actual_seed_bytes =
            device_hmac.derive_nonce_seed(self.stream_id, current_index, &self.seed_material);
        let actual_seed = ChaChaSeed::from_bytes(actual_seed_bytes);

        let mut chacha_nonce = [0u8; 12];
        chacha_nonce[0..core::mem::size_of_val(&current_index)]
            .copy_from_slice(current_index.to_le_bytes().as_ref());
        let mut chacha = ChaCha20::new(actual_seed.as_bytes().into(), &chacha_nonce.into());

        // Generate the next seed material (ratchet forward)
        let mut next_seed_material = [0u8; 32];
        chacha.apply_keystream(&mut next_seed_material);

        let mut secret_nonce_bytes = [0u8; 64];
        chacha.apply_keystream(&mut secret_nonce_bytes);
        let secret_nonce = binonce::SecretNonce::from_bytes(secret_nonce_bytes)
            .expect("computationally unreachable");

        // Update state for next iteration
        self.seed_material = next_seed_material;
        self.index += 1;

        // NOTE: This guard means that some do_work calls will go much faster
        // than others but that's ok. The point of do_work is create an upper
        // bound on how much work can be done at a time.
        if current_index >= self.skip_to {
            self.nonces
                .push(NonceKeyPair::from_secret(secret_nonce).public());
        }

        self.index >= self.target_index
    }

    /// Run the task synchronously until completion
    pub fn run_until_finished(&mut self, device_hmac: &mut impl DeviceSecretDerivation) {
        while !self.do_work(device_hmac) {}
    }

    /// How many nonces this job will actually emit, i.e. the size of the work it
    /// represents. Exposed so callers and tests can bound coordinator-influenced
    /// work before running it: each nonce is a ChaCha20 + EC derivation.
    pub fn n_nonces_to_generate(&self) -> u32 {
        self.target_index.saturating_sub(self.skip_to)
    }

    /// Total derivations required to finish, including the ones skipped over to
    /// reach `skip_to`. This is the number that actually bounds runtime.
    pub fn n_derivations_remaining(&self) -> u32 {
        self.target_index.saturating_sub(self.index)
    }

    /// Convert completed task into a NonceStreamSegment
    ///
    /// # Panics
    ///
    /// Local state-machine invariant: `do_work` returns the completion flag, so a
    /// caller that drives the job to completion before calling this cannot trip
    /// it. Not reachable from wire data.
    pub fn into_segment(self) -> NonceStreamSegment {
        assert!(
            self.index >= self.target_index,
            "into_segment called on unfinished NonceJob (generated {}/{} nonces)",
            self.index - self.skip_to,
            self.target_index - self.skip_to
        );
        NonceStreamSegment {
            stream_id: self.stream_id,
            index: self.skip_to,
            nonces: self.nonces.into(),
        }
    }
}

/// A batch of nonce generation jobs that will produce a single NonceResponse
#[derive(Clone, Debug)]
pub struct NonceJobBatch {
    tasks: Vec<NonceJob>,
    current_task_index: usize,
}

impl NonceJobBatch {
    pub fn new(tasks: Vec<NonceJob>) -> Self {
        Self {
            tasks,
            current_task_index: 0,
        }
    }

    /// Do one unit of work - generate a single nonce from the current task
    pub fn do_work(&mut self, device_hmac: &mut impl DeviceSecretDerivation) -> bool {
        if let Some(task) = self.tasks.get_mut(self.current_task_index) {
            if task.do_work(device_hmac) {
                // Current task finished, move to next
                self.current_task_index += 1;
            }
        }
        // Return true when ALL tasks are complete
        self.current_task_index >= self.tasks.len()
    }

    /// Run all tasks synchronously until completion
    pub fn run_until_finished(&mut self, device_hmac: &mut impl DeviceSecretDerivation) {
        while !self.do_work(device_hmac) {}
    }

    /// Convert completed batch into NonceStreamSegments
    pub fn into_segments(self) -> Vec<NonceStreamSegment> {
        assert!(
            self.current_task_index >= self.tasks.len(),
            "into_segments called on unfinished NonceJobBatch ({}/{} tasks complete)",
            self.current_task_index,
            self.tasks.len()
        );
        self.tasks.into_iter().map(|t| t.into_segment()).collect()
    }
}

/// Raw seed material that gets ratcheted forward and stored between uses.
/// This is passed through HMAC to derive the actual ChaChaSeed.
pub type RatchetSeedMaterial = [u8; 32];

#[derive(bincode::Encode, bincode::Decode, Copy, Clone, Debug, PartialEq)]
pub struct ChaChaSeed([u8; 32]);

impl ChaChaSeed {
    pub fn new(rng: &mut impl RngCore) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self(seed)
    }

    /// Only for deserialization or when we ratchet up
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, bincode::Encode, bincode::Decode)]
pub struct SecretNonceSlot {
    pub index: u32,
    pub nonce_stream_id: NonceStreamId,
    pub ratchet_prg_seed_material: RatchetSeedMaterial,
    /// for clearing slots based on least recently used
    pub last_used: u32,
    pub signing_state: Option<SigningState>,
}

#[derive(Clone, Debug, PartialEq, bincode::Encode, bincode::Decode)]
pub struct SigningState {
    pub session_id: SignSessionId,
    pub signature_shares: Vec<SignatureShare>,
}

pub trait NonceStreamSlot {
    fn read_slot_versioned(&mut self) -> Option<Versioned<SecretNonceSlot>>;
    fn write_slot_versioned(&mut self, value: Versioned<&SecretNonceSlot>);
    fn read_slot(&mut self) -> Option<SecretNonceSlot> {
        match self.read_slot_versioned()? {
            Versioned::V0(v) => Some(v),
        }
    }

    fn write_slot(&mut self, value: &SecretNonceSlot) {
        self.write_slot_versioned(Versioned::V0(value))
    }

    fn initialize(&mut self, stream_id: NonceStreamId, last_used: u32, rng: &mut impl RngCore) {
        let mut ratchet_prg_seed_material: RatchetSeedMaterial = [0u8; 32];
        rng.fill_bytes(&mut ratchet_prg_seed_material);
        let value = SecretNonceSlot {
            index: 0,
            nonce_stream_id: stream_id,
            ratchet_prg_seed_material,
            last_used,
            signing_state: None,
        };
        self.write_slot(&value);
    }

    /// Decide what nonce generation work the coordinator's claimed stream state
    /// implies, if any.
    ///
    /// `state` is entirely coordinator-controlled and arrives pre-consent via
    /// `OpenNonceStreams` (`device.rs:283-296`), so `state.index` must be treated
    /// as hostile. Two things previously went wrong here, both reproduced:
    ///
    /// - A claimed `index` of `u32::MAX` panicked in `nonce_task` ("cannot have an
    ///   index at u32::MAX") with **no user interaction** — a pre-consent
    ///   reset-loop trigger, which the panic-site enumeration listed as
    ///   unreachable local arithmetic.
    /// - A merely large claimed `index` produced a `NonceJob` demanding that many
    ///   derivations and a `Vec::with_capacity` of `length * 288` bytes
    ///   (`size_of::<binonce::Nonce>()`, measured), i.e. an allocation and CPU
    ///   hang with no panic at all.
    ///
    /// The gap is now closed by clamping the requested length to
    /// `nonce_batch_size` — the most the device ever intends to generate in one
    /// go — rather than trusting the coordinator's arithmetic. Returning `None`
    /// makes a bad request a no-op, which is the correct conservative response:
    /// declining to replenish cannot lose key material, it only stalls signing
    /// until a well-formed request arrives.
    fn reconcile_coord_nonce_stream_state(
        &mut self,
        state: CoordNonceStreamState,
        nonce_batch_size: u32,
    ) -> Option<NonceJob> {
        let value = self.read_slot()?;
        let our_index = value.index;
        let length = if our_index > state.index || state.remaining < nonce_batch_size {
            nonce_batch_size
        } else if our_index == state.index {
            return None;
        } else {
            // Never generate more than one batch regardless of how far ahead the
            // coordinator claims to be.
            (state.index - our_index).min(nonce_batch_size)
        };
        value.try_nonce_task(None, length as usize).ok()
    }

    fn nonce_stream_id(&mut self) -> Option<NonceStreamId> {
        self.read_slot().map(|value| value.nonce_stream_id)
    }

    fn sign_guaranteeing_nonces_destroyed(
        &mut self,
        session_id: SignSessionId,
        coord_nonce_state: CoordNonceStreamState,
        last_used: u32,
        sessions: impl IntoIterator<Item = (PairedSecretShare<EvenY>, PartySignSession)>,
        device_hmac: &mut impl DeviceSecretDerivation,
        nonce_batch_size: u32,
    ) -> Result<(Vec<SignatureShare>, Option<NonceJob>), NoncesUnavailable> {
        // Was `.expect("cannot sign with uninitialized slot")`. `device.rs:358-368`
        // does pre-check `read_slot()` for `RequestSign`, so on the happy path this
        // is Some — but on hardware `read_slot` goes through `AbSlot::read` and a
        // flash read error yields None, so it can still fire if flash degrades
        // between that check and here. That must not be a halt.
        let slot_value = self.read_slot().ok_or(NoncesUnavailable::SlotUnreadable)?;
        // Genuinely unreachable via `AbSlots::sign_guaranteeing_nonces_destroyed`
        // (`:361-364`), which looks the slot UP by `coord_nonce_state.stream_id`
        // (`get` compares `nonce_stream_id`, `:424`) and then passes that same
        // `coord_nonce_state` down. Kept as an assert because it guards a local
        // state-machine invariant, not wire data; it would only become
        // wire-reachable if this trait method were called directly, which no
        // vendored code does.
        assert_eq!(
            coord_nonce_state.stream_id, slot_value.nonce_stream_id,
            "wrong stream id"
        );

        // Check if we have cached signatures for this session first
        let with_signatures = match &slot_value.signing_state {
            Some(SigningState {
                session_id: saved_session_id,
                ..
            }) if *saved_session_id == session_id => {
                // We've already got the signatures for this session on flash so we don't need to
                // sign. But this doesn't mean we don't need to write it to flash again. We don't
                // know that the previous state was erased. So we may redundantly rewrite it but
                // that's ok.
                slot_value
            }
            _ => {
                // Only check nonce availability if we're not using cached signatures
                if coord_nonce_state.index < slot_value.index {
                    return Err(NoncesUnavailable::IndexUsed {
                        current: slot_value.index,
                        requested: coord_nonce_state.index,
                    });
                }
                // `:254` above proved `coord_nonce_state.index >= slot_value.index`,
                // so this cannot underflow. But it is otherwise UNBOUNDED and
                // coordinator-controlled, and `skip` on `iter_secret_nonces` does a
                // real ChaCha20 + EC derivation per skipped index — it is not a
                // cheap seek. An index near `u32::MAX` is ~4.29e9 derivations, which
                // on a 120MHz Cortex-M4 is effectively permanent. Critically it
                // never panics, so the panic handler and reboot counter never run
                // and only the watchdog escapes; under DECISIONS.md decision 6 that
                // is worse than a panic, and a panic-site audit cannot see it.
                let skip = coord_nonce_state.index - slot_value.index;
                let max_skip = nonce_batch_size.saturating_mul(MAX_NONCE_SKIP_BATCHES);
                if skip > max_skip {
                    return Err(NoncesUnavailable::SkipTooLarge {
                        skip,
                        max: max_skip,
                    });
                }
                let mut nonce_iter = slot_value
                    .iter_secret_nonces(device_hmac)
                    .skip(skip as usize);
                let mut signature_shares = vec![];
                let mut next_prg_state: Option<(u32, RatchetSeedMaterial)> = None;

                for (secret_share, session) in sessions.into_iter() {
                    // Was `.expect("tried to sign with nonces out of range")`.
                    // Wire-reachable: `iter_secret_nonces` terminates once index
                    // reaches `u32::MAX` (`:451`), and the only guard on
                    // `coord_nonce_state.index` is the `< slot_value.index` check at
                    // `:254`, so a coordinator claiming a high enough index
                    // exhausts the iterator. Reproduced against the real state
                    // machine before this fix. Nothing has been written to flash at
                    // this point, so returning is safe: the slot still holds its
                    // pre-sign state and no nonce has been consumed.
                    let Some((current_index, secret_nonce, next_seed_material)) = nonce_iter.next()
                    else {
                        return Err(NoncesUnavailable::Overflow);
                    };
                    let next_index = current_index + 1;
                    next_prg_state = Some((next_index, next_seed_material));
                    let signature_share = session.sign(&secret_share, secret_nonce);
                    // TODO: verify the signature share as a sanity check
                    signature_shares.push(signature_share);
                }

                // `next_prg_state` is `Some` iff the loop body ran at least once,
                // so this single check subsumes the former separate
                // `signature_shares.is_empty()` panic and `.unwrap()`. Empty
                // sessions are already unreachable from the wire — `GroupSignReq::check`
                // enforces `agg_nonces.len() == n_sign_items` and
                // `SignTaskError::NothingToSign` rejects input-less tasks — but this
                // is the backstop if that invariant is ever bypassed.
                let Some((next_index, next_prg_seed_material)) = next_prg_state else {
                    return Err(NoncesUnavailable::Overflow);
                };
                SecretNonceSlot {
                    nonce_stream_id: slot_value.nonce_stream_id,
                    index: next_index,
                    last_used,
                    ratchet_prg_seed_material: next_prg_seed_material,
                    signing_state: Some(SigningState {
                        session_id,
                        signature_shares,
                    }),
                }
            }
        };

        self.write_slot(&with_signatures);

        // XXX Read the slot back in to be 100% certain it was written
        //
        // These three sites were `.expect("guaranteed")` / `assert_eq!`. "Guaranteed"
        // holds only if flash never fails; on STM32 `PROGERR`/`WRPERR` they fire, and
        // the equality check fires precisely when flash did NOT take the write — i.e.
        // exactly when nonce state is untrustworthy. Halting there is the worst
        // option: it neither persists the advance nor lets the caller refuse.
        //
        // Returning Err is safe against nonce reuse, and that is the load-bearing
        // point. `device.rs:507` maps this to `ActionError::StateInconsistent` and
        // aborts without emitting a signature share, so no share ever leaves the
        // device for a nonce whose consumption we could not confirm. A later retry
        // of the SAME session is handled by the cached-signature branch above
        // (`:241-251`), which matches on `session_id` and re-writes rather than
        // re-deriving — so a retry cannot advance the index twice.
        let read_back_state = self
            .read_slot()
            .ok_or(NoncesUnavailable::WriteVerifyFailed)?;

        if read_back_state != with_signatures {
            return Err(NoncesUnavailable::WriteVerifyFailed);
        }

        let signature_shares = read_back_state
            .signing_state
            .ok_or(NoncesUnavailable::WriteVerifyFailed)?
            .signature_shares;

        let replenishment =
            self.reconcile_coord_nonce_stream_state(coord_nonce_state, nonce_batch_size);
        Ok((signature_shares, replenishment))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct AbSlots<S> {
    slots: Vec<S>,
    last_used: u32,
}

impl<S: NonceStreamSlot> AbSlots<S> {
    pub fn new(mut slots: Vec<S>) -> Self {
        let last_used = slots
            .iter_mut()
            .filter_map(|slot| slot.read_slot().map(|v| v.last_used))
            .max()
            .unwrap_or(0);
        Self {
            slots: slots.into_iter().collect(),
            last_used,
        }
    }

    pub fn sign_guaranteeing_nonces_destroyed(
        &mut self,
        session_id: SignSessionId,
        coord_nonce_state: CoordNonceStreamState,
        sessions: impl IntoIterator<Item = (PairedSecretShare<EvenY>, PartySignSession)>,
        device_hmac: &mut impl DeviceSecretDerivation,
        nonce_batch_size: u32,
    ) -> Result<(Vec<SignatureShare>, Option<NonceJob>), NoncesUnavailable> {
        let last_used = self.last_used + 1;
        let slot = self
            .get(coord_nonce_state.stream_id)
            .ok_or(NoncesUnavailable::Overflow)?; // Using Overflow as a placeholder for "stream not found"
        let out = slot.sign_guaranteeing_nonces_destroyed(
            session_id,
            coord_nonce_state,
            last_used,
            sessions,
            device_hmac,
            nonce_batch_size,
        )?;
        self.last_used = last_used;
        Ok(out)
    }

    fn increment_last_used(&mut self) -> u32 {
        self.last_used += 1;
        self.last_used
    }

    pub fn get_or_create(&mut self, stream_id: NonceStreamId, rng: &mut impl RngCore) -> &mut S {
        // the algorithm is to find the first empty slot or to choose the one with the lowest `last_used`
        let mut i = 0;
        let mut lowest_last_used = u32::MAX;
        let mut idx_lowest_last_used = 0;
        let last_used = self.increment_last_used();
        let found = loop {
            if i >= self.slots.len() {
                break None;
            }
            let ab_slot = &mut self.slots[i];
            let value = ab_slot.read_slot();
            match value {
                Some(value) => {
                    if value.nonce_stream_id == stream_id {
                        break Some(i);
                    } else if value.last_used < lowest_last_used {
                        idx_lowest_last_used = i;
                        lowest_last_used = value.last_used;
                    }
                }
                None => {
                    ab_slot.initialize(stream_id, last_used, rng);
                    break Some(i);
                }
            }
            i += 1;
        };

        match found {
            Some(i) => &mut self.slots[i],
            None => {
                let ab_slot = &mut self.slots[idx_lowest_last_used];
                ab_slot.initialize(stream_id, last_used, rng);
                ab_slot
            }
        }
    }

    pub fn get(&mut self, stream_id: NonceStreamId) -> Option<&mut S> {
        //XXX: clippy is wrong about this
        #[allow(clippy::manual_find)]
        for slot in &mut self.slots {
            if slot.nonce_stream_id() == Some(stream_id) {
                return Some(slot);
            }
        }
        None
    }

    pub fn all_stream_ids(&mut self) -> impl Iterator<Item = NonceStreamId> + '_ {
        self.slots
            .iter_mut()
            .filter_map(|slot| slot.nonce_stream_id())
    }

    pub fn total_slots(&self) -> usize {
        self.slots.len()
    }
}

impl SecretNonceSlot {
    fn iter_secret_nonces<'a>(
        &'a self,
        device_hmac: &'a mut impl DeviceSecretDerivation,
    ) -> impl Iterator<Item = (u32, binonce::SecretNonce, RatchetSeedMaterial)> + 'a {
        let mut seed_material = self.ratchet_prg_seed_material;
        let mut index = self.index;

        core::iter::from_fn(move || {
            if index == u32::MAX {
                return None;
            }

            let current_index = index;

            // Derive actual nonce seed from material AND eFuse HMAC
            let actual_seed_bytes =
                device_hmac.derive_nonce_seed(self.nonce_stream_id, current_index, &seed_material);
            let actual_seed = ChaChaSeed::from_bytes(actual_seed_bytes);

            let mut chacha_nonce = [0u8; 12];
            chacha_nonce[0..core::mem::size_of_val(&current_index)]
                .copy_from_slice(current_index.to_le_bytes().as_ref());
            let mut chacha = ChaCha20::new(actual_seed.as_bytes().into(), &chacha_nonce.into());

            // Generate the next seed material (ratchet forward)
            let mut next_seed_material = [0u8; 32];
            chacha.apply_keystream(&mut next_seed_material);

            let mut secret_nonce_bytes = [0u8; 64];
            chacha.apply_keystream(&mut secret_nonce_bytes);
            let secret_nonce = binonce::SecretNonce::from_bytes(secret_nonce_bytes)
                .expect("computationally unreachable");

            seed_material = next_seed_material;
            index += 1;

            Some((current_index, secret_nonce, next_seed_material))
        })
    }

    pub fn are_nonces_available(&self, index: u32, n: u32) -> Result<(), NoncesUnavailable> {
        let current = self.index;
        let requested = index;
        if requested < current {
            return Err(NoncesUnavailable::IndexUsed { current, requested });
        }
        if index.saturating_add(n) == u32::MAX {
            return Err(NoncesUnavailable::Overflow);
        }
        Ok(())
    }

    /// Fallible form of [`SecretNonceSlot::nonce_task`].
    ///
    /// All three former panics here are reachable **pre-consent** from a single
    /// `OpenNonceStreams` message, with no user interaction at all — the
    /// coordinator's claimed `index` flows into `length` via
    /// `reconcile_coord_nonce_stream_state` (`:227`). Reproduced: a claimed index
    /// of `u32::MAX` panics at the former `:485` before any prompt is shown.
    pub fn try_nonce_task(
        &self,
        start: Option<u32>,
        length: usize,
    ) -> Result<NonceJob, NoncesUnavailable> {
        let start = start.unwrap_or(self.index);
        // Only reachable via an explicit `Some(start)`; `None` yields `self.index`.
        if start < self.index {
            return Err(NoncesUnavailable::IndexUsed {
                current: self.index,
                requested: start,
            });
        }
        let length_u32: u32 = length.try_into().map_err(|_| NoncesUnavailable::Overflow)?;
        let last = start.saturating_add(length_u32);
        // `u32::MAX` is the iterator's terminator (`iter_secret_nonces`, `:451`),
        // so it can never be a real target index.
        if last == u32::MAX {
            return Err(NoncesUnavailable::Overflow);
        }

        // `Vec::with_capacity(length)` below is a real allocation of
        // `length * size_of::<binonce::Nonce>()`, and `size_of` is 288 bytes
        // (measured). An unbounded `length` from the wire is therefore both an
        // unbounded allocation and unbounded ChaCha20+EC work. Callers bound
        // `length` before getting here; this is the backstop.
        Ok(NonceJob {
            stream_id: self.nonce_stream_id,
            seed_material: self.ratchet_prg_seed_material,
            // Start from the slot's current index, not the requested start
            // The task will skip forward as needed
            index: self.index,
            target_index: last,
            nonces: Vec::with_capacity(length),
            skip_to: start,
        })
    }

    /// Panicking wrapper over [`SecretNonceSlot::try_nonce_task`], kept so
    /// upstream callers and tests compile unchanged. New code should use
    /// `try_nonce_task`; the only in-tree caller of this one is a test.
    pub fn nonce_task(&self, start: Option<u32>, length: usize) -> NonceJob {
        match self.try_nonce_task(start, length) {
            Ok(job) => job,
            Err(e) => panic!("nonce_task: {e}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Default)]
pub struct MemoryNonceSlot {
    inner: Option<Versioned<SecretNonceSlot>>,
}

impl NonceStreamSlot for MemoryNonceSlot {
    fn read_slot_versioned(&mut self) -> Option<Versioned<SecretNonceSlot>> {
        self.inner.clone()
    }

    fn write_slot_versioned(&mut self, value: Versioned<&SecretNonceSlot>) {
        self.inner = Some(value.cloned())
    }
}

#[derive(Clone, Debug)]
pub enum NoncesUnavailable {
    IndexUsed {
        current: u32,
        requested: u32,
    },
    Overflow,
    /// The slot could not be read. On hardware this is a flash read failure;
    /// previously an `.expect(..)`, which under `panic = "abort"` is a halt.
    SlotUnreadable,
    /// The slot was written but reading it back did not reproduce what was
    /// written, i.e. flash did not take the write. Nonce state is untrustworthy
    /// and the caller must abort rather than sign.
    WriteVerifyFailed,
    /// The coordinator asked us to skip further ahead in the nonce stream than
    /// this device is willing to derive in one request. Each skipped index costs
    /// a real ChaCha20 + EC derivation, so an unbounded skip is a CPU-exhaustion
    /// hang rather than a panic — no reset, no reboot counter, only the watchdog.
    SkipTooLarge {
        skip: u32,
        max: u32,
    },
}

impl core::fmt::Display for NoncesUnavailable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            NoncesUnavailable::IndexUsed { current, requested } => {
                write!(
                    f,
                    "Attempt to reuse nonces! Current index: {current}. Requested: {requested}."
                )
            }
            NoncesUnavailable::Overflow => {
                write!(f, "nonces were requested beyond the final index")
            }
            NoncesUnavailable::SlotUnreadable => {
                write!(f, "the nonce slot could not be read")
            }
            NoncesUnavailable::WriteVerifyFailed => {
                write!(f, "nonce slot did not read back the same as written")
            }
            NoncesUnavailable::SkipTooLarge { skip, max } => {
                write!(
                    f,
                    "coordinator asked to skip {skip} nonces, more than the {max} limit"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for NoncesUnavailable {}
