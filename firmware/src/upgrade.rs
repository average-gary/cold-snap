//! Firmware-upgrade STAGING: admit the upgrade messages, stream the chunk bytes
//! into PSRAM's lower half, and verify the announced digest by reading PSRAM back.
//!
//! **Nothing here burns anything.** No callgate sub-call is bound by this module,
//! `psram::check_burn_len` — the selector-18/7 gate — has no caller in any build
//! that can reach hardware, and `pin_firmware_upgrade` stays unbound and stays
//! classified `Destructive` in `hal/src/callgate.rs`. A staged image is bytes in
//! RAM that neither channel able to DESCRIBE an image to the bootloader names: the
//! recovery header at `PSRAM_BASE + PSRAM_LEN - 2048` is unnameable from the
//! staging window (const-asserted in `hal/src/psram.rs`), and 18/7 is unbound. The
//! bootloader does READ the lower half on a failed-verify boot
//! (`psram_recover_firmware`), and that path gates on `verify_world_checksum`
//! against SE1, so it can only replay the image the PIN holder already blessed —
//! a torn-burn net, not an install path. The worst a staged image can do is be
//! overwritten by the next one.
//!
//! # Why this is not in `Session`
//!
//! [`run`] must be reachable on a device whose SE1, SE2, flash and identity are
//! ALL broken, because that is the failure it exists to survive: at RDP=2 there is
//! no DFU (`mk4-bootloader/dispatch.c:150-165` returns `EPERM`), no SWD, and
//! `sdcard_recovery` restores only the image SE1 already blesses. So the listener
//! cannot be reached through a type that only exists once `Session::open` has
//! succeeded, and `Session::recv` keeps refusing all three `Upgrade` variants
//! unchanged (see [`crate::Refusal::FirmwareUpgrade`]).
//!
//! Upstream's shape is the same: a standalone `FirmwareUpgradeMode` with its own
//! state enum and its own pump (`frostsnap/device/src/ota.rs:255-370`).
//!
//! # The pre-Session containment, and it is a property of a signature
//!
//! [`run`] holds no `Session`, no `DeviceId`, no [`crate::Outbox`], no `Entropy`
//! and no flash handle. So `RequestHeldShares` — which upstream admits with no
//! consent screen at all, and which leaks `key_id`/`threshold`/`share_image` — is
//! not *declined* here, it is **unanswerable**: every device-to-coordinator frame
//! is a `DeviceSendMessage { from: DeviceId, .. }`
//! (`vendor/frostsnap/frostsnap_comms/src/lib.rs:455-461`) and there is no
//! `DeviceId` in this module to put in one. The entire outbound vocabulary is two
//! constant byte strings: `comms::MAGIC_REPLY` and
//! `FIRMWARE_NEXT_CHUNK_READY_SIGNAL`.
//!
//! That is the `Session::confirm_at` funnel argument applied to a whole module: a
//! capability the type does not have, rather than a capability a caller remembers
//! not to use. `nothing_in_this_module_can_answer_a_message_or_allocate` is a
//! TRIPWIRE on it and not the guard.
//!
//! # Allocation
//!
//! Allocation-free, and here that is **by construction rather than structural**:
//! `crate`'s `extern crate alloc` at `firmware/src/lib.rs:49` is ungated, so
//! unlike `hal/src/psram.rs` (whose own rule this follows, see its
//! `SELFTEST_CHUNK` docs) this module gets no help from the crate boundary. What
//! holds it: [`Stager`] is a fixed-size struct with a `[u8; 4]` carry, chunk bytes
//! are written straight from the wire slice with no intermediate buffer, and
//! nothing here names `Vec`, `Box`, `collect` or `alloc`. The arena has 5,024 B
//! spare of 65,536 (`hal/src/heap.rs:394,449`) and a staged image is ~388 KiB, so
//! a heap buffer was never available to be considered.

use coldsnap_hal::comms::{self, CoordinatorSendBody};
use coldsnap_hal::memmap;
use coldsnap_hal::psram::{self, Psram, PsramError};
use coldsnap_hal::usb;
use frostsnap_comms::{
    CoordinatorUpgradeMessage, Sha256Digest, FIRMWARE_NEXT_CHUNK_READY_SIGNAL,
    FIRMWARE_UPGRADE_CHUNK_LEN,
};

use crate::firmware_digest;

/// Why staging was refused.
///
/// Every one of these is a VALUE, never a panic, on a path both targets compile.
/// Upstream's equivalents are two `assert!`s on attacker-supplied input
/// (`frostsnap/device/src/ota.rs:228-235`) which contradict its own
/// `decide_upgrade` doc four lines up the file (`ota.rs:46-50`: "Everything
/// examined here is attacker-controlled, so every failure is a verdict, never a
/// panic"). On this unit a panic is a counted reset with no DFU beyond it
/// (DECISIONS.md decision 6), so a refusal is the only available answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refuse {
    /// Legacy `PrepareUpgrade`, which announces the full-image digest including
    /// the signature block (`frostsnap_coordinator/src/firmware.rs:243-245`).
    ///
    /// Upstream reaches the same verdict, but only at `ota.rs:500` — after
    /// streaming AND flashing the whole image — because a full-image digest can
    /// never equal a body digest and nothing checks the two before the transfer.
    /// Same outcome, ~390 KiB earlier.
    Legacy,

    /// `EnterUpgradeMode` with no accepted size, or chunk bytes with no stream.
    OutOfOrder,

    /// `size % memmap::FW_BODY_ALIGN != 0`.
    ///
    /// ONE rule covering two needs: 512 is what [`firmware_digest`] demands of the
    /// header's length field (`firmware/src/lib.rs:3029-3034`; **this pin read `:2998-3003`
    /// until 2026-09-17, wrong by exactly the +31 lines this change's own `lib.rs`
    /// diff inserted above it**), and `512 % 4 == 0`
    /// so `psram::WRITE_ALIGN` follows from it rather than being a second test.
    /// A `size` that would need a pad byte invented for it is refused here instead.
    Unaligned,

    /// `size < memmap::FW_MIN_BODY_LEN`.
    ///
    /// NOT decoration: `received == size` is only evaluated after bytes are
    /// consumed, so `size == 0` would be a stream that never completes — which is
    /// exactly what upstream's `byte_count == upgrade_size` at `ota.rs:420` does.
    TooSmall,

    /// `size > psram::BURN_LEN_MAX`.
    ///
    /// The STAGING ceiling is the BURN ceiling, so an image that could never be
    /// legally burned is never stored. 1,441,792 against `PSRAM_STAGE_LEN`'s
    /// 4,194,304 is 2.9x tighter, which puts the bootloader's recovery header out
    /// of reach twice over.
    TooLarge,

    /// [`psram::readback_selftest`] refused or mismatched at admission.
    ///
    /// This is what makes "PSRAM dead, unmapped, or not this target" a refusal
    /// before a byte moves, instead of a digest mismatch ~390 KiB later.
    Selftest(PsramError),

    /// A [`Psram::write`] refused mid-stream.
    ///
    /// Defence in depth with no reachable test: after admission every write is
    /// proven word-aligned and inside a span `readback_selftest` already checked,
    /// so this cannot fire. Kept because `?` needs a variant, and stated as
    /// unreachable rather than claimed as covered.
    Psram(PsramError),

    /// More bytes arrived than were announced. The whole call is discarded — never
    /// truncated to fit.
    ExtraBytes,

    /// The staged window is not readable as an image **at all**: no view, or a
    /// header slice that is not there.
    ///
    /// [`psram::StageError::NotInStagingWindow`] and
    /// [`psram::StageError::HeaderUnreadable`] only, because admission already
    /// bounds `size` to `[FW_MIN_BODY_LEN, BURN_LEN_MAX]` and both of those need a
    /// span outside it. The three that ARE reachable — a streamed header field that
    /// is too small, too large or longer than what arrived — answer
    /// [`Refuse::LengthDisagreement`], which is what they mean.
    ///
    /// **This doc read "Unreachable after admission" until 2026-09-18, and so did
    /// UPGRADE-PLAN §7b, and it was false**: `verify` mapped every `staged_burn_len`
    /// error here, and three of those are driven by a streamed, coordinator-supplied
    /// byte field. So the variant fired on ordinary hostile input while carrying a
    /// doc comment saying it could not. Fail-closed either way — no burn exists in
    /// this phase and the state is `Refused` — but the diagnosis was wrong and the
    /// pin was false, which in this tree is the tracked defect.
    Unreadable,

    /// The wire's `size` and the staged header's `firmware_length` disagree.
    ///
    /// UPGRADE-PLAN §3.2's lesson as code: `cli/signit.py:296-316` writes
    /// `firmware_length` as the whole file length, so for any real artifact the two
    /// numbers are one number, and nothing may stage an image where they are not.
    /// The bootloader's signature check reads the header's field while its burn
    /// reads a caller-supplied length, and those are DECOUPLED — refusing the
    /// disagreement at staging is the cheapest place to close it.
    ///
    /// Covers the in-band disagreement (`staged_burn_len` returned a length and it
    /// is not `size`) **and** the out-of-band ones: a declared length below
    /// [`psram::BURN_LEN_MIN`], above [`psram::BURN_LEN_MAX`], or longer than the
    /// bytes that arrived. All four are "the header's number is not `size`".
    /// **Until 2026-09-18 the last three answered [`Refuse::Unreadable`] instead**,
    /// which left this variant reachable only for a declared length inside
    /// `[BURN_LEN_MIN, size]` — the narrow slice the one test happened to use.
    LengthDisagreement,

    /// The read-back digest is not the announced one.
    Digest,
}

/// The staging state.
///
/// `Streaming` is the only state in which [`run`] does not call
/// `hal::comms::Link::poll` at all, which is why "a frame arrived mid-stream" is
/// not a refusal here — in that state there is no framer to admit one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Nothing announced.
    Idle,
    /// A `PrepareUpgrade2` was accepted; `EnterUpgradeMode` has not arrived.
    Prepared {
        /// Announced byte count.
        size: u32,
    },
    /// Raw mode: `received` of `size` bytes consumed.
    Streaming {
        /// Announced byte count.
        size: u32,
        /// Bytes consumed off the wire so far.
        received: u32,
    },
    /// All `size` bytes landed in PSRAM and the read-back digest matched.
    Staged {
        /// Announced byte count, which is also the staged length.
        size: u32,
    },
    /// Refused, with the reason. Only a fresh `PrepareUpgrade2` leaves this state.
    Refused(Refuse),
}

/// The staging machine.
///
/// Target-independent: there is no `#[cfg]` anywhere in [`Stager::admit`],
/// [`Stager::feed`] or its digest check, so the host suite is evidence about ARM.
/// The only thing a target changes is which [`Psram`] is handed in.
pub struct Stager<P: Psram> {
    psram: P,
    state: State,
    expected: Sha256Digest,
    /// The 0..3 bytes of a word that a packet boundary split. `Psram::write` takes
    /// word multiples only (`psram.c`: "All writes must be word aligned"), and a
    /// 64-byte USB packet is a word multiple but a `feed` slice need not be.
    carry: [u8; psram::WRITE_ALIGN as usize],
    carry_len: u8,
    /// Bytes actually written to PSRAM. Advances by word multiples only, so every
    /// offset handed to `check_write` is word-aligned by construction.
    written: u32,
}

impl<P: Psram> Stager<P> {
    /// A stager over `psram`, in [`State::Idle`].
    pub fn new(psram: P) -> Self {
        Self {
            psram,
            state: State::Idle,
            expected: Sha256Digest([0u8; 32]),
            carry: [0u8; psram::WRITE_ALIGN as usize],
            carry_len: 0,
            written: 0,
        }
    }

    /// The current state.
    pub fn state(&self) -> State {
        self.state
    }

    /// Is the machine in raw-byte mode? [`run`]'s branch, and the only thing that
    /// decides whether a packet reaches `Link::poll` or [`Stager::feed`].
    pub fn is_streaming(&self) -> bool {
        matches!(self.state, State::Streaming { .. })
    }

    /// Admit one `CoordinatorUpgradeMessage`.
    ///
    /// First failure wins, and the ORDER picks the reason rather than the outcome
    /// — upstream states the same rule at `ota.rs:48-50`. Nothing is ever
    /// half-admitted: an `Err` leaves [`State::Refused`] and no accepted size.
    ///
    /// # Errors
    ///
    /// Any [`Refuse`] except [`Refuse::ExtraBytes`], [`Refuse::Digest`],
    /// [`Refuse::LengthDisagreement`] and [`Refuse::Unreadable`], which are
    /// [`Stager::feed`]'s.
    pub fn admit(&mut self, m: &CoordinatorUpgradeMessage) -> Result<(), Refuse> {
        match m {
            // Refused before a byte moves, and specifically before the
            // `readback_selftest` below scribbles over the window: a legacy digest
            // covers the signature block, so it can never equal what
            // `firmware_digest` computes, and streaming 390 KiB to discover that
            // is what upstream does.
            CoordinatorUpgradeMessage::PrepareUpgrade { .. } => self.refuse(Refuse::Legacy),

            CoordinatorUpgradeMessage::PrepareUpgrade2 {
                size,
                firmware_digest,
            } => {
                // FIRST, before any bound is evaluated: a verified image must never
                // be half-overwritten while still reading as `Staged`. The
                // `readback_selftest` below is destructive to the whole window, so
                // by the time it runs the old verdict has to be gone already.
                //
                // THE `state` LINE IS BELT-AND-BRACES AND NO TEST CAN SEE IT.
                // MEASURED 2026-09-17: deleting it left all 191 firmware tests GREEN,
                // exit 0, because every exit from this arm assigns the state anyway —
                // each of the three bounds and the self-test go through `refuse`, and
                // the success path assigns `Prepared`. So the invariant currently
                // holds by exhaustion over four paths rather than unconditionally.
                // Kept, and labelled rather than deleted, because a fifth path is one
                // `?` away and a stale `Staged` is exactly what a future phase would
                // burn. Do NOT read it as covered.
                //
                // The two RESET lines below are load-bearing and are covered:
                // dropping `written = 0` reddens
                // `re_preparing_over_a_verified_image_clears_the_verdict_first` at
                // `Err(Psram(OutOfBounds))` (MEASURED, exit 101, 1 of 191 failed),
                // because a second image would then be written past the first.
                self.state = State::Idle;
                self.written = 0;
                self.carry_len = 0;

                let size = *size;
                if size % memmap::FW_BODY_ALIGN != 0 {
                    return self.refuse(Refuse::Unaligned);
                }
                if size < memmap::FW_MIN_BODY_LEN {
                    return self.refuse(Refuse::TooSmall);
                }
                if size > psram::BURN_LEN_MAX {
                    return self.refuse(Refuse::TooLarge);
                }

                // Prove the silicon before spending 390 KiB of wire on it. Legal and
                // non-redundant: `readback_selftest` runs `check_write` over the
                // WHOLE span itself before mutating anything, so an explicit
                // admission `check_write` here would be dead code — the three bounds
                // above already guarantee `size % 4 == 0` (`512 % 4 == 0`) and
                // `size <= BURN_LEN_MAX < PSRAM_STAGE_LEN`.
                //
                // It runs HERE and never after, because it is destructive to the
                // staging window by design.
                //
                // ponytail: this doubles PSRAM traffic before staging and has never
                // run on real OCTOSPI, because nothing in this project has run on
                // silicon at all. If it ever measures slow, stride it to a sample of
                // the window; do NOT delete it — it is the only thing that stops a
                // host `MappedPsram` reporting a fully staged image of nothing, and
                // the only thing that turns dead PSRAM into a refusal rather than a
                // digest mismatch a whole transfer later.
                if let Err(e) =
                    psram::readback_selftest(&mut self.psram, psram::PSRAM_STAGE_OFFSET, size)
                {
                    return self.refuse(Refuse::Selftest(e));
                }

                self.expected = *firmware_digest;
                self.state = State::Prepared { size };
                Ok(())
            }

            // Raw mode is unreachable without an accepted size, which is what makes
            // `Refuse::OutOfOrder` the answer to a coordinator that tries to open
            // the byte stream first.
            CoordinatorUpgradeMessage::EnterUpgradeMode => match self.state {
                State::Prepared { size } => {
                    self.state = State::Streaming { size, received: 0 };
                    Ok(())
                }
                _ => self.refuse(Refuse::OutOfOrder),
            },
        }
    }

    /// Feed raw wire bytes.
    ///
    /// Returns how many `FIRMWARE_NEXT_CHUNK_READY_SIGNAL` bytes the caller now
    /// owes the coordinator — see [`run`] for the accounting and why the last one
    /// is not a special case.
    ///
    /// # Errors
    ///
    /// An `Err` means no acks and the attempt is over. Acks earned earlier in the
    /// SAME call are dropped with it, which is unreachable for any
    /// `bytes.len() <= 4096` — that is every caller in the tree (64-byte USB
    /// packets, 64-byte host reads).
    pub fn feed(&mut self, bytes: &[u8]) -> Result<u32, Refuse> {
        // FIRST statement, so chunk bytes cannot move an unprepared window.
        let (size, received) = match self.state {
            State::Streaming { size, received } => (size, received),
            _ => return self.refuse_n(Refuse::OutOfOrder),
        };

        // The whole call is discarded rather than truncated to fit: a coordinator
        // that sent too much is a coordinator whose accounting disagrees with ours,
        // and staging the prefix of a disagreement is how a wrong image gets a
        // matching digest.
        let n = match u32::try_from(bytes.len()) {
            Ok(n) if received.saturating_add(n) <= size => n,
            _ => return self.refuse_n(Refuse::ExtraBytes),
        };

        // 1. Top the carry up to a whole word and flush it.
        let mut rest = bytes;
        if self.carry_len > 0 {
            let want = psram::WRITE_ALIGN as usize - self.carry_len as usize;
            let take = want.min(rest.len());
            self.carry[self.carry_len as usize..self.carry_len as usize + take]
                .copy_from_slice(&rest[..take]);
            self.carry_len += take as u8;
            rest = &rest[take..];
            if self.carry_len == psram::WRITE_ALIGN as u8 {
                // `self.carry` copied out first: `write` takes `&mut self.psram`
                // while `&self.carry` would be a second borrow of `self`.
                let word = self.carry;
                self.put(&word)?;
                self.carry_len = 0;
            }
        }

        // GUARDED ON `rest` BEING NON-EMPTY, and it must be: steps 2 and 3 below are
        // only correct once step 1 has left the carry EMPTY, which it does exactly
        // when it had bytes to spare. If it did not, `take == rest.len()`, so `rest`
        // is empty here and the carry holds 1..3 bytes that steps 2 and 3 must not
        // touch.
        //
        // MEASURED: without this guard, step 3's unconditional `self.carry_len =
        // tail.len() as u8` zeroed a carry step 1 had just part-filled, so feeding
        // the image one byte at a time dropped three of every four bytes and the
        // transfer ended in `Refuse::LengthDisagreement` — **re-measured 2026-09-18;
        // this read `Refuse::Unreadable`, which was the verdict before that day's
        // refusal remap, and the underlying defect is unchanged**. Caught by
        // `a_word_split_across_two_packets_lands_the_same_bytes_as_one_chunk`'s
        // `step 1` leg, which is the whole reason that test streams at 1, 2 and 3.
        if !rest.is_empty() {
            // 2. The largest word multiple of what remains, straight from the wire
            //    slice. No 4 KiB staging buffer exists to be sized wrong, and
            //    DECISIONS.md decision 7's declared 2 x `FRAME_LIMIT` SRAM cost is
            //    unchanged because no third `FRAME_LIMIT` buffer is added.
            let whole = rest.len() - rest.len() % psram::WRITE_ALIGN as usize;
            if whole > 0 {
                self.put(&rest[..whole])?;
            }

            // 3. Keep the 0..3-byte remainder for the next call.
            let tail = &rest[whole..];
            self.carry[..tail.len()].copy_from_slice(tail);
            self.carry_len = tail.len() as u8;
        }

        let before = received;
        let received = received + n;
        self.state = State::Streaming { size, received };

        // THE ACK ARITHMETIC, with no special case, so no off-by-one can exist in
        // it. `acks_at(r)` is the number of ready bytes owed once `r` bytes have
        // landed: one per COMPLETED chunk, and completion of the last chunk is
        // `r == size` however short that chunk is.
        //
        // We deliberately diverge from upstream, which emits one ready byte BEFORE
        // chunk 0 and then one per completed sector except the last
        // (`ota.rs:411-412,455,466-470` — `downstream_ready` starts true with no
        // downstream and `told_upstream_im_ready` starts false). Same total,
        // `ceil(size/4096)`, shifted by one; upstream is NOT relying on reboot
        // magic bytes to satisfy a dangling host read, and a comment claiming it
        // forgets the last ack would be false.
        //
        // Three reasons for the shift, all fail-closed: an ack after a chunk is
        // real backpressure rather than a promise made in advance; there is no
        // special case to get wrong; and THE FINAL ACK CARRIES THE VERDICT — a
        // coordinator cannot learn "staged" without this device having read PSRAM
        // back and matched the digest. That last one is the only outcome channel
        // this module has, because it can never send a frame.
        //
        // Protocol-identical to the real coordinator either way: it counts bytes,
        // reads one after EVERY chunk including the last, and only logs at DEBUG
        // when the value is not 0x11 (`usb_serial_manager.rs:704-723`).
        let acks_at = |r: u32| {
            if r == size {
                size.div_ceil(FIRMWARE_UPGRADE_CHUNK_LEN)
            } else {
                r / FIRMWARE_UPGRADE_CHUNK_LEN
            }
        };
        let owed = acks_at(received) - acks_at(before);

        if received == size {
            // An `Err` here means zero acks for this call, so the MISSING ack is
            // the refusal. A host driver blocking on it learns "not staged" without
            // this module needing a frame to say so in.
            self.verify()?;
        }
        Ok(owed)
    }

    /// One PSRAM write at the staging cursor.
    ///
    /// `w.len() % WRITE_ALIGN == 0` at every call site and `self.written` only ever
    /// advances by word multiples from `PSRAM_STAGE_OFFSET`, so every offset this
    /// hands `check_write` is word-aligned by construction rather than by check.
    fn put(&mut self, w: &[u8]) -> Result<(), Refuse> {
        self.psram
            .write(psram::PSRAM_STAGE_OFFSET + self.written, w)
            .map_err(Refuse::Psram)?;
        self.written += w.len() as u32;
        Ok(())
    }

    /// Read the staged window back and check it against the announced digest.
    ///
    /// The digest is taken from PSRAM READ-BACK and not from the wire bytes as they
    /// passed, which is what makes a write that silently dropped bytes visible.
    /// Upstream makes the same choice for the same reason (`ota.rs:487-500` digests
    /// the flashed partition, not the stream).
    ///
    /// `firmware_digest` is called VERBATIM. It is the only implementation of the
    /// Mk4 bootloader's signed range in this tree — `image[0..16_320)` then
    /// `image[16_384..firmware_length)`, i.e. the range with the 64-byte RSA
    /// signature that sits INSIDE the header punched out
    /// (`firmware/src/lib.rs:3037-3038`, was `:3005-3008` until 2026-09-17 — same +31,
    /// `mk4-bootloader/verify.c:265-273`) — and a
    /// second reader of that range, or of the offset-24 length field, is exactly
    /// the drift `hal/src/psram.rs`'s `FW_LENGTH_FIELD_OFFSET` docs record.
    ///
    /// Note what is NOT claimed: this is not the same COMPUTATION as upstream's
    /// `PrepareUpgrade2` digest. Upstream's is a contiguous prefix
    /// `sha256(bytes[..firmware_size])`
    /// (`frostsnap_coordinator/src/firmware.rs:206-213`); ours is two discontiguous
    /// ranges, because the Mk4 signature lives at byte 16,320 of the image rather
    /// than appended to it. It is the same CLASS of digest — signature-excluding,
    /// which is what `PrepareUpgrade2` is for — and a stock coordinator's announced
    /// digest will therefore not match ours. That is the fail-closed direction, and
    /// it costs nothing while the driver is a host tool.
    fn verify(&mut self) -> Result<(), Refuse> {
        let State::Streaming { size, .. } = self.state else {
            return self.refuse(Refuse::OutOfOrder);
        };
        let expected = self.expected;

        // The verdict is computed while the view's borrow is live and applied after
        // it ends. `Psram::view` takes `&self` precisely so the borrow checker is
        // what stops a write happening under a view — the cost is that `refuse`,
        // which takes `&mut self`, cannot be called from inside this match.
        //
        // `staged_burn_len` and NOT `check_burn_len`: `check_burn_len`'s own doc
        // claims every caller of selector 18/7 passes through it, and this phase has
        // no such caller — invoking it would advertise a gate over a path with
        // nothing to gate. `staged_burn_len` supplies the window / floor / ceiling /
        // truncation bounds for free and adds no further home for offset 24.
        let verdict = match self.psram.view(size) {
            Err(_) => Err(Refuse::Unreadable),
            Ok(view) => match psram::staged_burn_len(view) {
                // THREE of the five `StageError`s mean exactly "the header's number
                // is not `size`", and they are the COMMON diagnosis for a corrupt
                // transfer rather than an exotic one. Admission pins
                // `BURN_LEN_MIN <= size <= BURN_LEN_MAX` and `view(size)` makes
                // `staged.len() == size`, so `TooSmall` implies
                // `declared < BURN_LEN_MIN <= size`, `TooLarge` implies
                // `declared > BURN_LEN_MAX >= size` and `Truncated` implies
                // `declared > size`. **These three answered `Refuse::Unreadable`
                // until 2026-09-18**, which put the §3.2 refusal out of reach for
                // every declared length outside `[BURN_LEN_MIN, size]` and answered
                // a variant whose own doc said it was unreachable.
                //
                // The other two stay `Unreadable` and ARE unreachable here:
                // `NotInStagingWindow` needs `size > PSRAM_STAGE_LEN` and
                // `HeaderUnreadable` needs `size < 16_384`, and admission refused
                // both before a byte moved.
                Err(
                    psram::StageError::TooSmall
                    | psram::StageError::TooLarge
                    | psram::StageError::Truncated,
                ) => Err(Refuse::LengthDisagreement),
                Err(_) => Err(Refuse::Unreadable),
                Ok(declared) if declared != size => Err(Refuse::LengthDisagreement),
                // `None` is unreachable after admission — `declared == size` implies
                // every one of `firmware_digest`'s three bounds — so it is an arm
                // and never an `expect`: an unreachable `expect` on this unit is a
                // brick.
                Ok(_) => match firmware_digest(view) {
                    None => Err(Refuse::Unreadable),
                    Some(got) if got != expected => Err(Refuse::Digest),
                    Some(_) => Ok(()),
                },
            },
        };

        match verdict {
            Ok(()) => {
                self.state = State::Staged { size };
                Ok(())
            }
            Err(why) => self.refuse(why),
        }
    }

    /// Record the refusal and report it. One place, so no refusal can leave a state
    /// that still reads as prepared or staged.
    fn refuse(&mut self, why: Refuse) -> Result<(), Refuse> {
        self.state = State::Refused(why);
        Err(why)
    }

    /// [`Stager::refuse`] for [`Stager::feed`]'s return type.
    fn refuse_n(&mut self, why: Refuse) -> Result<u32, Refuse> {
        self.state = State::Refused(why);
        Err(why)
    }
}

/// The transport seam: read a packet, write some bytes.
///
/// It exists for exactly one reason. Without it the raw/framed switch and the 0x11
/// accounting — the two things most likely to be silently wrong on silicon — would
/// be ARM-only code that no test executes, because `usb::Cdc`'s every method is
/// `Err(NotOnThisTarget)` off ARM (`hal/src/usb.rs:886,948,1055`) and its `OtgPort`
/// double (`SimPort`) is gated to `hal`'s own test build and so is unreachable from
/// this crate.
///
/// The gate attribute is spelled here as prose and not as the literal, on purpose:
/// `nothing_in_this_module_can_answer_a_message_or_allocate` cuts this file at the
/// FIRST occurrence of that literal, and MEASURED — this doc line said it in code
/// font, the cut landed 180 lines above `run`, and the test's own
/// dropped-the-production-half assertion is what caught it. That assertion is the
/// only thing standing between the needles below and matching nothing.
pub trait Wire {
    /// One packet, or `None` if the wire is gone.
    ///
    /// A transport error the wire can SURVIVE must be reported as `Some(0)` and
    /// never as `None`: `Cdc::poll` fails on a coordinator-chosen oversize packet
    /// and drains the FIFO anyway, which is why the shipped event loop's
    /// `unwrap_or(0)` exists (`firmware/src/main.rs`'s step 10, and this function's
    /// `Cdc` impl below). One bad packet must not abort a transfer.
    fn read(&mut self, buf: &mut [u8; usb::MAX_PACKET_SIZE]) -> Option<usize>;

    /// Best-effort write. No `Result`: nothing this module sends is worth resetting
    /// over, and a coordinator that misses an ack times out on its own.
    fn write(&mut self, bytes: &[u8]);
}

impl Wire for usb::Cdc {
    fn read(&mut self, buf: &mut [u8; usb::MAX_PACKET_SIZE]) -> Option<usize> {
        // `unwrap_or(0)` and `.min(buf.len())` for the two reasons `boot`'s event
        // loop gives at its own `cdc.poll`: a coordinator chooses the packet
        // length, so a failure must never be a remote reset, and the clamp keeps
        // the slice bound local to the code that depends on it.
        //
        // Never `None`: this wire does not close. `Cdc` has no disconnect to
        // report — a host that unplugs simply stops sending — so a `None` here
        // would end the listener on a transient error.
        Some(self.poll(buf).unwrap_or(0).min(buf.len()))
    }

    fn write(&mut self, bytes: &[u8]) {
        // Spelled as the inherent call rather than `self.write(..)`. Inherent
        // methods do win over trait methods, so the short form resolves correctly
        // today — but it resolves to THIS function the day the inherent one is
        // renamed, and that is an infinite recursion into a stack with no MSPLIM
        // guard page beneath it.
        let _ = usb::Cdc::write(self, bytes);
    }
}

/// How the listener ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// An image of `size` bytes is in PSRAM's lower half and its digest matched.
    /// Nothing has been burned and nothing can be: no callgate sub-call is bound.
    Staged {
        /// The staged length.
        size: u32,
    },
    /// The wire closed. Host-only in practice — see [`Wire::read`].
    Closed,
}

/// The upgrade listener: answer the magic handshake, admit the upgrade messages,
/// stage the chunk stream, and stop when an image is staged.
///
/// Holds no `Session`, no `DeviceId`, no `Outbox`, no `Entropy` and no flash
/// handle — see the module docs for why that signature IS the containment.
///
/// # What is admitted
///
/// `MagicBytes` (answered with `comms::MAGIC_REPLY`) and
/// `CoordinatorSendBody::Upgrade`. Everything else, decoded or not, falls to
/// `_ => {}` on every target, with no `#[cfg]` anywhere near the refusal.
///
/// # The conch
///
/// Not serviced, and it does not need to be. `wait_for_conch` is
/// `if self.conch_enabled && !self.has_conch()`, a no-op when conch is off
/// (`frostsnap_coordinator/src/serial_port.rs:164-171`), and `conch_enabled` is
/// derived from the version signal in our own `MAGIC_REPLY`
/// (`serial_port.rs:77-97`). `Downstream::VERSION_SIGNAL` is 2 and the conch
/// protocol needs 1, which `firmware/src/main.rs`'s event loop already states. So
/// sending `MAGIC_REPLY` is itself what turns the conch off.
///
/// ponytail: if upstream ever enables the conch for version 2, the coordinator
/// blocks in `wait_for_conch` and the upgrade NEVER STARTS — no staging, no
/// partial state, fail-closed but silent. The upgrade path is one
/// `comms::downstream_conch()` reply on the `ReceiveSerial::Conch` arm that today
/// falls to `_ => {}`.
///
/// ponytail: no panel. A progress bar would need `PanelToken`, and the
/// identity-fault diagnostic that token draws is worth more than a progress bar on
/// exactly the device this listener exists for. The driver is a host tool, which
/// has the progress. Upgrade path: an `Option<&mut display::Panel>` parameter, in
/// the phase that burns.
///
/// ponytail: no timeout on the chunk stream. Upstream has none either — its timer
/// is used only for a 100 ms baud settle it does not need on USB (`ota.rs:399-402`)
/// — and the only timeout in this protocol lives on the host
/// (`serial_port.rs:257-260`, 5,000 ms). Safe ONLY because this phase cannot burn:
/// a stalled transfer leaves a device sitting in a listener with a half-written
/// PSRAM window that nothing can install. The phase that binds selector 18/7 must
/// revisit it.
pub fn run<W: Wire, P: Psram>(wire: &mut W, psram: P) -> Outcome {
    let mut stager = Stager::new(psram);
    let mut link = comms::Link::new();
    let mut buf = [0u8; usb::MAX_PACKET_SIZE];

    loop {
        let Some(n) = wire.read(&mut buf) else {
            return Outcome::Closed;
        };

        if stager.is_streaming() {
            // NOT `link.poll`. A 4,096-byte chunk cannot be a frame, for two
            // independent reasons: no `CoordinatorUpgradeMessage` variant carries
            // bulk (`vendor/frostsnap/frostsnap_comms/src/lib.rs:310-326`) and
            // adding one is a `vendor/` edit; and even with one, the minimum
            // bincode envelope for `ReceiveSerial::Message(CoordinatorSendMessage
            // { Destination::All, body })` is >= 6 B, so 4,102 B is past
            // `FRAME_LIMIT` and refused in both directions (`comms.rs`'s
            // `encode_frame` staging array, and `Link`'s own `rx`).
            //
            // DECISIONS.md decision 7 is untouched because chunks are neither sent
            // nor reassembled as frames — NOT because `FIRMWARE_UPGRADE_CHUNK_LEN`
            // and `FRAME_LIMIT` are both 4,096, which is a coincidence.
            //
            // THE PROPERTY UPSTREAM RELIES ON AND WE DO NOT HAVE: upstream's framer
            // buffers zero bytes — its `Reader::read` pulls one byte at a time
            // straight from `SerialIo` (`frostsnap/device/src/io.rs:180-205`) — so
            // handing the raw port over loses nothing. `Link` BUFFERS. Chunk bytes
            // arriving in the same read as the `EnterUpgradeMode` frame are already
            // inside a private `rx` with only a `pending()` count to see them by,
            // so chunk 0 would lose its head. Two defences, in order: the
            // coordinator's own 100 ms gap after `EnterUpgradeMode`
            // (`frostsnap_coordinator/src/usb_serial_manager.rs:681-682`), and
            // behind it the digest — which is the load-bearing backstop and the
            // honest reason the cheap digest check is worth having at all. A lost
            // head is `Refuse::Digest`, never a staged image.
            if let Ok(acks) = stager.feed(&buf[..n]) {
                for _ in 0..acks {
                    wire.write(&[FIRMWARE_NEXT_CHUNK_READY_SIGNAL]);
                }
            }
            if let State::Staged { size } = stager.state() {
                return Outcome::Staged { size };
            }
            continue;
        }

        // `reply_magic` is set inside the callback and acted on after `poll` returns,
        // because the reply is a WIRE WRITE and the callback should not carry the
        // write path on its stack — the same `send_magic_reply` pattern the shipped
        // event loop uses, and for the same reason.
        //
        // `admit` is NOT deferred, and that asymmetry is the fix for a real defect.
        // It was a `let mut msg = None;` set in the callback until 2026-09-17, which
        // meant that when a coordinator's `PrepareUpgrade2` and `EnterUpgradeMode`
        // frames landed in ONE read — which they legitimately can, both being a few
        // dozen bytes against a 64-byte packet — the second `Some` OVERWROTE the
        // first and only `EnterUpgradeMode` was admitted, from `Idle`, i.e.
        // `Refuse::OutOfOrder` and an upgrade that could never start. It survived
        // hostcheck because a pty happened to deliver the two `raw_send`s
        // separately. `admit` touches neither `link` nor the wire, so calling it here
        // is sound and every frame in a packet is admitted in arrival order.
        let mut reply_magic = false;
        let polled = link.poll::<comms::FromCoordinator, _>(&buf[..n], |frame| match frame {
            comms::ReceiveSerial::MagicBytes(_) => reply_magic = true,
            comms::ReceiveSerial::Message(m) => {
                if let Ok(CoordinatorSendBody::Upgrade(u)) = comms::decode_body(m.message_body) {
                    // `let _`: the refusal is already in `stager.state()`, and this
                    // module has no channel to report it on. A coordinator learns a
                    // refusal from the ack it does not get.
                    let _ = stager.admit(&u);
                }
            }
            // Every other body, and every other `ReceiveSerial` variant, on every
            // target and under no `cfg`. `RequestHeldShares` lands here — and even
            // if this arm were deleted, there is no `DeviceId` in this function to
            // frame an answer with.
            _ => {}
        });

        if polled.is_err() {
            // `Link::poll` has already unlinked, so recovery is to wait for the
            // coordinator's next magic bytes. Not a reset: a desync is a
            // coordinator that mis-spoke.
            continue;
        }
        if reply_magic {
            // A const, not an `encode_frame` call, for the reason the event loop
            // gives: the send path should not need a `FRAME_LIMIT` staging buffer
            // and a monomorphised encoder to say hello. This is also what puts the
            // port into the coordinator's `ready` map, which is keyed by PORT NAME
            // and not by `DeviceId` (`usb_serial_manager.rs:43,254`) — the whole
            // reason a device with no identity can be upgraded at all.
            wire.write(&comms::MAGIC_REPLY);
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use coldsnap_hal::psram::fake::FakePsram;
    use sha2::{Digest, Sha256};
    use std::vec;
    use std::vec::Vec;

    /// The canonical hostile size: 64 x 4,096 + 512.
    ///
    /// `>= 262,144`, `% 512 == 0`, `% 4096 != 0`, so it exercises the short tail
    /// AND 65 chunks of ack arithmetic. A 97 x 4,096 exact fit — which is what a
    /// REAL artifact always is, since `cli/signit.py:302-306` re-aligns the Mk4
    /// body to 4,096 — could not fail either and would be the vacuous version.
    const SIZE: u32 = 262_656;

    /// A staged image of `size` bytes: a deterministic pattern with `declared` in
    /// the header's length field.
    ///
    /// The offset is the LITERAL `16_280` and never
    /// `FW_HEADER_OFFSET + FW_LENGTH_FIELD_OFFSET`. UPGRADE-PLAN §7 records that
    /// exact tautology surviving a required 24 -> 28 mutation GREEN, because writer
    /// and reader moved together.
    fn image_declaring(size: usize, declared: u32) -> Vec<u8> {
        let mut v: Vec<u8> = (0..size).map(|i| (i * 7 + i / 251) as u8).collect();
        v[16_280..16_284].copy_from_slice(&declared.to_le_bytes());
        v
    }

    /// [`image_declaring`] with the header agreeing with its own length.
    fn image(size: usize) -> Vec<u8> {
        image_declaring(size, size as u32)
    }

    /// The digest the coordinator would announce for `img`: sha256 over
    /// `[0, 16_320)` then `[16_384, length)`.
    ///
    /// Computed HERE from literals rather than by calling `firmware_digest`, so a
    /// mutation of the skip window reddens the expectations below instead of moving
    /// with them.
    fn announce(img: &[u8]) -> Sha256Digest {
        let length = u32::from_le_bytes(img[16_280..16_284].try_into().unwrap()) as usize;
        let mut h = Sha256::new();
        h.update(&img[..16_320]);
        h.update(&img[16_384..length]);
        Sha256Digest(h.finalize().into())
    }

    /// A digest for the admission-bound tests, none of which ever reaches a digest
    /// check. Not `announce(..)` of anything: a fixture that had to build a whole
    /// image to test a size bound would be a fixture that could not test a size
    /// bound above its own capacity.
    fn unchecked_digest() -> Sha256Digest {
        Sha256Digest([0u8; 32])
    }

    fn prepare2(size: u32, digest: Sha256Digest) -> CoordinatorUpgradeMessage {
        CoordinatorUpgradeMessage::PrepareUpgrade2 {
            size,
            firmware_digest: digest,
        }
    }

    /// A stager whose fake is EXACTLY `size` bytes, so the double's last
    /// addressable byte is touched by every test in this file — UPGRADE-PLAN §7's
    /// `FakePsram::span` capacity-edge finding closed locally rather than trusted
    /// to the three lines in `psram.rs` that closed it there.
    fn armed(img: &[u8]) -> Stager<FakePsram> {
        let mut s = Stager::new(FakePsram::new(img.len()));
        s.admit(&prepare2(img.len() as u32, announce(img)))
            .expect("this fixture is admissible");
        s.admit(&CoordinatorUpgradeMessage::EnterUpgradeMode)
            .expect("a prepared stager enters raw mode");
        s
    }

    /// Feed `img` in `step`-byte slices, summing the acks.
    fn stream(s: &mut Stager<FakePsram>, img: &[u8], step: usize) -> Result<u32, Refuse> {
        let mut acks = 0;
        for c in img.chunks(step) {
            acks += s.feed(c)?;
        }
        Ok(acks)
    }

    /// The staging ceiling is the BURN ceiling, so an image that could never be
    /// legally burned is never stored.
    ///
    /// THE MUTATION: `size > psram::BURN_LEN_MAX` -> `> psram::PSRAM_STAGE_LEN`.
    /// The legs are the literals below and neither derives from the constant, so
    /// the fixture cannot move with the thing it pins.
    ///
    /// MEASURED 2026-09-17: exit 101, 1 of 191 failed, this test, at the over-size
    /// leg, `left: Err(Selftest(OutOfBounds))` / `right: Err(TooLarge)`. Note what
    /// the diagnosis is: with the ceiling raised, 1,442,304 gets PAST this bound and
    /// is refused two lines later by the self-test, because the fake is only
    /// 1,441,792 bytes. The mutation is caught and the reason it names is the
    /// second-line refusal, not the first — which is exactly the residue to be aware
    /// of, since on real 4 MiB PSRAM the self-test would NOT refuse it.
    #[test]
    fn prepare_refuses_a_size_that_would_burn_past_flash_fs() {
        // The ceiling itself is admissible. A fake that large is a 1.4 MiB
        // allocation, which the host has and the device does not — the arena rule
        // is `Stager`'s, not the double's (`hal/src/heap.rs:328`: `hal` registers no
        // `#[global_allocator]`).
        let mut ok = Stager::new(FakePsram::new(1_441_792));
        assert_eq!(ok.admit(&prepare2(1_441_792, unchecked_digest())), Ok(()));
        assert_eq!(ok.state(), State::Prepared { size: 1_441_792 });

        // One 512-byte alignment step past it is refused, and the refusal is
        // `TooLarge` and not the alignment or floor rule above it.
        let mut over = Stager::new(FakePsram::new(1_441_792));
        assert_eq!(
            over.admit(&prepare2(1_442_304, unchecked_digest())),
            Err(Refuse::TooLarge)
        );
        assert_eq!(over.state(), State::Refused(Refuse::TooLarge));
    }

    /// An image below the bootloader's own floor is refused before it is staged.
    ///
    /// THE MUTATION: delete the `TooSmall` arm. Legs are the literals `262_144`
    /// (admitted) and `261_632` (refused).
    #[test]
    fn prepare_refuses_an_image_below_the_bootloaders_floor() {
        let mut at = Stager::new(FakePsram::new(262_144));
        assert_eq!(at.admit(&prepare2(262_144, unchecked_digest())), Ok(()));

        let mut under = Stager::new(FakePsram::new(262_144));
        assert_eq!(
            under.admit(&prepare2(261_632, unchecked_digest())),
            Err(Refuse::TooSmall)
        );
    }

    /// A `size` the burn cannot align is refused, and the rule is the DIGEST's 512
    /// rather than PSRAM's 4.
    ///
    /// THE MUTATION: `% memmap::FW_BODY_ALIGN` -> `% psram::WRITE_ALIGN`. Then
    /// `262_660 % 4 == 0` and it gets PAST this bound — with a `size`
    /// `firmware_digest` would refuse, so on real PSRAM the stream could only ever
    /// end in a refusal after 262 KiB of wire.
    ///
    /// MEASURED 2026-09-17: exit 101, 1 of 191 failed, this test, `left:
    /// Err(Selftest(OutOfBounds))` / `right: Err(Unaligned)` — the 262,660 leg went
    /// past the alignment check and was caught by the self-test against a
    /// 262,656-byte fake. Caught, with the second-line refusal as the diagnosis.
    /// The 262,657 leg is the one that is `% 4 != 0` too and so stays `Unaligned`
    /// under the mutation; it is here to keep the fixture from resting entirely on
    /// the fake's capacity.
    ///
    /// This is a SECOND tripwire on `memmap::FW_BODY_ALIGN`, alongside
    /// `firmware_digest_alignment_bound_is_looser_than_mk4_requires`. Correcting
    /// that constant to the 4,096 the Mk4 actually requires reddens both,
    /// deliberately: this fixture would then have to move to a 4,096-aligned size.
    #[test]
    fn prepare_refuses_a_size_the_burn_cannot_align() {
        for (size, want) in [
            (262_656u32, Ok(())),
            (262_660, Err(Refuse::Unaligned)),
            (262_657, Err(Refuse::Unaligned)),
        ] {
            let mut s = Stager::new(FakePsram::new(262_656));
            assert_eq!(s.admit(&prepare2(size, unchecked_digest())), want, "{size}");
        }
    }

    /// The legacy `PrepareUpgrade` is refused before a byte moves — including
    /// before the self-test's own pattern moves.
    ///
    /// THE MUTATION: route `PrepareUpgrade` into the `PrepareUpgrade2` arm. The
    /// assertion is on the CELLS and not on the return value, because the
    /// mutation's `readback_selftest` writes its pattern over the whole window and
    /// no return value could describe that.
    #[test]
    fn the_legacy_prepare_is_refused_before_a_byte_moves() {
        let img = image(SIZE as usize);
        let mut s = Stager::new(FakePsram::new(img.len()));
        assert_eq!(
            s.admit(&CoordinatorUpgradeMessage::PrepareUpgrade {
                size: SIZE,
                firmware_digest: announce(&img),
            }),
            Err(Refuse::Legacy)
        );
        assert_eq!(s.state(), State::Refused(Refuse::Legacy));
        assert!(
            s.psram.cells().iter().all(|b| *b == 0),
            "a legacy prepare must not even run the self-test that scribbles the window"
        );
        // And it cannot open the byte stream either.
        assert_eq!(
            s.admit(&CoordinatorUpgradeMessage::EnterUpgradeMode),
            Err(Refuse::OutOfOrder)
        );
    }

    /// Chunk bytes are refused until `EnterUpgradeMode`.
    ///
    /// THE MUTATION: let `feed` write while `Prepared`. The assertion compares the
    /// cells against a snapshot taken AT RUNTIME after admission — the self-test's
    /// pattern is already in them — rather than against anything derived from
    /// `size`.
    #[test]
    fn chunks_are_refused_until_enter_upgrade_mode() {
        let img = image(SIZE as usize);
        let mut s = Stager::new(FakePsram::new(img.len()));
        s.admit(&prepare2(SIZE, announce(&img))).unwrap();
        let after_admit = s.psram.cells().to_vec();

        assert_eq!(s.feed(&img[..4096]), Err(Refuse::OutOfOrder));
        assert_eq!(s.state(), State::Refused(Refuse::OutOfOrder));
        assert_eq!(
            s.psram.cells(),
            &after_admit[..],
            "a chunk before the stream is opened must move nothing"
        );
    }

    /// `EnterUpgradeMode` before a prepare is refused, and raw mode stays shut.
    ///
    /// THE MUTATION: allow the transition from `Idle`. It would produce
    /// `Streaming { size: 0 }` — a stream that can never complete, because
    /// `received == size` is checked only after bytes are consumed, which is
    /// upstream's own unbounded-loop shape at `ota.rs:420`.
    #[test]
    fn enter_upgrade_mode_is_refused_before_a_prepare() {
        let mut s = Stager::new(FakePsram::new(4096));
        assert_eq!(
            s.admit(&CoordinatorUpgradeMessage::EnterUpgradeMode),
            Err(Refuse::OutOfOrder)
        );
        assert!(!s.is_streaming());
        assert_eq!(s.feed(&[0u8; 4]), Err(Refuse::OutOfOrder));
    }

    /// Every chunk is acked exactly once, and the LAST ack is the digest verdict.
    ///
    /// TWO REQUIRED MUTATIONS:
    /// 1. drop the `r == size` case from `acks_at` — the short final chunk then
    ///    earns no ack and the clean leg sums 64 instead of 65;
    /// 2. return the ack BEFORE `verify` — the corrupt leg then sums 65 instead of
    ///    64, i.e. a coordinator is told "ready" for an image that failed its
    ///    digest.
    ///
    /// The totals are the literals 65 and 64. Production never computes a chunk
    /// count: it computes `r / 4096` and `div_ceil`, so the expectation cannot move
    /// with the code.
    #[test]
    fn every_chunk_is_acked_once_and_the_last_ack_is_the_digest_verdict() {
        let img = image(SIZE as usize);

        let mut good = armed(&img);
        assert_eq!(stream(&mut good, &img, 4096), Ok(65));
        assert_eq!(good.state(), State::Staged { size: SIZE });

        // One flipped byte in chunk 40, inside the hashed range.
        let mut bad = img.clone();
        bad[40 * 4096 + 7] ^= 0x80;
        let mut s = Stager::new(FakePsram::new(bad.len()));
        // Announced against the CLEAN image, streamed the corrupt one: that is the
        // shape of a corrupted download.
        s.admit(&prepare2(SIZE, announce(&img))).unwrap();
        s.admit(&CoordinatorUpgradeMessage::EnterUpgradeMode).unwrap();
        let mut acks = 0;
        let mut last = Ok(0);
        for c in bad.chunks(4096) {
            match s.feed(c) {
                Ok(a) => acks += a,
                e => {
                    last = e;
                    break;
                }
            }
        }
        assert_eq!(last, Err(Refuse::Digest));
        assert_eq!(acks, 64, "the 65th ack is the verdict and must not be sent");
        assert_eq!(s.state(), State::Refused(Refuse::Digest));
    }

    /// Staged bytes land at the offset they arrived at.
    ///
    /// THE MUTATION: `psram.write(PSRAM_STAGE_OFFSET + self.written, ..)` ->
    /// `psram.write(PSRAM_STAGE_OFFSET, ..)`. Asserted through `cells()` and NOT
    /// through a read-back at the same offsets, which is `hal/src/psram.rs`'s own
    /// point: an off-by-one in a chunk loop is invisible to a read through the same
    /// wrong offset.
    #[test]
    fn staged_bytes_land_at_the_offset_they_arrived_at() {
        let img = image(SIZE as usize);
        let mut s = armed(&img);
        assert_eq!(stream(&mut s, &img, 4096), Ok(65));
        assert_eq!(s.psram.cells(), &img[..], "every byte, at its own offset");
    }

    /// A byte past the announced size is refused and stores nothing.
    ///
    /// THE MUTATION: delete the `received + n > size` guard. The final slice is 512
    /// bytes too long, so under the mutation it would write past `size` and, on a
    /// fake sized to `size`, be a capacity refusal — hence the snapshot assertion,
    /// which sees the mutation whichever way it fails.
    #[test]
    fn a_byte_after_the_announced_size_is_refused_and_stores_nothing() {
        let img = image(SIZE as usize);
        let mut s = armed(&img);
        // Everything but the last chunk.
        assert_eq!(stream(&mut s, &img[..64 * 4096], 4096), Ok(64));
        let before = s.psram.cells().to_vec();

        // 1,024 bytes where 512 remain.
        let mut over = vec![0u8; 1024];
        over[..512].copy_from_slice(&img[64 * 4096..]);
        assert_eq!(s.feed(&over), Err(Refuse::ExtraBytes));
        assert_eq!(s.state(), State::Refused(Refuse::ExtraBytes));
        assert_eq!(
            s.psram.cells(),
            &before[..],
            "an over-long call is discarded whole, never truncated to fit"
        );
    }

    /// The staged header's length field must agree with the announced size.
    ///
    /// THE MUTATION: delete the `declared != size` comparison. The fixture declares
    /// `size - 512` in the header and announces the digest OF THOSE ACTUAL BYTES,
    /// so with the check gone the verdict becomes `Staged` — the expectation is a
    /// variant name and not a number, so it cannot be satisfied by arithmetic.
    ///
    /// This is UPGRADE-PLAN §3.2 as a refusal: the bootloader's signature check
    /// reads the header's field while its burn reads a caller-supplied length, and
    /// the two are DECOUPLED by 655,360 B.
    ///
    /// FOUR legs, because `SIZE - 512` alone was a false pin on the variant. It is
    /// `262_144` = `BURN_LEN_MIN` exactly, i.e. sitting ON `staged_burn_len`'s floor,
    /// so it was the only leg of the four that reached the `Ok(declared)` arm — the
    /// other three exit through `staged_burn_len`'s own bounds, which answered
    /// `Refuse::Unreadable` until 2026-09-18. **`0` is the mutation-free proof that
    /// "`Unreadable` is unreachable after admission" was false**: it needs no edit
    /// to production code, only a header field a coordinator controls.
    #[test]
    fn the_header_length_must_agree_with_the_announced_size() {
        for declared in [
            // In-band: above the floor, below the ceiling, not `SIZE`. The only leg
            // `staged_burn_len` returns `Ok` for.
            SIZE - 512,
            // Below `BURN_LEN_MIN` — `StageError::TooSmall`. An all-zero or garbage
            // stream lands here, so this is the ORDINARY corrupt-transfer diagnosis.
            0,
            // Longer than what arrived — `StageError::Truncated`.
            SIZE + 512,
            // Past `BURN_LEN_MAX`, so a burn would erase into `FLASH_FS` —
            // `StageError::TooLarge`.
            psram::BURN_LEN_MAX + 512,
        ] {
            let img = image_declaring(SIZE as usize, declared);
            let mut s = Stager::new(FakePsram::new(img.len()));
            // `announce` reads the header's own field for the in-band leg, so the
            // digest is right for those bytes and only the length disagreement is
            // left to catch them. For the three out-of-band legs `staged_burn_len`
            // refuses before any digest is taken, so the announced digest is
            // whatever the fixture computed and never the reason.
            s.admit(&prepare2(SIZE, unchecked_digest())).unwrap();
            s.admit(&CoordinatorUpgradeMessage::EnterUpgradeMode).unwrap();
            let mut last = Ok(0);
            for c in img.chunks(4096) {
                last = s.feed(c);
                if last.is_err() {
                    break;
                }
            }
            assert_eq!(
                last,
                Err(Refuse::LengthDisagreement),
                "a header declaring {declared} against an announced {SIZE} is a \
                 length disagreement, not an unreadable window"
            );
            assert_eq!(s.state(), State::Refused(Refuse::LengthDisagreement));
        }

        // And the in-band leg is not passing because the digest was wrong: with the
        // digest OF THOSE ACTUAL BYTES announced, the length check is the only thing
        // left, which is what makes deleting `declared != size` reach `Staged`.
        let img = image_declaring(SIZE as usize, SIZE - 512);
        let mut s = Stager::new(FakePsram::new(img.len()));
        s.admit(&prepare2(SIZE, announce(&img))).unwrap();
        s.admit(&CoordinatorUpgradeMessage::EnterUpgradeMode).unwrap();
        let mut last = Ok(0);
        for c in img.chunks(4096) {
            last = s.feed(c);
            if last.is_err() {
                break;
            }
        }
        assert_eq!(last, Err(Refuse::LengthDisagreement));
    }

    /// A word split across two packets lands the same bytes as one whole chunk.
    ///
    /// THE MUTATION: write `bytes` straight through with no carry. The odd-slice run
    /// then returns `Err(Psram(NotAligned))`, because `FakePsram` refuses an
    /// unaligned write through the same `check_write` the silicon uses — which is
    /// the entire reason that double exists.
    ///
    /// The extra leg proves the CARRY and not the total: after exactly 4,093 bytes,
    /// the last word of chunk 0 is still untouched, so the three orphaned bytes are
    /// held rather than written short. The fixture never mentions `WRITE_ALIGN`.
    #[test]
    fn a_word_split_across_two_packets_lands_the_same_bytes_as_one_chunk() {
        let img = image(SIZE as usize);

        let mut whole = armed(&img);
        assert_eq!(stream(&mut whole, &img, 4096), Ok(65));

        // Slices that are mostly not word multiples, and one of them is a single
        // byte. 64 is in the list because it is the real USB packet size.
        for step in [1usize, 2, 3, 5, 7, 11, 64, 4095] {
            let mut s = armed(&img);
            assert_eq!(stream(&mut s, &img, step), Ok(65), "step {step}");
            assert_eq!(s.psram.cells(), whole.psram.cells(), "step {step}");
        }

        // The carry itself: 4,093 bytes in, chunk 0's last word must still hold the
        // self-test pattern the admission left there.
        let mut part = armed(&img);
        let pattern = part.psram.cells()[4092..4096].to_vec();
        assert_eq!(part.feed(&img[..4093]), Ok(0), "no chunk is complete yet");
        assert_eq!(
            &part.psram.cells()[4092..4096],
            &pattern[..],
            "three orphaned bytes are carried, never written short"
        );
        // And the carry is flushed by the bytes that complete the word.
        assert_eq!(part.feed(&img[4093..4096]), Ok(1));
        assert_eq!(&part.psram.cells()[..4096], &img[..4096]);
    }

    /// On a target with no PSRAM, staging refuses at admission rather than
    /// reporting success.
    ///
    /// THE MUTATION: remove the `readback_selftest` call from `admit`. The stager
    /// then reads `Prepared` — and every subsequent `MappedPsram::write` of a
    /// non-empty word multiple returns `NotOnThisTarget`, so the transfer dies
    /// 390 KiB later instead of before it starts.
    ///
    /// This asserts the OFF-ARM leg only, and it is exactly the trap
    /// `hal/src/psram.rs`'s `write` was written for: `Ok` from a PSRAM write does
    /// not mean bytes moved, so a machine that treated any `Ok` as progress would
    /// report a fully staged image of nothing.
    #[test]
    fn staging_on_a_target_with_no_psram_refuses_rather_than_reporting_success() {
        let mut s = Stager::new(psram::MappedPsram);
        assert_eq!(
            s.admit(&prepare2(SIZE, announce(&image(SIZE as usize)))),
            Err(Refuse::Selftest(PsramError::NotOnThisTarget))
        );
        assert_eq!(
            s.state(),
            State::Refused(Refuse::Selftest(PsramError::NotOnThisTarget))
        );
        assert!(!s.is_streaming());
    }

    /// Re-preparing over a verified image resets the staging cursor.
    ///
    /// THE MUTATION: drop `self.written = 0` from the `PrepareUpgrade2` arm. The
    /// second image is then written starting where the first ended, which on a fake
    /// sized to one image is `Err(Psram(OutOfBounds))` and on the silicon would be a
    /// second image staged at the wrong offset behind a passing digest of the first.
    ///
    /// **THIS TEST'S FIRST DOC CLAIMED A DIFFERENT MUTATION AND WAS WRONG ABOUT IT.**
    /// It said "keep the old state on re-prepare", and MEASURED 2026-09-17 that
    /// mutation — deleting `self.state = State::Idle;` — left ALL 191 firmware tests
    /// GREEN, exit 0. It is unobservable from outside `admit`, because every exit
    /// from that arm assigns the state anyway. The claim was corrected rather than
    /// the test deleted: the `written` reset it actually covers is the half that can
    /// stage bytes at the wrong offset. See `admit`'s own comment for the residue.
    ///
    /// It follows that the `Prepared` assertion below is the WEAK leg and the `feed`
    /// legs are the load-bearing ones. Do not read the first `assert_eq!` as the
    /// guard.
    #[test]
    fn re_preparing_over_a_verified_image_clears_the_verdict_first() {
        let img = image(SIZE as usize);
        let mut s = armed(&img);
        assert_eq!(stream(&mut s, &img, 4096), Ok(65));
        assert_eq!(s.state(), State::Staged { size: SIZE });

        s.admit(&prepare2(SIZE, announce(&img))).unwrap();
        assert_eq!(s.state(), State::Prepared { size: SIZE });
        s.admit(&CoordinatorUpgradeMessage::EnterUpgradeMode).unwrap();
        assert_eq!(s.feed(&img[..4096]), Ok(1));
        assert_eq!(
            s.state(),
            State::Streaming {
                size: SIZE,
                received: 4096
            }
        );
    }

    /// **A TRIPWIRE, NOT THE GUARD.** The guard is [`run`]'s signature, which holds
    /// no `Session`, no `DeviceId` and no `Outbox`, so there is nothing in this
    /// module to frame a reply with. A needle is evadable by aliasing, and a leak
    /// routed through a helper in another file would still have to build a
    /// `DeviceSendMessage` with a `DeviceId` this module does not have.
    ///
    /// THE MUTATION: add `use crate::Session;` above the cut.
    #[test]
    fn nothing_in_this_module_can_answer_a_message_or_allocate() {
        let prod = include_str!("upgrade.rs")
            .split_once("#[cfg(test)]")
            .expect("`#[cfg(test)]` occurs nowhere in this file, not even as this literal")
            .0;
        // The cut kept the production half. Without this, a cut that landed at byte
        // 0 would satisfy every `contains` below vacuously.
        assert!(
            prod.contains("pub fn run"),
            "the cut dropped the production half"
        );
        // COMMENT LINES ARE DROPPED, and that is not a weakening — it is what makes
        // the needles mean "in code". This module's own doc has to NAME `Session`,
        // `Outbox` and `DeviceId` to explain why it holds none of them, so a needle
        // over the raw text would be red on the prose and could never be anything
        // but deleted. `main.rs`'s `production_source` has the opposite problem and
        // therefore the opposite rule.
        //
        // A `/* */` block comment is NOT dropped by this filter, so it makes a
        // needle MORE likely to fire, not less — the fail-closed direction, unlike
        // the depth anchors in `main.rs` that a block comment defeats. Nothing here
        // needs a `/*` count for soundness; use `// ` above the cut anyway or expect
        // a false red.
        let code: std::string::String = prod
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            code.contains("pub fn run<W: Wire, P: Psram>"),
            "the filter dropped the code as well as the comments"
        );
        for needle in [
            "Session",
            "Outbox",
            "DeviceId",
            "encode_frame",
            "HeldShares",
            "extern crate alloc",
            "Vec<",
            "Box<",
            ".collect(",
        ] {
            assert_eq!(
                code.matches(needle).count(),
                0,
                "`{needle}` appears in this module's production CODE: the pre-Session \
                 window must admit upgrade staging and nothing else, and it must \
                 allocate nothing"
            );
        }
        // The only thing this module reaches out of the crate root for. Not a style
        // rule: `Session`, `Outbox` and every other leak this module must not have
        // are unreachable without a `crate::` path or a `use crate::`, so freezing
        // the count at one is what the needles above are a tripwire ON.
        assert_eq!(
            code.matches("crate::").count(),
            1,
            "exactly one path out of the crate root, and it is `use crate::firmware_digest;`"
        );
        assert!(code.contains("use crate::firmware_digest;"));
    }
}
