//! The device's session logic: **one** dispatch, compiled into the ARM image
//! *and* driven on the host.
//!
//! Everything here is generic over `F: NorFlash` and `impl RngCore`, so
//! `StmFlash` + `Entropy` drive it on silicon and `FakeFlash` + a seeded
//! `Entropy` drive it in this file's tests and (once repointed) in
//! `hostcheck/`'s pty harness. There is deliberately **no** `cfg(target_arch)`,
//! no register access, no backup register and no callgate in this module: the
//! moment one appears, the tested path stops being the shipped path, which is
//! the exact gap this module exists to close.
//!
//! What lives in the bin (`main.rs`) and must never move here: the singletons
//! (`rng::Sources::take_all`, `StmFlashToken`, `UsbToken`, `PanelToken`), the
//! `#[global_allocator]`, the vector table, `BootHealth`, and the decision to
//! *hold dark*. What lives here: signer construction from durable flash state,
//! the coordinator dispatch, the outbox framing caps, the announce, and — the
//! reason the first of those says *durable* — the share and name writes, at the
//! one point where they are provably ahead of the acknowledgement they back.
//!
//! ## Consent is not in this module's gift
//!
//! [`Session::recv`] never answers a `CheckKeyGen` or a `SignatureRequest`. It
//! *returns* them, and the caller — a human at a screen and a button on the
//! device, `hostcheck`'s auto-ack in the harness — decides and calls
//! [`Session::confirm`]. A dispatch that acked those itself would be a device
//! that signs whatever a coordinator asks for.
//!
//! ## Heap
//!
//! Construction allocates one `Vec` of 4 `NonceAbSlot`s (~192 B on 32-bit), plus —
//! on a device that holds a share — the reloaded keygen triple, which is one
//! `String` of at most 60 B and one `Box<SaveShareMutation>` of ~125 B, both
//! consumed by `apply_mutation` and gone before `open` returns. Saving allocates
//! nothing at all (`store`'s record is a stack `[u8; 512]`, the name record a stack
//! `[u8; 72]`). MEASURED: `examples/heap_session` still reports an arena high-water
//! of 60,512 B of 65,536, i.e. the same 5,024 B spare as before this landed. The
//! flash-backed slots hold their state on flash rather than in
//! `MemoryNonceSlot`, so live bytes should fall relative to
//! `heap::MEASURED_LIVE_BYTES`. The one number this module *adds* is the outbox:
//! it holds encoded frames until the caller drains them, so a 4-stream nonce
//! replenishment parks **8,160 B** of `Vec<u8>` until [`Outbox::take`] — MEASURED
//! (4 frames x 2,040 B, which is also PLAN.md's single-segment figure) by
//! `nonce_response_is_split_one_segment_per_frame`. Drain every loop iteration;
//! that 8,160 B is the largest single thing this module keeps on the heap.

#![no_std]
#![warn(missing_docs)]

extern crate alloc;

use alloc::{collections::VecDeque, string::String, string::ToString, vec, vec::Vec};
use core::cell::RefCell;
use core::fmt;

use coldsnap_hal::comms::{self, CommsError, CoordinatorSendBody, ReceiveSerial, FRAME_LIMIT};
use coldsnap_hal::identity::IdentitySecret;
use coldsnap_hal::memmap;
use coldsnap_hal::ui;
use embedded_storage::nor_flash::{ErrorType, NorFlash, ReadNorFlash};
use frostsnap_comms::{
    CommsMisc, DeviceName, DeviceSendBody, DeviceSendMessage, Downstream, NameCommand, Sha256Digest,
};
use frostsnap_core::device::{
    restoration::{BackupDisplayPhase, EnterBackupPhase, ToUserRestoration},
    DeviceSecretDerivation, DeviceToUserMessage, FrostSigner,
};
use frostsnap_core::message::{
    keygen::Keygen, signing::CoordinatorSigning, signing::DeviceSigning, CoordinatorRestoration,
    CoordinatorToDeviceMessage, DeviceSend, DeviceToCoordinatorMessage,
};
use frostsnap_core::schnorr_fun::fun::{prelude::*, KeyPair};
use frostsnap_core::{
    AccessStructureRef, CheckedSignTask, CoordShareDecryptionContrib, DeviceId, SignTask,
    SymmetricKey,
};
use frostsnap_embedded::{AbSlot, AbWriteOutcome, FlashPartition, NonceAbSlot, SECTOR_SIZE};
use sha2::{Digest, Sha256};

// Durable share storage, drained at the top of [`Session::run`] and replayed by
// [`Session::open`].
// A plain comment, not `///`: a doc comment here would be concatenated with
// `store.rs`'s `//!` docs and resolve their intra-doc links in *this* scope,
// which is 11 rustdoc warnings.
pub mod store;

pub mod wordentry;

use store::{ShareStore, StoreFault};

// The nonce partition, in SECTORS. `FlashPartition::new` takes sectors and every
// `memmap::FS_*` constant is in bytes; getting that wrong aims nonce writes at
// the identity record two sectors below.
const NONCE_OFFSET_SECTOR: u32 = memmap::FS_NONCE_OFFSET / SECTOR_SIZE as u32;
const NONCE_SECTORS: u32 = memmap::FS_NONCE_LEN / SECTOR_SIZE as u32;
const _: () = {
    assert!(memmap::FS_NONCE_OFFSET % SECTOR_SIZE as u32 == 0);
    // `load_slots` consumes 2 sectors per A/B slot and drops any odd tail.
    assert!(NONCE_SECTORS % 2 == 0);
    assert!(NONCE_SECTORS >= 2);
};

/// How many nonce streams the flash partition can hold, i.e. what a coordinator
/// asking for more than this will silently lose (`AbSlots::get_or_create` evicts
/// by `last_used`). 4 today, and the flutter coordinator's `N_NONCE_STREAMS` is
/// also 4.
pub const NONCE_SLOTS: u32 = NONCE_SECTORS / 2;

/// Ceiling on `DeviceSendBody::Debug`'s string, in bytes — cap (c).
///
/// Truncation happens on a UTF-8 boundary; `String::truncate` panics off one and
/// `panic = "abort"` makes that a brick.
pub const DEBUG_MESSAGE_LIMIT: usize = 256;

/// Something went wrong, as a value. Never a panic: every input here is
/// coordinator-controlled and every reachable panic on this unit is a brick with
/// no DFU recovery (DECISIONS.md decision 6).
#[derive(Debug, Clone)]
pub enum Fault {
    /// The stored identity secret is not a usable scalar. Unreachable through
    /// `identity::load_or_create`, which only ever returns bytes it has checked
    /// are `0 < s < n` — but it is `Option`, so it is an arm and not an
    /// `expect`. Route it to the same permanent hold as `IdentityFault`.
    IdentityScalar,
    /// Framing refused the reply. Nothing was written to the outbox.
    Comms(CommsError),
    /// `frostsnap_core` rejected the message for its state.
    Signer(frostsnap_core::Error),
    /// `frostsnap_core` rejected the confirmation: the phase the human answered
    /// no longer matches the signer's state (a `Cancel` in between, say).
    Action(frostsnap_core::ActionError),
    /// The device refuses to act on this message. Not an error: a policy.
    Refused(Refusal),
    /// [`Session::confirm`] was handed a prompt that is not a consent prompt, or
    /// a page of one that may not authorise it.
    NotConfirmable,
    /// Durable storage refused. **Nothing was acknowledged**: this is returned
    /// from the top of `Session::run`, before the outbox is touched, so a
    /// coordinator never hears about a share this device did not keep.
    Store(StoreFault),
}

impl From<CommsError> for Fault {
    fn from(e: CommsError) -> Self {
        Fault::Comms(e)
    }
}

/// Why a coordinator message was refused. Each of these is a thing this device
/// cannot do at all, not a thing it failed to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// `Upgrade`: there is no OTA path on this hardware and there cannot be one.
    /// RDP=2 makes DFU hardware-impossible and the image is signed-flash-only.
    FirmwareUpgrade,
    /// `DataErase`: destroys shares. Only ever behind physical consent, and no
    /// such screen or button path exists yet.
    DataErase,
    /// `Challenge`: needs the ESP32 hardware-RSA DS peripheral and a factory
    /// certificate this device does not have. Upstream never sends it
    /// (`DO_GENUINE_CHECK = false`).
    GenuineChallenge,
    /// `DisplayBackup`: this device cannot show **this** backup, so it will not
    /// reveal it.
    ///
    /// No longer a blanket refusal of the message — [`Session::recv`] admits it and
    /// [`prompt_screen_at`] draws its consent screen — but the same fail-closed
    /// direction for every case where the reveal could not be *complete*: a share
    /// index that is not a `u32` (so the page that makes the backup restorable
    /// cannot be printed), a word `ui::BackupPages::new` will not render, or a page
    /// index past the end of the set. Also what [`Session::show_backup`] returns
    /// when no human has consented, which is the case that matters most: a reveal
    /// with no grant behind it is refused, not drawn.
    DisplayBackup,
    /// A physical-backup operation this device will not perform.
    ///
    /// No longer the blanket refusal of five messages it was: `EnterPhysicalBackup`,
    /// `SavePhysicalBackup`, `SavePhysicalBackup2` and `Consolidate` are ADMITTED
    /// ([`Session::recv`]) and drive [`wordentry::Entry`] behind a consent digit.
    /// What is left under this name:
    ///
    /// * **`CheckBackup` — still refused outright.** It is not the cheap one: its
    ///   screen renders the TRUE word among three *and* all 25
    ///   (`frostsnap_widgets/src/backup/check_backup.rs:98-111`), so its exposure
    ///   exceeds `DisplayBackup`'s, and the distractor picker DECISIONS.md:46
    ///   declined to vendor does not exist. Admitting it while `show_backup` draws
    ///   plain words would answer a quiz request with a full plaintext reveal.
    /// * A `Consolidate` whose share index is not a `u32`, so the consent screen
    ///   cannot name the share the human is being asked to store.
    /// * [`Session::entry_key`] with no entry in progress — the fail-closed answer
    ///   to a caller that has lost track of the flow, and the reason a keypress
    ///   cannot start an ingest that no digit consented to.
    PhysicalBackup,
    /// `ScreenVerify`: address display. Harmless but unimplemented; refusing
    /// beats silently dropping it, which leaves the app waiting.
    AddressVerify,
    /// `Keygen::Begin` naming more than [`MAX_PARTIES`] devices, or a threshold
    /// outside `1..=devices`.
    ///
    /// This is a HEAP bound wearing a protocol hat, and it is the one refusal here
    /// whose absence could permanently destroy a unit. PLAN.md declares an envelope
    /// of n <= 12, but until 2026-08-25 that existed only in prose — no code refused
    /// a larger group. An n=16 `CertifyPlease` is 3,775 B by PLAN.md §7's own
    /// measured formula, comfortably inside `comms::FRAME_LIMIT` (4,096), so it is
    /// wire-legal; and `heap::MEASURED_ARENA_FOOTPRINT_BYTES` leaves only 5,024 B
    /// spare at n=12. At n=16 the allocator refuses, the FIRST refusal landing in
    /// keygen requesting 4,256 B — i.e. **before any consent screen**. On device an
    /// allocation failure is `handle_alloc_error` -> panic -> reset, and with
    /// `panic = "abort"`, RDP=2, no PIN UI, and `sdcard_try_file` demanding an SE1
    /// CHECKMAC (`sdcard.c:248`, `verify.c:300-306`), that reset loop is permanent.
    /// One coordinator message would end the device. Hence: bounded here, before the
    /// signer sees it.
    GroupTooLarge,
    /// The device cannot show, in full, what it is being asked to authorise —
    /// an output with no address form (OP_RETURN, a bare `ScriptBuf::new()`), a
    /// recipient list longer than the screen, an address that is not printable
    /// ASCII, or a fee that does not compute.
    ///
    /// Fail-closed, and this is the direction PLAN.md §4.2 requires: a human
    /// cannot consent to what they were not shown, so a partial consent screen
    /// is worse than no consent screen. [`sign_consent`] is where it is decided
    /// and [`Session::confirm`] is what makes it binding.
    Undisplayable,
}

/// Largest group this device will begin a keygen for.
///
/// PLAN.md's declared envelope: **n <= 12 devices, any t <= n**. This is the code
/// that makes the prose true — see [`Refusal::GroupTooLarge`] for why its absence was
/// a permanent-brick path rather than a tidiness issue.
///
/// Not a tunable. Raising it requires re-running
/// `firmware/examples/heap_session.rs` and re-deriving
/// `heap::MEASURED_ARENA_FOOTPRINT_BYTES`, which at n=12 already leaves only 5,024 B
/// of the 65,536-byte arena spare.
pub const MAX_PARTIES: usize = 12;

/// The `core::fmt::Debug` shim that `FrostSigner::new` demands.
///
/// `FrostSigner`'s entire inherent impl is bounded
/// `S: NonceStreamSlot + core::fmt::Debug` (`device.rs:156`) and
/// `NonceAbSlot<'a, S>` derives `Debug`, so the flash type must be `Debug`.
/// Neither `StmFlash` nor `FakeFlash` is, and this module may not edit the HAL —
/// so wrap. Prints the type name and nothing else: a flash `Debug` that dumped
/// cells would print the identity secret.
///
/// Delete this the day the HAL grows its own two-line `Debug` impls; it forwards
/// every associated const unchanged and is therefore exactly as permissive as
/// whatever it wraps, no more.
pub struct DebugFlash<F>(pub F);

impl<F> fmt::Debug for DebugFlash<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DebugFlash(..)")
    }
}

impl<F: ErrorType> ErrorType for DebugFlash<F> {
    type Error = F::Error;
}

impl<F: ReadNorFlash> ReadNorFlash for DebugFlash<F> {
    const READ_SIZE: usize = F::READ_SIZE;
    fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
        self.0.read(offset, bytes)
    }
    fn capacity(&self) -> usize {
        self.0.capacity()
    }
}

impl<F: NorFlash> NorFlash for DebugFlash<F> {
    const WRITE_SIZE: usize = F::WRITE_SIZE;
    const ERASE_SIZE: usize = F::ERASE_SIZE;
    fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
        self.0.erase(from, to)
    }
    fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
        self.0.write(offset, bytes)
    }
}

/// The two secrets `frostsnap_core` asks the device to derive, derived from the
/// durable identity secret.
///
/// Both are SHA-256 with a domain string and length-prefixed inputs, the same
/// shape upstream uses (`device/src/efuse.rs:511-546`) with our identity secret
/// standing in for the ESP32's efuse-held HMAC key. Deterministic, so a share
/// encrypted before a power cycle still decrypts after one — which is the whole
/// reason the identity is durable.
///
/// ponytail: ceiling named. This is a SOFTWARE derivation from a secret that
/// lives in FLASH_FS. A shipping COLDCARD should derive it in SE1/SE2, where the
/// key never reaches the CPU; the upgrade path is to replace this one type
/// without touching any caller. It is a forever wire/on-flash decision (change
/// it and every already-saved share stops decrypting) and it deserves its own
/// review — see the open list.
pub struct Secrets {
    seed: [u8; 32],
}

impl Secrets {
    /// Bind the derivations to this device's durable identity.
    pub fn new(secret: &IdentitySecret) -> Self {
        Self {
            seed: *secret.expose_secret(),
        }
    }
}

/// SHA-256 over a domain string and length-prefixed parts, so no two different
/// input tuples can concatenate to the same bytes.
fn tagged(domain: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain.as_bytes());
    for part in parts {
        h.update((part.len() as u32).to_le_bytes());
        h.update(part);
    }
    h.finalize().into()
}

impl DeviceSecretDerivation for Secrets {
    fn get_share_encryption_key(
        &mut self,
        access_structure_ref: AccessStructureRef,
        party_index: frostsnap_core::schnorr_fun::frost::ShareIndex,
        coord_key: CoordShareDecryptionContrib,
    ) -> SymmetricKey {
        SymmetricKey(tagged(
            "coldsnap/share-encryption/v1",
            &[
                &self.seed,
                access_structure_ref.key_id.to_bytes().as_slice(),
                access_structure_ref
                    .access_structure_id
                    .to_bytes()
                    .as_slice(),
                party_index.to_bytes().as_slice(),
                coord_key.to_bytes().as_slice(),
            ],
        ))
    }

    fn derive_nonce_seed(
        &mut self,
        nonce_stream_id: frostsnap_core::nonce_stream::NonceStreamId,
        index: u32,
        seed_material: &[u8; 32],
    ) -> [u8; 32] {
        tagged(
            "coldsnap/nonce-seed/v1",
            &[
                &self.seed,
                nonce_stream_id.to_bytes().as_slice(),
                &index.to_be_bytes(),
                seed_material,
            ],
        )
    }
}

/// Frames waiting to go out, already encoded, with the three framing caps
/// applied at the single point where a body becomes bytes.
///
/// Bodies are encoded on `push` rather than on drain so that a refusal is
/// reported to the code that produced the body, and so a refused body leaves
/// **nothing** behind: the wire has no length prefix and no resync marker, so a
/// half-written frame desynchronises the coordinator permanently.
pub struct Outbox {
    from: DeviceId,
    bytes: Vec<u8>,
    frames: usize,
}

impl Outbox {
    /// An empty outbox that stamps every frame with this device's id.
    pub fn new(from: DeviceId) -> Self {
        Self {
            from,
            bytes: Vec::new(),
            frames: 0,
        }
    }

    /// How many whole frames are buffered. Framing is self-delimiting, so this
    /// is bookkeeping for tests and logs, not something the wire needs.
    pub fn frames(&self) -> usize {
        self.frames
    }

    /// The buffered bytes, in order. Write them out in whatever chunks the USB
    /// endpoint wants — frame boundaries do not need to line up with writes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Hand over the buffered bytes and reset. Call this every loop iteration;
    /// an undrained outbox is the one heap cost this module adds.
    pub fn take(&mut self) -> Vec<u8> {
        self.frames = 0;
        core::mem::take(&mut self.bytes)
    }

    /// Encode one body into one or more frames, applying the caps.
    ///
    /// - **cap (a), one nonce segment per frame**: a multi-segment
    ///   `NonceResponse` becomes one frame per segment. 4 segments at
    ///   `NONCE_BATCH_SIZE = 30` is ~8 KB and `FRAME_LIMIT` is 4,096, so without
    ///   the split a coordinator that does not call `OpenNonceStreams::split()`
    ///   gets no reply at all and waits forever. Splitting is legal: the
    ///   coordinator's handler is a per-segment loop with no cross-segment state.
    /// - **cap (c), `Debug` truncation**: the message is cut to
    ///   [`DEBUG_MESSAGE_LIMIT`] on a UTF-8 boundary.
    /// - **cap (b), `HeldShares2`**: no special case, deliberately. It is
    ///   refused whole as `CommsError::FrameTooLong` if the device holds too many
    ///   shares to describe in one frame. Truncating a restoration reply would
    ///   tell the coordinator a share does not exist, which is a data-loss-shaped
    ///   lie; refusing is recoverable and visible.
    pub fn push(&mut self, body: DeviceSendBody) -> Result<(), CommsError> {
        match body {
            DeviceSendBody::Core(DeviceToCoordinatorMessage::Signing(
                DeviceSigning::NonceResponse { segments },
            )) if segments.len() > 1 => {
                for segment in segments {
                    // Depth 2 at most: each recursion carries exactly one segment.
                    self.push(DeviceSendBody::Core(DeviceToCoordinatorMessage::Signing(
                        DeviceSigning::NonceResponse {
                            segments: vec![segment],
                        },
                    )))?;
                }
                Ok(())
            }
            DeviceSendBody::Debug { message } => self.encode(DeviceSendBody::Debug {
                message: truncate_debug(message),
            }),
            other => self.encode(other),
        }
    }

    fn encode(&mut self, body: DeviceSendBody) -> Result<(), CommsError> {
        let frame = ReceiveSerial::<Downstream>::Message(DeviceSendMessage {
            from: self.from,
            body: body.into(),
        });
        let mut buf = [0u8; FRAME_LIMIT];
        let len = comms::encode_frame(&frame, &mut buf)?;
        self.bytes.extend_from_slice(&buf[..len]);
        self.frames += 1;
        Ok(())
    }
}

/// Cut a debug string to [`DEBUG_MESSAGE_LIMIT`] bytes without splitting a
/// character. `String::truncate` panics off a boundary, and a panic here is a
/// brick.
fn truncate_debug(mut message: String) -> String {
    if message.len() <= DEBUG_MESSAGE_LIMIT {
        return message;
    }
    let mut end = DEBUG_MESSAGE_LIMIT;
    while !message.is_char_boundary(end) {
        end -= 1; // `is_char_boundary(0)` is always true, so this terminates.
    }
    message.truncate(end);
    message
}

/// Longest device name this device will keep, in **bytes**.
///
/// `DeviceName` is `FixedString<DEVICE_NAME_MAX_LENGTH>` and that bound is 14
/// **chars**, not 14 bytes (`fixed_string.rs:31-40` counts `chars()`), so a
/// coordinator-supplied name is up to 56 UTF-8 bytes. Its `Decode` truncates
/// instead of erroring (`:131-140`) and cuts on `chars().take(N)`, so it never
/// splits a codepoint — but it decodes an unbounded `String` first, which is why
/// the byte bound has to be re-applied here, at the flash boundary.
pub const DEVICE_NAME_MAX_BYTES: usize = 4 * frostsnap_comms::DEVICE_NAME_MAX_LENGTH;

/// Domain separation for the name record's checksum, and its format version. A
/// record written under a different domain fails the check and reads as no name —
/// which is the right direction for a name (retypeable) and the wrong one for a
/// share, hence `store::MAGIC`'s explicit version half there and none here.
const NAME_DOMAIN: &str = "coldsnap/device-name/v1";

/// `name_len` at 0, the UTF-8 bytes at 1, zero padding, then the checksum in the
/// final doubleword — the same commit-last shape as `store`'s share record and
/// `identity`'s `MAGIC`, and for the same reason: `StmFlash::write` programs
/// doublewords in ascending order (`hal/src/flash.rs:1256`), so a tear leaves the
/// tail at `0xff` and the record reads as absent rather than as a truncated name.
const NAME_OFF: usize = 1;
const NAME_TAG_OFF: usize = 64;
const NAME_RECORD_LEN: usize = NAME_TAG_OFF + 8;

const _: () = {
    assert!(NAME_OFF + DEVICE_NAME_MAX_BYTES <= NAME_TAG_OFF);
    assert!(NAME_RECORD_LEN % coldsnap_hal::flash::WRITE_SIZE == 0);
    // `AbSlot::new` asserts these at RUNTIME (`ab_write.rs:26-32`), and an assert
    // during boot construction is a brick. Settle them here.
    assert!(memmap::FS_NAME_OFFSET % SECTOR_SIZE as u32 == 0);
    assert!(NAME_SECTORS >= 2 && NAME_SECTORS % 2 == 0);
    // Each A/B copy gets half the region; `SlotValue` prepends a 4-byte index.
    assert!(NAME_RECORD_LEN + 4 <= (NAME_SECTORS as usize / 2) * SECTOR_SIZE);
};

const NAME_OFFSET_SECTOR: u32 = memmap::FS_NAME_OFFSET / SECTOR_SIZE as u32;
const NAME_SECTORS: u32 = memmap::FS_NAME_LEN / SECTOR_SIZE as u32;

/// `sha256(NAME_DOMAIN ‖ body)[..8]`. Integrity, not authentication: it catches a
/// tear or rot and claims nothing against someone who can already program flash.
fn name_tag(body: &[u8]) -> [u8; 8] {
    let mut tag = [0u8; 8];
    tag.copy_from_slice(&tagged(NAME_DOMAIN, &[body])[..8]);
    tag
}

/// The device name, on flash at [`memmap::FS_NAME_OFFSET`], as two A/B copies of
/// one fixed-shape record.
///
/// A separate region from the share on purpose: the loss consequences differ —
/// the share is unrecoverable on this port (`DisplayBackup` and every physical
/// backup path are refused), a name is retyped in five seconds — and separate
/// regions mean a rename can never erase a sector the share lives in.
///
/// Fixed shape, no `String` and no `Vec` on flash, for the reason `store`'s docs
/// give at length: bincode's `Vec<u8>::decode` runs `alloc::vec![0u8; len]` on a
/// raw length claim, so a damaged length field in a durable record is a failed
/// allocation at *boot* — i.e. a permanent reset loop under `panic = "abort"`.
///
/// ponytail: this belongs beside `store::ShareStore`, whose record shape it
/// copies; it is here because this change owns `lib.rs` only. Move it when the two
/// are next touched together — the flash layout does not change when it moves.
#[derive(Clone, Debug)]
pub struct NameStore<'a, F> {
    slot: AbSlot<'a, F>,
}

impl<'a, F: NorFlash> NameStore<'a, F> {
    /// Open the region. Reads nothing and cannot fail: the geometry is
    /// const-asserted above, so `AbSlot::new`'s runtime asserts are unreachable.
    #[must_use]
    pub fn open(flash: &'a RefCell<F>) -> Self {
        Self {
            slot: AbSlot::new(FlashPartition::new(
                flash,
                NAME_OFFSET_SECTOR,
                NAME_SECTORS,
                "name",
            )),
        }
    }

    /// Write the name. Call it **before** pushing `SetName`, never after.
    ///
    /// # Errors
    ///
    /// [`StoreFault::TooBig`] for a name over [`DEVICE_NAME_MAX_BYTES`] — refused
    /// rather than cut, because the caller's name came off the wire as a
    /// `DeviceName` that is already bounded, so a long one here means a bug and
    /// not a hostile coordinator. [`StoreFault::Flash`] if the region refused the
    /// write, in which case the previous name is still live.
    ///
    /// `AbWriteOutcome::CommittedSingleCopy` is success: the value reads back
    /// (`ab_write.rs:83-92`).
    pub fn save(&self, name: &str) -> Result<(), StoreFault> {
        let bytes = name.as_bytes();
        // THE BOUND, and the only thing standing between a `String` on the wire
        // and a 4-byte-per-char overrun of the record. Checked before any
        // `copy_from_slice`, which panics on a length mismatch.
        if bytes.len() > DEVICE_NAME_MAX_BYTES {
            return Err(StoreFault::TooBig);
        }
        let mut record = [0u8; NAME_RECORD_LEN];
        record[0] = bytes.len() as u8;
        record[NAME_OFF..NAME_OFF + bytes.len()].copy_from_slice(bytes);
        let tag = name_tag(&record[..NAME_TAG_OFF]);
        record[NAME_TAG_OFF..].copy_from_slice(&tag);
        match self.slot.try_write(&record) {
            AbWriteOutcome::Committed | AbWriteOutcome::CommittedSingleCopy(_) => Ok(()),
            AbWriteOutcome::NotCommitted(e) => Err(StoreFault::Flash(e)),
        }
    }

    /// The stored name, or `None` for a blank, damaged or non-UTF-8 region.
    ///
    /// One `None` for all of those on purpose: every one of them means "this
    /// device has no name to announce", and the recovery is identical — send
    /// `NeedName` and let a human type it again. A share may not fold its states
    /// together like this (`store::HeldShare` has three) because there the states
    /// call for different handling.
    #[must_use]
    pub fn load(&self) -> Option<String> {
        let record = self.slot.read::<[u8; NAME_RECORD_LEN]>()?;
        let (body, tag) = record.split_at(NAME_TAG_OFF);
        if tag != name_tag(body) {
            return None;
        }
        let len = usize::from(record[0]);
        // Bounded before it slices, and bounded to the FIELD rather than to the
        // record: without this a forged length reads the zero padding, and a
        // `get` alone would still let it.
        if len > DEVICE_NAME_MAX_BYTES {
            return None;
        }
        Some(String::from(
            core::str::from_utf8(body.get(NAME_OFF..NAME_OFF + len)?).ok()?,
        ))
    }
}

/// Everything the device is, between resets: the signer, its flash-backed nonce
/// slots, and the secrets derived from its durable identity.
pub struct Session<'a, F: NorFlash + fmt::Debug> {
    /// The real signer. Public because persistence (`staged_mutations()`) and
    /// `device_id()` are the caller's business, not this module's.
    pub signer: FrostSigner<NonceAbSlot<'a, F>>,
    /// Set once the coordinator has acknowledged our announce. Upstream gates
    /// its debug channel on this.
    pub coordinator_acked: bool,
    secrets: Secrets,
    shares: ShareStore<'a, F>,
    names: NameStore<'a, F>,
    /// A name the coordinator has PREVIEWED and no human has approved yet. Never
    /// written to flash and never announced from here: see [`Session::recv`]'s
    /// `Naming` arm for why a preview cannot be a consent event.
    pending_name: Option<DeviceName>,
    /// The backup a human has CONSENTED to reveal, and the only thing that lets
    /// [`Session::show_backup`] draw a word.
    ///
    /// Private, and written in exactly one place — [`Session::confirm_at`]'s
    /// `DisplayBackup` arm, i.e. behind the funnel. That is what makes "consent
    /// precedes the reveal" a property of the type rather than of a caller's
    /// discipline: `show_backup` has no other way to learn which share to decrypt,
    /// so a caller that skips the consent step has nothing to render.
    ///
    /// It holds the phase and **not** the words. The phase is what the prompt
    /// already carried (an encrypted share plus the coordinator's decryption
    /// contribution — no plaintext), so the reveal costs no new resident secret;
    /// `show_backup` re-derives the 25 words per page and drops them with the stack
    /// frame. HEAP: one `String` key name and the root `SharedKey`'s point
    /// polynomial (12 points at n=12, ~400 B all told), live only between the
    /// consent and the last page.
    ///
    /// Cleared on `Cancel`, when the pages run out, and on any fault while
    /// revealing — so a grant cannot outlive the reveal it was given for. It is NOT
    /// a page cursor: the page is an argument to `show_backup`, exactly as it is to
    /// `confirm_at`.
    reveal: Option<BackupDisplayPhase>,
    /// A reveal has SHOWN EVERY PAGE and then ended, and nobody has been asked yet
    /// whether they wrote the words down. The one gate on
    /// [`Session::backup_recorded`].
    ///
    /// Set in exactly one place — [`Session::show_backup`]'s `Ok(false)` leg, and
    /// there only when `seen_pages` covers the whole set — and that leg is reachable
    /// only past the grant `take()` at the top of it, so this flag cannot be raised
    /// without a human having consented to a reveal first. Consumed by
    /// `backup_recorded`, so one reveal buys at most one ack.
    ///
    /// This is a `bool` and not the phase because the ack carries nothing
    /// (`CommsMisc::BackupRecorded` is a unit variant) and because keeping the
    /// phase alive past the reveal would keep an encrypted share and a
    /// `SharedKey` resident for as long as a human takes to answer a question
    /// that does not need them. A share cannot reach the outbox through a flag.
    ///
    /// RAM-only, like the grant: an unplug mid-question is a backup nobody
    /// confirmed, and the coordinator's own `disconnected` handler aborts the
    /// protocol (`frostsnap_coordinator/src/display_backup.rs:76-79`).
    record_pending: bool,
    /// Which pages of the CURRENT reveal have been composed into a frame, one bit
    /// per page index.
    ///
    /// Cleared in exactly ONE place: [`Session::confirm_at`], where a grant is issued.
    /// That is the only way back into [`Session::show_backup`], so one site covers
    /// every reveal — including one that faulted out mid-way, which the reveal's own
    /// legs do not reach. A second reset on the end leg or in `Cancel` would be a line
    /// no mutation can falsify, so there is none (MEASURED, and reported).
    ///
    /// A bit set and not a high-water mark: pages are paged forwards and backwards,
    /// so "the highest page reached" and "every page reached" are different facts and
    /// only the second one licenses the ack. A `u32` covers 31 pages against the 8
    /// this device draws; [`all_pages`] returns `None` above that and the ack is
    /// refused, which is the right direction for a constant nobody has changed yet.
    ///
    /// This is NOT the page cursor. It never decides what to draw — `page` remains an
    /// argument to [`Session::show_backup`], exactly as it is to
    /// [`Session::confirm_at`] — it only records what was drawn.
    seen_pages: u32,
    /// The share a human has CONSENTED to type IN, mid-transcription.
    ///
    /// The mirror image of `reveal`, and private for the same reason: written in
    /// exactly one place — [`Session::confirm_at`]'s `EnterBackup` arm, i.e. behind
    /// the [`prompt_screen_at`] funnel — so "consent precedes the ingest" is a
    /// property of the type. [`Session::entry_key`] is the only thing that reads it
    /// and it refuses when there is nothing here, so a caller cannot start an ingest
    /// by pressing a key: there is no other constructor for a
    /// [`wordentry::Entry`] on this side of the seam and no way to hand one in.
    ///
    /// A restore INGESTS a secret, which is why the gate is a digit and not a
    /// keypress: the 25 words go on the glass as they are typed, and this device
    /// must not be steerable into displaying a share-shaped screen by a coordinator
    /// message alone.
    ///
    /// It holds no plaintext until the human types one — the `EnterBackupPhase` the
    /// prompt carried is a 16-byte `EnterPhysicalId` and nothing else — and it never
    /// holds a `ShareBackup`: [`wordentry::Step::Entered`] is consumed inside
    /// `entry_key`, which hands it straight to
    /// `tell_coordinator_about_backup_load_result` and drops this. So the completed
    /// share never crosses back to the caller and cannot be logged by one. ~270 B on
    /// 32-bit, allocating nothing (see `wordentry`'s heap note).
    ///
    /// Cleared on `Cancel` and when entry ends either way. RAM-only, like the reveal
    /// grant and like the restore progress `store::ShareStore::persist_staged` drops:
    /// an unplug mid-restore costs re-typing 25 words and never a share.
    entry: Option<wordentry::Entry>,
}

impl<'a, F: NorFlash + fmt::Debug> Session<'a, F> {
    /// Build the signer from durable state: the keypair from the identity
    /// secret, the nonce slots from `FLASH_FS` at [`memmap::FS_NONCE_OFFSET`].
    ///
    /// Not `new_random`, and not `MemoryNonceSlot`: a signer whose nonces do not
    /// survive a power cycle would re-issue nonces after a reset, and FROST
    /// nonce reuse is a key leak. `load_slots` reads every slot to recover
    /// `last_used`, so this is also where a torn nonce write is noticed.
    ///
    /// Call `identity::load_or_create` **before** this — it wants
    /// `&mut F`, and the partition takes a shared borrow of the same `RefCell`
    /// that lives for as long as the session.
    /// It is also where a saved share comes BACK: the keygen triple is replayed
    /// through `FrostSigner::apply_mutation` in staging order, which is the only
    /// way into the signer's `keys` (the field is private and has no other
    /// constructor) and exactly how upstream restores at boot
    /// (`esp32_run.rs:148-155`). Without this a share persisted by
    /// `Session::run` would sit on flash while `RequestHeldShares` answered
    /// empty — the gap being closed here, seen from the other end.
    pub fn open(flash: &'a RefCell<F>, secret: &IdentitySecret) -> Result<Self, Fault> {
        let scalar = Scalar::<Secret, NonZero>::from_bytes(*secret.expose_secret())
            .ok_or(Fault::IdentityScalar)?;
        let slots = NonceAbSlot::load_slots(FlashPartition::new(
            flash,
            NONCE_OFFSET_SECTOR,
            NONCE_SECTORS,
            "nonces",
        ));
        let mut signer = FrostSigner::new(KeyPair::<Normal>::new(scalar), slots);
        let shares = ShareStore::open(flash);
        if let store::HeldShare::Share(reload) = shares.load() {
            for mutation in reload.mutations() {
                // IN THE GIVEN ORDER. `apply_mutation` inserts for `NewKey` and
                // only `and_modify`s for the other two (`device.rs:176-235`), so a
                // `SaveShare` replayed first is dropped with NO error and the
                // device boots believing it holds nothing.
                //
                // The return value is the mutation itself, discarded: `mutate` is
                // what stages, `apply_mutation` does not (`device.rs:170-244`), so
                // a reload cannot re-enter the persist path.
                let _ = signer.apply_mutation(mutation);
            }
        }
        // `HeldShare::Damaged` deliberately does nothing here. It means "no share
        // is readable this boot", not "hold": a record that failed its own
        // checksum was never acked (the persist in `run` precedes the outbox), so
        // no coordinator believes that share exists, and holding instead would
        // brick a unit with no PIN UI and no recovery install path.
        Ok(Session {
            signer,
            coordinator_acked: false,
            secrets: Secrets::new(secret),
            shares,
            names: NameStore::open(flash),
            pending_name: None,
            // A reveal grant is RAM-only and deliberately does not survive a reset:
            // consent is to one ceremony, and a coordinator that wants the backup
            // again must ask again.
            reveal: None,
            record_pending: false,
            seen_pages: 0,
            // Same rule, other direction: a half-typed share does not survive a
            // reset, and consent is to one ceremony.
            entry: None,
        })
    }

    /// The name a coordinator has previewed but no human has approved, for a
    /// caller that wants to draw it (`ui::standby(frame, name, "naming...", None)`
    /// is the intended screen — naming is not one of PLAN.md §4.2's eight, so it
    /// does not get one of its own).
    ///
    /// Drawing is the caller's because this module never touches a panel; that is
    /// the same split [`prompt_screen`] keeps.
    #[must_use]
    pub fn pending_name(&self) -> Option<&str> {
        self.pending_name.as_ref().map(DeviceName::as_str)
    }

    /// The name on flash, if any. Survives a reset; a preview does not.
    #[must_use]
    pub fn stored_name(&self) -> Option<String> {
        self.names.load()
    }

    /// This device's wire identity: 33 SEC1-compressed bytes derived from the
    /// durable secret, therefore the same across every reset.
    pub fn device_id(&self) -> DeviceId {
        self.signer.device_id()
    }

    /// Say hello: `Announce` carrying the firmware digest, then either `SetName`
    /// (we have a durable name) or `NeedName` (we do not).
    ///
    /// Both in one call, because announce alone never makes this device usable —
    /// the coordinator inserts into `registered_devices` only for a device it has a
    /// `device_names` entry for (`usb_serial_manager.rs:462-478`).
    ///
    /// **`SetName` is the only message that creates that entry**, and getting this
    /// backwards is what the comment here used to do: `SetName` ->
    /// `DeviceChange::NameChange` (`usb_serial_manager.rs:366-375`) ->
    /// `accept_device_name` (`coordinator.rs:232-254`, its only caller) ->
    /// `device_names.insert` (`:634-636`). `NeedName` reaches
    /// `DeviceChange::NeedsName` -> `DeviceMode::Blank` (`:343-344`,
    /// `coordinator.rs:258-260`): it makes the app ASK for a name, it never
    /// registers anything.
    ///
    /// Order matters and is not negotiable: `Announce` first, always. The app's
    /// `DeviceChange::Registered` handler is
    /// `.expect("registered means connected already emitted")`
    /// (`frostsnapp/rust/src/device_list.rs:117-120`), so a `SetName` that
    /// overtook the announce would panic the coordinator. Upstream sends the pair
    /// in the same burst for the same reason (`esp32_run.rs:355-363`).
    ///
    /// Send this on the magic-bytes **edge**, not once per boot: a coordinator
    /// that restarts re-sends magic and expects a fresh announce.
    pub fn announce(&self, firmware_digest: Sha256Digest, out: &mut Outbox) -> Result<(), Fault> {
        out.push(DeviceSendBody::Announce { firmware_digest })?;
        match self.names.load() {
            // `truncate` cannot shorten anything that got here: the name was
            // stored from a `DeviceName`, which is already 14 chars or fewer. It is
            // the infallible constructor, which is why it beats `new().expect()`.
            Some(name) => out.push(DeviceSendBody::SetName {
                name: DeviceName::truncate(name),
            })?,
            None => out.push(DeviceSendBody::NeedName)?,
        }
        Ok(())
    }

    /// Handle one decoded coordinator body.
    ///
    /// Feed it [`comms::decode_body`]'s output — the bounded decoder. The
    /// vendored `.decode()` will allocate 32,640 B for a 20-byte inner blob.
    ///
    /// Returns the prompts a human must answer. Replies go into `out`.
    pub fn recv<R: rand_core::RngCore>(
        &mut self,
        body: CoordinatorSendBody,
        rng: &mut R,
        out: &mut Outbox,
    ) -> Result<Vec<DeviceToUserMessage>, Fault> {
        match body {
            CoordinatorSendBody::Core(core) => self.recv_core(core, rng, out),

            // A preview is REMEMBERED and nothing else: no flash write, no
            // prompt, no keypress. The app calls `updateNamePreview` from the
            // text field's `onChanged` (`device_setup.dart:88-91`), i.e. once per
            // typed CHARACTER, so a keypress gate here would demand one press per
            // letter, and a flash write here would erase the region per letter.
            //
            // Consent lives at the commit instead — `Session::run`'s
            // `FinalizeKeyGen` arm, which no coordinator can reach without a
            // `Session::confirm` first — so the name is written and `SetName` sent
            // only inside a flow a human already approved with a digit. That is
            // upstream's own shape
            // (`esp32_run.rs:515-521` previews, `:230-241` commits, called only
            // from the three approved flows) and it is what makes a silent rename
            // structurally impossible — no coordinator message commits a name on
            // its own.
            //
            // Bounded on the way in as well as at the flash boundary: `DeviceName`
            // is `FixedString<14>`, whose `Decode` truncates to 14 chars
            // (`fixed_string.rs:131-140`).
            CoordinatorSendBody::Naming(NameCommand::Preview(name)) => {
                self.pending_name = Some(name);
                Ok(Vec::new())
            }

            // `_Prompt` is a retired slot-reserver: the vendored doc-comment says
            // so itself (`frostsnap_comms/src/lib.rs:332-335`, "Nothing sends it;
            // devices ignore it") and upstream's device is `_Prompt(_) => {}`
            // (`esp32_run.rs:522`). Gating naming on it would be dead code.
            CoordinatorSendBody::Naming(NameCommand::_Prompt(_)) => Ok(Vec::new()),

            CoordinatorSendBody::AnnounceAck => {
                self.coordinator_acked = true;
                Ok(Vec::new())
            }

            // The coordinator abandoned whatever it had started. Dropping the
            // half-finished keygen/backup state matters: keeping it makes the
            // next legitimate message fail on a stale state.
            CoordinatorSendBody::Cancel => {
                self.signer.clear_tmp_data();
                // Including the previewed name: it belonged to the flow that was
                // just abandoned, and keeping it would let the NEXT approved
                // keygen commit a name typed for a ceremony the human cancelled.
                // Upstream clears it too (`esp32_run.rs:507`, `:256`).
                self.pending_name = None;
                // And the backup reveal grant, for the stronger version of the same
                // reason: a human consented to reveal a share to the ceremony the
                // coordinator has just abandoned. Leaving the grant up would let the
                // next `show_backup` call put that share on the glass for a flow
                // nobody approved.
                self.reveal = None;
                // And the unanswered "did you write it down?" question, so a
                // cancelled ceremony acks nothing at all. The ack is a claim about a
                // protocol run the coordinator has just abandoned, and the whole
                // point of `BackupRecorded` is that it is trusted. `seen_pages` needs
                // no clearing here: `confirm_at` clears it when it issues a grant,
                // and a grant is the only way back into `show_backup`.
                self.record_pending = false;
                // And the half-typed share, for the reveal grant's reason run
                // backwards: the human consented to type a share into THIS ceremony,
                // and `clear_tmp_data` above has just dropped the signer's
                // `tmp_loaded_backups`, so a surviving `Entry` would be typing words
                // towards an `enter_physical_id` no coordinator is listening for —
                // words that would sit on the glass for whatever comes next.
                self.entry = None;
                Ok(Vec::new())
            }

            // All three `CoordinatorUpgradeMessage` variants (`PrepareUpgrade`,
            // `PrepareUpgrade2`, `EnterUpgradeMode`) refuse together: there is no
            // OTA path on this unit at any version.
            CoordinatorSendBody::Upgrade(_) => Err(Fault::Refused(Refusal::FirmwareUpgrade)),
            CoordinatorSendBody::DataErase => Err(Fault::Refused(Refusal::DataErase)),
            CoordinatorSendBody::Challenge(_) => Err(Fault::Refused(Refusal::GenuineChallenge)),
        }
    }

    /// The `Core` arm, enumerated. Every variant is named so that a vendored
    /// bump that adds one is a compile error rather than a silent accept.
    fn recv_core<R: rand_core::RngCore>(
        &mut self,
        core: CoordinatorToDeviceMessage,
        rng: &mut R,
        out: &mut Outbox,
    ) -> Result<Vec<DeviceToUserMessage>, Fault> {
        match &core {
            // Keygen: all four steps go to the signer. `Finalize` is what saves
            // the share, so refusing any one of them means keygen never
            // completes.
            // `Begin` is bounded BEFORE the signer sees it: it is the message that
            // starts the allocation-heavy work, and the only one carrying the device
            // list. The later three steps carry only a `keygen_id`, so a keygen this
            // device refused to begin cannot be advanced by them.
            CoordinatorToDeviceMessage::KeyGen(Keygen::Begin(begin)) => {
                if begin.devices.len() > MAX_PARTIES {
                    return Err(Fault::Refused(Refusal::GroupTooLarge));
                }
                // t must be within the group. `t == 0` would be a threshold no
                // subset can meet and `t > n` is unsatisfiable; neither is worth
                // handing to the curve, and both are coordinator-chosen.
                let n = begin.devices.len();
                if begin.threshold == 0 || usize::from(begin.threshold) > n {
                    return Err(Fault::Refused(Refusal::GroupTooLarge));
                }
            }
            CoordinatorToDeviceMessage::KeyGen(
                Keygen::CertifyPlease { .. } | Keygen::Check { .. } | Keygen::Finalize { .. },
            ) => {}
            // Signing: both steps go to the signer. `OpenNonceStreams` is the
            // one cap (a) exists for.
            CoordinatorToDeviceMessage::Signing(
                CoordinatorSigning::OpenNonceStreams(_) | CoordinatorSigning::RequestSign(_),
            ) => {}
            // Read-only, and the only restoration message that is safe without a
            // consent screen. Its reply is what cap (b) bounds.
            CoordinatorToDeviceMessage::Restoration(CoordinatorRestoration::RequestHeldShares) => {}
            // ADMITTED, and it is the one restoration message that is. It writes no
            // device state, stages no mutation and answers nothing: the signer
            // returns a `ToUserRestoration::DisplayBackup` PROMPT
            // (`device/restoration.rs:248-262`) and `run` hands it back to the
            // caller, so what a coordinator gets for asking is a question on a
            // screen. The three gates behind it, in order:
            //
            //  1. THE SIGNER. It refuses unless this device actually holds that
            //     share (`device/restoration.rs:216-247`: key, access structure,
            //     share index), so a request for a share we do not have is a
            //     `Fault::Signer` before any human is asked.
            //  2. THE CONSENT SCREEN. [`prompt_screen_at`] draws it and it carries
            //     NO WORD — structurally, not by care: that function has no
            //     `Secrets`, so nothing reachable from it can decrypt a share.
            //  3. THE GRANT. Only [`Session::confirm_at`] sets `self.reveal`, and
            //     only [`Session::show_backup`] reads it. Consent therefore
            //     precedes the reveal by construction rather than by ordering.
            //
            // A coordinator asking for a backup is asking this device to hand out
            // its share, so the request is treated as hostile throughout: nothing
            // here infers consent, and every one of the three gates fails closed.
            CoordinatorToDeviceMessage::Restoration(CoordinatorRestoration::DisplayBackup {
                ..
            }) => {}
            // THE RESTORE FLOW, ADMITTED — the four messages that between them let a
            // human type a share back IN. It is the only path on this device that
            // INGESTS a secret, so the order of the gates matters more here than
            // anywhere else and is worth stating once:
            //
            //  1. `EnterPhysicalBackup` writes NOTHING and stages NOTHING. The signer
            //     answers with a `ToUserRestoration::EnterBackup` PROMPT carrying an
            //     `EnterBackupPhase`, which is a 16-byte `EnterPhysicalId` and no
            //     secret at all (`device/restoration.rs:57-63`). What a coordinator
            //     gets for asking is a question on a screen.
            //  2. THE CONSENT DIGIT. [`prompt_screen_at`] draws it and
            //     [`Session::confirm_at`] is the only thing that can grant the
            //     [`wordentry::Entry`] — `self.entry` has no other writer and
            //     `Entry::new` no other caller. So a coordinator cannot put a
            //     share-shaped screen on the glass, and a caller cannot type into one
            //     that no human authorised.
            //  3. THE WORDS NEVER LEAVE. [`Session::entry_key`] consumes
            //     `Step::Entered` itself and sends `DeviceRestoration::PhysicalEntered`,
            //     whose payload is the `EnteredPhysicalBackup { enter_physical_id,
            //     share_image }` — a PUBLIC point and index, upstream's own reply
            //     (`:350-357`). No word, no scalar, no `Debug`.
            //     `no_word_of_a_typed_backup_ever_reaches_the_outbox` holds that.
            //  4. `SavePhysicalBackup`/`SavePhysicalBackup2` move the typed share from
            //     the signer's `tmp_loaded_backups` into its `saved_backups` and stage
            //     a `Mutation::Restoration(Save2)` carrying a PLAINTEXT `ShareBackup`.
            //     That mutation is DROPPED at the top of `run`, never written — see
            //     [`store::ShareStore::persist_staged`]. Both are admitted without a
            //     second consent screen deliberately: they move nothing off the
            //     device, they write nothing durable, and the human has already
            //     consented to the ingest that produced the material. The legacy
            //     `SavePhysicalBackup` is upstream's own alias — it rebuilds itself as
            //     a `SavePhysicalBackup2` and recurses (`:64-82`) — so refusing one
            //     while admitting the other would be a version check dressed as a
            //     policy.
            //  5. `Consolidate` is the DESTRUCTIVE one and it gets its own digit. It
            //     validates the typed share's polynomial checksum against the
            //     coordinator's `root_shared_key` (`:137-158`) and, on consent,
            //     `finish_consolidation` encrypts it and stages the keygen triple —
            //     which REPLACES whatever share this device already held, because the
            //     store keeps one record. Its screen says so.
            //
            // NO TIMEOUT on any of it, chosen and not missing: transcribing 25 words
            // is slow and a screen that blanks mid-flow costs a second full
            // disclosure. `wordentry` has no clock to expire against.
            CoordinatorToDeviceMessage::Restoration(
                CoordinatorRestoration::EnterPhysicalBackup { .. }
                | CoordinatorRestoration::SavePhysicalBackup { .. }
                | CoordinatorRestoration::SavePhysicalBackup2(_)
                | CoordinatorRestoration::Consolidate(_),
            ) => {}
            // `CheckBackup` STAYS REFUSED, and not one of the blockers is in this
            // file. Recorded here so the next reader does not re-derive the wrong
            // order; nothing below is repaired:
            //  - `CheckBackup` is not the cheap one, and it is NOT a `DisplayBackup`
            //    with a quiz bolted on. Upstream's quiz renders the TRUE word among
            //    three for the index and all 25 words
            //    (`frostsnap_widgets/src/backup/check_backup.rs:98-111`), so it
            //    reveals as much as `DisplayBackup` and additionally wants the
            //    distractor picker DECISIONS.md:46 declined to vendor. `ui` now has
            //    the SCREEN (`ui::backup_quiz_word`: mandatory `rng`, every option
            //    row noised); what is still missing is the picker and the key
            //    routing, and admitting this message with either of them absent
            //    would be worse than refusing it. `confirm_at`'s grant is read by
            //    `show_backup`, which draws PLAIN WORDS, and `boot()` starts a
            //    reveal on any confirmed `Restoration` prompt — so a `CheckBackup`
            //    admitted today would answer a quiz request with a full plaintext
            //    reveal and never send `CommsMisc::BackupChecked`. Landing it needs
            //    a second grant, a second `Reveal` state and 1/2/3 key handling,
            //    all of which live in `main.rs`.
            //
            //    Do NOT port `frostsnap_widgets/src/backup/distractor.rs` when it
            //    does land. `find_closest_distractors` is a pure function of the
            //    TRUE word (`levenshtein*3 - shared_suffix*2`, no RNG), so the
            //    triple identifies its own answer: MEASURED over the vendored 2048
            //    words, 1288 of them are recovered from the displayed triple with
            //    no human input, leaving ~0.467 of `log2(3)` bits per word — 11.7
            //    bits over 25 words, which `ShareBackup::from_words`' 11-bit word
            //    checksum plus its 8-bit poly checksum reduce to one candidate. A
            //    photograph of upstream's quiz is a full share disclosure. Its index
            //    screen is worse: the three options are always consecutive integers
            //    and the true one is always the median. The rule that does not leak
            //    is uniform choice inside a predicate SYMMETRIC over the triple —
            //    three draws from `rng::Entropy` over all 2048, rejecting the true
            //    word and duplicates under a hard iteration cap, and indices drawn
            //    from `1..=n` rather than `correct ± 1`.
            //
            //    Landing it also needs the ONE thing the restore flow above did not
            //    weaken: `show_backup`'s grant and this device's confirm digit. A
            //    `CheckBackup` admitted on the entry path would be a quiz answered
            //    with a reveal, so it stays here.
            CoordinatorToDeviceMessage::Restoration(CoordinatorRestoration::CheckBackup {
                ..
            }) => return Err(Fault::Refused(Refusal::PhysicalBackup)),
            CoordinatorToDeviceMessage::ScreenVerify(_) => {
                return Err(Fault::Refused(Refusal::AddressVerify))
            }
        }
        let sends = self
            .signer
            .recv_coordinator_message(core, rng)
            .map_err(Fault::Signer)?;
        self.run(sends, out)
    }

    /// The human said yes to this prompt. Hand back the prompt that
    /// [`Session::recv`] returned.
    ///
    /// Only the two consent prompts are answerable, and only from here — never
    /// from the dispatch. Everything else is informational.
    /// Page 0, for a caller that cannot page. See [`Session::confirm_at`], which
    /// this is, with the page the human was on hardcoded to the first one.
    ///
    /// Kept because it is what every existing caller calls, and because for the
    /// two single-page consent screens (`CheckKeyGen`, `SignTask::Test`) page 0
    /// **is** the page that authorises. A multi-page bitcoin transaction is
    /// [`Fault::NotConfirmable`] through here, which is the fail-closed direction:
    /// page 0 of 67 shows recipient 1 and no fee.
    pub fn confirm<R: rand_core::RngCore>(
        &mut self,
        prompt: DeviceToUserMessage,
        rng: &mut R,
        out: &mut Outbox,
    ) -> Result<Vec<DeviceToUserMessage>, Fault> {
        self.confirm_at(prompt, 0, rng, out)
    }

    /// The human said yes to this prompt, on **this page** of it. Hand back the
    /// prompt [`Session::recv`] returned and the page that was on the glass when
    /// the key was pressed.
    ///
    /// `page` is an argument and not state on `Session` on purpose: the caller
    /// already holds the `(prompt, ConfirmDigit)` pair that was rendered, and the
    /// page belongs in that same tuple. A cursor kept here would be a second copy
    /// of it, free to drift out of step with the glass the moment a second prompt
    /// arrives — and "the screen the human read" is precisely what must not drift.
    ///
    /// What this call is NOT is the consent gate. A caller that skips the keypress
    /// check can pass any page index until it gets a `true` back, so the gate is
    /// the caller's: the drawn digit, checked against the key, on a page reached by
    /// single advances. This is the renderability gate, and nothing more is claimed
    /// for it.
    pub fn confirm_at<R: rand_core::RngCore>(
        &mut self,
        prompt: DeviceToUserMessage,
        page: usize,
        rng: &mut R,
        out: &mut Outbox,
    ) -> Result<Vec<DeviceToUserMessage>, Fault> {
        // FAIL CLOSED, before any share or signature share exists. A `confirm`
        // can only mean "the human read the screen and pressed yes", so a prompt
        // this device could not have DRAWN IN FULL is one no human can have
        // consented to — whatever the caller thinks it saw. One funnel, the same
        // [`prompt_screen`] the ARM path draws with, so the screen and the
        // consent cannot disagree.
        //
        // [`Shown::Nothing`] — no screen for this prompt — is refused rather than
        // waved through, and that is load-bearing twice over: it is what an
        // informational prompt looks like, and it is also what a DELETED screen
        // arm looks like, so removing a screen from `prompt_screen_at` disables
        // consent instead of blinding it. `Page { last: false }` is refused for a
        // third reason: it is a page with more to read after it, so it prints no
        // digit, so no human can have pressed the digit it did not show.
        //
        // The `Frame` is 1,024 B on the stack of a function that already runs on
        // `boot`'s frame (548,268 B of runway, MEASURED), which is cheaper than
        // a second copy of the renderability rules.
        // The digit drawn here is thrown away with the frame, and that is not a
        // hole: `confirm` means "the human already read the screen and pressed
        // the digit it showed", so the key check belongs to whoever held THAT
        // frame — the caller, with the `ConfirmDigit` it drew and rendered. This
        // call is the renderability gate only. Drawn from `rng` rather than
        // hardcoded so no fixed digit exists anywhere for a script to find.
        match prompt_screen_at(
            &mut ui::Frame::new(),
            &prompt,
            ui::ConfirmDigit::draw(rng),
            page,
        ) {
            Ok(Shown::Page { last: true }) => {}
            Ok(_) => return Err(Fault::NotConfirmable),
            Err(refusal) => return Err(Fault::Refused(refusal)),
        }
        match prompt {
            DeviceToUserMessage::CheckKeyGen { phase, .. } => {
                let ack = self
                    .signer
                    .keygen_ack(*phase, &mut self.secrets, rng)
                    .map_err(Fault::Action)?;
                self.run(ack, out)
            }
            DeviceToUserMessage::SignatureRequest { phase } => {
                // The renderability gate is the `prompt_screen` call above, which
                // runs `sign_consent` itself — one funnel, not two.
                let sends = self
                    .signer
                    .sign_ack(*phase, &mut self.secrets)
                    .map_err(Fault::Action)?;
                self.run(sends, out)
            }
            // THE BACKUP GRANT. The human read `prompt_screen_at`'s consent screen —
            // which named the key and the share index and showed no word — and
            // pressed the digit it printed. This is what that press buys, and it is
            // *all* it buys: permission for [`Session::show_backup`] to draw.
            //
            // `out` is not touched, and that is deliberate rather than incidental.
            // The coordinator's `DisplayBackupProtocol` waits for
            // `CommsMisc::BackupRecorded` (`frostsnap_coordinator/src/display_backup.rs:87`),
            // which upstream sends when a human confirms they WROTE THE WORDS DOWN
            // (`esp32_run.rs:744-746`). Sending it here would claim a backup was
            // recorded before a single word had been drawn — the same
            // ack-ahead-of-the-fact this crate's persist-before-ack ordering exists
            // to prevent, in the one direction where the fact is a human's pen. The
            // ack is [`Session::backup_recorded`], gated on `record_pending`, which
            // [`Session::show_backup`] sets only once the pages have RUN OUT under a
            // live grant — so the earliest moment this device can claim a backup was
            // recorded is after every word has been on the glass and a human has
            // answered [`ui::backup_recorded`]'s digit. Not here.
            //
            // `Ok(Vec::new())`, not the prompt back again: `recv` returns prompts and
            // `confirm` answers them, and a prompt returned from here would be
            // re-parked and re-consented on the next loop.
            DeviceToUserMessage::Restoration(restoration) => match *restoration {
                ToUserRestoration::DisplayBackup { phase, .. } => {
                    // Refuse BEFORE granting anything, on the same principle
                    // `sign_consent` applies to a transaction: a backup this device
                    // could not draw IN FULL is one no human can transcribe, and a
                    // grant for it would be a grant to show 24 of 25 words. The
                    // derived words are dropped at the end of this statement — the
                    // grant keeps the phase, never the plaintext.
                    backup_pages(&phase, &mut self.secrets, |_| ())?;
                    // A NEW grant retires the previous one's unanswered question and
                    // its page set. This is the only place `self.reveal` is written,
                    // so it is the one place that can guarantee it: without the
                    // first line, a reveal shown whole and never answered would let
                    // an abort of the NEXT reveal ack the coordinator's current
                    // ceremony (`CommsMisc::BackupRecorded` names no share, so
                    // whatever dialog is open is the one that closes); without the
                    // second, the pages already seen would count towards it.
                    self.record_pending = false;
                    self.seen_pages = 0;
                    self.reveal = Some(phase);
                    Ok(Vec::new())
                }
                // THE ENTRY GRANT, and the mirror image of the reveal one: the human
                // read `prompt_screen_at`'s "type in a backup?" screen and pressed the
                // digit it printed. This is what that press buys, and all of it —
                // permission for [`Session::entry_key`] to accept a keystroke.
                //
                // `out` is not touched. `DeviceRestoration::PhysicalEntered` is the
                // wire answer and it belongs to the moment 25 words CHECKSUM, not to
                // the moment a human agrees to start typing: the coordinator's
                // `enter_physical_backup.rs` dialog closes on it, so sending it here
                // would claim a share had been entered before a letter was typed. The
                // same ack-ahead-of-the-fact this crate's persist-before-ack ordering
                // exists to prevent.
                //
                // A NEW grant discards a previous entry, unfinished words and all.
                // That is the honest direction rather than the destructive one: the
                // coordinator has issued a fresh `enter_physical_id`, so the words
                // typed towards the old one can no longer be acked against anything,
                // and `wordentry`'s "nothing is ever discarded" property is about the
                // 25 slots WITHIN one entry, not across two ceremonies.
                ToUserRestoration::EnterBackup { phase } => {
                    self.entry = Some(wordentry::Entry::new(phase.enter_physical_id));
                    Ok(Vec::new())
                }
                // CONSOLIDATION — the one restore step that writes flash, and the one
                // that can destroy a share. `finish_consolidation` encrypts the typed
                // share under this device's own derivation and stages the
                // `NewKey`/`NewAccessStructure`/`SaveShare` triple
                // (`device/restoration.rs:410-434`), which `run` persists at its top,
                // BEFORE the `FinishedConsolidation` ack reaches the outbox. Same
                // ordering as the keygen and for a stronger version of the same
                // reason: the store holds ONE record, so this write replaces whatever
                // share the device had, and a coordinator told the consolidation
                // finished when the write did not would believe in a share that is
                // gone. `consolidation_persists_the_share_before_it_acks` holds it.
                //
                // The polynomial checksum was already checked, by the signer, before
                // this prompt existed (`:137-158`) — a share that does not belong to
                // the coordinator's `root_shared_key` never reaches a human.
                //
                // `phase` carries a PLAINTEXT `SecretShare` (`CompleteSecretShare`,
                // `device.rs:629-635`). It is consumed here and never returned, and
                // the screen that asked prints the key name, the share index and the
                // threshold — no word and no scalar.
                ToUserRestoration::ConsolidateBackup(phase) => {
                    let sends = self
                        .signer
                        .finish_consolidation(&mut self.secrets, phase, rng);
                    self.run(sends, out)
                }
                // `BackupSaved` is informational — `prompt_screen_at` draws no screen
                // for it, so the funnel above has already refused it — and
                // `CheckBackup` is reached only through a message `recv` refuses.
                // Fail closed.
                _ => Err(Fault::NotConfirmable),
            },
            _ => Err(Fault::NotConfirmable),
        }
    }

    /// Draw page `page` of the backup a human has consented to reveal. `false` past
    /// the end of the set, which is also what ENDS the reveal.
    ///
    /// This is the only function in the tree that puts share material on a
    /// framebuffer, and every gate it has is a refusal:
    ///
    /// * **No grant, nothing drawn.** `self.reveal` is set only by
    ///   [`Session::confirm_at`], so a caller that never obtained consent gets
    ///   [`Refusal::DisplayBackup`] and a `frame` this call has not touched. That is
    ///   the requirement "consent precedes the reveal" as a type: there is no
    ///   argument to this function that could carry a share.
    /// * **`page` is an ARGUMENT.** Exactly as it is to `confirm_at`, and for the
    ///   same reason: the caller holds the cursor for the glass it owns, and a copy
    ///   kept here would be free to drift from the page a human is reading.
    /// * **One-way.** The grant is taken at entry and put back only while pages
    ///   remain, so `page` past the end (or any fault) ends the reveal and the next
    ///   call refuses. A coordinator wanting a second look must ask again and a
    ///   human must consent again. Running off the end — and *only* that, never a
    ///   fault — also arms [`Session::backup_recorded`]; see `record_pending`.
    /// * **Noised.** The words go through [`ui::BackupPages::render`], whose RNG is a
    ///   required parameter, so PLAN.md §4.2's side-channel defence
    ///   ([`ui::Frame::mark_sensitive`]) covers every word row. There is no
    ///   un-noised path here because that function offers none. The open edge is
    ///   that defence's own: the noise is fresh per render and a page turn is a
    ///   redraw, so N observations average it down by roughly `sqrt(N)`.
    ///
    /// Nothing reaches an outbox: this function has no `Outbox` parameter and cannot
    /// acquire one.
    ///
    /// # Errors
    ///
    /// [`Refusal::DisplayBackup`] for no grant, a share index that is not a `u32`,
    /// or a word `ui::BackupPages::new` refuses. [`Fault::Action`] if the stored
    /// share no longer decrypts under the coordinator's contribution. `frame` is
    /// untouched on every one of them — drawing [`ui::refusal`] is the caller's, the
    /// same split [`prompt_screen_at`] keeps.
    pub fn show_backup<R: rand_core::RngCore>(
        &mut self,
        page: usize,
        frame: &mut ui::Frame,
        rng: &mut R,
    ) -> Result<bool, Fault> {
        // TAKEN, not borrowed: every exit from here that is not "a page was drawn"
        // leaves the grant gone, so the fail-closed direction needs no `else` branch
        // anyone could forget.
        let Some(phase) = self.reveal.take() else {
            return Err(Fault::Refused(Refusal::DisplayBackup));
        };
        let (drawn, len) = backup_pages(&phase, &mut self.secrets, |pages| {
            (pages.render(page, frame, rng), pages.len())
        })?;
        if drawn {
            // One bit per page that has actually been on the glass. Not a cursor —
            // it decides nothing about what is drawn, and `page` stays an argument —
            // but it is the only thing this function can consult to know whether a
            // human has seen the whole share, and see below for why a caller's
            // paging discipline is not an acceptable substitute.
            self.seen_pages |= page_bit(page).unwrap_or(0);
            self.reveal = Some(phase);
        } else {
            // THE REVEAL ENDED. Not "a fault happened" and not "nobody consented":
            // both of those return `Err` above, so this leg means a grant existed
            // and the pages ran out under it.
            //
            // Ending is NOT enough to earn the right to ask a human whether they
            // wrote the words down. `main.rs` ends an ABORTED reveal through this
            // same call — any unadvertised key on a backup page asks for the page
            // past the last one, deliberately, so there is one ending and not two —
            // so "a page was drawn and then the set ended" is also what pressing `x`
            // on page 0 looks like from here. Arming on that would offer
            // "wrote it down?" to someone who has seen the share index and no word,
            // and one fumbled digit later the coordinator closes its dialog and the
            // app presents an unbacked-up wallet as backed up.
            //
            // So the gate is the WHOLE SET, checked as a bit set: every page of this
            // reveal has been composed into a frame. That is enforced here rather
            // than left to the caller's `+1`/`-1` paging because the caller is
            // `boot()`, which is `#[cfg(target_arch = "arm")]` and therefore
            // compiled by no gate in this tree and executed by none (PLAN.md §9 item
            // 22) — a property that lives only in that function is a property
            // nothing checks. A caller that jumps straight to the last page gets a
            // refusal, not an ack.
            //
            // `seen_pages` is deliberately NOT reset here. The reset that matters is
            // at the grant, which is the only way back into this function, so a reset
            // here would be a line no mutation can falsify — MEASURED: deleting it
            // left all 98 tests green. One clearing site, at the choke point.
            self.record_pending = all_pages(len).is_some_and(|all| self.seen_pages == all);
        }
        Ok(drawn)
    }

    /// Is the device waiting for a human to say they wrote the backup down?
    ///
    /// True from the moment a reveal runs off the end of its pages until
    /// [`Session::backup_recorded`] spends it. The caller draws
    /// [`ui::backup_recorded`] while this holds; nothing else reads it.
    pub fn record_pending(&self) -> bool {
        self.record_pending
    }

    /// A human answered YES to [`ui::backup_recorded`]: tell the coordinator the
    /// backup is on paper.
    ///
    /// This is the ack the coordinator's `DisplayBackupProtocol` blocks on
    /// (`frostsnap_coordinator/src/display_backup.rs:87`), and without it the app's
    /// dialog never closes however correct the reveal was. Upstream sends the same
    /// message at the same moment — when its display widget finishes, not when the
    /// reveal is granted (`device/src/frosty_ui.rs:330-336`,
    /// `esp32_run.rs:744-746`).
    ///
    /// **Call this only from a keypress on the digit that screen drew.** Two gates
    /// stand behind it and they are independent:
    ///
    /// * `record_pending` — a reveal must have ENDED. It is set past the grant
    ///   `take()` in [`Session::show_backup`], so a device that never revealed
    ///   anything cannot ack, and it is taken here, so one reveal cannot ack twice.
    ///   A coordinator has no way to raise it.
    /// * the keypress — the caller's, on the randomised digit
    ///   [`ui::backup_recorded`] printed. `ui::CONFIRM_CHARSET` is const-asserted
    ///   off both paging keys, so the key that walked a human onto that screen
    ///   cannot also answer it.
    ///
    /// **Nothing about the share goes out.** `CommsMisc::BackupRecorded` is a unit
    /// variant: no share index, no words, no phase, nothing derived from any of
    /// them. This function has no `Secrets`, no RNG and no `BackupDisplayPhase` in
    /// scope, so there is nothing here it *could* leak.
    ///
    /// # Errors
    ///
    /// [`Refusal::DisplayBackup`] when no reveal has ended — the fail-closed
    /// direction, and the reason this is not an infallible `fn`: a caller that has
    /// lost track of the flow gets a refusal on the glass rather than a false claim
    /// on the wire. [`Fault::Comms`] if the frame will not encode.
    pub fn backup_recorded(&mut self, out: &mut Outbox) -> Result<(), Fault> {
        if !core::mem::take(&mut self.record_pending) {
            return Err(Fault::Refused(Refusal::DisplayBackup));
        }
        out.push(DeviceSendBody::Misc(CommsMisc::BackupRecorded))?;
        Ok(())
    }

    /// What the backup-entry flow wants on the glass, or `None` when no entry is
    /// live.
    ///
    /// `None` is the whole gate seen from the drawing side: [`Session::confirm_at`]
    /// is the only writer of the grant, so a caller with no consent behind it has
    /// nothing to render and no cursor to advance. Borrowed from the
    /// [`wordentry::Entry`], so this is not a copy of anything typed.
    ///
    /// Draw it with `ui::EntryPages`/[`ui::WordEntry`], whose `rng` is mandatory —
    /// the word and prefix rows are `ui::Frame::mark_sensitive`'d, exactly as the
    /// reveal's are. [`wordentry::Step::Unchanged`] means **do not redraw**: an
    /// unchanged share row redrawn is a second noise sample over the same pixels,
    /// which is the one thing that averaging defence cannot afford.
    #[must_use]
    pub fn entry_screen(&self) -> Option<wordentry::Screen<'_>> {
        self.entry.as_ref().map(wordentry::Entry::screen)
    }

    /// One keypress into the backup a human consented to type in.
    ///
    /// The live keys are [`ui::ENTRY_LETTER_KEYS`], [`ui::ENTRY_PAGE_KEY`],
    /// [`ui::ENTRY_OK_KEY`] and [`ui::ENTRY_DELETE_KEY`]; every other byte is
    /// [`Typed::Unchanged`]. The decision is [`wordentry::Entry::key`]'s — pure, and
    /// pinned there over all 2,048 words — and this function is only the two impure
    /// halves it cannot own: the grant, and the wire.
    ///
    /// **The completed share does not come back.** [`wordentry::Step::Entered`] is
    /// consumed here: the `ShareBackup` goes straight into
    /// `tell_coordinator_about_backup_load_result`, which parks it in the signer's
    /// RAM-only `tmp_loaded_backups` and answers
    /// `DeviceRestoration::PhysicalEntered` — an `enter_physical_id` and a
    /// `share_image`, both public (`device/restoration.rs:337-360`). So there is no
    /// return value a caller could log, no `Outbox` push carrying a word, and no
    /// `Debug` anywhere on the path (`wordentry::Step` has a hand-written one that
    /// prints the variant name).
    ///
    /// **A failed checksum discards nothing.** All 25 words stay in the
    /// [`wordentry::Entry`] and the machine returns to word 25 on the next key, so a
    /// device that has accepted 24 correct words never throws them away — the
    /// half-built restore that would invite trust and then lose a share. Nothing is
    /// sent for a failure either; the coordinator's dialog stays open, which is what
    /// upstream's own `cancel()` ends.
    ///
    /// # Errors
    ///
    /// [`Refusal::PhysicalBackup`] when no entry is live — no consent, or entry has
    /// already ended. [`Fault::Comms`] if the reply will not frame, and
    /// [`Fault::Store`] from `run`'s persist, which on this path drains nothing (an
    /// entry stages no mutation) and so cannot fail on its own account.
    ///
    /// ponytail: ceiling named. Both of those fire AFTER the `take` above, so a fault
    /// on the completing keypress ends the entry rather than offering a retry — the
    /// 25 words are unreachable from the glass. It is not a lost share and not
    /// reachable in practice: `Fault::Store` here needs a keygen triple left staged by
    /// an EARLIER flash failure (a device whose flash is broken cannot finish the
    /// restore either way), `Fault::Comms` needs a `PhysicalEntered` — one id and one
    /// share image — to overrun `comms::FRAME_LIMIT`, and in both cases the typed
    /// share is already in the signer's `tmp_loaded_backups`, so `Consolidate` can
    /// still reach it and dropping the [`wordentry::Entry`] reduces no exposure. Left as is
    /// because preserving it would buy a retry that fails identically. The upgrade
    /// path is putting `entry` back on the `Err` leg, which is four lines and needs no
    /// new state.
    pub fn entry_key(&mut self, key: u8, out: &mut Outbox) -> Result<Typed, Fault> {
        // TAKEN, like the reveal grant: every exit that is not "still typing" leaves
        // the entry gone, so the fail-closed direction needs no `else` a later edit
        // could forget.
        let Some(mut entry) = self.entry.take() else {
            return Err(Fault::Refused(Refusal::PhysicalBackup));
        };
        match entry.key(key) {
            wordentry::Step::Unchanged => {
                self.entry = Some(entry);
                Ok(Typed::Unchanged)
            }
            wordentry::Step::Redraw => {
                self.entry = Some(entry);
                Ok(Typed::Redraw)
            }
            // The human backed out. SILENCE is the honest wire behaviour and not a
            // gap: `DeviceRestoration` has no message for an abandoned entry, and
            // upstream's coordinator ends the dialog on its own `cancel()`
            // (`frostsnap_coordinator/src/enter_physical_backup.rs`). PUNTED
            // UPSTREAM, not worked around.
            wordentry::Step::Abort => Ok(Typed::Ended(Vec::new())),
            wordentry::Step::Entered(backup) => {
                let sends = self.signer.tell_coordinator_about_backup_load_result(
                    EnterBackupPhase {
                        enter_physical_id: entry.enter_physical_id(),
                    },
                    backup,
                );
                // The entry is already dropped by the `take` above, so the words are
                // gone before the frame is built. `run` is the funnel every other
                // reply goes through, so the caps and the persist ordering apply here
                // too.
                self.run(sends, out).map(Typed::Ended)
            }
        }
    }

    /// Persist a previewed name, then tell the coordinator about it.
    ///
    /// PERSIST BEFORE THE ACK, the same ordering as the share and for a related
    /// reason: `SetName` is what makes the app record this device in
    /// `device_names` and show it as registered, so a name acked but not stored is
    /// a device the app labels and this device cannot answer to after an unplug.
    ///
    /// Nothing to commit is `Ok(())`, which is the common case — the shipped
    /// Flutter app only renders its name field on the `upToDate` branch of
    /// `firmwareUpgradeEligibility` (`wallet_create.dart:662-704`), and cold-snap's
    /// digest can never be `UpToDate` (`frostsnap_coordinator/src/firmware.rs:35-69`
    /// needs byte equality with the app's bundled digest or a `VersionNumber` table
    /// hit). So the real app will not offer to name this device however correct the
    /// device side is; `hostcheck` is what exercises the path. Do not describe this
    /// as "naming works in the Frostsnap app". It does not.
    fn commit_name(&mut self, out: &mut Outbox) -> Result<(), Fault> {
        let Some(name) = self.pending_name.take() else {
            return Ok(());
        };
        self.names.save(name.as_str()).map_err(Fault::Store)?;
        out.push(DeviceSendBody::SetName { name })?;
        Ok(())
    }

    /// Run the signer's work queue to quiescence: coordinator-bound messages go
    /// to the outbox, nonce work is done here, prompts come back to the caller.
    ///
    /// **The share is persisted here, at the top, before the loop that fills the
    /// outbox** — and the ordering is a correctness property rather than a style
    /// choice. On the keygen ack the coordinator applies its own
    /// `NewShare { access_structure_ref, device_id, share_index }`
    /// (`coordinator/keys.rs:74-78`) and then presents the wallet as complete, so
    /// a power cut between the ack and the write leaves it believing `n` shares
    /// exist when `n-1` do: every later signing session that needs this device to
    /// reach `t` fails, and with `DisplayBackup` and every physical-backup path
    /// refused on this port the share cannot be reconstructed. The threshold is
    /// silently short and the coins are unspendable. Upstream orders it the same
    /// way (`esp32_run.rs:588-600` writes, then `:618-624` sends).
    ///
    /// On failure this returns before the loop, so the ack never reaches the
    /// outbox and the coordinator hears nothing at all — the fail-closed
    /// direction, and the reason the persist is here and not at `main.rs`'s outbox
    /// drain, which lives inside a `cfg(target_arch = "arm")` `boot()` that no
    /// test, clippy run or rustdoc pass ever compiles (PLAN.md §9 item 22).
    ///
    /// This is the single funnel it needs to be: `recv_core` ends here, both arms
    /// of `confirm_at` end here, `keygen_ack` stages the triple before returning
    /// the sends it is called with, and nothing inside the loop calls a mutating
    /// signer method.
    fn run<I: IntoIterator<Item = DeviceSend>>(
        &mut self,
        sends: I,
        out: &mut Outbox,
    ) -> Result<Vec<DeviceToUserMessage>, Fault> {
        self.shares
            .persist_staged(self.signer.staged_mutations())
            .map_err(Fault::Store)?;
        let mut work: VecDeque<DeviceSend> = sends.into_iter().collect();
        let mut prompts = Vec::new();
        while let Some(send) = work.pop_front() {
            match send {
                DeviceSend::ToCoordinator(msg) => out.push(DeviceSendBody::Core(*msg))?,
                DeviceSend::ToUser(msg) => match *msg {
                    // Not a prompt: work. A human has nothing to say about
                    // generating nonces. Real firmware should spread this over
                    // idle time so the UI keeps running; doing it inline is the
                    // lazy version and the ceiling is responsiveness, not
                    // correctness.
                    DeviceToUserMessage::NonceJobs(mut batch) => {
                        batch.run_until_finished(&mut self.secrets);
                        out.push(DeviceSendBody::Core(DeviceToCoordinatorMessage::Signing(
                            DeviceSigning::NonceResponse {
                                segments: batch.into_segments(),
                            },
                        )))?;
                    }
                    // THE ONE PLACE A NAME IS COMMITTED, and it is upstream's site
                    // exactly (`esp32_run.rs:625-632`, minus the `assert!` there,
                    // which on this unit would be a brick). Reachable only through
                    // a human's keygen consent: `keygen_finalize` needs a
                    // `tmp_keygen_pending_finalize` entry
                    // (`device/keygen.rs:273-282`) and `keygen_ack` is the only
                    // thing that inserts one (`:333`). So no coordinator message
                    // commits a name on its own — the property a per-keystroke
                    // `Preview` gate could never give.
                    //
                    // And it lands AFTER the share: the triple is staged by this
                    // very message (`keygen_finalize` -> `save_complete_share` ->
                    // `mutate`, `device.rs:526-542`) and persisted at the top of
                    // this call.
                    DeviceToUserMessage::FinalizeKeyGen { key_name } => {
                        self.commit_name(out)?;
                        prompts.push(DeviceToUserMessage::FinalizeKeyGen { key_name });
                    }
                    other => prompts.push(other),
                },
            }
        }
        Ok(prompts)
    }
}

/// What the human must be shown for one sign request — or a [`Refusal`].
///
/// This is the missing glue PLAN.md §8.1 defect 12 is about: `user_prompt()`
/// returns `Option` precisely so that a caller can reject, and until now it had
/// **no caller in this tree**, so "None means reject" was written down and
/// implemented nowhere. `ui::SignPages::new`'s three refusals (too many
/// recipients, non-ASCII address, over-long address) were in the same position:
/// tested in `hal`, reachable from no device path.
///
/// - `Ok(Some(t))` — every foreign recipient and the fee are renderable, and
///   `show` was handed the validated page set (with **all** of them: nothing is
///   dropped to make a transaction fit).
/// - `Ok(None)` — a `Test` task: no recipient list to bound, and its own screen
///   ([`ui::sign_test_message`]) is the display contract. What this function must
///   never do is *invent* consent for it.
/// - `Err(Refusal::Undisplayable)` — refuse the request whole.
///
/// The closure exists because `ui::Recipient` borrows its address `&str` and the
/// address strings have to be allocated here; returning the pages would return a
/// borrow of a local. `show` is where a phase-5 renderer goes.
///
/// Pure: no framebuffer, no `cfg`, host-testable, and the same code on ARM.
pub fn sign_consent<T>(
    task: &CheckedSignTask,
    show: impl FnOnce(&ui::SignPages<'_>) -> T,
) -> Result<Option<T>, Refusal> {
    let (tx, network) = match &task.inner {
        SignTask::BitcoinTransaction {
            tx_template,
            network,
        } => (tx_template, *network),
        SignTask::Test { .. } => return Ok(None),
        // NOTHING in this tree renders a Nostr event — there is no screen, no
        // recipient list and no page builder — so the only honest answer is to
        // refuse the request. It used to share `Test`'s `Ok(None)`, which meant
        // `Session::confirm` would have signed an event whose screen said
        // CANNOT DISPLAY: a blind signer. Give it a page builder and this arm
        // becomes a `SignPages`-shaped one; until then it is a refusal.
        //
        // NOT host-testable in this tree: `nostr::UnsignedEvent`'s fields are
        // private and its only constructor is behind the `serde_json` feature,
        // so no test can build a Nostr task. Fail-closed, so the untested
        // direction is the safe one.
        SignTask::Nostr { .. } => return Err(Refusal::Undisplayable),
    };
    // `None` here is an output with no address form in this network (OP_RETURN, a
    // bare `ScriptBuf::new()`) or a fee that does not compute — and upstream's own
    // `check` deliberately ACCEPTS such a template (`sign_task.rs:343-350`), so
    // this is the only place it is caught.
    let prompt = tx.user_prompt(network).ok_or(Refusal::Undisplayable)?;
    let addresses: Vec<String> = prompt
        .foreign_recipients
        .iter()
        .map(|(address, _)| address.to_string())
        .collect();
    let recipients: Vec<ui::Recipient<'_>> = prompt
        .foreign_recipients
        .iter()
        .zip(&addresses)
        .map(|((_, amount), address)| ui::Recipient {
            address,
            sats: amount.to_sat(),
        })
        .collect();
    let pages =
        ui::SignPages::new(&recipients, prompt.fee.to_sat()).map_err(|_| Refusal::Undisplayable)?;
    Ok(Some(show(&pages)))
}

/// Bit `page` of [`Session::seen_pages`], or `None` for a page index no `u32` bit
/// set can hold.
///
/// A function and not `1 << page` inline, for the reason two mutations that survived
/// all six gates were closed by making one: this is the arithmetic that decides
/// whether a human is told their backup is safe. `overflow-checks = false` in
/// release, so `1u32 << 32` there is `1` — page 32 aliasing page 0 — and
/// `checked_shl` is what makes it `None` instead. `None` is fail-closed at both call
/// sites: an un-recordable bit is never set, and an un-representable set is never
/// complete.
fn page_bit(page: usize) -> Option<u32> {
    1u32.checked_shl(u32::try_from(page).ok()?)
}

/// Every page of a `len`-page set, as a full bit set — the value
/// [`Session::seen_pages`] must equal for a reveal to have been shown WHOLE.
///
/// `None` for a set of no pages (nothing to see is not "everything seen") and for one
/// of more than 31, so a future [`ui::WORDS_PER_PAGE`] that pushed the count past what
/// the bits hold would refuse the ack rather than accept a truncated set. 31 rather
/// than 32 because the mask is built from the bit ONE PAST the last page; the shipped
/// geometry needs 8.
fn all_pages(len: usize) -> Option<u32> {
    match page_bit(len)? {
        // `len == 0`. `checked_shl` never yields 0, so `bits - 1` below cannot wrap.
        1 => None,
        bits => Some(bits - 1),
    }
}

/// Derive the 25 BIP39 words for one consented backup and hand the validated page
/// set to `show` — the **only** place in this crate where a plaintext share exists.
///
/// [`sign_consent`]'s shape, for [`sign_consent`]'s reason: `ui::BackupPages`
/// borrows its `&[&str]` and the words are a local, so returning the pages would
/// return a borrow of a local. `show` is the closure that draws (or, at the consent
/// step, that draws nothing and only asks whether it *could* have).
///
/// The crypto is entirely `frost_backup`'s and none of it is re-implemented here:
/// [`BackupDisplayPhase::decrypt_to_backup`] derives the share encryption key
/// through our [`Secrets`], decrypts, and builds a `ShareBackup` whose `to_words()`
/// is upstream's own 11-bits-per-word packing plus its two checksums
/// (`frost_backup/src/share_backup.rs`). Note the crate is named nowhere: it is
/// already a non-optional dependency of `frostsnap_core`, so these are inherent
/// methods on a type this crate need not — and does not — import.
///
/// # LEAK AUDIT of this function, which is where a leak would live
///
/// The `ShareBackup` and the `[&str; 25]` are locals of this call. They are moved
/// into no field, formatted by nothing (`ShareBackup` derives `Debug` and it is
/// never invoked; `ui::BackupPages` does too and likewise), pushed to no `Outbox`
/// — there is no `Outbox` in scope — and dropped when `show` returns. `show`'s only
/// two callers are [`Session::confirm_at`], which passes `|_| ()`, and
/// [`Session::show_backup`], which draws pixels and returns `(bool, usize)` — a
/// "was it drawn" and a page COUNT, neither of which is derived from a word.
///
/// # Errors
///
/// [`Refusal::DisplayBackup`] if the share index will not fit a `u32` (the
/// share-index page is what makes a transcribed backup restorable, so a backup
/// whose index cannot be printed is refused whole, not shown short) or if any word
/// is one `ui::BackupPages::new` will not render — the cross-crate gate
/// `every_vendored_bip39_word_is_renderable` says none is, and this is what happens
/// if that ever stops being true. [`Fault::Action`] if the stored ciphertext does
/// not decrypt under the coordinator's contribution.
fn backup_pages<T>(
    phase: &BackupDisplayPhase,
    secrets: &mut Secrets,
    show: impl FnOnce(&ui::BackupPages<'_>) -> T,
) -> Result<T, Fault> {
    let backup = phase.decrypt_to_backup(secrets).map_err(Fault::Action)?;
    // `try_from`, never the `expect` upstream's own `Display` impl uses
    // (`share_backup.rs`, "Share index should fit in u32"): the index arrives off the
    // wire, and a reachable panic on this unit is permanent.
    let index =
        u32::try_from(phase.share_index).map_err(|_| Fault::Refused(Refusal::DisplayBackup))?;
    let words = backup.to_words();
    let pages =
        ui::BackupPages::new(index, &words).map_err(|_| Fault::Refused(Refusal::DisplayBackup))?;
    Ok(show(&pages))
}

/// The backup-reveal consent screen: what is being asked for, and the digit that
/// grants it.
///
/// **It cannot show a word, and that is structural rather than careful.** This
/// function takes no phase, no `Secrets` and no share; the only secret-adjacent
/// thing on it is the share *index*, which is `1..=n` and is printed on the
/// coordinator's own screen. So "consent precedes the reveal" is not an ordering
/// this function has to get right — there is nothing here to reveal.
///
/// `share_index` is shown because it is what a human matches against the request
/// they made: a coordinator that asks for share 2 while the app says share 1 is
/// visible here and nowhere else.
///
/// The legend is `sign_test_message_confirm`'s, word for word ("Press (N) x=no"), so
/// the highest-consequence screen on the device asks for consent in the form the
/// rest of it already uses — and `x` is spelled out because a refusal must be as
/// easy to reach as an approval.
///
/// ponytail: ceiling named. This is a NINTH §4.2 screen and its layout belongs in
/// `hal/src/ui.rs` beside the other eight, where `tools/pixel-check.py` and the
/// simulator would cover it. It is composed here from `ui::Frame` primitives
/// because that file is owned by another change; the upgrade path is
/// `ui::backup_reveal_confirm(frame, key_name, share_index, confirm)` and deleting
/// this function, with no caller change beyond the name.
fn backup_consent(
    frame: &mut ui::Frame,
    key_name: &str,
    share_index: u32,
    confirm: ui::ConfirmDigit,
) {
    let mut what = ui::Buf::<16>::new();
    what.push_str("share #").push_u64(share_index as u64);
    consent_screen(
        frame,
        ["Reveal backup?", key_name, what.as_str(), "SECRET on glass"],
        confirm,
    );
}

/// The consent screen for typing a share back IN.
///
/// There is nothing here for a human to *match*: the `EnterBackupPhase` carries a
/// 16-byte `EnterPhysicalId` and no key name, no share index and no threshold — the
/// coordinator does not know which share is about to be typed either, since finding
/// out is the point of the exercise. So the question this screen asks is the only one
/// it can ask honestly: are you about to type a secret into this device?
///
/// That makes the digit the whole gate, and it is why this screen exists at all
/// rather than the entry starting on the coordinator's word. A restore INGESTS a
/// secret and puts it on the glass letter by letter; a coordinator message must not
/// be able to reach that screen on its own.
fn entry_consent(frame: &mut ui::Frame, confirm: ui::ConfirmDigit) {
    let mut words = ui::Buf::<16>::new();
    words.push_u64(ui::BACKUP_WORDS as u64).push_str(" words");
    consent_screen(
        frame,
        [
            "Type a backup?",
            words.as_str(),
            "onto THIS device",
            "SECRET on glass",
        ],
        confirm,
    );
}

/// The consent screen for STORING a typed share — the destructive one.
///
/// Everything on it is public: the coordinator-supplied key name, the share index
/// and the threshold, all of which are on the app's own screen. The
/// `ConsolidatePhase` behind it holds a plaintext `SecretShare` and this function is
/// not handed it.
///
/// The "replaces stored" line is the part that is not decoration. `store` keeps ONE
/// record, so consolidating overwrites whatever share this device already held, and a
/// coordinator that wanted to destroy a share would send exactly this message. There
/// is no undo and no second copy.
fn consolidate_consent(
    frame: &mut ui::Frame,
    key_name: &str,
    share_index: u32,
    threshold: u16,
    confirm: ui::ConfirmDigit,
) {
    let mut what = ui::Buf::<16>::new();
    what.push_str("#")
        .push_u64(share_index as u64)
        .push_str(" of ")
        .push_u64(threshold as u64)
        .push_str("-of-n");
    consent_screen(
        frame,
        ["Store share?", key_name, what.as_str(), "REPLACES stored"],
        confirm,
    );
}

/// The shape all three restoration consent screens share: four lines and the digit
/// that grants.
///
/// One function and not three copies, because the property that matters is common to
/// all of them — the legend prints the key, so a screen that forgot it would be
/// asking for a gesture it never showed, and the mutation that deletes it fails every
/// one of their tests at once. The legend text is
/// `ui::sign_test_message_confirm`'s word for word ("Press (N) x=no"), so the
/// highest-consequence screens on the device ask in the form the rest of it uses, and
/// `x` is spelled out because a refusal must be as easy to reach as an approval.
///
/// `lines` land on rows 0, 2, 4 and 6 of 8. Every one of them may be
/// attacker-controlled — a key name came off a coordinator's `Begin` — and
/// `ui::Frame::text` is documented safe for arbitrary text of arbitrary length:
/// walked with `chars()`, truncated at `ui::COLS`, never sliced.
fn consent_screen(frame: &mut ui::Frame, lines: [&str; 4], confirm: ui::ConfirmDigit) {
    frame.clear();
    for (row, line) in lines.iter().enumerate() {
        frame.text(0, row * 2, line);
    }
    let mut legend = ui::Buf::<16>::new();
    legend
        .push_str("Press (")
        .push_str(confirm.as_str())
        .push_str(") x=no");
    frame.text(0, 7, legend.as_str());
}

/// One page of a bitcoin transaction's consent screen, drawn.
///
/// Split out of [`prompt_screen_at`]'s arm so that the paging is REACHABLE FROM A
/// TEST. `SignPhase1`'s fields are private (`device.rs:143-148`), so nothing in
/// this crate can build the `SignatureRequest` prompt that carries the task, and
/// the page arithmetic guarding a signature would otherwise be code no gate ever
/// executes — the same blind spot PLAN.md §9 item 22 records for the 152 `cfg-arm`
/// blocks, arriving by a different route. What is left unreached in
/// `prompt_screen_at` is now one getter call.
///
/// `last` comes from [`ui::SignPages::is_last`] on the very set that was just
/// rendered, so the render that drew the glass and the check that admits a keypress
/// ask one function rather than each recomputing `page == len() - 1`.
fn sign_page(
    task: &CheckedSignTask,
    confirm: ui::ConfirmDigit,
    page: usize,
    frame: &mut ui::Frame,
) -> Result<Shown, Refusal> {
    match sign_consent(task, |pages| {
        let pages = pages.confirming(confirm);
        (pages.render(page, frame), pages.is_last(page))
    }) {
        Ok(Some((true, last))) => Ok(Shown::Page { last }),
        // `render` says the page could not be drawn in full (a page past the end of
        // the set, or an address that will not print), or `sign_consent` says this
        // is not a task with a page set at all (`Test` is handled by the caller and
        // `Nostr` already refuses, so this is the arm a new `SignTask` variant lands
        // in — fail closed).
        Ok(_) => Err(Refusal::Undisplayable),
        Err(refusal) => Err(refusal),
    }
}

/// Draw the screen for one prompt, or say that this device cannot draw it.
///
/// The **only** prompt-to-screen map in the tree, and deliberately here rather
/// than in `main.rs`: `boot()` is `#[cfg(target_arch = "arm")]`, so a map living
/// there is unreachable from every host test and from the pty harness, and
/// [`Session::confirm`] could not share it. Sharing it is the whole point —
/// `confirm` gates on this function, so a request whose screen refused can never
/// produce a signature share, and a screen ARM draws is a screen the harness has
/// already executed.
///
/// - `Ok(Shown::Page { last })` — `frame` holds page `page` of the request, drawn
///   in full. `last` is [`ui::SignPages::is_last`]: the page that prints the
///   confirm digit, and the only page a signature may be authorised on.
/// - `Ok(Shown::Nothing)` — informational prompt with no screen; `frame` is
///   untouched.
/// - `Err(refusal)` — this device cannot show the request, so it must not be
///   signed. `frame` holds [`ui::refusal`] on the way out, never a partial layout.
///
/// `page` past the end of the set is `Err(Refusal::Undisplayable)`, not a wrap and
/// not a clamp: [`ui::SignPages::render`] leaves the frame untouched and returns
/// `false` there, so an over-advanced cursor draws a refusal and consents to
/// nothing.
///
/// Every screen reached from here is reached *honestly*: `keygen_check` renders a
/// real `KeyGenPhase3`'s own session hash and t-of-n, `sign_test_message` a real
/// `SignTask::Test`, `SignPages` a real `BitcoinTransaction` — the one sign task
/// `Session::recv` admits and this device could otherwise sign blind — and the
/// backup-reveal question a real `BackupDisplayPhase`'s key name and share index.
/// The backup-ENTRY question and the consolidation question join them here, and are
/// honest in the same way: the entry screen carries nothing (an `EnterBackupPhase` is
/// a 16-byte id) and the consolidation screen carries a real `ConsolidatePhase`'s key
/// name, share index and threshold — never its plaintext `SecretShare`. The two §4.2
/// screens still without a caller are the QUIZ and address verify, because
/// `CheckBackup` and `ScreenVerify` are refused in [`Session::recv`]; adding a screen
/// for either would be a lie about what the device does.
///
/// The backup *words* are not drawn from here and cannot be: this function has no
/// [`Secrets`] to decrypt with and no RNG to noise with. [`Session::show_backup`] is
/// the reveal, and the grant it needs comes only from [`Session::confirm_at`] — so
/// the screen that asks and the screen that shows are separated by a consent step
/// that no caller can route around.
///
/// `confirm` is the randomised digit the two **signing** screens print, drawn by
/// the caller from its own RNG (on ARM `rng::Entropy`, never libngu — PLAN.md
/// §1). One value flows from here into the legend, and the caller holds the same
/// value to answer the keypress with
/// [`ui::ConfirmDigit::accepts`](coldsnap_hal::ui::ConfirmDigit::accepts): the
/// screen that DISPLAYS the digit and the logic that ACCEPTS it are the same
/// `ConfirmDigit`, so they cannot disagree. `keygen_check` deliberately keeps its
/// plain `1=match` — the stronger gesture belongs on the screens that authorise
/// a signature, which was the pre-existing split and the only part of it that
/// was wrong was that it asked for a *hold* the numpad cannot produce.
pub fn prompt_screen_at(
    frame: &mut ui::Frame,
    prompt: &DeviceToUserMessage,
    confirm: ui::ConfirmDigit,
    page: usize,
) -> Result<Shown, Refusal> {
    let shown = match prompt {
        DeviceToUserMessage::CheckKeyGen { phase } => {
            let (threshold, parties) = phase.t_of_n();
            // The first 4 bytes of the 32-byte VRF session hash, exactly as
            // upstream (`device/src/widget_tree.rs:102-105`). Indexed by hand
            // rather than sliced so there is no bounds check to panic.
            let h = phase.session_hash().0;
            ui::keygen_check(
                frame,
                threshold,
                parties,
                [h[0], h[1], h[2], h[3]],
                phase.key_name(),
            );
            // One page, and the whole request is on it: `last` is what says "this
            // screen may authorise", and for a single-page screen that is page 0.
            Ok(Shown::Page { last: true })
        }
        DeviceToUserMessage::SignatureRequest { phase } => match &phase.sign_task().inner {
            // An unrenderable message is a REFUSAL and not a truncated layout:
            // showing 64 characters of 4,000 while signing all 4,000 is a blind
            // signer. Until this was wired into `confirm`, such a request was
            // drawn as a refusal and then signed anyway.
            SignTask::Test { message } => ui::sign_test_message_confirm(frame, message, confirm)
                .map(|()| Shown::Page { last: true })
                .map_err(|_| Refusal::Undisplayable),
            // Page `page` of the validated set. `sign_consent` — the same call
            // `confirm_at` makes — either accepts the whole transaction or refuses
            // it, so there is no page here that omits a recipient.
            //
            // `last` comes out of the SAME render that drew the glass, from
            // `SignPages::is_last`, and that is the point of returning it rather
            // than letting the caller recompute `page == len() - 1`: the render and
            // the consent check ask one function, so they cannot disagree about
            // which page prints the digit. `ui::SignPages::render` draws the digit
            // only on that page (`hal/src/ui.rs`'s footer), so a page with more to
            // read after it advertises the advance key and no yes key at all.
            _ => sign_page(phase.sign_task(), confirm, page, frame),
        },
        // The backup-reveal consent screen. ONE page, and it is page 0: the reveal
        // itself is not a page of this set and cannot be, because drawing a word
        // needs [`Secrets`] and a `rand_core::RngCore` and this function has
        // neither. [`Session::show_backup`] is the reveal, and it is unreachable
        // without the grant only [`Session::confirm_at`] can set.
        //
        // `page != 0` is a REFUSAL, not a clamp and not a wrap. Nothing on the device
        // can produce it — `main.rs`'s `answer` clamps `NEXT_KEY` to `Answer::Wait`
        // on a `last` page, so the cursor never advances off this screen — but a
        // caller that hands `confirm_at` a page it invented must not be able to keep
        // guessing until something says `last: true`.
        DeviceToUserMessage::Restoration(restoration) => match &**restoration {
            ToUserRestoration::DisplayBackup {
                key_name, phase, ..
            } => match u32::try_from(phase.share_index) {
                Ok(index) if page == 0 => {
                    backup_consent(frame, key_name, index, confirm);
                    // The whole question is on this page, so this page may authorise
                    // — and the thing it authorises is a reveal, not a signature.
                    Ok(Shown::Page { last: true })
                }
                // A share index outside `u32` cannot be printed, so the human could
                // not tell which share they were being asked for. Same refusal
                // `backup_pages` raises, at the earlier of the two points.
                _ => Err(Refusal::DisplayBackup),
            },
            // The question that gates an INGEST. One page, page 0, and `page != 0` is
            // a refusal for `DisplayBackup`'s reason: a caller that invents a page
            // must not be able to keep guessing until something says `last: true`.
            ToUserRestoration::EnterBackup { .. } if page == 0 => {
                entry_consent(frame, confirm);
                Ok(Shown::Page { last: true })
            }
            // The question that gates a flash write which REPLACES a share.
            ToUserRestoration::ConsolidateBackup(phase) if page == 0 => {
                match u32::try_from(phase.complete_share.secret_share.index) {
                    Ok(index) => {
                        consolidate_consent(
                            frame,
                            &phase.complete_share.key_name,
                            index,
                            phase.complete_share.threshold,
                            confirm,
                        );
                        Ok(Shown::Page { last: true })
                    }
                    // A share index outside `u32` cannot be printed, so the human
                    // cannot tell what they are being asked to store over. `try_from`
                    // and never the `expect` upstream's own `Display` uses
                    // (`share_backup.rs`, "Share index should fit in u32"): the index
                    // came off the wire and a reachable panic here is permanent.
                    Err(_) => Err(Refusal::PhysicalBackup),
                }
            }
            // `BackupSaved` is informational, `CheckBackup` is reached only through a
            // message `Session::recv` refuses, and the two arms above fall here for
            // any page but 0. `Shown::Nothing` is what makes `confirm_at` answer
            // `NotConfirmable`, which is the fail-closed direction for all three.
            _ => Ok(Shown::Nothing),
        },
        // `FinalizeKeyGen` is informational and `VerifyAddress` is reached only
        // through a message `Session::recv` refuses.
        _ => Ok(Shown::Nothing),
    };
    if shown.is_err() {
        ui::refusal(frame);
    }
    shown
}

/// What one [`prompt_screen_at`] call put on the glass.
///
/// `last` travels back out with the render because the caller has two questions to
/// answer — "may I park this?" and "may this keypress authorise?" — and both are
/// about the page that is on the glass *now*. See [`Session::confirm_at`] for why
/// the page is an argument and not state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shown {
    /// No screen for this prompt: informational. The frame is untouched, and
    /// nothing about this prompt is answerable.
    Nothing,
    /// A page was drawn in full. `last` means it is the final page of the set —
    /// the one that prints the confirm digit, and the only one on which a
    /// signature may be authorised.
    Page {
        /// Nothing left to read: this page prints the digit.
        last: bool,
    },
}

/// What one [`Session::entry_key`] press did — the typing-side counterpart of
/// [`Shown`].
///
/// Three states and not two, for the same reason [`wordentry::Step`] has them: an
/// invalid key must be distinguishable from a valid one, because a *redraw* of an
/// unchanged share row re-samples [`ui::Frame::mark_sensitive`]'s noise over pixels
/// that did not change, and that is the one thing an averaging defence cannot
/// afford.
///
/// No `Debug` and no share: the completed `ShareBackup` is consumed inside
/// `entry_key` and never reaches this value.
#[must_use]
pub enum Typed {
    /// The key did nothing. **Do not redraw.**
    Unchanged,
    /// The state changed: draw [`Session::entry_screen`].
    Redraw,
    /// Entry is over — either the human backed out of the share index, or 25 words
    /// passed their checksum and the coordinator has been told. Either way
    /// [`Session::entry_screen`] is now `None` and the caller returns to standby.
    ///
    /// The `Vec` is whatever prompts the completion produced, which today is empty:
    /// `tell_coordinator_about_backup_load_result` returns one coordinator-bound send
    /// and nothing else (`device/restoration.rs:337-360`). Carried rather than
    /// dropped so a vendored bump that adds a prompt cannot lose it silently — the
    /// caller parks it exactly as it parks [`Session::recv`]'s.
    Ended(Vec<DeviceToUserMessage>),
}

/// [`prompt_screen_at`] at page 0, reporting only whether the drawn screen is one a
/// human may answer.
///
/// The transitional funnel for callers with no page cursor — `main.rs`'s
/// `draw_prompt`, `examples/stub.rs`, the harness. Its `Ok(true)` means exactly
/// what it did before: "a consent screen showing the request in full is on the
/// glass, and it printed a key". So a multi-page bitcoin transaction is
/// `Ok(false)` here rather than `Ok(true)` on page 1 of 67, and that closes a live
/// hole: a caller that parks page 0 and then accepts the digit accepts a screen
/// reading "Send amount #1 of 2" with no fee and no confirm page — a blind signer,
/// at a one-in-five guess, which PLAN.md §4.2 forbids outright.
///
/// Walking the pages is [`prompt_screen_at`] plus a keypad
/// (`ui::NEXT_KEY`/`ui::BACK_KEY`); it belongs to whoever owns the event loop.
pub fn prompt_screen(
    frame: &mut ui::Frame,
    prompt: &DeviceToUserMessage,
    confirm: ui::ConfirmDigit,
) -> Result<bool, Refusal> {
    prompt_screen_at(frame, prompt, confirm, 0).map(|shown| shown == Shown::Page { last: true })
}

/// SHA-256 over the range the Mk4 bootloader signs, which is the only digest
/// this device can compute honestly.
///
/// `image` must be the flash starting at [`memmap::FLASH_ISR_BASE`]. The two
/// hashed chunks skip the header's trailing 64-byte signature exactly as
/// `mk4-bootloader/verify.c:265-273` does, and `firmware_length` is read from
/// the header at offset 24 (`sigheader.h:25-31`) and bounds-checked before use.
///
/// **Single** SHA-256, not the bootloader's double, because the digest's only
/// consumers are coordinator-side and single is their convention
/// (`frostsnap_coordinator/src/firmware.rs:206-212`).
///
/// What it does **not** attest: nothing verifies it. The coordinator uses it for
/// display and upgrade eligibility only. It identifies the image *as flashed*
/// (the header's post-link timestamp and version string are inside the range),
/// not the source tree, and it is not a signature — the bootloader's signature
/// check is what makes running code trustworthy, and it has already happened by
/// the time this runs.
pub fn firmware_digest(image: &[u8]) -> Option<Sha256Digest> {
    let header_end = (memmap::FW_HEADER_OFFSET + memmap::FW_HEADER_SIZE) as usize;
    let header = image.get(memmap::FW_HEADER_OFFSET as usize..header_end)?;
    let length = u32::from_le_bytes(header.get(24..28)?.try_into().ok()?);

    // Every one of these is a bound on a field read out of flash, before it is
    // used as a length. They are OURS, not a mirror of the bootloader's: of the
    // three, only the floor is shared.
    //
    // * Floor. `verify.c:215` also refuses `firmware_length < 256 K`. Note the
    //   constant is named for the *body* but this field is the whole image from
    //   `FLASH_ISR_BASE` (`signit.py:315`), so here the check is merely looser than
    //   its name, never tighter. The real body floor is signit's alone
    //   (`signit.py:293`), and signit binds 16 K sooner than the device.
    // * Alignment. The bootloader enforces NONE (`verify.c:212-217` has no
    //   alignment test). This is ours, and it is 8x too loose for this part:
    //   `signit.py:302-306` re-aligns the Mk4 body to 4096 and `verify.c:106` says
    //   the length must match the 4 K flash erase unit, so every real artifact is
    //   4096-aligned. `memmap::FW_BODY_ALIGN` records the mk1-3 512 and is `hal`'s
    //   to correct, not this crate's — duplicating 4096 here would give a memmap
    //   number a second home, which is the drift `link.x`'s ASSERTs exist to catch.
    //   `firmware_digest_alignment_bound_is_looser_than_mk4_requires` is the live
    //   tripwire on that gap and fails the moment the constant is fixed.
    // * Upper bound. The bootloader's is the constant `FW_MAX_LENGTH_MK4`
    //   (2,031,616); ours is the slice we were handed, which is what keeps the two
    //   `image.get(..)` calls below from ever needing to fail.
    if length < memmap::FW_MIN_BODY_LEN
        || length % memmap::FW_BODY_ALIGN != 0
        || length as usize > image.len()
    {
        return None;
    }

    let mut h = Sha256::new();
    h.update(image.get(..header_end - 64)?);
    h.update(image.get(header_end..length as usize)?);
    Some(Sha256Digest(h.finalize().into()))
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use coldsnap_hal::flash::fake::FakeFlash;
    use coldsnap_hal::identity;
    use coldsnap_hal::rng::{mix_sources, Entropy, ProvenSeed, SE1_BYTES, SE2_BYTES, TRNG_BYTES};
    use frostsnap_core::message::signing::OpenNonceStreams;
    use frostsnap_core::message::HeldShare2;
    use frostsnap_core::nonce_stream::{CoordNonceStreamState, NonceStreamId};
    use frostsnap_core::schnorr_fun::frost::{ShareImage, ShareIndex};
    use std::vec::Vec as StdVec;

    /// A fake at the shipped FLASH_FS geometry, sized so that a write past the
    /// nonce region is out of bounds rather than silently landing in
    /// `FS_FREE`.
    fn fs_flash() -> RefCell<DebugFlash<FakeFlash>> {
        RefCell::new(DebugFlash(FakeFlash::new(
            (memmap::FS_FREE_OFFSET / SECTOR_SIZE as u32) as usize,
        )))
    }

    /// Copied from `hal/examples/stub.rs`: a deterministic `Entropy` through the
    /// real `mix_sources` seam.
    fn entropy(salt: u8) -> Entropy {
        let varying = |len: usize, salt: u8| {
            let mut b = [0u8; 32];
            let mut v = salt;
            for slot in b.iter_mut().take(len) {
                v = v.wrapping_mul(7).wrapping_add(11);
                *slot = v;
            }
            b
        };
        let t = varying(TRNG_BYTES, salt);
        let s1 = varying(SE1_BYTES, salt.wrapping_add(1));
        let s2 = varying(SE2_BYTES, salt.wrapping_add(2));
        let seed: ProvenSeed = mix_sources(&t[..TRNG_BYTES], &s1[..SE1_BYTES], &s2[..SE2_BYTES])
            .expect("three good draws must mix");
        Entropy::from_proven_seed(seed)
    }

    fn open_streams(n: usize, rng: &mut Entropy) -> (StdVec<NonceStreamId>, CoordinatorSendBody) {
        let ids: StdVec<NonceStreamId> = (0..n).map(|_| NonceStreamId::random(rng)).collect();
        let streams = ids
            .iter()
            .map(|id| CoordNonceStreamState {
                stream_id: *id,
                index: 0,
                remaining: 0,
            })
            .collect();
        (
            ids,
            CoordinatorSendBody::Core(CoordinatorToDeviceMessage::Signing(
                CoordinatorSigning::OpenNonceStreams(OpenNonceStreams { streams }),
            )),
        )
    }

    /// THE property flash-backed identity and flash-backed nonces exist for. A
    /// signer rebuilt from the same flash is the same device, and the nonce
    /// stream it opened before the reset is still there — so it will not reissue
    /// nonces, which for FROST is a key leak.
    #[test]
    fn signer_reconstructed_from_flash_keeps_device_id_and_nonce_stream() {
        let flash = fs_flash();
        let mut rng = entropy(7);

        let secret = identity::load_or_create(&mut *flash.borrow_mut(), &mut rng)
            .expect("a blank fake flash must yield a fresh identity");
        let (ids, body) = open_streams(1, &mut rng);
        let first_id = {
            let mut session = Session::open(&flash, &secret).expect("signer construction");
            let mut out = Outbox::new(session.device_id());
            session.recv(body, &mut rng, &mut out).expect("dispatch");
            assert!(out.frames() > 0, "OpenNonceStreams must be answered");
            session.device_id()
        };

        // Reset: reload the identity from flash and rebuild.
        let secret_again = identity::load_or_create(&mut *flash.borrow_mut(), &mut rng)
            .expect("the stored identity must load");
        let session = Session::open(&flash, &secret_again).expect("signer reconstruction");
        assert_eq!(
            first_id,
            session.device_id(),
            "DeviceId must survive a reset"
        );
        // And it is a real 33-byte compressed point: a coordinator's
        // `DeviceId::pubkey()` `debug_assert`s this and silently substitutes G in
        // release if it fails.
        assert!(Point::<Normal, Public, NonZero>::from_bytes(session.device_id().0).is_some());

        // The nonce state is on flash at the memmap offsets, not in RAM.
        let mut reloaded = NonceAbSlot::load_slots(FlashPartition::new(
            &flash,
            NONCE_OFFSET_SECTOR,
            NONCE_SECTORS,
            "nonces",
        ));
        assert_eq!(reloaded.total_slots(), NONCE_SLOTS as usize);
        let found: StdVec<_> = reloaded.all_stream_ids().collect();
        assert_eq!(found, ids, "the nonce stream did not survive the reset");

        // AND the id must be DERIVED from the stored secret, not merely stable.
        // Stability alone is satisfied by a hardcoded constant: a mutation replacing
        // the identity scalar in `Session::open` with `[7u8; 32]` passed every
        // assertion above and was caught only by the 90-second pty harness. A second
        // flash with different entropy must therefore yield a DIFFERENT device.
        let other_flash = fs_flash();
        let mut other_rng = entropy(9);
        let other_secret = identity::load_or_create(&mut *other_flash.borrow_mut(), &mut other_rng)
            .expect("a second blank flash must yield its own identity");
        let other = Session::open(&other_flash, &other_secret).expect("second construction");
        assert_ne!(
            first_id,
            other.device_id(),
            "two devices with different flash secrets derived the SAME DeviceId, so \
             the id is not a function of the stored secret"
        );
    }

    /// PLAN.md §9 item 18, the property that actually matters: a nonce index
    /// **consumed before a reset is refused after one**. In FROST, signing twice
    /// at one index leaks the share, so this is the whole reason the slots are on
    /// flash instead of in RAM.
    ///
    /// The test above proves the *stream* survives; it never reads `.index`, so a
    /// rewound counter passes it. This one reads the index back through
    /// `Session::open` — the shipped constructor, at the shipped
    /// [`memmap::FS_NONCE_OFFSET`] — and then asks the guard itself.
    ///
    /// Consumption is simulated with the identical write the sign path makes
    /// (`device_nonces.rs:379-392`: a new `index`, then `write_slot`), because
    /// reaching the real one needs a completed keygen and a `PartySignSession`,
    /// i.e. a `FrostCoordinator` (std + rusqlite), which no lib test can hold.
    /// SEAM, stated plainly: this proves durability-plus-refusal, the firmware's
    /// half. That the signer advances the index at sign time is vendored, and its
    /// flash read-back is covered by the `FaultyNorFlash` tests in
    /// `frostsnap_embedded`.
    #[test]
    fn a_nonce_consumed_before_a_reset_is_refused_after_one() {
        use frostsnap_core::device_nonces::{NonceStreamSlot, NoncesUnavailable};

        /// Enough that "every index below it" is a real range, not one case.
        const CONSUMED: u32 = 5;

        let flash = fs_flash();
        let mut rng = entropy(31);
        let secret = identity::load_or_create(&mut *flash.borrow_mut(), &mut rng)
            .expect("a blank fake flash must yield a fresh identity");
        let (ids, body) = open_streams(1, &mut rng);
        let stream = ids[0];

        {
            let mut session = Session::open(&flash, &secret).expect("signer construction");
            let mut out = Outbox::new(session.device_id());
            session.recv(body, &mut rng, &mut out).expect("dispatch");
            let slot = session
                .signer
                .nonce_slots()
                .get(stream)
                .expect("OpenNonceStreams must have created the slot");
            let mut value = slot.read_slot().expect("a created slot must read back");
            assert_eq!(value.index, 0, "a fresh stream starts at 0");
            value.index = CONSUMED;
            slot.write_slot(&value);
        }
        // --- reset: nothing above survives except the bytes in `flash`. -------

        let secret_again = identity::load_or_create(&mut *flash.borrow_mut(), &mut rng)
            .expect("the stored identity must load");
        let mut session = Session::open(&flash, &secret_again).expect("signer reconstruction");
        let slot = session
            .signer
            .nonce_slots()
            .get(stream)
            .expect("the nonce stream must survive the reset");
        let value = slot
            .read_slot()
            .expect("the slot must read back after the reset");
        assert_eq!(
            value.index, CONSUMED,
            "the consumed index did not survive the reset: every nonce below it \
             would be reissued, and reissuing one leaks the share"
        );

        // THE REFUSAL, per index and not merely "the stream exists". This is the
        // only thing standing between a power cycle and nonce reuse.
        for used in 0..CONSUMED {
            assert!(
                matches!(
                    value.are_nonces_available(used, 1),
                    Err(NoncesUnavailable::IndexUsed {
                        current: CONSUMED,
                        requested,
                    }) if requested == used
                ),
                "index {used} was consumed before the reset and must be refused after it, \
                 got {:?}",
                value.are_nonces_available(used, 1)
            );
        }
        // And the control: the first UNUSED index is still available, so the
        // refusal above is a boundary and not a device that refuses everything.
        assert!(
            value.are_nonces_available(CONSUMED, 1).is_ok(),
            "the first unconsumed index must still be usable"
        );
    }

    /// Cap (a). Four streams at once — what the flutter coordinator asks for —
    /// must come back as four frames, each inside `FRAME_LIMIT`. One frame with
    /// four segments is ~8 KB and would be refused, leaving the coordinator
    /// waiting forever on a replenishment.
    #[test]
    fn nonce_response_is_split_one_segment_per_frame() {
        let flash = fs_flash();
        let mut rng = entropy(9);
        let secret = identity::load_or_create(&mut *flash.borrow_mut(), &mut rng).unwrap();
        let mut session = Session::open(&flash, &secret).unwrap();
        let mut out = Outbox::new(session.device_id());

        // `remaining: 0` on every stream is what makes the device generate a full
        // `NONCE_BATCH_SIZE` batch per stream, which is what makes the reply too
        // big for one frame.
        let (ids, body) = open_streams(NONCE_SLOTS as usize, &mut rng);
        session.recv(body, &mut rng, &mut out).expect("dispatch");
        assert_eq!(
            out.frames(),
            ids.len(),
            "one frame per stream segment, not one frame with all of them"
        );
        assert!(
            out.bytes().len() > FRAME_LIMIT,
            "the reply must be too big for a single frame, or this test proves nothing \
             (got {} bytes)",
            out.bytes().len()
        );
    }

    /// Cap (b). A `HeldShares2` reply too large for one frame is refused whole:
    /// no frame, no partial write, and never a silent truncation — dropping
    /// shares from a restoration reply tells the coordinator a share does not
    /// exist.
    #[test]
    fn held_shares2_over_frame_limit_is_refused_whole() {
        let mut out = Outbox::new(DeviceId([2u8; 33]));
        let share = HeldShare2 {
            access_structure_ref: None,
            share_image: ShareImage {
                index: ShareIndex::one(),
                image: Point::zero(),
            },
            threshold: None,
            key_name: None,
            purpose: None,
            needs_consolidation: false,
        };
        let one = frostsnap_core::message::DeviceRestoration::HeldShares2(vec![share.clone()]);
        out.push(DeviceSendBody::Core(
            DeviceToCoordinatorMessage::Restoration(one),
        ))
        .expect("one share fits");
        assert_eq!(out.frames(), 1);
        let before = out.bytes().len();

        let many = frostsnap_core::message::DeviceRestoration::HeldShares2(vec![share; 4096]);
        let refused = out.push(DeviceSendBody::Core(
            DeviceToCoordinatorMessage::Restoration(many),
        ));
        assert_eq!(refused, Err(CommsError::FrameTooLong));
        assert_eq!(out.frames(), 1, "a refused body must add no frame");
        assert_eq!(
            out.bytes().len(),
            before,
            "a refused body must add no bytes at all"
        );
    }

    /// Cap (c). Truncation must land on a UTF-8 boundary: `String::truncate` off
    /// one panics, and under `panic = "abort"` that is a brick.
    #[test]
    fn debug_message_is_truncated_on_a_char_boundary() {
        // A 3-byte character straddling the limit.
        let mut message = String::from_utf8(vec![b'x'; DEBUG_MESSAGE_LIMIT - 1]).unwrap();
        message.push('€');
        assert!(message.len() > DEBUG_MESSAGE_LIMIT);
        let cut = truncate_debug(message);
        assert_eq!(cut.len(), DEBUG_MESSAGE_LIMIT - 1);
        assert!(cut.chars().all(|c| c == 'x'));

        let mut out = Outbox::new(DeviceId([3u8; 33]));
        out.push(DeviceSendBody::Debug {
            message: "a".repeat(FRAME_LIMIT * 2),
        })
        .expect("a debug message must never be able to exceed the frame");
        assert_eq!(out.frames(), 1);
        assert!(out.bytes().len() < FRAME_LIMIT);
    }

    /// `Debug` is the only free-text outbox shape, so it is the only one that could
    /// carry share material off the device. `Outbox::push`'s truncating arm is the
    /// one place in this crate allowed to construct it.
    ///
    /// MUTATION-VERIFY, and it was found BY a mutation: adding
    /// `out.push(DeviceSendBody::Debug { .. })` to `run`'s informational
    /// `other => prompts.push(other)` arm — the shape a logging patch takes — left
    /// every other test in this crate green. A prompt's `Debug` is share-adjacent
    /// already (`BackupDisplayPhase` carries the ciphertext and the coordinator's
    /// decryption contribution, and `ShareBackup` derives `Debug`), and
    /// `truncate_debug` would forward it happily. Asserted against the SOURCE
    /// because the property is a negative — no arm anywhere logs a secret — and a
    /// negative has no runtime witness.
    #[test]
    fn nothing_but_the_outbox_truncating_arm_may_construct_a_debug_send() {
        let src = include_str!("lib.rs");
        let production = src
            .split("#[cfg(test)]")
            .next()
            .expect("the test module is behind cfg(test)");
        let sites = production.matches("DeviceSendBody::Debug {").count();
        assert_eq!(
            sites, 2,
            "`Outbox::push`'s match arm and the truncated re-encode it makes are \
             the only `DeviceSendBody::Debug` constructions allowed outside tests; \
             found {sites}"
        );
    }

    fn refuse(body: CoordinatorSendBody) -> Refusal {
        let flash = fs_flash();
        let mut rng = entropy(11);
        let secret = identity::load_or_create(&mut *flash.borrow_mut(), &mut rng).unwrap();
        let mut session = Session::open(&flash, &secret).unwrap();
        let mut out = Outbox::new(session.device_id());
        let fault = session
            .recv(body, &mut rng, &mut out)
            .expect_err("this body must be refused");
        assert_eq!(out.frames(), 0, "a refusal must not answer");
        match fault {
            Fault::Refused(r) => r,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// There is no OTA on this hardware and there cannot be one: RDP=2 makes DFU
    /// hardware-impossible and the image path is signed-flash-only.
    #[test]
    fn firmware_upgrade_is_refused() {
        assert_eq!(
            refuse(CoordinatorSendBody::Upgrade(
                frostsnap_comms::CoordinatorUpgradeMessage::EnterUpgradeMode
            )),
            Refusal::FirmwareUpgrade
        );
    }

    /// `DataErase` destroys shares. Never without physical consent, and no such
    /// path exists.
    #[test]
    fn data_erase_is_refused() {
        assert_eq!(refuse(CoordinatorSendBody::DataErase), Refusal::DataErase);
    }

    /// `DisplayBackup` for a share this device does not hold is refused **before any
    /// human is asked**, by the signer, and it grants nothing.
    ///
    /// This is the first of the three gates in front of the reveal (see `recv_core`'s
    /// `DisplayBackup` arm) and it is the reason admitting the message is safe: a
    /// coordinator cannot make this device draw a consent screen for a key it has
    /// never held, so there is no screen to guess a digit at.
    #[test]
    fn display_backup_for_a_share_we_do_not_hold_is_refused_pre_consent() {
        let flash = fs_flash();
        let mut rng = entropy(13);
        let secret = identity::load_or_create(&mut *flash.borrow_mut(), &mut rng).unwrap();
        let mut session = Session::open(&flash, &secret).unwrap();
        let id = session.device_id();
        let shared_key = frostsnap_core::schnorr_fun::frost::SharedKey::from_poly(vec![session
            .signer
            .keypair()
            .public_key()
            .mark_zero()])
        .non_zero()
        .expect("a one-coefficient poly with a non-zero constant term");
        let body = CoordinatorSendBody::Core(CoordinatorToDeviceMessage::Restoration(
            CoordinatorRestoration::DisplayBackup {
                access_structure_ref: AccessStructureRef::from_root_shared_key(&shared_key),
                coord_share_decryption_contrib: CoordShareDecryptionContrib::for_master_share(
                    id,
                    ShareIndex::one(),
                    &shared_key,
                ),
                share_index: ShareIndex::one(),
                root_shared_key: shared_key,
            },
        ));
        let mut out = Outbox::new(id);
        let fault = session
            .recv(body, &mut rng, &mut out)
            .expect_err("a backup we do not hold must be refused");
        assert!(
            matches!(fault, Fault::Signer(_)),
            "expected the signer to refuse, got {fault:?}"
        );
        assert_eq!(out.frames(), 0, "a refused backup request must not answer");
        assert!(
            session.signer.staged_mutations().is_empty(),
            "a refused backup request must stage nothing"
        );
        // And nothing was granted, so the reveal is still shut.
        let mut frame = ui::Frame::new();
        assert!(matches!(
            session.show_backup(0, &mut frame, &mut rng),
            Err(Fault::Refused(Refusal::DisplayBackup))
        ));
    }

    /// `AnnounceAck` is the only signal that our announce landed.
    #[test]
    fn announce_ack_is_latched_and_announce_asks_for_a_name() {
        let flash = fs_flash();
        let mut rng = entropy(17);
        let secret = identity::load_or_create(&mut *flash.borrow_mut(), &mut rng).unwrap();
        let mut session = Session::open(&flash, &secret).unwrap();
        let mut out = Outbox::new(session.device_id());

        session
            .announce(Sha256Digest([1u8; 32]), &mut out)
            .expect("announce must fit a frame");
        assert_eq!(
            out.frames(),
            2,
            "Announce alone never registers a device: the coordinator's gate is a name"
        );

        assert!(!session.coordinator_acked);
        session
            .recv(CoordinatorSendBody::AnnounceAck, &mut rng, &mut out)
            .expect("AnnounceAck is handled");
        assert!(session.coordinator_acked);
    }

    /// The digest is our own SHA-256 over the bootloader's signed range, and
    /// every length it reads off flash is bounded first.
    #[test]
    fn firmware_digest_hashes_the_signed_range_and_bounds_the_length() {
        let header_end = (memmap::FW_HEADER_OFFSET + memmap::FW_HEADER_SIZE) as usize;
        let length = memmap::FW_MIN_BODY_LEN;
        let mut image = vec![0xa5u8; length as usize];
        image[memmap::FW_HEADER_OFFSET as usize + 24..memmap::FW_HEADER_OFFSET as usize + 28]
            .copy_from_slice(&length.to_le_bytes());

        let mut h = Sha256::new();
        h.update(&image[..header_end - 64]);
        h.update(&image[header_end..length as usize]);
        let want: [u8; 32] = h.finalize().into();
        assert_eq!(firmware_digest(&image).expect("well-formed image").0, want);

        // The 64 signature bytes are excluded, so changing them changes nothing.
        let mut resigned = image.clone();
        resigned[header_end - 64..header_end].copy_from_slice(&[0x5au8; 64]);
        assert_eq!(firmware_digest(&resigned).unwrap().0, want);

        // Every bound refuses rather than reading out of range.
        let bad_len = |v: u32| {
            let mut i = image.clone();
            i[memmap::FW_HEADER_OFFSET as usize + 24..memmap::FW_HEADER_OFFSET as usize + 28]
                .copy_from_slice(&v.to_le_bytes());
            firmware_digest(&i)
        };
        assert!(bad_len(0).is_none(), "under FW_MIN_BODY_LEN");
        assert!(bad_len(length + 1).is_none(), "misaligned");
        assert!(bad_len(length * 4).is_none(), "past the end of the image");
        assert!(firmware_digest(&image[..header_end]).is_none(), "truncated");
        assert!(firmware_digest(&[]).is_none(), "empty");
    }

    /// `coldcardFirmwareHeader_t` as `cli/signit.py` actually packs it, byte for
    /// byte, at the measured length of the current release image.
    ///
    /// Nothing in this crate emits this — `signit.py:315-325` builds it at pack
    /// time and `signit.py:275-276` throws away whatever the input had in the slot.
    /// It is replicated here because [`firmware_digest`] reads offset 24 out of it
    /// on hardware, and an offset that disagrees with the C struct is a refused
    /// image at best. Every field is cited to
    /// `coldcard-firmware/stm32/mk4-bootloader/sigheader.h`; all integers are
    /// little-endian (`FWH_PY_FORMAT = "<I8s8sIIII8s20s64s"`, `sigheader.h:56`).
    fn signit_header(firmware_length: u32) -> [u8; 128] {
        let mut h = [0u8; 128];
        // 0..4   magic_value   `sigheader.h:26`, value `sigheader.h:41`.
        h[0..4].copy_from_slice(&0xCC00_1234u32.to_le_bytes());
        // 4..12  timestamp     `sigheader.h:27`; BCD YYMMDDHHMMSS0000
        //                      (`signit.py:30-45`). Byte 0 must be < 0x40
        //                      (`verify.c:214`), so a plausible year, not 0xff.
        h[4..12].copy_from_slice(&[0x26, 0x08, 0x25, 0x15, 0x46, 0x33, 0, 0]);
        // 12..20 version_string `sigheader.h:28`; NUL-padded ASCII, < 8 chars
        //                      (`signit.py:263`). Byte 0 may be neither 0
        //                      (`verify.c:213`) nor 0xff (`verify.c:324`), and the
        //                      major digit must be >= 3 or the *install* path calls
        //                      it a downgrade (`verify.c:169-177`).
        h[12..19].copy_from_slice(b"6.0.0cs");
        // 20..24 pubkey_num    `sigheader.h:29`, offset pinned at `sigheader.h:61`.
        //                      0 = the published dev key; < 6 (`verify.c:217`).
        h[20..24].copy_from_slice(&0u32.to_le_bytes());
        // 24..28 firmware_length `sigheader.h:30`. THE WHOLE IMAGE from
        //                      FLASH_ISR_BASE, header and 16 K vector region
        //                      included (`signit.py:315`) — not the body.
        h[24..28].copy_from_slice(&firmware_length.to_le_bytes());
        // 28..32 install_flags `sigheader.h:31`. 0; never FWHIF_HIGH_WATER, which
        //                      is a one-way OTP ratchet. Unread by this bootloader.
        // 32..36 hw_compat     `sigheader.h:32`. MK_4_OK|MK_5_OK = 0x28
        //                      (`sigheader.h:71,73`; `signit.py:282-284`). Enforced
        //                      by MicroPython (`shared/utils.py:391-415`), not here.
        h[32..36].copy_from_slice(&0x28u32.to_le_bytes());
        // 36..44 best_ts       `sigheader.h:33`, zeros (`signit.py:318`).
        // 44..64 future[5]     `sigheader.h:34`, zeros. NB `FWH_NUM_FUTURE = 7`
        //                      (`sigheader.h:58`) contradicts the `20s` in
        //                      FWH_PY_FORMAT; `struct.pack` truncates, so the
        //                      shipped header is 128 B and this slot is 20.
        // 64..128 signature    `sigheader.h:35`, raw r||s secp256k1. OUTSIDE the
        //                      signed range, so its bytes cannot affect the digest.
        h[64..128].copy_from_slice(&[0x5au8; 64]);
        h
    }

    /// The header shape a real signed artifact has makes [`firmware_digest`]
    /// return `Some`, over exactly `firmware_length - 64` bytes.
    ///
    /// This is the case `boot()` hits on hardware; before signing existed it
    /// returned `None` and `boot()` announced 32 zero bytes.
    #[test]
    fn firmware_digest_accepts_a_signit_shaped_header() {
        // Measured from the signed artifact: 73 * 4096. Not a constant anywhere —
        // it moves with every rebuild, which is why the field is the packer's.
        const FIRMWARE_LENGTH: u32 = 299_008;
        let header_off = memmap::FW_HEADER_OFFSET as usize;
        let header_end = header_off + memmap::FW_HEADER_SIZE as usize;

        // The whole slice `main.rs` hands it: FLASH_ISR + FLASH_TEXT, erased 0xff.
        let mut image = vec![0xffu8; (memmap::FLASH_ISR_LEN + memmap::FLASH_TEXT_LEN) as usize];
        image[header_off..header_end].copy_from_slice(&signit_header(FIRMWARE_LENGTH));

        let got = firmware_digest(&image).expect("a signit-shaped header must hash");

        // Recomputed from `verify.c:80,83-84` — the bootloader's two spans — rather
        // than from the implementation, so a moved split fails here.
        let mut h = Sha256::new();
        h.update(&image[..header_end - 64]);
        h.update(&image[header_end..FIRMWARE_LENGTH as usize]);
        assert_eq!(got.0, <[u8; 32]>::from(h.finalize()));
        assert_eq!(
            (header_end - 64) + (FIRMWARE_LENGTH as usize - header_end),
            FIRMWARE_LENGTH as usize - 64,
            "hashed span must be firmware_length - 64 (verify.c:92)"
        );

        // The trap in the length field's name: writing the padded BODY length
        // (282,624) instead of the total passes every bound and still yields a
        // different digest, i.e. a signature mismatch and a refused image.
        let mut body_len = image.clone();
        body_len[header_off..header_end].copy_from_slice(&signit_header(282_624));
        assert_ne!(
            firmware_digest(&body_len).expect("also well-formed").0,
            got.0,
            "the length field is the total, not the body"
        );
    }

    /// Tripwire, not an endorsement: our alignment refusal is 8x looser than the
    /// Mk4 artifact actually is.
    ///
    /// `signit.py:302-306` re-aligns the Mk4/Mk5 body to 4096 and `verify.c:106`
    /// ties the length to the 4 K flash erase unit, so no real artifact is
    /// 512-but-not-4096 aligned. `memmap::FW_BODY_ALIGN` records the mk1-3 512 and
    /// belongs to `hal`. When it is corrected to 4096 this test FAILS — flip the
    /// assertion to `is_none()` then, and delete this paragraph.
    #[test]
    fn firmware_digest_alignment_bound_is_looser_than_mk4_requires() {
        let header_off = memmap::FW_HEADER_OFFSET as usize;
        let mut image = vec![0xffu8; (memmap::FLASH_ISR_LEN + memmap::FLASH_TEXT_LEN) as usize];
        let misaligned = 299_008 + 512;
        assert_eq!(misaligned % 512, 0);
        assert_ne!(misaligned % 4096, 0);
        image[header_off..header_off + memmap::FW_HEADER_SIZE as usize]
            .copy_from_slice(&signit_header(misaligned));
        assert!(
            firmware_digest(&image).is_some(),
            "FW_BODY_ALIGN was fixed to 4096 — flip this to is_none()"
        );
    }

    /// A group larger than [`MAX_PARTIES`] is REFUSED before the signer, and a
    /// threshold outside `1..=n` with it.
    ///
    /// This is the permanent-brick guard, so the test asserts the refusal happens
    /// with **no frame emitted** — the refusal must precede the work, not follow it.
    /// n=13 and n=16 are both wire-legal (PLAN.md §7: `CertifyPlease = 195n + 33t +
    /// 127`, so n=16 is 3,775 B inside `FRAME_LIMIT` 4,096), and n=16 is where the
    /// allocator was measured to refuse mid-keygen, pre-consent.
    #[test]
    fn a_group_over_max_parties_or_a_bad_threshold_is_refused_before_the_signer() {
        let flash = fs_flash();
        let mut rng = entropy(23);
        let secret = identity::load_or_create(&mut *flash.borrow_mut(), &mut rng).unwrap();
        let mut session = Session::open(&flash, &secret).unwrap();
        let id = session.device_id();

        let begin_with = |n: usize, threshold: u16| frostsnap_core::message::keygen::Begin {
            keygen_id: frostsnap_core::KeygenId([5u8; 16]),
            // Distinct ids do not matter to the bound; the length does.
            devices: (0..n)
                .map(|i| {
                    let mut d = id;
                    d.0[32] = i as u8;
                    d
                })
                .collect(),
            threshold,
            key_name: String::from("t"),
            purpose: frostsnap_core::device::KeyPurpose::Test,
            coordinator_public_keys: vec![frostsnap_core::schnorr_fun::fun::G.normalize()],
        };

        // Every case that must be refused, and why it is reachable:
        //   (13, 13) one over the envelope        (16, 16) where the allocator dies
        //   (13, 1)  large n, small t             (1, 0)   t = 0, unsatisfiable
        //   (1, 2)   t > n, unsatisfiable
        for (n, threshold) in [(13, 13u16), (16, 16), (13, 1), (1, 0), (1, 2)] {
            let mut out = Outbox::new(id);
            let r = session.recv(
                CoordinatorSendBody::Core(CoordinatorToDeviceMessage::KeyGen(Keygen::Begin(
                    begin_with(n, threshold),
                ))),
                &mut rng,
                &mut out,
            );
            assert!(
                matches!(r, Err(Fault::Refused(Refusal::GroupTooLarge))),
                "n={n} t={threshold} must be refused as GroupTooLarge, got {r:?}"
            );
            assert_eq!(
                out.frames(),
                0,
                "n={n} t={threshold}: the refusal must precede any work, so no frame \
                 may be emitted"
            );
        }

        // And the boundary is exactly MAX_PARTIES, not one either side of it: n=12
        // must NOT be refused for its size.
        let mut out = Outbox::new(id);
        let r = session.recv(
            CoordinatorSendBody::Core(CoordinatorToDeviceMessage::KeyGen(Keygen::Begin(
                begin_with(MAX_PARTIES, MAX_PARTIES as u16),
            ))),
            &mut rng,
            &mut out,
        );
        assert!(
            !matches!(r, Err(Fault::Refused(Refusal::GroupTooLarge))),
            "n=MAX_PARTIES must not be refused for its size, got {r:?}"
        );
    }

    /// Keygen is routed to the real signer, not dropped. The reply proves
    /// `recv_coordinator_message` ran with our flash-derived keypair.
    #[test]
    fn keygen_begin_reaches_the_signer() {
        let flash = fs_flash();
        let mut rng = entropy(19);
        let secret = identity::load_or_create(&mut *flash.borrow_mut(), &mut rng).unwrap();
        let mut session = Session::open(&flash, &secret).unwrap();
        let id = session.device_id();
        let mut out = Outbox::new(id);

        let begin = frostsnap_core::message::keygen::Begin {
            keygen_id: frostsnap_core::KeygenId([4u8; 16]),
            devices: vec![id],
            threshold: 1,
            key_name: String::from("t"),
            purpose: frostsnap_core::device::KeyPurpose::Test,
            // Not our own key: a key in both the contributor and receiver sets is
            // rejected before the state machine is reached.
            coordinator_public_keys: vec![frostsnap_core::schnorr_fun::fun::G.normalize()],
        };
        let prompts = session
            .recv(
                CoordinatorSendBody::Core(CoordinatorToDeviceMessage::KeyGen(Keygen::Begin(begin))),
                &mut rng,
                &mut out,
            )
            .expect("Begin must be handled");
        assert_eq!(out.frames(), 1, "the device must answer Begin");
        assert!(prompts.is_empty(), "Begin asks the human nothing yet");
    }

    /// A well-formed `SharedKey` and a decryption contribution for it, from a
    /// fixed point rather than a real keygen: every refusal below fires before the
    /// signer looks at either, so they only have to typecheck as wire values.
    fn shared_key() -> frostsnap_core::schnorr_fun::frost::SharedKey {
        frostsnap_core::schnorr_fun::frost::SharedKey::from_poly(vec![
            frostsnap_core::schnorr_fun::fun::G.normalize().mark_zero(),
        ])
        .non_zero()
        .expect("a one-coefficient poly with a non-zero constant term")
    }

    fn appkey() -> frostsnap_core::MasterAppkey {
        frostsnap_core::MasterAppkey::derive_from_rootkey(
            frostsnap_core::schnorr_fun::fun::G.normalize(),
        )
    }

    /// THE REFUSAL TO SIGN. Nothing in this project asserted one before: the
    /// harness's stub auto-acks, and every refusal is an `Err` it would have died
    /// on. Pre-consent, so no human is ever asked and nothing is staged.
    #[test]
    fn sign_request_for_a_key_we_do_not_hold_is_refused_pre_consent() {
        let flash = fs_flash();
        let mut rng = entropy(29);
        let secret = identity::load_or_create(&mut *flash.borrow_mut(), &mut rng).unwrap();
        let mut session = Session::open(&flash, &secret).unwrap();
        let id = session.device_id();
        let mut out = Outbox::new(id);

        // This device holds NO key (blank flash, no keygen), so `keys.get(&key_id)`
        // is the FIRST thing that fails -- which is what makes the empty
        // `parties`/`agg_nonces` below unreachable rather than sloppy, and what
        // makes this a pre-consent refusal rather than a late one.
        let request = frostsnap_core::message::RequestSign {
            group_sign_req: frostsnap_core::message::GroupSignReq {
                parties: alloc::collections::BTreeSet::new(),
                agg_nonces: Vec::new(),
                sign_task: frostsnap_core::WireSignTask::Test {
                    message: String::from("give me a signature"),
                },
                access_structure_id: frostsnap_core::AccessStructureId([0u8; 32]),
            },
            device_sign_req: frostsnap_core::message::DeviceSignReq {
                nonces: CoordNonceStreamState {
                    stream_id: NonceStreamId::random(&mut rng),
                    index: 0,
                    remaining: 0,
                },
                rootkey: frostsnap_core::schnorr_fun::fun::G.normalize(),
                coord_share_decryption_contrib: CoordShareDecryptionContrib::for_master_share(
                    id,
                    ShareIndex::one(),
                    &shared_key(),
                ),
            },
        };
        let fault = session
            .recv(
                CoordinatorSendBody::Core(CoordinatorToDeviceMessage::Signing(
                    CoordinatorSigning::RequestSign(alloc::boxed::Box::new(request)),
                )),
                &mut rng,
                &mut out,
            )
            .expect_err("a sign request for a key we do not hold must be refused");
        assert!(
            matches!(fault, Fault::Signer(_)),
            "expected the signer to refuse, got {fault:?}"
        );
        assert_eq!(out.frames(), 0, "a refused sign request must not answer");
        assert!(
            session.signer.staged_mutations().is_empty(),
            "a refused sign request must stage nothing"
        );
    }

    /// `CheckBackup` is the LAST message the `PhysicalBackup` refusal covers, and the
    /// arm a blanket `_ => {}` over `Restoration` would swallow now that its four
    /// siblings are admitted.
    ///
    /// DECISIONS: it is not the cheap one. Its screen renders the true word among
    /// three **and** all 25, so its exposure exceeds `DisplayBackup`'s, and its 26
    /// redraws make `mark_sensitive`'s sqrt(N) averaging ~1.8x worse. The screen
    /// exists (`ui::backup_quiz_word`); the distractor picker does not. Admitting it
    /// while `show_backup` draws plain words would answer a quiz request with a full
    /// plaintext reveal.
    ///
    /// MUTATION-VERIFY: add `| CoordinatorRestoration::CheckBackup { .. }` to the
    /// admitted restore arm — the one-line "while we're here" edit — and this fails.
    #[test]
    fn check_backup_alone_stays_refused() {
        let body = CoordinatorSendBody::Core(CoordinatorToDeviceMessage::Restoration(
            CoordinatorRestoration::CheckBackup {
                coord_share_decryption_contrib: CoordShareDecryptionContrib::for_master_share(
                    DeviceId([2u8; 33]),
                    ShareIndex::one(),
                    &shared_key(),
                ),
                share_index: ShareIndex::one(),
                root_shared_key: shared_key(),
            },
        ));
        assert_eq!(refuse(body), Refusal::PhysicalBackup);
    }

    /// **A `SavePhysicalBackup2` for a share nobody typed in is a CLEAN refusal** —
    /// the signer's, before it stages anything.
    ///
    /// This is the message that stages a `Mutation::Restoration` carrying a plaintext
    /// `ShareBackup` (`device/restoration.rs:83-97`), and it is now ADMITTED by the
    /// dispatch. The gate is no longer this file's refusal but the signer's own
    /// `tmp_loaded_backups` lookup: with no entered backup there is nothing to save,
    /// so a coordinator that skips the consented entry step gets
    /// `Fault::Signer(InvalidMessage)` and an untouched device.
    ///
    /// MUTATION-VERIFY: make `recv_core` short-circuit this message to `Ok` (the shape
    /// a "the app expects an answer" patch takes) and the frames assert fails.
    ///
    /// What this does NOT fix, and cannot from here: the coordinator hears **silence**.
    /// A `Fault` draws `ui::refusal` on the glass and pushes nothing, and the wire
    /// protocol has no "I refuse" message for a device to send — `DeviceSendBody`
    /// carries no such variant and `DisplayBackupProtocol`/`RestorationProtocol` only
    /// ever consume `CommsMisc`. So every refused restoration message leaves the app
    /// waiting. UPSTREAM's gap; not worked around here.
    #[test]
    fn save_physical_backup2_without_an_entered_backup_is_refused_by_the_signer() {
        let flash = fs_flash();
        let mut rng = entropy(107);
        let secret = identity::load_or_create(&mut *flash.borrow_mut(), &mut rng).unwrap();
        let mut session = Session::open(&flash, &secret).unwrap();
        let mut out = Outbox::new(session.device_id());

        let body = CoordinatorSendBody::Core(CoordinatorToDeviceMessage::Restoration(
            CoordinatorRestoration::SavePhysicalBackup2(alloc::boxed::Box::new(HeldShare2 {
                access_structure_ref: None,
                share_image: ShareImage {
                    index: ShareIndex::one(),
                    image: Point::zero(),
                },
                threshold: None,
                key_name: None,
                purpose: None,
                needs_consolidation: false,
            })),
        ));
        let fault = session
            .recv(body, &mut rng, &mut out)
            .expect_err("this message must be refused");
        assert!(
            matches!(fault, Fault::Signer(_)),
            "expected the signer to refuse a save with nothing entered, got {fault:?}"
        );
        assert_eq!(out.frames(), 0, "a refused message must not answer");
        assert!(
            session.signer.staged_mutations().is_empty(),
            "a refused save staged a `Mutation::Restoration` carrying a plaintext share"
        );
        // And the device still works afterwards.
        assert!(session
            .recv(CoordinatorSendBody::AnnounceAck, &mut rng, &mut out)
            .is_ok());
    }

    /// The genuine check needs the ESP32 DS peripheral and a factory certificate
    /// this device does not have. Answering it with anything would be a lie.
    #[test]
    fn genuine_challenge_is_refused() {
        assert_eq!(
            refuse(CoordinatorSendBody::Challenge(alloc::boxed::Box::new(
                frostsnap_comms::GenuineChallenge([0u8; 32])
            ))),
            Refusal::GenuineChallenge
        );
    }

    /// Address verification is a screen this device does not have. Refusing beats
    /// dropping it, which leaves the app waiting forever.
    #[test]
    fn address_verify_is_refused() {
        let body = CoordinatorSendBody::Core(CoordinatorToDeviceMessage::ScreenVerify(
            frostsnap_core::message::screen_verify::ScreenVerify::VerifyAddress {
                master_appkey: appkey(),
                derivation_index: 0,
            },
        ));
        assert_eq!(refuse(body), Refusal::AddressVerify);
    }

    /// `confirm` answers the two consent prompts and NOTHING else. The dispatch
    /// hands back informational messages too, and treating one of those as consent
    /// is a device acking on its own.
    #[test]
    fn confirm_on_a_non_consent_prompt_is_not_confirmable() {
        let flash = fs_flash();
        let mut rng = entropy(31);
        let secret = identity::load_or_create(&mut *flash.borrow_mut(), &mut rng).unwrap();
        let mut session = Session::open(&flash, &secret).unwrap();
        let mut out = Outbox::new(session.device_id());
        let fault = session
            .confirm(
                DeviceToUserMessage::FinalizeKeyGen {
                    key_name: String::from("k"),
                },
                &mut rng,
                &mut out,
            )
            .expect_err("FinalizeKeyGen is not a consent prompt");
        assert!(matches!(fault, Fault::NotConfirmable), "got {fault:?}");
        assert_eq!(out.frames(), 0, "an unanswerable prompt must not answer");
    }

    /// A foreign output that HAS an address in `Network::Bitcoin`, so the control
    /// cases below are genuinely displayable.
    fn addressable(seed: u8) -> bitcoin::ScriptBuf {
        use bitcoin::hashes::Hash as _;
        bitcoin::ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([seed; 20]))
    }

    fn address_of(spk: &bitcoin::ScriptBuf) -> String {
        bitcoin::Address::from_script(spk, bitcoin::Network::Bitcoin)
            .expect("addressable() must be addressable")
            .to_string()
    }

    /// A Bitcoin sign task built from RAW WIRE VALUES, which is what a coordinator
    /// controls: the builder API cannot express an unaddressable output, the wire
    /// format can, and `WireSignTask::check` accepts one on purpose
    /// (`sign_task.rs:343-350`).
    ///
    /// Assembled as a `CheckedSignTask` directly: the phase the device prompts with
    /// already carries a CHECKED task, so a display refusal that only held for
    /// unchecked ones would hold nowhere.
    fn bitcoin_task(outputs: &[(u64, bitcoin::ScriptBuf)]) -> CheckedSignTask {
        use bitcoin::hashes::Hash as _;
        use frostsnap_core::bitcoin_transaction::{PushInput, TransactionTemplate};
        let mut tx = TransactionTemplate::new();
        let funding = bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(1_000_000),
            script_pubkey: addressable(0xaa),
        };
        tx.push_foreign_input(PushInput::spend_outpoint(
            &funding,
            bitcoin::OutPoint::new(bitcoin::Txid::from_byte_array([1u8; 32]), 0),
        ));
        for (value, spk) in outputs {
            tx.push_foreign_output(bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(*value),
                script_pubkey: spk.clone(),
            });
        }
        CheckedSignTask {
            master_appkey: appkey(),
            inner: SignTask::BitcoinTransaction {
                tx_template: tx,
                network: bitcoin::Network::Bitcoin,
            },
        }
    }

    /// PLAN.md §8.1 defect 12, made load-bearing. One output with no address form
    /// refuses the WHOLE request; it does not fall back to drawing the recipients
    /// it can draw.
    #[test]
    fn an_unaddressable_output_refuses_the_whole_sign_request() {
        // CONTROL, and it asserts the positive property too: EVERY recipient
        // reaches the consent screen, in order, with its own amount. Without this
        // half, "refused" below is indistinguishable from "never displayable".
        let shown = sign_consent(
            &bitcoin_task(&[(300_000, addressable(1)), (200_000, addressable(2))]),
            |pages| {
                (
                    pages
                        .recipients()
                        .iter()
                        .map(|r| (String::from(r.address), r.sats))
                        .collect::<StdVec<_>>(),
                    pages.fee_sats(),
                )
            },
        )
        .expect("two addressable recipients must be displayable")
        .expect("a Bitcoin task must produce pages");
        assert_eq!(
            shown.0,
            vec![
                (address_of(&addressable(1)), 300_000u64),
                (address_of(&addressable(2)), 200_000u64),
            ],
            "the consent screen must name EVERY recipient, in order, or it is a lie"
        );
        assert_eq!(shown.1, 500_000, "fee = 1_000_000 in - 500_000 out");

        // THE DEFECT. `Address::from_script` has no answer for either of these, so
        // `user_prompt` returns `None` -- the fail-closed direction its `Option`
        // exists for, which until now nothing in this tree consumed.
        for bad in [
            bitcoin::ScriptBuf::new_op_return([]),
            bitcoin::ScriptBuf::new(),
        ] {
            assert_eq!(
                sign_consent(
                    &bitcoin_task(&[(300_000, addressable(1)), (1, bad)]),
                    |_| ()
                )
                .err(),
                Some(Refusal::Undisplayable),
                "an output with no address form must refuse the whole transaction"
            );
        }

        // A `Test` task carries no recipient list: not refused (the harness signs
        // one) and not consent either.
        let test_task = CheckedSignTask {
            master_appkey: appkey(),
            inner: SignTask::Test {
                message: String::from("cold-snap M5"),
            },
        };
        assert!(sign_consent(&test_task, |_| ())
            .expect("a Test task is not undisplayable")
            .is_none());
    }

    /// More recipients than the screen holds is refused, not truncated -- and the
    /// bound is `ui::MAX_RECIPIENTS`, not "whatever fit".
    #[test]
    fn more_recipients_than_the_screen_holds_refuses_rather_than_truncating() {
        let outs = |n: usize| -> StdVec<(u64, bitcoin::ScriptBuf)> {
            (0..n).map(|i| (1_000u64, addressable(i as u8))).collect()
        };
        assert_eq!(
            sign_consent(&bitcoin_task(&outs(ui::MAX_RECIPIENTS)), |p| p
                .recipients()
                .len())
            .expect("exactly MAX_RECIPIENTS must fit"),
            Some(ui::MAX_RECIPIENTS)
        );
        assert_eq!(
            sign_consent(&bitcoin_task(&outs(ui::MAX_RECIPIENTS + 1)), |_| ()).err(),
            Some(Refusal::Undisplayable),
            "one recipient past the bound must refuse the transaction, not drop it"
        );
    }

    // -----------------------------------------------------------------------
    // GAP 1: the share is persisted BEFORE the ack, and it comes back.
    // -----------------------------------------------------------------------

    /// Exactly what `FrostSigner::save_complete_share` stages
    /// (`frostsnap_core/src/device.rs:526-542`), in its order.
    ///
    /// Staged by hand because reaching the real call needs a completed keygen and
    /// therefore a `FrostCoordinator` (std + rusqlite), which no lib test can hold.
    /// `staged_mutations()` is the same `&mut VecDeque` the real path pushes onto,
    /// so the drain under test is the shipped one — the seam is the *producer*.
    fn stage_a_finished_keygen(session: &mut Session<'_, DebugFlash<FakeFlash>>, seed: u8) {
        use frostsnap_core::device::{
            keys::KeyMutation, EncryptedSecretShare, KeyPurpose, Mutation, SaveShareMutation,
        };
        use frostsnap_core::{AccessStructureId, AccessStructureKind, Ciphertext, KeyId};

        let access_structure_ref = AccessStructureRef {
            key_id: KeyId([seed; 32]),
            access_structure_id: AccessStructureId([seed.wrapping_add(1); 32]),
        };
        let share = EncryptedSecretShare {
            share_image: ShareImage {
                index: ShareIndex::one(),
                image: Point::zero(),
            },
            ciphertext: Ciphertext::encrypt(
                SymmetricKey([seed; 32]),
                &Scalar::<Secret, Zero>::zero(),
                &mut entropy(seed),
            ),
        };
        let staged = session.signer.staged_mutations();
        staged.push_back(Mutation::Keygen(KeyMutation::NewKey {
            key_id: access_structure_ref.key_id,
            key_name: String::from("vault"),
            purpose: KeyPurpose::Test,
        }));
        staged.push_back(Mutation::Keygen(KeyMutation::NewAccessStructure {
            access_structure_ref,
            threshold: 1,
            kind: AccessStructureKind::Master,
        }));
        staged.push_back(Mutation::Keygen(KeyMutation::SaveShare(
            alloc::boxed::Box::new(SaveShareMutation {
                access_structure_ref,
                encrypted_secret_share: share,
            }),
        )));
    }

    /// A body that reaches `Session::run` and answers with exactly one frame,
    /// without touching flash on the way — so a frame in the outbox can only mean
    /// the persist at the top of `run` was skipped or reordered.
    fn one_frame_body(id: DeviceId) -> CoordinatorSendBody {
        CoordinatorSendBody::Core(CoordinatorToDeviceMessage::KeyGen(Keygen::Begin(
            frostsnap_core::message::keygen::Begin {
                keygen_id: frostsnap_core::KeygenId([6u8; 16]),
                devices: vec![id],
                threshold: 1,
                key_name: String::from("t"),
                purpose: frostsnap_core::device::KeyPurpose::Test,
                coordinator_public_keys: vec![frostsnap_core::schnorr_fun::fun::G.normalize()],
            },
        )))
    }

    /// Every one of the 2,048 vendored BIP39 words is renderable by `ui`.
    ///
    /// This test exists because its absence let a real defect ship. `ui::check_word`
    /// demanded `is_ascii_lowercase` while `frost_backup::bip39_words::BIP39_WORDS`
    /// is uppercase (`"ABANDON", "ABILITY", ...`), so `ui::BackupPages::new` refused
    /// **every share a keygen can produce** — the backup screen could not draw a real
    /// backup at all.
    ///
    /// Nothing caught it because the two halves live in crates that never met:
    /// `coldsnap_hal` has no `frost_backup` dependency, so `ui`'s own tests supplied
    /// lowercase fixtures and agreed with themselves. This crate has both, so this is
    /// the only place the comparison can be made. Mutate `ui::check_word` back to
    /// `is_ascii_lowercase` and this fails on the first word.
    #[test]
    fn every_vendored_bip39_word_is_renderable() {
        use frost_backup::bip39_words::BIP39_WORDS;
        for (i, w) in BIP39_WORDS.iter().enumerate() {
            assert!(
                coldsnap_hal::ui::BackupPages::new(1, &[*w; 25]).is_ok(),
                "vendored word {i} {w:?} is not renderable by ui::BackupPages"
            );
        }
    }

    /// THE GAP, closed: a keygen that finished before an unplug is still held
    /// after one, and `RequestHeldShares` answers from it.
    ///
    /// MUTATION-VERIFY. Delete the `persist_staged` call at the top of
    /// `Session::run`, or replay fewer than three mutations in `Session::open`, and
    /// this fails at `held_shares` — which is exactly the symptom the device showed
    /// before: a completed 9-of-9 keygen died at the next power cycle and
    /// `RequestHeldShares` answered empty forever.
    #[test]
    fn a_persisted_keygen_survives_a_reset_and_answers_request_held_shares() {
        let flash = fs_flash();
        let mut rng = entropy(41);
        let secret = identity::load_or_create(&mut *flash.borrow_mut(), &mut rng).unwrap();

        {
            let mut session = Session::open(&flash, &secret).unwrap();
            let id = session.device_id();
            let mut out = Outbox::new(id);
            assert_eq!(
                session.signer.held_shares().count(),
                0,
                "a blank flash must hold no share"
            );
            stage_a_finished_keygen(&mut session, 9);
            session
                .recv(one_frame_body(id), &mut rng, &mut out)
                .expect("dispatch");
            assert!(
                session.signer.staged_mutations().is_empty(),
                "a committed save must drain the staged set, or the next run rewrites it"
            );
        }
        // --- reset: nothing survives but the bytes in `flash`. -----------------

        let mut session = Session::open(&flash, &secret).unwrap();
        assert_eq!(
            session.signer.held_shares().count(),
            1,
            "the share did not come back: a completed keygen died at the unplug"
        );

        // And the coordinator hears about it, which is the user-visible half.
        let mut out = Outbox::new(session.device_id());
        session
            .recv(
                CoordinatorSendBody::Core(CoordinatorToDeviceMessage::Restoration(
                    CoordinatorRestoration::RequestHeldShares,
                )),
                &mut rng,
                &mut out,
            )
            .expect("RequestHeldShares is answered");
        let with_share = out.bytes().len();

        let blank = fs_flash();
        let blank_secret = identity::load_or_create(&mut *blank.borrow_mut(), &mut rng).unwrap();
        let mut empty_session = Session::open(&blank, &blank_secret).unwrap();
        let mut empty_out = Outbox::new(empty_session.device_id());
        empty_session
            .recv(
                CoordinatorSendBody::Core(CoordinatorToDeviceMessage::Restoration(
                    CoordinatorRestoration::RequestHeldShares,
                )),
                &mut rng,
                &mut empty_out,
            )
            .expect("RequestHeldShares is answered");
        assert!(
            with_share > empty_out.bytes().len(),
            "the reply after a reset ({with_share} B) is no bigger than a device with \
             no share ({} B): the share is not in it",
            empty_out.bytes().len()
        );
    }

    /// THE ORDERING PROPERTY. A share that could not be written is a share the
    /// coordinator must never hear about: it applies its own `NewShare` on the ack
    /// and then shows the wallet as complete (`coordinator/keys.rs:74-78`), so an
    /// ack this device cannot back leaves a threshold silently short with no backup
    /// path to rebuild it.
    ///
    /// MUTATION-VERIFY. Move the `persist_staged` call in `Session::run` below the
    /// `while let Some(send)` loop — i.e. ack first, as upstream deliberately does
    /// not (`esp32_run.rs:588-600` writes, `:618-624` sends) — and this fails on
    /// the frame count: the reply reaches the outbox before the write is known to
    /// have failed.
    #[test]
    fn a_share_that_cannot_be_written_is_never_acked() {
        let flash = fs_flash();
        let mut rng = entropy(43);
        let secret = identity::load_or_create(&mut *flash.borrow_mut(), &mut rng).unwrap();
        let mut session = Session::open(&flash, &secret).unwrap();
        let id = session.device_id();
        let mut out = Outbox::new(id);

        stage_a_finished_keygen(&mut session, 11);
        flash.borrow_mut().0.refuse_erases_now();
        let fault = session
            .recv(one_frame_body(id), &mut rng, &mut out)
            .expect_err("a persist failure must fail the whole message");
        assert!(
            matches!(fault, Fault::Store(store::StoreFault::Flash(_))),
            "expected a store fault, got {fault:?}"
        );
        assert_eq!(
            out.frames(),
            0,
            "the ack reached the outbox although the share was not written"
        );
        assert_eq!(
            session.signer.staged_mutations().len(),
            3,
            "a refused save must keep the staged set so a retry is possible"
        );

        // The device is not poisoned: with flash healthy the same set persists and
        // the reply goes out.
        flash.borrow_mut().0.heal();
        session
            .recv(one_frame_body(id), &mut rng, &mut out)
            .expect("dispatch after the flash recovers");
        assert!(out.frames() > 0, "the retry must answer");
        assert!(session.signer.staged_mutations().is_empty());
    }

    // -----------------------------------------------------------------------
    // GAP 2: the page cursor.
    // -----------------------------------------------------------------------

    /// The digit accepted by `d`, found through the public predicate because the
    /// value itself is private (so nothing can forge one).
    fn key_of(d: &ui::ConfirmDigit) -> u8 {
        *ui::CONFIRM_CHARSET
            .iter()
            .find(|k| d.accepts(**k))
            .expect("a drawn digit must accept one charset key")
    }

    /// Two digits that are not the same digit.
    fn two_digits(rng: &mut Entropy) -> (ui::ConfirmDigit, ui::ConfirmDigit) {
        let a = ui::ConfirmDigit::draw(rng);
        loop {
            let b = ui::ConfirmDigit::draw(rng);
            if key_of(&b) != key_of(&a) {
                return (a, b);
            }
        }
    }

    /// EVERY page of a real transaction draws, and **only the last one prints the
    /// key that signs**.
    ///
    /// Proved without a glyph decoder: the same page rendered with two different
    /// `ConfirmDigit`s gives identical pixels *unless* the digit is on it. So
    /// "differs" is "this page advertises a key", with no assumption about where
    /// the legend sits or how it is spelled.
    ///
    /// MUTATION-VERIFY. Hardcode `render(0, frame)` (the state before this change),
    /// or return `last: true` for every page, or move the digit onto a
    /// non-final page in `ui`, and this fails. A page showing "Send amount #1 of 2"
    /// with no fee that advertises a signing key is a blind signer at a
    /// one-in-five guess, which PLAN.md §4.2 forbids outright.
    #[test]
    fn only_the_last_page_of_a_transaction_advertises_the_key_that_signs() {
        let mut rng = entropy(47);
        let (a, b) = two_digits(&mut rng);
        // Two recipients and a high fee: 4 recipient pages + warning + fee +
        // confirm = 7, so "last" is well past page 0 and there is a middle.
        let task = bitcoin_task(&[(1, addressable(1)), (2, addressable(2))]);
        let pages = sign_consent(&task, |p| p.len())
            .expect("displayable")
            .expect("a bitcoin task has pages");
        assert!(pages > 2, "this task must have several pages, got {pages}");

        let draw = |page: usize, digit: ui::ConfirmDigit| {
            let mut frame = ui::Frame::new();
            let shown = sign_page(&task, digit, page, &mut frame);
            (shown, frame)
        };

        for page in 0..pages {
            let (shown, first) = draw(page, a);
            let (again, second) = draw(page, b);
            let last = page == pages - 1;
            assert_eq!(
                shown,
                Ok(Shown::Page { last }),
                "page {page} of {pages}: wrong render outcome"
            );
            assert_eq!(shown, again);
            assert_eq!(
                first.as_bytes() != second.as_bytes(),
                last,
                "page {page} of {pages}: the confirm digit is {} this page",
                if last { "missing from" } else { "printed on" }
            );
        }

        // Past the end is a refusal, not a wrap and not a clamp: an over-advanced
        // cursor draws `ui::refusal` and can consent to nothing.
        for page in [pages, pages + 1, usize::MAX] {
            assert_eq!(
                draw(page, a).0,
                Err(Refusal::Undisplayable),
                "page {page} is past the end of a {pages}-page set and must refuse"
            );
        }
    }

    /// The two facts the consent gate rests on, asserted against the SOURCE,
    /// because `SignPhase1`'s fields are private (`device.rs:143-148`) so no test
    /// in this crate can build a `SignatureRequest` prompt to drive them.
    ///
    /// Same remedy `hal/src/keypad.rs`'s
    /// `the_scan_order_is_actually_shuffled_at_the_only_call_site` uses for a call
    /// site no test can reach: pin it textually rather than leave it unenforced.
    ///
    /// MUTATION-VERIFY. Pass `0` instead of `page`, or widen the accepting arm to
    /// `Ok(Shown::Page { .. })`, and this fails. Either one means a human can
    /// authorise a page they never saw.
    #[test]
    fn the_consent_gate_uses_the_page_it_was_given_and_demands_the_last_one() {
        let src = include_str!("lib.rs");
        let body = src
            .split("pub fn confirm_at")
            .nth(1)
            .expect("confirm_at must exist");
        let call = body
            .split("prompt_screen_at(")
            .nth(1)
            .expect("confirm_at must gate on prompt_screen_at");
        let args = call
            .split("\n        ) {")
            .next()
            .expect("the gate call must be a multi-line call");
        assert!(
            args.trim_end().ends_with("\n            page,"),
            "confirm_at must render the page it was handed, not a fixed one; got \
             arguments:{args}"
        );
        let arms = call
            .split("match prompt {")
            .next()
            .expect("the gate's arms come before the prompt match");
        assert!(
            arms.contains("Ok(Shown::Page { last: true }) => {}"),
            "only the last page may authorise; got:{arms}"
        );
        assert!(
            arms.contains("Ok(_) => return Err(Fault::NotConfirmable),"),
            "every other render outcome must refuse — a no-screen prompt and a \
             deleted screen arm look identical from here; got:{arms}"
        );
    }

    /// The transitional page-0 funnel is fail-closed for a paged request: a caller
    /// with no cursor is told "not answerable", never "answerable" on page 1 of 67.
    #[test]
    fn the_page_0_funnel_reports_a_paged_transaction_as_unanswerable() {
        let mut rng = entropy(53);
        let digit = ui::ConfirmDigit::draw(&mut rng);
        let task = bitcoin_task(&[(1, addressable(3))]);
        let mut frame = ui::Frame::new();
        assert_eq!(
            sign_page(&task, digit, 0, &mut frame),
            Ok(Shown::Page { last: false }),
            "page 0 of a multi-page transaction must not be the authorising page"
        );
        // Which is what `prompt_screen`'s `Ok(false)` means for the same input, and
        // `confirm`'s `NotConfirmable`.
        assert!(!(Shown::Page { last: false } == Shown::Page { last: true }));
    }

    // -----------------------------------------------------------------------
    // GAP 3: naming.
    // -----------------------------------------------------------------------

    fn preview(name: &str) -> CoordinatorSendBody {
        CoordinatorSendBody::Naming(NameCommand::Preview(DeviceName::truncate(String::from(
            name,
        ))))
    }

    /// A preview commits NOTHING: no flash write, no `SetName`, no prompt. The
    /// coordinator sends one per typed character (`device_setup.dart:88-91`), so a
    /// preview that wrote would erase the region per keystroke and a preview that
    /// prompted would demand one keypress per letter.
    ///
    /// MUTATION-VERIFY. Save or announce the name from the `Naming` arm and this
    /// fails: a coordinator would be able to name this device with no human
    /// involved at all.
    #[test]
    fn a_previewed_name_is_neither_written_nor_announced() {
        let flash = fs_flash();
        let mut rng = entropy(59);
        let secret = identity::load_or_create(&mut *flash.borrow_mut(), &mut rng).unwrap();
        let mut session = Session::open(&flash, &secret).unwrap();
        let mut out = Outbox::new(session.device_id());

        let programs = flash.borrow().0.programs;
        let prompts = session
            .recv(preview("cold-1"), &mut rng, &mut out)
            .expect("a preview is handled");
        assert!(prompts.is_empty(), "a preview asks the human nothing");
        assert_eq!(out.frames(), 0, "a preview is not answered");
        assert_eq!(
            flash.borrow().0.programs,
            programs,
            "a preview reached flash"
        );
        assert_eq!(session.pending_name(), Some("cold-1"));
        assert_eq!(session.stored_name(), None, "a preview is not durable");

        // And it is dropped when the coordinator abandons the flow, so the NEXT
        // approved keygen cannot commit a name typed for a cancelled one.
        session
            .recv(CoordinatorSendBody::Cancel, &mut rng, &mut out)
            .expect("Cancel is handled");
        assert_eq!(session.pending_name(), None);
    }

    /// The name is committed when the keygen FINISHES, and `SetName` goes out only
    /// after the write.
    ///
    /// MUTATION-VERIFY, twice. Delete the `commit_name` call from `run`'s
    /// `FinalizeKeyGen` arm and the first half fails — the name is previewed,
    /// approved and then forgotten at the unplug, which is the state before this
    /// change. Push `SetName` before `NameStore::save` and the second half fails:
    /// the app records a `device_names` entry (`usb_serial_manager.rs:634-636`) and
    /// shows a device registered under a name it will not answer to after a reset.
    #[test]
    fn a_name_is_committed_at_finalize_and_written_before_it_is_announced() {
        let flash = fs_flash();
        let mut rng = entropy(67);
        let secret = identity::load_or_create(&mut *flash.borrow_mut(), &mut rng).unwrap();
        let mut session = Session::open(&flash, &secret).unwrap();
        let mut out = Outbox::new(session.device_id());
        session.recv(preview("cold-1"), &mut rng, &mut out).unwrap();

        // `FinalizeKeyGen` is the informational prompt `keygen_finalize` returns,
        // reachable only after a `keygen_ack` (`device/keygen.rs:273-282`, `:333`).
        let finalize = || {
            [DeviceSend::ToUser(alloc::boxed::Box::new(
                DeviceToUserMessage::FinalizeKeyGen {
                    key_name: String::from("vault"),
                },
            ))]
        };

        // A name that cannot be written is not announced, and the fault is not
        // swallowed.
        flash.borrow_mut().0.refuse_erases_now();
        let fault = session
            .run(finalize(), &mut out)
            .expect_err("a name that cannot be stored must not be announced");
        assert!(
            matches!(fault, Fault::Store(store::StoreFault::Flash(_))),
            "got {fault:?}"
        );
        assert_eq!(out.frames(), 0, "SetName went out before the write landed");
        assert_eq!(session.pending_name(), None, "the name was consumed");

        // Re-preview and do it properly.
        flash.borrow_mut().0.heal();
        session.recv(preview("cold-1"), &mut rng, &mut out).unwrap();
        let prompts = session.run(finalize(), &mut out).expect("finalize");
        assert_eq!(
            session.stored_name().as_deref(),
            Some("cold-1"),
            "the approved name was not written: it dies at the next unplug"
        );
        assert_eq!(out.frames(), 1, "exactly one SetName");
        assert!(
            out.bytes().windows(6).any(|w| w == b"cold-1"),
            "the name is not on the wire"
        );
        assert!(
            matches!(
                prompts.as_slice(),
                [DeviceToUserMessage::FinalizeKeyGen { .. }]
            ),
            "the prompt must still reach the caller, got {prompts:?}"
        );
        assert_eq!(session.pending_name(), None);
    }

    /// A stored name is announced as `SetName`, strictly AFTER `Announce`, and a
    /// device with no name still asks for one.
    ///
    /// `SetName` is the only message that populates the coordinator's
    /// `device_names` and so the only thing that registers this device
    /// (`usb_serial_manager.rs:366-375`, `coordinator.rs:232-254`, `:634-636`,
    /// `:462-478`) — the claim the comment here used to make for `NeedName`.
    /// Ordering is the app's `.expect("registered means connected already emitted")`
    /// (`device_list.rs:117-120`).
    #[test]
    fn a_stored_name_is_announced_as_setname_after_the_announce() {
        let flash = fs_flash();
        let mut rng = entropy(61);
        let secret = identity::load_or_create(&mut *flash.borrow_mut(), &mut rng).unwrap();

        let nameless = {
            let session = Session::open(&flash, &secret).unwrap();
            let mut out = Outbox::new(session.device_id());
            session.announce(Sha256Digest([1u8; 32]), &mut out).unwrap();
            assert_eq!(out.frames(), 2, "Announce and a name message");
            out.take()
        };

        NameStore::open(&flash).save("cold-1").unwrap();
        let session = Session::open(&flash, &secret).unwrap();
        assert_eq!(session.stored_name().as_deref(), Some("cold-1"));
        let mut out = Outbox::new(session.device_id());
        session.announce(Sha256Digest([1u8; 32]), &mut out).unwrap();
        assert_eq!(out.frames(), 2, "Announce and SetName");
        let named = out.bytes();

        // The name is on the wire, and it is in the SECOND frame: the announce
        // frame is byte-identical either way, so anything that differs is after it.
        assert!(
            named.windows(6).any(|w| w == b"cold-1"),
            "the stored name is not on the wire"
        );
        let common = named
            .iter()
            .zip(&nameless)
            .take_while(|(a, b)| a == b)
            .count();
        assert!(
            common > 40,
            "SetName overtook the announce: only {common} leading bytes match the \
             nameless announce, and the app's Registered handler expects the \
             connection first"
        );
    }

    /// The name a human approved is persisted BEFORE it is announced, and the
    /// bound is applied at the flash boundary.
    ///
    /// MUTATION-VERIFY. Drop `NameStore::save`'s length check and this fails —
    /// on the panic `copy_from_slice` raises for a name longer than the record,
    /// which under `panic = "abort"` is a brick. `DeviceName`'s own bound is 14
    /// CHARS (`fixed_string.rs:31-40`), i.e. up to 56 bytes, and its `Decode`
    /// truncates a `String` it has already allocated, so the byte bound has to be
    /// re-applied here.
    #[test]
    fn an_over_long_device_name_is_refused_and_nothing_is_written() {
        let flash = fs_flash();
        let store = NameStore::open(&flash);
        let programs = flash.borrow().0.programs;

        let long = "e".repeat(DEVICE_NAME_MAX_BYTES + 1);
        assert_eq!(store.save(&long), Err(store::StoreFault::TooBig));
        assert_eq!(
            flash.borrow().0.programs,
            programs,
            "a refused name reached flash"
        );
        assert_eq!(store.load(), None);

        // The whole budget still fits: 14 four-byte chars, which is the widest
        // `DeviceName` there is.
        let widest = "\u{1d11e}".repeat(frostsnap_comms::DEVICE_NAME_MAX_LENGTH);
        assert_eq!(widest.len(), DEVICE_NAME_MAX_BYTES);
        store.save(&widest).expect("the widest legal name must fit");
        assert_eq!(store.load().as_deref(), Some(widest.as_str()));
    }

    /// A torn or scribbled name region reads as NO NAME, never as a truncated
    /// name: the checksum is the last doubleword of the record, and program order
    /// is ascending (`hal/src/flash.rs:1256`).
    ///
    /// MUTATION-VERIFY. Delete the `tag != name_tag(body)` arm from
    /// `NameStore::load` and this fails: the 0xff tail decodes as a name whose
    /// length byte is whatever survived.
    #[test]
    fn a_torn_name_record_reads_as_no_name() {
        for torn in [8usize, 24, NAME_RECORD_LEN] {
            let flash = fs_flash();
            let store = NameStore::open(&flash);
            store.save("cold-1").unwrap();
            assert_eq!(store.load().as_deref(), Some("cold-1"));

            // `SlotValue` prepends a 4-byte index, so copy A's record starts 4
            // bytes into the region. This is byte-for-byte what a power cut leaves:
            // `refuse_programs_now` refuses before touching a cell, so it models a
            // clean refusal rather than a tear.
            let end = memmap::FS_NAME_OFFSET as usize + 4 + NAME_RECORD_LEN;
            flash.borrow_mut().0.scribble(end - torn, torn, 0xff);
            assert_eq!(store.load(), None, "a {torn}-byte tear read back as a name");
        }

        // The three fill patterns this board produces naturally are not names
        // either: 0xff erased flash, 0x00 zeroed SRAM, 0xef a byte of the
        // bootloader's 0xdeadbeef.
        for fill in [0xffu8, 0x00, 0xef] {
            let flash = fs_flash();
            flash.borrow_mut().0.scribble(
                memmap::FS_NAME_OFFSET as usize,
                memmap::FS_NAME_LEN as usize,
                fill,
            );
            assert_eq!(
                NameStore::open(&flash).load(),
                None,
                "a region filled with {fill:#04x} read as a name"
            );
        }
    }

    /// A forged length must not read the record's zero padding as name bytes, and
    /// must not slice out of the body.
    #[test]
    fn a_forged_name_length_is_refused_before_it_slices() {
        for len in [DEVICE_NAME_MAX_BYTES + 1, 0xff] {
            let flash = fs_flash();
            let store = NameStore::open(&flash);
            store.save("cold-1").unwrap();

            // The record is deterministic, so the forged body is built here rather
            // than read back off flash — and re-tagged, so the length is the only
            // thing wrong with it and the checksum cannot be what refuses.
            let mut body = [0u8; NAME_TAG_OFF];
            body[0] = len as u8;
            body[NAME_OFF..NAME_OFF + 6].copy_from_slice(b"cold-1");
            let tag = name_tag(&body);
            let base = memmap::FS_NAME_OFFSET as usize + 4;
            {
                let mut f = flash.borrow_mut();
                for (i, b) in body.iter().chain(tag.iter()).enumerate() {
                    f.0.scribble(base + i, 1, *b);
                }
            }
            assert_eq!(store.load(), None, "length {len} was accepted");
        }
    }

    // -----------------------------------------------------------------------
    // GAP 4: DisplayBackup — consent, then the reveal, and nothing in between.
    // -----------------------------------------------------------------------

    /// A real key, one real share of it, and the `DisplayBackup` request a
    /// coordinator sends to ask for that share.
    ///
    /// Nothing here is faked past the point it matters. The share comes out of
    /// `frost_backup::ShareBackup::generate_shares`, so its polynomial checksum is
    /// upstream's; it is encrypted under the key **this device's** `Secrets` derives
    /// for that `(access structure, index, coordinator contribution)` triple, so the
    /// decrypt under test is the shipped derivation and not a stub; and `words` is
    /// `ShareBackup::to_words()` computed here, independently of anything `lib.rs`
    /// does, so it is a real answer to compare against rather than a restatement.
    ///
    /// `Fingerprint::NONE` rather than `frost_backup::FINGERPRINT`: the production
    /// fingerprint grinds 18 zero bits per coefficient (`schnorr_fun`'s
    /// `Fingerprint::FROST_V0`), i.e. ~262,144 hashes, which in a debug test build is
    /// minutes. Nothing on the path under test reads a fingerprint — it is a
    /// coordinator-side resource-exhaustion guard — so grinding one would buy the
    /// test nothing but wall clock.
    ///
    /// The three mutations go in through `FrostSigner::apply_mutation`, which is
    /// exactly how `Session::open` replays a share off flash
    /// (`a_persisted_keygen_survives_a_reset_and_answers_request_held_shares` covers
    /// the flash leg), so the device state here is the post-unplug state.
    struct HeldBackup {
        request: CoordinatorSendBody,
        words: [&'static str; ui::BACKUP_WORDS],
        index: u32,
    }

    fn hold_a_backup(
        session: &mut Session<'_, DebugFlash<FakeFlash>>,
        secret: &identity::IdentitySecret,
        rng: &mut Entropy,
    ) -> HeldBackup {
        use frostsnap_core::device::{
            keys::KeyMutation, EncryptedSecretShare, KeyPurpose, Mutation, SaveShareMutation,
        };
        use frostsnap_core::AccessStructureKind;

        let group = Scalar::<Secret, NonZero>::from_bytes([0x2bu8; 32])
            .expect("a fixed non-zero scalar below the order");
        let (shares, root_shared_key) = frost_backup::ShareBackup::generate_shares(
            group,
            1,
            1,
            frost_backup::Fingerprint::NONE,
            rng,
        );
        let backup = shares.into_iter().next().expect("one share was asked for");
        let words = backup.to_words();
        let share_index = backup.index();
        let index = u32::try_from(share_index).expect("index 1 fits a u32");
        let access_structure_ref = AccessStructureRef::from_root_shared_key(&root_shared_key);
        let coord_share_decryption_contrib = CoordShareDecryptionContrib::for_master_share(
            session.device_id(),
            share_index,
            &root_shared_key,
        );
        let secret_share = backup
            .extract_secret(&root_shared_key)
            .expect("the poly we generated the share from");
        let encrypted_secret_share = EncryptedSecretShare::encrypt(
            secret_share,
            access_structure_ref,
            coord_share_decryption_contrib,
            &mut Secrets::new(secret),
            rng,
        );

        for mutation in [
            Mutation::Keygen(KeyMutation::NewKey {
                key_id: access_structure_ref.key_id,
                key_name: String::from("vault"),
                purpose: KeyPurpose::Test,
            }),
            Mutation::Keygen(KeyMutation::NewAccessStructure {
                access_structure_ref,
                threshold: 1,
                kind: AccessStructureKind::Master,
            }),
            Mutation::Keygen(KeyMutation::SaveShare(alloc::boxed::Box::new(
                SaveShareMutation {
                    access_structure_ref,
                    encrypted_secret_share,
                },
            ))),
        ] {
            let _ = session.signer.apply_mutation(mutation);
        }

        HeldBackup {
            request: CoordinatorSendBody::Core(CoordinatorToDeviceMessage::Restoration(
                CoordinatorRestoration::DisplayBackup {
                    access_structure_ref,
                    coord_share_decryption_contrib,
                    share_index,
                    root_shared_key,
                },
            )),
            words,
            index,
        }
    }

    /// A live session holding one real share, plus the request for it. The shipped
    /// constructor over the shipped geometry; only the keygen that produced the share
    /// is stood in for.
    fn a_device_holding_a_backup<'a>(
        flash: &'a RefCell<DebugFlash<FakeFlash>>,
        rng: &mut Entropy,
    ) -> (Session<'a, DebugFlash<FakeFlash>>, HeldBackup) {
        let secret = identity::load_or_create(&mut *flash.borrow_mut(), rng)
            .expect("a blank fake flash must yield a fresh identity");
        let mut session = Session::open(flash, &secret).expect("signer construction");
        let held = hold_a_backup(&mut session, &secret, rng);
        (session, held)
    }

    /// The text of one row, read back out of the PIXELS by reverse glyph lookup —
    /// so these assertions are about what a human would see and not about what a
    /// formatter was handed.
    ///
    /// `cols` is capped at 12 for a word row: `mark_sensitive`'s noise runs from
    /// x=97 (`hal/src/ui.rs`'s `SENSITIVE_MAX` = 31 against `WIDTH` = 128), which
    /// lands inside cell 12, so cells 0..=11 are the ones a glyph lookup can match.
    /// That is also exactly the `"NN: " + 8 letters` budget the noise geometry
    /// reserves.
    fn row_text(frame: &ui::Frame, row: usize, cols: usize) -> String {
        (0..cols)
            .map(|col| frame.cell(col, row).map_or('~', |(c, _)| c as char))
            .collect::<String>()
            .trim_end()
            .to_string()
    }

    fn all_rows(frame: &ui::Frame, cols: usize) -> String {
        (0..ui::ROWS)
            .map(|row| row_text(frame, row, cols))
            .collect::<StdVec<_>>()
            .join("\n")
    }

    /// Drive the request to the one prompt it produces.
    fn backup_prompt(
        session: &mut Session<'_, DebugFlash<FakeFlash>>,
        held: &HeldBackup,
        rng: &mut Entropy,
        out: &mut Outbox,
    ) -> DeviceToUserMessage {
        let mut prompts = session
            .recv(held.request.clone(), rng, out)
            .expect("a backup we hold must reach the human");
        assert_eq!(prompts.len(), 1, "one request, one question");
        prompts.pop().expect("checked above")
    }

    /// **CONSENT PRECEDES THE REVEAL.** `recv` returns the question and answers
    /// nothing; the words appear only after `confirm_at`, and never before.
    ///
    /// MUTATION-VERIFY. Set `self.reveal` from `recv_core`'s `DisplayBackup` arm —
    /// which is the shape a "just wire it up" patch takes, because that is where the
    /// phase first exists — and the `show_backup` call before the confirm succeeds,
    /// failing this test on "a backup was drawn with no consent behind it". Delete
    /// the `self.reveal.take()` guard in `show_backup` and it does not compile, which
    /// is the stronger version of the same property.
    #[test]
    fn a_backup_is_never_drawn_before_the_digit_is_pressed() {
        let flash = fs_flash();
        let mut rng = entropy(71);
        let (mut session, held) = a_device_holding_a_backup(&flash, &mut rng);
        let mut out = Outbox::new(session.device_id());

        let prompt = backup_prompt(&mut session, &held, &mut rng, &mut out);
        assert_eq!(
            out.frames(),
            0,
            "`recv` must answer NOTHING for a backup request"
        );

        // BEFORE the confirm: no grant, no pixels.
        let mut frame = ui::Frame::new();
        assert!(
            matches!(
                session.show_backup(0, &mut frame, &mut rng),
                Err(Fault::Refused(Refusal::DisplayBackup))
            ),
            "a backup was drawn with no consent behind it"
        );
        assert!(
            frame.as_bytes().iter().all(|b| *b == 0),
            "a refused reveal touched the frame"
        );

        // The consent screen, then the digit.
        assert_eq!(
            prompt_screen(&mut frame, &prompt, ui::ConfirmDigit::draw(&mut rng)),
            Ok(true),
            "the backup question must be a single-page screen that prints a key"
        );
        session
            .confirm(prompt, &mut rng, &mut out)
            .expect("the reveal grant");
        assert_eq!(
            out.frames(),
            0,
            "consenting to a reveal must not answer the coordinator either"
        );

        // AFTER: every page draws.
        for page in 0..1 + ui::BACKUP_WORDS.div_ceil(ui::WORDS_PER_PAGE) {
            assert!(
                session
                    .show_backup(page, &mut frame, &mut rng)
                    .expect("a granted reveal must draw"),
                "page {page} of a granted reveal did not draw"
            );
        }
    }

    /// The consent screen carries **NO WORD**, and it prints the digit that grants
    /// the reveal.
    ///
    /// Both halves matter and they are the same defect from two sides: a screen that
    /// shows words before the press has already leaked them, and a screen that prints
    /// no digit is one no human can answer — so any key would have to be accepted.
    ///
    /// The digit half is proved without a glyph decoder, the same way
    /// `only_the_last_page_of_a_transaction_advertises_the_key_that_signs` does it:
    /// two renders of the same screen with two different `ConfirmDigit`s differ in
    /// their pixels only if the digit is on the screen.
    ///
    /// MUTATION-VERIFY, twice. Draw the words on the consent screen (pass the phase
    /// to `backup_consent` and page `BackupPages` there) and the first half fails,
    /// naming the word. Drop the `Press (N)` line from `backup_consent` and the
    /// second half fails: the screen asks for a key it never showed.
    #[test]
    fn the_backup_consent_screen_shows_no_word_and_prints_the_digit() {
        let flash = fs_flash();
        let mut rng = entropy(73);
        let (mut session, held) = a_device_holding_a_backup(&flash, &mut rng);
        let mut out = Outbox::new(session.device_id());
        let prompt = backup_prompt(&mut session, &held, &mut rng, &mut out);

        let (a, b) = two_digits(&mut rng);
        let draw = |digit: ui::ConfirmDigit| {
            let mut frame = ui::Frame::new();
            let shown = prompt_screen_at(&mut frame, &prompt, digit, 0);
            (shown, frame)
        };
        let (shown, first) = draw(a);
        assert_eq!(
            shown,
            Ok(Shown::Page { last: true }),
            "the backup question is one page and it is the page that authorises"
        );

        let text = all_rows(&first, ui::COLS);
        for (i, word) in held.words.iter().enumerate() {
            assert!(
                !text.contains(word),
                "word {} ({word:?}) is on the CONSENT screen — it was revealed before \
                 anyone consented to it. Screen:\n{text}",
                i + 1
            );
        }
        // It does say which share, so a human can match it against the request.
        let mut what = ui::Buf::<16>::new();
        what.push_str("share #").push_u64(held.index as u64);
        assert!(
            text.contains(what.as_str()),
            "the consent screen must name the share index; got:\n{text}"
        );

        let (again, second) = draw(b);
        assert_eq!(again, shown);
        assert!(
            first.as_bytes() != second.as_bytes(),
            "the consent screen does not print the confirm digit, so no human can \
             read the key that grants the reveal"
        );
    }

    /// The words on the glass are the words `frost_backup` derives from the stored
    /// share — all 25, in order, once each.
    ///
    /// The cross-crate check `every_vendored_bip39_word_is_renderable` makes; this is
    /// the other half of it, and it is what a mutation in the derivation would fail.
    /// Read back out of the PIXELS, so it covers the layout too: a page that drew the
    /// right word at the wrong number, or dropped one, fails here.
    ///
    /// MUTATION-VERIFY. Render `page` instead of `page` — i.e. hand `BackupPages` a
    /// fixed page — and the words repeat. Reuse `BackupPages::new(1, ..)` with a
    /// hardcoded index and the share-index page names the wrong share.
    #[test]
    fn the_revealed_backup_is_the_words_frost_backup_derives_in_order() {
        let flash = fs_flash();
        let mut rng = entropy(79);
        let (mut session, held) = a_device_holding_a_backup(&flash, &mut rng);
        let mut out = Outbox::new(session.device_id());
        let prompt = backup_prompt(&mut session, &held, &mut rng, &mut out);
        session.confirm(prompt, &mut rng, &mut out).expect("grant");

        // Page 0 is the share index, and it is not optional: a backup written down
        // without it is unrestorable.
        let mut frame = ui::Frame::new();
        assert!(session.show_backup(0, &mut frame, &mut rng).unwrap());
        let mut expect_index = ui::Buf::<16>::new();
        expect_index.push_str("#").push_u64(held.index as u64);
        let page0 = all_rows(&frame, ui::COLS);
        assert!(
            page0.contains(expect_index.as_str()),
            "the share-index page must name share {}; got:\n{page0}",
            held.index
        );

        // Then every word, at its own number.
        let mut seen = StdVec::new();
        let pages = 1 + ui::BACKUP_WORDS.div_ceil(ui::WORDS_PER_PAGE);
        for page in 1..pages {
            assert!(session.show_backup(page, &mut frame, &mut rng).unwrap());
            for row in 0..ui::WORDS_PER_PAGE {
                let number = (page - 1) * ui::WORDS_PER_PAGE + row + 1;
                if number > ui::BACKUP_WORDS {
                    break;
                }
                let line = row_text(&frame, 2 + row, 12);
                let mut want = ui::Buf::<12>::new();
                want.push_u8_pad2(number as u8)
                    .push_str(": ")
                    .push_str(held.words[number - 1]);
                assert_eq!(
                    line,
                    want.as_str(),
                    "page {page} row {row}: word {number} is wrong on the glass"
                );
                seen.push(held.words[number - 1]);
            }
        }
        assert_eq!(
            seen.len(),
            ui::BACKUP_WORDS,
            "the reveal showed {} of {} words",
            seen.len(),
            ui::BACKUP_WORDS
        );
    }

    /// **NO SHARE MATERIAL REACHES THE OUTBOX** on any path this flow adds — not a
    /// word, not the index, not a `Debug` line.
    ///
    /// The whole flow is driven, including a page past the end and a second reveal
    /// attempt, and then the outbox is searched for every one of the 25 words. The
    /// structural version of the same claim is stronger and worth stating beside it:
    /// `Session::show_backup` has no `Outbox` parameter, so the function that holds
    /// the plaintext cannot reach the wire at all.
    ///
    /// MUTATION-VERIFY. Push the words as a `DeviceSendBody::Debug` from
    /// `confirm_at`'s `DisplayBackup` arm — the shape a "let the harness see it" patch
    /// takes — and this fails on the first word.
    /// `nothing_but_the_outbox_truncating_arm_may_construct_a_debug_send` is the
    /// second net and catches the same edit textually.
    #[test]
    fn no_word_of_a_revealed_backup_ever_reaches_the_outbox() {
        let flash = fs_flash();
        let mut rng = entropy(83);
        let (mut session, held) = a_device_holding_a_backup(&flash, &mut rng);
        let mut out = Outbox::new(session.device_id());

        // Announce first, so the outbox is not trivially empty and the search below
        // is a search rather than a length check.
        session.announce(Sha256Digest([9u8; 32]), &mut out).unwrap();
        let framed = out.frames();
        assert!(framed > 0);

        let prompt = backup_prompt(&mut session, &held, &mut rng, &mut out);
        session.confirm(prompt, &mut rng, &mut out).expect("grant");
        let mut frame = ui::Frame::new();
        let pages = 1 + ui::BACKUP_WORDS.div_ceil(ui::WORDS_PER_PAGE);
        for page in 0..=pages {
            let _ = session.show_backup(page, &mut frame, &mut rng);
        }
        assert_eq!(
            out.frames(),
            framed,
            "the backup flow put {} extra frame(s) on the wire",
            out.frames() - framed
        );

        let bytes = out.bytes();
        for (i, word) in held.words.iter().enumerate() {
            let needle = word.as_bytes();
            assert!(
                !bytes.windows(needle.len()).any(|w| w == needle),
                "word {} ({word:?}) reached the outbox",
                i + 1
            );
            // And in the case the table's own case does not match the wire's.
            let lower = word.to_lowercase();
            assert!(
                !bytes
                    .windows(lower.len())
                    .any(|w| w.eq_ignore_ascii_case(lower.as_bytes())),
                "word {} ({word:?}) reached the outbox in some other case",
                i + 1
            );
        }
    }

    /// A grant is for ONE reveal: it ends when the pages run out, and `Cancel`
    /// revokes it mid-way.
    ///
    /// The `Cancel` half is the one that matters. A coordinator that abandons the
    /// ceremony must not leave a live grant behind for the next `show_backup` call to
    /// honour — the human consented to reveal a share to *that* flow.
    ///
    /// MUTATION-VERIFY. Drop `self.reveal = None` from `recv`'s `Cancel` arm and the
    /// second half fails: a cancelled backup keeps drawing. Borrow instead of taking
    /// in `show_backup` (`self.reveal.as_ref()`) and the first half fails: the reveal
    /// never ends, so one consent grants every future page for the rest of the boot.
    #[test]
    fn a_reveal_grant_ends_with_its_pages_and_is_revoked_by_cancel() {
        let flash = fs_flash();
        let mut rng = entropy(89);
        let (mut session, held) = a_device_holding_a_backup(&flash, &mut rng);
        let mut out = Outbox::new(session.device_id());
        let pages = 1 + ui::BACKUP_WORDS.div_ceil(ui::WORDS_PER_PAGE);
        let mut frame = ui::Frame::new();

        // Run off the end: the page past the last is `false`, and that ENDS it.
        let prompt = backup_prompt(&mut session, &held, &mut rng, &mut out);
        session.confirm(prompt, &mut rng, &mut out).expect("grant");
        for page in 0..pages {
            assert!(session.show_backup(page, &mut frame, &mut rng).unwrap());
        }
        assert!(
            !session
                .show_backup(pages, &mut frame, &mut rng)
                .expect("past the end is not a fault, it is the end"),
            "there must be no page after the last one"
        );
        assert!(
            matches!(
                session.show_backup(0, &mut frame, &mut rng),
                Err(Fault::Refused(Refusal::DisplayBackup))
            ),
            "the grant outlived its reveal: a second look needs a second consent"
        );

        // Cancel mid-reveal.
        let prompt = backup_prompt(&mut session, &held, &mut rng, &mut out);
        session.confirm(prompt, &mut rng, &mut out).expect("grant");
        assert!(session.show_backup(1, &mut frame, &mut rng).unwrap());
        session
            .recv(CoordinatorSendBody::Cancel, &mut rng, &mut out)
            .expect("Cancel is handled");
        assert!(
            matches!(
                session.show_backup(2, &mut frame, &mut rng),
                Err(Fault::Refused(Refusal::DisplayBackup))
            ),
            "a cancelled ceremony left a live reveal grant behind"
        );
    }

    /// **A backup nobody revealed can never be acked as recorded**, and one that was
    /// can be acked exactly once.
    ///
    /// The ack is a claim to the coordinator that 25 words exist on paper; the app
    /// closes its dialog and shows the wallet as backed up
    /// (`display_backup.rs:87-93`). So the fail-open direction is a user who believes
    /// they have a backup and does not, which is unrecoverable in exactly the case
    /// the backup existed for. Hence: unreachable without a reveal that RAN TO ITS
    /// END, and one-shot.
    ///
    /// MUTATION-VERIFY. Make `backup_recorded` unconditional (drop the
    /// `core::mem::take` guard and its `Err`) and both the fresh-session leg and the
    /// second-call leg fail. Set `record_pending` on the `Ok(true)` leg of
    /// `show_backup` instead of `Ok(false)` — the "arm it as soon as we start
    /// drawing" simplification — and the mid-reveal leg fails: a human could ack
    /// after seeing the share index and no word.
    #[test]
    fn only_a_reveal_that_ran_to_its_end_can_be_acked_as_recorded() {
        let flash = fs_flash();
        let mut rng = entropy(101);
        let (mut session, held) = a_device_holding_a_backup(&flash, &mut rng);
        let mut out = Outbox::new(session.device_id());
        let pages = 1 + ui::BACKUP_WORDS.div_ceil(ui::WORDS_PER_PAGE);
        let mut frame = ui::Frame::new();

        // A device that has revealed nothing.
        assert!(!session.record_pending());
        assert!(
            matches!(
                session.backup_recorded(&mut out),
                Err(Fault::Refused(Refusal::DisplayBackup))
            ),
            "a device that never revealed a backup acked one as recorded"
        );

        let prompt = backup_prompt(&mut session, &held, &mut rng, &mut out);
        session.confirm(prompt, &mut rng, &mut out).expect("grant");
        // Consent is not a reveal, and the first pages are not the last one.
        assert!(!session.record_pending(), "the grant alone armed the ack");
        for page in 0..pages {
            assert!(session.show_backup(page, &mut frame, &mut rng).unwrap());
            assert!(
                !session.record_pending(),
                "page {page} of {pages} armed the ack before the words ran out"
            );
        }

        // Off the end: the reveal is over, so now a human may be asked.
        let framed = out.frames();
        assert!(!session.show_backup(pages, &mut frame, &mut rng).unwrap());
        assert!(
            session.record_pending(),
            "a finished reveal did not arm the ack"
        );
        // Still nothing on the wire until a key is pressed: `show_backup` has no
        // outbox and `record_pending` is not an ack.
        assert_eq!(
            out.frames(),
            framed,
            "the reveal ending sent something itself"
        );

        session.backup_recorded(&mut out).expect("the ack");
        assert_eq!(out.frames(), framed + 1, "the ack did not reach the outbox");
        // One reveal, one ack. A second press must not re-claim it.
        assert!(!session.record_pending());
        assert!(
            matches!(
                session.backup_recorded(&mut out),
                Err(Fault::Refused(Refusal::DisplayBackup))
            ),
            "one reveal acked twice"
        );

        // And the ack itself carries no share material — it is a unit variant, so
        // this is checking the encoder as much as the call.
        let bytes = out.bytes();
        for word in held.words.iter() {
            let lower = word.to_lowercase();
            assert!(
                !bytes
                    .windows(lower.len())
                    .any(|w| w.eq_ignore_ascii_case(lower.as_bytes())),
                "{word:?} reached the outbox on the recorded ack"
            );
        }
    }

    /// **A reveal a human WALKED OUT OF cannot be acked**, and it reaches
    /// [`Session::show_backup`] looking exactly like one that finished.
    ///
    /// This is the hazard the bit set exists for. `main.rs` deliberately has ONE
    /// ending: any unadvertised key on a backup page asks for the page past the last,
    /// the same call the natural `(9)next` off the end makes. So "a page was drawn,
    /// then the set ended" is equally what `x` on page 0 looks like, and arming on
    /// that would put "wrote it down?" in front of someone who has seen the share
    /// index and no word — one fumbled digit from an app that presents an
    /// unbacked-up wallet as backed up.
    ///
    /// The forwards-and-backwards leg is why a high-water page number is not enough
    /// either: it is only "every page" that licenses the ack, and it stays licensed
    /// once earned however the human then pages.
    ///
    /// MUTATION-VERIFY, all four caught here:
    ///   * `self.record_pending = true` on the `Ok(false)` leg (the pre-bit-set
    ///     shape) — the abort legs fail.
    ///   * `page_bit`/`all_pages` off by one (`bits` for `bits - 1`) — the completed
    ///     leg fails, because a whole set never equals the mask.
    ///   * drop either half of `confirm_at`'s grant reset — the last two legs fail,
    ///     one for `record_pending` and one for `seen_pages`.
    #[test]
    fn a_reveal_the_human_abandoned_early_cannot_be_acked_as_recorded() {
        let flash = fs_flash();
        let mut rng = entropy(109);
        let (mut session, held) = a_device_holding_a_backup(&flash, &mut rng);
        let mut out = Outbox::new(session.device_id());
        let pages = 1 + ui::BACKUP_WORDS.div_ceil(ui::WORDS_PER_PAGE);
        let mut frame = ui::Frame::new();

        // `x` on the share-index page: one page drawn, then the same end-of-set call
        // the natural ending makes.
        let prompt = backup_prompt(&mut session, &held, &mut rng, &mut out);
        session.confirm(prompt, &mut rng, &mut out).expect("grant");
        assert!(session.show_backup(0, &mut frame, &mut rng).unwrap());
        assert!(!session.show_backup(pages, &mut frame, &mut rng).unwrap());
        assert!(
            !session.record_pending(),
            "walking out on the share-index page armed the ack: no word was drawn"
        );

        // And one page short of the end is still short.
        let prompt = backup_prompt(&mut session, &held, &mut rng, &mut out);
        session.confirm(prompt, &mut rng, &mut out).expect("grant");
        for page in 0..pages - 1 {
            assert!(session.show_backup(page, &mut frame, &mut rng).unwrap());
        }
        assert!(!session.show_backup(pages, &mut frame, &mut rng).unwrap());
        assert!(
            !session.record_pending(),
            "{} of {pages} pages armed the ack: the last four words were never drawn",
            pages - 1
        );
        let framed = out.frames();
        assert!(
            matches!(
                session.backup_recorded(&mut out),
                Err(Fault::Refused(Refusal::DisplayBackup))
            ),
            "a reveal that skipped a page was acked as recorded"
        );
        assert_eq!(out.frames(), framed, "a refused ack still reached the wire");

        // A caller that JUMPS to the last page has shown no more than one page,
        // whatever the number on it. `boot()` cannot do this — it pages `+1`/`-1` —
        // but `boot()` is `cfg(target_arch = "arm")` and no gate here executes it, so
        // the rule is enforced where it can be checked.
        let prompt = backup_prompt(&mut session, &held, &mut rng, &mut out);
        session.confirm(prompt, &mut rng, &mut out).expect("grant");
        assert!(session
            .show_backup(pages - 1, &mut frame, &mut rng)
            .unwrap());
        assert!(!session.show_backup(pages, &mut frame, &mut rng).unwrap());
        assert!(
            !session.record_pending(),
            "jumping to the last page armed the ack"
        );

        // The whole set, and then paging back: earned, and it stays earned.
        let prompt = backup_prompt(&mut session, &held, &mut rng, &mut out);
        session.confirm(prompt, &mut rng, &mut out).expect("grant");
        for page in 0..pages {
            assert!(session.show_backup(page, &mut frame, &mut rng).unwrap());
        }
        assert!(session.show_backup(1, &mut frame, &mut rng).unwrap());
        assert!(!session.show_backup(pages, &mut frame, &mut rng).unwrap());
        assert!(
            session.record_pending(),
            "a reveal that showed every page and was then paged back did not arm the ack"
        );
        session.backup_recorded(&mut out).expect("the ack");

        // A NEW grant retires the previous question. Show everything, do not answer,
        // then start again and walk out: nothing is owed to the second ceremony, and
        // the ack names no share, so the first one's credit must not close its dialog.
        let prompt = backup_prompt(&mut session, &held, &mut rng, &mut out);
        session.confirm(prompt, &mut rng, &mut out).expect("grant");
        for page in 0..pages {
            assert!(session.show_backup(page, &mut frame, &mut rng).unwrap());
        }
        assert!(!session.show_backup(pages, &mut frame, &mut rng).unwrap());
        assert!(session.record_pending());
        let prompt = backup_prompt(&mut session, &held, &mut rng, &mut out);
        session.confirm(prompt, &mut rng, &mut out).expect("grant");
        assert!(
            !session.record_pending(),
            "a new grant left the previous reveal's unanswered question armed"
        );
        assert!(session.show_backup(0, &mut frame, &mut rng).unwrap());
        assert!(!session.show_backup(pages, &mut frame, &mut rng).unwrap());
        assert!(
            !session.record_pending(),
            "the previous reveal's pages counted towards this one's set"
        );
    }

    /// The two bit-set helpers, at the edges the reveal never reaches — because the
    /// day [`ui::WORDS_PER_PAGE`] changes is the day they do.
    ///
    /// MUTATION-VERIFY. `1u32 << page` for `page_bit`'s `checked_shl` and the page-32
    /// case fails (in release it would alias page 0, and `overflow-checks = false`
    /// means silently). `Some(bits)` for `Some(bits - 1)` and every case fails.
    #[test]
    fn a_page_set_too_wide_for_the_bits_refuses_rather_than_wrapping() {
        assert_eq!(page_bit(0), Some(1));
        assert_eq!(page_bit(7), Some(0x80));
        assert_eq!(page_bit(31), Some(1 << 31));
        assert_eq!(page_bit(32), None, "page 32 aliased page 0");
        assert_eq!(page_bit(usize::MAX), None);

        assert_eq!(all_pages(0), None, "an empty set counted as fully seen");
        assert_eq!(all_pages(1), Some(0b1));
        // The shipped geometry: 1 index page + 7 word pages.
        assert_eq!(
            all_pages(1 + ui::BACKUP_WORDS.div_ceil(ui::WORDS_PER_PAGE)),
            Some(0xff)
        );
        // 31 and not 32: the mask is built from the bit ONE PAST the last page, so a
        // 32-page set has no representable "all seen" value and is refused.
        assert_eq!(all_pages(31), Some(u32::MAX >> 1));
        assert_eq!(all_pages(32), None, "a 32-page set claimed a complete u32");
    }

    /// A ceremony the coordinator ABANDONED acks nothing, even if the human had
    /// already read every word.
    ///
    /// MUTATION-VERIFY. Drop `self.record_pending = false` from `recv`'s `Cancel` arm
    /// and this fails.
    #[test]
    fn a_cancelled_ceremony_cannot_be_acked_as_recorded() {
        let flash = fs_flash();
        let mut rng = entropy(103);
        let (mut session, held) = a_device_holding_a_backup(&flash, &mut rng);
        let mut out = Outbox::new(session.device_id());
        let pages = 1 + ui::BACKUP_WORDS.div_ceil(ui::WORDS_PER_PAGE);
        let mut frame = ui::Frame::new();

        let prompt = backup_prompt(&mut session, &held, &mut rng, &mut out);
        session.confirm(prompt, &mut rng, &mut out).expect("grant");
        for page in 0..pages {
            assert!(session.show_backup(page, &mut frame, &mut rng).unwrap());
        }
        assert!(!session.show_backup(pages, &mut frame, &mut rng).unwrap());
        assert!(session.record_pending());

        session
            .recv(CoordinatorSendBody::Cancel, &mut rng, &mut out)
            .expect("Cancel is handled");
        assert!(!session.record_pending(), "Cancel left the question armed");
        assert!(
            matches!(
                session.backup_recorded(&mut out),
                Err(Fault::Refused(Refusal::DisplayBackup))
            ),
            "an abandoned ceremony was acked as recorded"
        );
    }

    /// Every word row of the reveal is noised, so PLAN.md §4.2's side-channel
    /// defence is on the one path that actually puts a share on the glass.
    ///
    /// Asserted as freshness rather than by re-deriving `mark_sensitive`'s geometry
    /// (which `hal` already pins): two renders of the SAME page differ, and they
    /// differ only to the right of the 12-cell word budget, so the noise is on the
    /// row and not over the letters.
    ///
    /// MUTATION-VERIFY. Draw the words in `show_backup` with a `frame.text` loop
    /// instead of `ui::BackupPages::render` — the shape a "why do I need an RNG here"
    /// simplification takes — and this fails: two renders become identical.
    #[test]
    fn every_word_row_of_a_reveal_is_noised_and_the_words_stay_readable() {
        let flash = fs_flash();
        let mut rng = entropy(97);
        let (mut session, held) = a_device_holding_a_backup(&flash, &mut rng);
        let mut out = Outbox::new(session.device_id());
        let prompt = backup_prompt(&mut session, &held, &mut rng, &mut out);
        session.confirm(prompt, &mut rng, &mut out).expect("grant");

        let mut first = ui::Frame::new();
        let mut second = ui::Frame::new();
        assert!(session.show_backup(1, &mut first, &mut rng).unwrap());
        assert!(session.show_backup(1, &mut second, &mut rng).unwrap());
        assert!(
            first.as_bytes() != second.as_bytes(),
            "two renders of the same backup page are identical: the word rows are \
             not noised, so PLAN.md §4.2's defence is absent on the reveal path"
        );

        // The words are the same on both, and the difference is all in the margin.
        for row in 0..ui::WORDS_PER_PAGE {
            assert_eq!(
                row_text(&first, 2 + row, 12),
                row_text(&second, 2 + row, 12),
                "the noise reached the letters on word row {row}"
            );
        }
        let differing_columns = (0..ui::WIDTH)
            .filter(|x| (0..ui::HEIGHT).any(|y| first.pixel(*x, y) != second.pixel(*x, y)))
            .collect::<StdVec<_>>();
        assert!(
            differing_columns.iter().all(|x| *x >= 12 * ui::CELL),
            "the two renders differ inside the 12-cell word budget: columns \
             {differing_columns:?}"
        );
    }

    /// Only page 0 of the backup question may authorise, and no other page of it can
    /// be drawn at all.
    ///
    /// The consent screen is one page, so a caller handing `confirm_at` a page it
    /// invented must not be able to keep guessing until something answers
    /// `last: true`. Nothing on the device produces this — `main.rs`'s `answer`
    /// clamps the advance key on a last page — which is exactly why it is worth a
    /// test rather than a comment.
    ///
    /// MUTATION-VERIFY. Ignore `page` in `prompt_screen_at`'s `DisplayBackup` arm and
    /// this fails on page 1.
    #[test]
    fn only_page_0_of_the_backup_question_draws_or_authorises() {
        let flash = fs_flash();
        let mut rng = entropy(101);
        let (mut session, held) = a_device_holding_a_backup(&flash, &mut rng);
        let mut out = Outbox::new(session.device_id());
        let prompt = backup_prompt(&mut session, &held, &mut rng, &mut out);
        let digit = ui::ConfirmDigit::draw(&mut rng);

        for page in [1usize, 2, 8, usize::MAX] {
            let mut frame = ui::Frame::new();
            assert_eq!(
                prompt_screen_at(&mut frame, &prompt, digit, page),
                Err(Refusal::DisplayBackup),
                "page {page} of a one-page question must refuse"
            );
            let fault = session
                .confirm_at(prompt.clone(), page, &mut rng, &mut out)
                .expect_err("a page that does not draw cannot authorise");
            assert!(
                matches!(fault, Fault::Refused(Refusal::DisplayBackup)),
                "page {page}: got {fault:?}"
            );
            let mut glass = ui::Frame::new();
            assert!(
                matches!(
                    session.show_backup(0, &mut glass, &mut rng),
                    Err(Fault::Refused(Refusal::DisplayBackup))
                ),
                "page {page} granted a reveal"
            );
        }
        assert_eq!(out.frames(), 0, "a refused question must not answer");
    }

    // -----------------------------------------------------------------------
    // GAP 5: the RESTORE — consent, then 25 typed words, then the store.
    //
    // This is the one flow on the device that INGESTS a secret, so every test
    // below asserts on a fail-closed direction: no ingest without the digit, no
    // ack without 25 words that checksum, no flash write after the ack, no word
    // and no scalar on the wire, and nothing discarded when a checksum refuses.
    // -----------------------------------------------------------------------

    /// A real share to type back IN, and the plaintext that must never leave.
    ///
    /// `generate_shares` is upstream's own generator, so `words` is a genuine
    /// 25-word backup with a real polynomial checksum — which is what makes the
    /// `Consolidate` leg below a real validation rather than a stub. `plaintext` is
    /// the scalar those words encode, kept for the byte searches.
    ///
    /// `Fingerprint::NONE` for `hold_a_backup`'s reason: the production fingerprint
    /// grinds ~262,144 hashes per coefficient and nothing on this path reads one.
    struct ShareToTypeIn {
        index: u32,
        share_index: ShareIndex,
        share_image: ShareImage,
        words: [&'static str; ui::BACKUP_WORDS],
        root_shared_key: frostsnap_core::schnorr_fun::frost::SharedKey,
        plaintext: [u8; 32],
    }

    fn a_share_to_type_in(rng: &mut Entropy) -> ShareToTypeIn {
        a_share_of_group(rng, 0x3d)
    }

    fn a_share_of_group(rng: &mut Entropy, group_seed: u8) -> ShareToTypeIn {
        let group = Scalar::<Secret, NonZero>::from_bytes([group_seed; 32])
            .expect("a fixed non-zero scalar below the order");
        let (shares, root_shared_key) = frost_backup::ShareBackup::generate_shares(
            group,
            1,
            1,
            frost_backup::Fingerprint::NONE,
            rng,
        );
        let backup = shares.into_iter().next().expect("one share was asked for");
        let share_index = backup.index();
        ShareToTypeIn {
            index: u32::try_from(share_index).expect("index 1 fits a u32"),
            share_index,
            share_image: backup.share_image(),
            words: backup.to_words(),
            plaintext: backup
                .clone()
                .extract_secret(&root_shared_key)
                .expect("the polynomial we generated it from")
                .share
                .to_bytes(),
            root_shared_key,
        }
    }

    const RESTORED_KEY_NAME: &str = "restored";

    fn enter_request(id: u8) -> CoordinatorSendBody {
        CoordinatorSendBody::Core(CoordinatorToDeviceMessage::Restoration(
            CoordinatorRestoration::EnterPhysicalBackup {
                enter_physical_id: frostsnap_core::EnterPhysicalId([id; 16]),
            },
        ))
    }

    fn save_request(share: &ShareToTypeIn) -> CoordinatorSendBody {
        CoordinatorSendBody::Core(CoordinatorToDeviceMessage::Restoration(
            CoordinatorRestoration::SavePhysicalBackup2(alloc::boxed::Box::new(HeldShare2 {
                access_structure_ref: None,
                share_image: share.share_image,
                threshold: Some(1),
                key_name: Some(String::from(RESTORED_KEY_NAME)),
                purpose: Some(frostsnap_core::device::KeyPurpose::Test),
                needs_consolidation: true,
            })),
        ))
    }

    fn consolidate_request(share: &ShareToTypeIn) -> CoordinatorSendBody {
        CoordinatorSendBody::Core(CoordinatorToDeviceMessage::Restoration(
            CoordinatorRestoration::Consolidate(alloc::boxed::Box::new(
                frostsnap_core::message::ConsolidateBackup {
                    share_index: share.share_index,
                    root_shared_key: share.root_shared_key.clone(),
                    key_name: String::from(RESTORED_KEY_NAME),
                    purpose: frostsnap_core::device::KeyPurpose::Test,
                },
            )),
        ))
    }

    /// The variant name of a [`Typed`], for an `assert`.
    ///
    /// A helper and not `#[derive(Debug)]`, deliberately: `Typed::Ended` carries a
    /// `Vec<DeviceToUserMessage>`, and `ToUserRestoration::ConsolidateBackup`'s
    /// derived `Debug` prints a plaintext `SecretShare` in hex. A `Debug` on `Typed`
    /// would put that one `{:?}` away from any log.
    fn typed(step: &Typed) -> &'static str {
        match step {
            Typed::Unchanged => "Unchanged",
            Typed::Redraw => "Redraw",
            Typed::Ended(_) => "Ended",
        }
    }

    /// [`Session::entry_key`] must REFUSE. Returns the fault.
    ///
    /// A helper rather than `expect_err`, which would need `Typed: Debug` — and
    /// `Typed` deliberately has none (see `typed` above).
    fn refused_key(
        session: &mut Session<'_, DebugFlash<FakeFlash>>,
        key: u8,
        out: &mut Outbox,
    ) -> Fault {
        match session.entry_key(key, out) {
            Err(fault) => fault,
            Ok(step) => panic!(
                "key {key} was accepted with no live entry: {}",
                typed(&step)
            ),
        }
    }

    /// Take the coordinator's entry request all the way to a live entry: the prompt,
    /// then the consent digit.
    fn consent_to_an_entry(
        session: &mut Session<'_, DebugFlash<FakeFlash>>,
        rng: &mut Entropy,
        out: &mut Outbox,
        id: u8,
    ) {
        let mut prompts = session
            .recv(enter_request(id), rng, out)
            .expect("an entry request must reach the human");
        assert_eq!(prompts.len(), 1, "one request, one question");
        let prompt = prompts.pop().expect("checked above");
        session
            .confirm(prompt, rng, out)
            .expect("the digit grants the entry");
        assert!(
            session.entry_screen().is_some(),
            "the digit did not grant an entry"
        );
    }

    /// Type the share index and accept it, leaving the machine on word 1.
    fn type_index(session: &mut Session<'_, DebugFlash<FakeFlash>>, out: &mut Outbox, index: u32) {
        let mut digits = StdVec::new();
        let mut left = index;
        while left > 0 {
            digits.push(b'0' + (left % 10) as u8);
            left /= 10;
        }
        for digit in digits.iter().rev() {
            let step = session.entry_key(*digit, out).expect("a live entry");
            assert_eq!(typed(&step), "Redraw", "a share-index digit was dead");
        }
        let step = session
            .entry_key(ui::ENTRY_OK_KEY, out)
            .expect("a live entry");
        assert_eq!(typed(&step), "Redraw", "the share index would not accept");
    }

    /// Type `word` letter by letter through the SESSION's public API, paging when the
    /// letter is not on the page showing.
    ///
    /// The honest driver, as in `wordentry`'s own tests: it can only press keys the
    /// screen advertises, so a letter the ruler does not reach is a panic here rather
    /// than a silent skip. It reads the ruler through `entry_screen`, i.e. through the
    /// same value the renderer would be handed.
    fn type_word(session: &mut Session<'_, DebugFlash<FakeFlash>>, out: &mut Outbox, word: &str) {
        for wanted in word.bytes() {
            let mut turns = 0;
            loop {
                // Scoped, so the borrow of `session` for the ruler is over before the
                // `&mut` press.
                let found = {
                    let Some(wordentry::Screen::Word(showing)) = session.entry_screen() else {
                        panic!("expected a word page while typing {word:?}");
                    };
                    let start = showing.page * ui::ENTRY_LETTERS_PER_PAGE;
                    showing
                        .candidates
                        .as_bytes()
                        .iter()
                        .skip(start)
                        .take(ui::ENTRY_LETTERS_PER_PAGE)
                        .position(|&letter| letter == wanted)
                        .map(|slot| ui::ENTRY_LETTER_KEYS[slot])
                        .ok_or_else(|| showing.pages())
                };
                match found {
                    Ok(key) => {
                        let step = session.entry_key(key, out).expect("a live entry");
                        assert_eq!(typed(&step), "Redraw", "letter key {key} was dead");
                        break;
                    }
                    Err(pages) => {
                        assert!(
                            turns < pages,
                            "{} is on no page of the ruler for {word:?}",
                            wanted as char
                        );
                        turns += 1;
                        let step = session
                            .entry_key(ui::ENTRY_PAGE_KEY, out)
                            .expect("a live entry");
                        assert_eq!(typed(&step), "Redraw", "the page key was dead");
                    }
                }
            }
        }
    }

    /// Type words `0..count` of `share` and accept each one. Returns the last step.
    fn type_words(
        session: &mut Session<'_, DebugFlash<FakeFlash>>,
        out: &mut Outbox,
        words: &[&str],
    ) -> Typed {
        let mut last = Typed::Unchanged;
        for (n, word) in words.iter().enumerate() {
            type_word(session, out, word);
            last = session
                .entry_key(ui::ENTRY_OK_KEY, out)
                .expect("a live entry");
            assert_ne!(typed(&last), "Unchanged", "word {} would not accept", n + 1);
        }
        last
    }

    /// A device with a real share typed IN and saved, sitting on the `Consolidate`
    /// prompt. Everything up to the flash write, driven through the public API.
    fn a_device_ready_to_consolidate<'a>(
        flash: &'a RefCell<DebugFlash<FakeFlash>>,
        rng: &mut Entropy,
        out: &mut Outbox,
    ) -> (
        Session<'a, DebugFlash<FakeFlash>>,
        ShareToTypeIn,
        DeviceToUserMessage,
    ) {
        let secret = identity::load_or_create(&mut *flash.borrow_mut(), rng)
            .expect("a blank fake flash must yield a fresh identity");
        let mut session = Session::open(flash, &secret).expect("signer construction");
        let share = a_share_to_type_in(rng);

        consent_to_an_entry(&mut session, rng, out, 11);
        type_index(&mut session, out, share.index);
        let step = type_words(&mut session, out, &share.words);
        assert_eq!(typed(&step), "Ended", "a real 25-word share must checksum");

        session
            .recv(save_request(&share), rng, out)
            .expect("the entered share is there to save");
        let mut prompts = session
            .recv(consolidate_request(&share), rng, out)
            .expect("a saved share is there to consolidate");
        assert_eq!(prompts.len(), 1, "one consolidate request, one question");
        (session, share, prompts.pop().expect("checked above"))
    }

    /// **CONSENT PRECEDES THE INGEST.** `recv` returns the question and grants
    /// nothing; no key does anything until the digit that screen printed is pressed.
    ///
    /// The mirror of `a_backup_is_never_drawn_before_the_digit_is_pressed`, and the
    /// property that matters most on this flow: a restore puts a secret on the glass
    /// letter by letter, so a coordinator message must not be able to reach that
    /// screen on its own.
    ///
    /// MUTATION-VERIFY, three ways. Set `self.entry` from `recv_core`'s admitted arm
    /// — where the `enter_physical_id` first exists, so it is the shape a "just wire
    /// it up" patch takes — and the pre-confirm asserts fail. Make `entry_key` return
    /// `Ok(Typed::Unchanged)` instead of refusing when `self.entry` is `None` and the
    /// key loop fails. Drop the legend from `consent_screen` and the digit half fails:
    /// the screen asks for a key it never showed.
    #[test]
    fn typing_a_backup_in_needs_the_digit_first() {
        let flash = fs_flash();
        let mut rng = entropy(109);
        let secret = identity::load_or_create(&mut *flash.borrow_mut(), &mut rng).unwrap();
        let mut session = Session::open(&flash, &secret).unwrap();
        let mut out = Outbox::new(session.device_id());

        let mut prompts = session
            .recv(enter_request(3), &mut rng, &mut out)
            .expect("an entry request is admitted");
        assert_eq!(
            out.frames(),
            0,
            "`recv` must answer NOTHING for an entry request"
        );
        assert_eq!(prompts.len(), 1);
        let prompt = prompts.pop().expect("checked above");
        assert!(
            session.signer.staged_mutations().is_empty(),
            "an entry request staged a mutation"
        );

        // BEFORE the confirm: no screen to draw, and every live key refuses.
        assert!(
            session.entry_screen().is_none(),
            "an entry began with no consent behind it"
        );
        let mut keys = StdVec::from(ui::ENTRY_LETTER_KEYS);
        keys.extend([ui::ENTRY_PAGE_KEY, ui::ENTRY_OK_KEY, ui::ENTRY_DELETE_KEY]);
        for key in keys {
            let fault = refused_key(&mut session, key, &mut out);
            assert!(
                matches!(fault, Fault::Refused(Refusal::PhysicalBackup)),
                "key {key}: got {fault:?}"
            );
        }

        // The question is one page, it is the page that authorises, and it prints the
        // digit — two different digits, two different screens.
        let (a, b) = two_digits(&mut rng);
        let draw = |digit: ui::ConfirmDigit| {
            let mut frame = ui::Frame::new();
            let shown = prompt_screen_at(&mut frame, &prompt, digit, 0);
            (shown, frame)
        };
        let (shown, first) = draw(a);
        assert_eq!(shown, Ok(Shown::Page { last: true }));
        let (again, second) = draw(b);
        assert_eq!(again, shown);
        assert!(
            first.as_bytes() != second.as_bytes(),
            "the entry consent screen does not print the digit, so no human can read \
             the key that grants the ingest"
        );

        // And no page it invented authorises either.
        for page in [1usize, 2, usize::MAX] {
            let mut frame = ui::Frame::new();
            assert_eq!(
                prompt_screen_at(&mut frame, &prompt, a, page),
                Ok(Shown::Nothing),
                "page {page} of a one-page question must draw nothing"
            );
            let fault = session
                .confirm_at(prompt.clone(), page, &mut rng, &mut out)
                .expect_err("a page that does not draw cannot authorise");
            assert!(
                matches!(fault, Fault::NotConfirmable),
                "page {page}: {fault:?}"
            );
            assert!(
                session.entry_screen().is_none(),
                "page {page} granted an ingest"
            );
        }

        // AFTER the confirm: the share-index page, and still nothing on the wire.
        session
            .confirm(prompt, &mut rng, &mut out)
            .expect("the digit grants the entry");
        assert_eq!(
            session.entry_screen(),
            Some(wordentry::Screen::ShareIndex { typed: None })
        );
        assert_eq!(
            out.frames(),
            0,
            "granting an entry must not tell the coordinator a share was entered"
        );
    }

    /// **A 24-WORD SET IS NOT A SHARE.** Nothing reaches the coordinator until all 25
    /// words pass their checksum, and the entry stays alive until they do.
    ///
    /// The `wordentry` tests pin the keypress map over all 2,048 words; this pins the
    /// WIRE, which is the half a dispatch layer can get wrong. A device that acked at
    /// 24 would have the coordinator close its dialog on a share that does not exist.
    ///
    /// MUTATION-VERIFY. Make `wordentry::Entry::word_key`'s accept arm submit at
    /// `next < ui::BACKUP_WORDS - 1` and this fails on "24 of 25 words was acked".
    /// Have `entry_key` push the reply for `Step::Redraw` as well and it fails there
    /// too.
    #[test]
    fn a_typed_share_is_acked_only_when_all_twenty_five_words_checksum() {
        let flash = fs_flash();
        let mut rng = entropy(113);
        let secret = identity::load_or_create(&mut *flash.borrow_mut(), &mut rng).unwrap();
        let mut session = Session::open(&flash, &secret).unwrap();
        let mut out = Outbox::new(session.device_id());
        let share = a_share_to_type_in(&mut rng);

        consent_to_an_entry(&mut session, &mut rng, &mut out, 5);
        type_index(&mut session, &mut out, share.index);
        let step = type_words(&mut session, &mut out, &share.words[..ui::BACKUP_WORDS - 1]);
        assert_eq!(typed(&step), "Redraw");
        assert_eq!(out.frames(), 0, "24 of 25 words was acked");
        assert!(
            session.entry_screen().is_some(),
            "24 accepted words must keep the entry alive"
        );

        let step = type_words(&mut session, &mut out, &share.words[ui::BACKUP_WORDS - 1..]);
        match &step {
            Typed::Ended(prompts) => assert!(
                prompts.is_empty(),
                "an entered share produced {} prompt(s)",
                prompts.len()
            ),
            other => panic!("the 25th word did not end the entry: {}", typed(other)),
        }
        assert_eq!(out.frames(), 1, "one entered share, one reply");
        assert!(
            session.entry_screen().is_none(),
            "a completed entry must be gone, words and all"
        );
        assert!(
            session.signer.staged_mutations().is_empty(),
            "entering a share staged a mutation, and it would carry the plaintext"
        );
    }

    /// **A FAILED CHECKSUM DISCARDS NOTHING AND ACKS NOTHING.** All 25 words are still
    /// held, the machine walks back to word 25, and one corrected word finishes the
    /// share.
    ///
    /// A restore that threw away 24 correct words on the 25th would invite trust and
    /// then lose a share, which is worse than refusing to restore at all. `wordentry`
    /// pins the state; this pins that the wire stays silent through the failure and
    /// that the recovery really does complete.
    ///
    /// MUTATION-VERIFY. Return `Step::Entered` from `wordentry::Entry::submit`'s `Err`
    /// arm — the shape of "trust the words, the coordinator will check" — and the
    /// silence assert fails. Clear the word array on failure and the fix leg fails.
    #[test]
    fn a_wrong_word_is_not_acked_and_costs_nothing() {
        let flash = fs_flash();
        let mut rng = entropy(127);
        let secret = identity::load_or_create(&mut *flash.borrow_mut(), &mut rng).unwrap();
        let mut session = Session::open(&flash, &secret).unwrap();
        let mut out = Outbox::new(session.device_id());
        let share = a_share_to_type_in(&mut rng);

        // A different, real BIP39 word in the last slot. The 11-bit words checksum IS
        // word 25, so exactly one word completes the other 24 and this is not it.
        let last = share.words[ui::BACKUP_WORDS - 1];
        let wrong = frost_backup::bip39_words::BIP39_WORDS
            .iter()
            .copied()
            .find(|word| *word != last)
            .expect("2048 words");

        consent_to_an_entry(&mut session, &mut rng, &mut out, 9);
        type_index(&mut session, &mut out, share.index);
        let step = type_words(&mut session, &mut out, &share.words[..ui::BACKUP_WORDS - 1]);
        assert_eq!(typed(&step), "Redraw");
        let step = type_words(&mut session, &mut out, &[wrong]);
        assert_eq!(
            typed(&step),
            "Redraw",
            "a refused checksum is not an ending"
        );
        assert_eq!(
            session.entry_screen(),
            Some(wordentry::Screen::Failed),
            "a wrong word must say so"
        );
        assert_eq!(
            out.frames(),
            0,
            "a share that failed its checksum was acked"
        );

        // Any key walks back to word 25 with all 25 still in their slots.
        let step = session
            .entry_key(ui::ENTRY_LETTER_KEYS[0], &mut out)
            .expect("a failed entry is still live");
        assert_eq!(typed(&step), "Redraw");
        let Some(wordentry::Screen::Word(showing)) = session.entry_screen() else {
            panic!("expected the last word page");
        };
        assert_eq!(
            showing.number,
            ui::BACKUP_WORDS,
            "walked back to the wrong word"
        );
        assert_eq!(
            showing.partial,
            wrong.to_uppercase(),
            "the word was discarded"
        );

        // Fix exactly that one word: one delete per letter, then the right word.
        for _ in 0..wrong.len() {
            let step = session
                .entry_key(ui::ENTRY_DELETE_KEY, &mut out)
                .expect("a live entry");
            assert_eq!(typed(&step), "Redraw", "delete was dead");
        }
        let step = type_words(&mut session, &mut out, &[last]);
        assert_eq!(
            typed(&step),
            "Ended",
            "one corrected word did not finish a share whose other 24 were right"
        );
        assert_eq!(out.frames(), 1, "the corrected share was not acked");
    }

    /// **NO WORD AND NO SCALAR REACHES THE OUTBOX** on any path this flow adds — not
    /// a word, not the plaintext share, not a `Debug` line.
    ///
    /// The whole restore is driven, entry through consolidation, and then the outbox
    /// is searched for all 25 words in both cases and for the 32-byte scalar in both
    /// byte orders. The structural version of the claim is stronger and worth stating
    /// beside it: `wordentry` has no `Outbox` and no `Debug`, and `Session::entry_key`
    /// consumes `Step::Entered` itself, so the completed `ShareBackup` never crosses
    /// back to a caller that could log it.
    ///
    /// MUTATION-VERIFY. Push the entered words as a `DeviceSendBody::Debug` from
    /// `entry_key`'s `Entered` arm — the shape a "let the harness see it" patch takes
    /// — and this fails on the first word.
    /// `nothing_but_the_outbox_truncating_arm_may_construct_a_debug_send` is the
    /// second net and catches the same edit textually.
    #[test]
    fn no_word_of_a_typed_backup_ever_reaches_the_outbox() {
        let flash = fs_flash();
        let mut rng = entropy(131);
        let mut out = Outbox::new(DeviceId([0u8; 33]));
        let (mut session, share, prompt) =
            a_device_ready_to_consolidate(&flash, &mut rng, &mut out);
        session
            .confirm(prompt, &mut rng, &mut out)
            .expect("the digit stores the share");

        let bytes = out.bytes();
        assert!(!bytes.is_empty(), "the search below must be a search");
        for (i, word) in share.words.iter().enumerate() {
            let needle = word.as_bytes();
            assert!(
                !bytes.windows(needle.len()).any(|w| w == needle),
                "word {} ({word:?}) reached the outbox",
                i + 1
            );
            let lower = word.to_lowercase();
            assert!(
                !bytes
                    .windows(lower.len())
                    .any(|w| w.eq_ignore_ascii_case(lower.as_bytes())),
                "word {} ({word:?}) reached the outbox in some other case",
                i + 1
            );
        }
        let mut reversed = share.plaintext;
        reversed.reverse();
        for (name, needle) in [("big-endian", share.plaintext), ("byte-reversed", reversed)] {
            assert!(
                !bytes.windows(needle.len()).any(|w| w == needle),
                "the {name} plaintext share scalar reached the outbox"
            );
        }
    }

    /// **PERSIST BEFORE THE ACK**, on the restore path as on the keygen one — and here
    /// the write is DESTRUCTIVE, because the store keeps one record.
    ///
    /// A `FinishedConsolidation` the coordinator hears when the write did not happen
    /// leaves it believing this device holds a share it does not, and the restore the
    /// human just spent 25 words on is gone with no sign of it.
    ///
    /// Two sessions and not one retry, deliberately: `finish_consolidation` stages the
    /// triple before `run` sees it, so consenting twice would stage six mutations and
    /// `body_from` would refuse the pair. A flash that refuses is a broken device and
    /// the honest behaviour is to stay refused — which is what the first half asserts.
    ///
    /// MUTATION-VERIFY. Move `persist_staged` from the top of `Session::run` to after
    /// the loop and the first half fails on frames: the ack is on the wire and the
    /// share is not on flash. `a_share_that_cannot_be_written_is_never_acked` is the
    /// keygen-side twin.
    #[test]
    fn consolidation_persists_the_share_before_it_acks() {
        // A flash that refuses: nothing acked, nothing stored.
        let flash = fs_flash();
        let mut rng = entropy(137);
        let mut out = Outbox::new(DeviceId([0u8; 33]));
        let (mut session, _share, prompt) =
            a_device_ready_to_consolidate(&flash, &mut rng, &mut out);
        let framed = out.frames();
        flash.borrow_mut().0.refuse_erases_now();
        let fault = session
            .confirm(prompt, &mut rng, &mut out)
            .expect_err("a consolidation that cannot be stored must not be acked");
        assert!(
            matches!(fault, Fault::Store(_)),
            "expected a store fault, got {fault:?}"
        );
        assert_eq!(
            out.frames(),
            framed,
            "the coordinator was told a consolidation finished that did not"
        );
        flash.borrow_mut().0.heal();
        assert_eq!(
            store::ShareStore::open(&flash).load(),
            store::HeldShare::Vacant
        );

        // A healthy one: stored, THEN acked, and it survives the reset.
        let flash = fs_flash();
        let mut rng = entropy(139);
        let mut out = Outbox::new(DeviceId([0u8; 33]));
        let (mut session, share, prompt) =
            a_device_ready_to_consolidate(&flash, &mut rng, &mut out);
        let framed = out.frames();
        session
            .confirm(prompt, &mut rng, &mut out)
            .expect("the digit stores the share");
        assert_eq!(out.frames(), framed + 1, "one consolidation, one ack");
        assert!(
            session.signer.staged_mutations().is_empty(),
            "a committed save must drain the staged set"
        );

        // The reset. A fresh `Session::open` over the same cells is what the next boot
        // does, and the restored share must be a REAL hold — an access structure this
        // device can sign with, not a `needs_consolidation` backup.
        let secret = identity::load_or_create(&mut *flash.borrow_mut(), &mut rng)
            .expect("the identity is already there");
        let after = Session::open(&flash, &secret).expect("signer construction");
        let held: StdVec<_> = after.signer.held_shares().collect();
        assert_eq!(held.len(), 1, "a restored share did not survive the reset");
        assert!(
            !held[0].needs_consolidation,
            "the reloaded share still wants consolidating"
        );
        assert_eq!(held[0].share_image, share.share_image);
        assert_eq!(held[0].key_name.as_deref(), Some(RESTORED_KEY_NAME));
    }

    /// The consolidation question names what is about to be stored and what it will
    /// destroy, and shows **no word and no scalar** — which matters here more than on
    /// any other screen, because the `ConsolidatePhase` behind it is the one prompt in
    /// the tree that carries a PLAINTEXT `SecretShare`.
    ///
    /// MUTATION-VERIFY. Print `phase.complete_share.secret_share` on the screen (the
    /// shape a "show the human what they typed" patch takes) and the word/scalar half
    /// fails. Drop the "REPLACES stored" line and the destruction half fails: a human
    /// consents to storing a share without being told it overwrites one.
    #[test]
    fn the_consolidate_question_shows_no_secret_and_names_the_destruction() {
        let flash = fs_flash();
        let mut rng = entropy(149);
        let mut out = Outbox::new(DeviceId([0u8; 33]));
        let (_session, share, prompt) = a_device_ready_to_consolidate(&flash, &mut rng, &mut out);

        let (a, b) = two_digits(&mut rng);
        let draw = |digit: ui::ConfirmDigit| {
            let mut frame = ui::Frame::new();
            let shown = prompt_screen_at(&mut frame, &prompt, digit, 0);
            (shown, frame)
        };
        let (shown, first) = draw(a);
        assert_eq!(shown, Ok(Shown::Page { last: true }));
        let text = all_rows(&first, ui::COLS);
        for (i, word) in share.words.iter().enumerate() {
            assert!(
                !text.contains(word) && !text.to_lowercase().contains(&word.to_lowercase()),
                "word {} ({word:?}) is on the CONSOLIDATE screen. Screen:\n{text}",
                i + 1
            );
        }
        // It does say which share, under which name, and that storing replaces.
        assert!(
            text.contains(RESTORED_KEY_NAME),
            "the screen must name the key; got:\n{text}"
        );
        let mut what = ui::Buf::<16>::new();
        what.push_str("#").push_u64(share.index as u64);
        assert!(
            text.contains(what.as_str()),
            "the screen must name the share index; got:\n{text}"
        );
        assert!(
            text.contains("REPLACES"),
            "the screen must say that storing destroys the held share; got:\n{text}"
        );

        let (again, second) = draw(b);
        assert_eq!(again, shown);
        assert!(
            first.as_bytes() != second.as_bytes(),
            "the consolidate screen does not print the confirm digit"
        );
    }

    /// A coordinator `Cancel` mid-transcription drops the half-typed share.
    ///
    /// The reveal grant's rule run backwards: the human consented to type a share into
    /// THAT ceremony, and `clear_tmp_data` has just dropped the signer's side of it, so
    /// a surviving entry would be typing words towards an `enter_physical_id` nobody is
    /// listening for — words that would sit on the glass for whatever comes next.
    ///
    /// MUTATION-VERIFY. Drop `self.entry = None` from `recv`'s `Cancel` arm and this
    /// fails: a cancelled restore keeps taking letters.
    #[test]
    fn cancel_drops_a_half_typed_backup() {
        let flash = fs_flash();
        let mut rng = entropy(151);
        let secret = identity::load_or_create(&mut *flash.borrow_mut(), &mut rng).unwrap();
        let mut session = Session::open(&flash, &secret).unwrap();
        let mut out = Outbox::new(session.device_id());
        let share = a_share_to_type_in(&mut rng);

        consent_to_an_entry(&mut session, &mut rng, &mut out, 13);
        type_index(&mut session, &mut out, share.index);
        let step = type_words(&mut session, &mut out, &share.words[..3]);
        assert_eq!(typed(&step), "Redraw");

        session
            .recv(CoordinatorSendBody::Cancel, &mut rng, &mut out)
            .expect("Cancel is handled");
        assert!(
            session.entry_screen().is_none(),
            "a cancelled ceremony left a half-typed share on the glass"
        );
        let fault = refused_key(&mut session, ui::ENTRY_LETTER_KEYS[0], &mut out);
        assert!(
            matches!(fault, Fault::Refused(Refusal::PhysicalBackup)),
            "got {fault:?}"
        );
        assert_eq!(
            out.frames(),
            0,
            "an abandoned entry answered the coordinator"
        );
    }

    /// Backing out of the share index ends the entry and sends NOTHING.
    ///
    /// Silence is the honest wire behaviour and not a gap: `DeviceRestoration` has no
    /// message for an abandoned entry, and upstream's coordinator ends the dialog on
    /// its own `cancel()`. PUNTED UPSTREAM, not worked around.
    #[test]
    fn backing_out_of_the_share_index_ends_the_entry_in_silence() {
        let flash = fs_flash();
        let mut rng = entropy(157);
        let secret = identity::load_or_create(&mut *flash.borrow_mut(), &mut rng).unwrap();
        let mut session = Session::open(&flash, &secret).unwrap();
        let mut out = Outbox::new(session.device_id());

        consent_to_an_entry(&mut session, &mut rng, &mut out, 17);
        let step = session
            .entry_key(ui::ENTRY_DELETE_KEY, &mut out)
            .expect("a live entry");
        match &step {
            Typed::Ended(prompts) => assert!(prompts.is_empty()),
            other => panic!("delete on an empty index did not abort: {}", typed(other)),
        }
        assert!(session.entry_screen().is_none());
        assert_eq!(
            out.frames(),
            0,
            "an abandoned entry answered the coordinator"
        );
    }

    /// **A CONSOLIDATE NAMING A DIFFERENT POLYNOMIAL IS REFUSED**, and the human is
    /// never asked.
    ///
    /// This is the coordinator-hostile case on the restore path: the typed share is
    /// plaintext in the signer's RAM, and `Consolidate` is the message that decides
    /// which key it gets encrypted and stored under. A coordinator supplying its own
    /// `root_shared_key` must not be able to have the device store the share against
    /// it — nor to get a consent screen for doing so, because a screen is a chance for
    /// a human to press the wrong key.
    ///
    /// Two nets stand behind it and both are upstream's, which is why the useful thing
    /// to pin is the OUTCOME rather than the mechanism: the `share_image` derived from
    /// the wrong polynomial misses both backup maps (`device/restoration.rs:129-135`),
    /// and if it somehow hit, `extract_secret`'s polynomial checksum refuses
    /// (`:137-147`). Either way it is a `Fault::Signer` with nothing staged, nothing
    /// drawn and nothing written.
    ///
    /// MUTATION-VERIFY: give `recv_core`'s admitted arm a `Consolidate` fast path that
    /// answers `FinishedConsolidation` without the signer — the shape a "the app is
    /// waiting" patch takes — and the frames assert fails.
    #[test]
    fn a_consolidate_under_a_different_polynomial_is_refused() {
        let flash = fs_flash();
        let mut rng = entropy(163);
        let secret = identity::load_or_create(&mut *flash.borrow_mut(), &mut rng).unwrap();
        let mut session = Session::open(&flash, &secret).unwrap();
        let mut out = Outbox::new(session.device_id());
        let mine = a_share_of_group(&mut rng, 0x3d);
        let theirs = a_share_of_group(&mut rng, 0x71);
        assert_ne!(
            mine.share_image, theirs.share_image,
            "the two fixtures must be different shares for this test to mean anything"
        );

        consent_to_an_entry(&mut session, &mut rng, &mut out, 19);
        type_index(&mut session, &mut out, mine.index);
        let step = type_words(&mut session, &mut out, &mine.words);
        assert_eq!(typed(&step), "Ended");
        let framed = out.frames();

        let fault = session
            .recv(consolidate_request(&theirs), &mut rng, &mut out)
            .expect_err("a share we did not enter must not be consolidated");
        assert!(
            matches!(fault, Fault::Signer(_)),
            "expected the signer to refuse, got {fault:?}"
        );
        assert_eq!(
            out.frames(),
            framed,
            "a refused consolidation answered the coordinator"
        );
        assert!(
            session.signer.staged_mutations().is_empty(),
            "a refused consolidation staged a mutation"
        );
        assert_eq!(
            store::ShareStore::open(&flash).load(),
            store::HeldShare::Vacant,
            "a refused consolidation reached flash"
        );
    }

    /// `SavePhysicalBackup2` produces a `ToUserRestoration::BackupSaved` prompt, which
    /// is INFORMATIONAL: it has no screen and it answers nothing.
    ///
    /// A prompt a coordinator can now cause, so it is worth pinning on the way in
    /// rather than after someone gives it an arm. `prompt_screen_at` draws
    /// `Shown::Nothing` for it, which is what makes `confirm_at` refuse — the same
    /// mechanism that makes a DELETED screen disable consent instead of blinding it.
    #[test]
    fn the_backup_saved_prompt_draws_nothing_and_answers_nothing() {
        let flash = fs_flash();
        let mut rng = entropy(167);
        let secret = identity::load_or_create(&mut *flash.borrow_mut(), &mut rng).unwrap();
        let mut session = Session::open(&flash, &secret).unwrap();
        let mut out = Outbox::new(session.device_id());
        let share = a_share_to_type_in(&mut rng);

        consent_to_an_entry(&mut session, &mut rng, &mut out, 23);
        type_index(&mut session, &mut out, share.index);
        assert_eq!(
            typed(&type_words(&mut session, &mut out, &share.words)),
            "Ended"
        );

        let mut prompts = session
            .recv(save_request(&share), &mut rng, &mut out)
            .expect("the entered share is there to save");
        assert_eq!(prompts.len(), 1, "one save, one notice");
        let prompt = prompts.pop().expect("checked above");
        let digit = ui::ConfirmDigit::draw(&mut rng);
        let mut frame = ui::Frame::new();
        assert_eq!(
            prompt_screen_at(&mut frame, &prompt, digit, 0),
            Ok(Shown::Nothing),
            "an informational notice must draw no consent screen"
        );
        assert_eq!(
            frame.as_bytes(),
            ui::Frame::new().as_bytes(),
            "the frame was touched"
        );
        let fault = session
            .confirm(prompt, &mut rng, &mut out)
            .expect_err("an informational notice is not answerable");
        assert!(matches!(fault, Fault::NotConfirmable), "got {fault:?}");
    }

    /// Cancel is handled and silent: it clears half-finished state without
    /// answering.
    #[test]
    fn cancel_is_handled_and_silent() {
        let flash = fs_flash();
        let mut rng = entropy(23);
        let secret = identity::load_or_create(&mut *flash.borrow_mut(), &mut rng).unwrap();
        let mut session = Session::open(&flash, &secret).unwrap();
        let mut out = Outbox::new(session.device_id());
        let prompts = session
            .recv(CoordinatorSendBody::Cancel, &mut rng, &mut out)
            .expect("Cancel is handled");
        assert!(prompts.is_empty());
        assert_eq!(out.frames(), 0);
    }
}
