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
//! the coordinator dispatch, the outbox framing caps, and the announce.
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
//! Construction allocates one `Vec` of 4 `NonceAbSlot`s (~192 B on 32-bit) and
//! nothing else; the flash-backed slots hold their state on flash rather than in
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
    DeviceSendBody, DeviceSendMessage, Downstream, NameCommand, Sha256Digest,
};
use frostsnap_core::device::{
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
use frostsnap_embedded::{FlashPartition, NonceAbSlot, SECTOR_SIZE};
use sha2::{Digest, Sha256};

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
    /// [`Session::confirm`] was handed a prompt that is not a consent prompt.
    NotConfirmable,
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
    /// `DisplayBackup`: renders a secret share on the screen. Needs its own
    /// consent screen; refusing is the fail-closed direction.
    DisplayBackup,
    /// `EnterPhysicalBackup` / `SavePhysicalBackup` / `SavePhysicalBackup2` /
    /// `Consolidate` / `CheckBackup`: write or verify share material entered by
    /// a human. No entry UI exists, so there is nothing to consent with.
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
    pub fn open(flash: &'a RefCell<F>, secret: &IdentitySecret) -> Result<Self, Fault> {
        let scalar = Scalar::<Secret, NonZero>::from_bytes(*secret.expose_secret())
            .ok_or(Fault::IdentityScalar)?;
        let slots = NonceAbSlot::load_slots(FlashPartition::new(
            flash,
            NONCE_OFFSET_SECTOR,
            NONCE_SECTORS,
            "nonces",
        ));
        Ok(Session {
            signer: FrostSigner::new(KeyPair::<Normal>::new(scalar), slots),
            coordinator_acked: false,
            secrets: Secrets::new(secret),
        })
    }

    /// This device's wire identity: 33 SEC1-compressed bytes derived from the
    /// durable secret, therefore the same across every reset.
    pub fn device_id(&self) -> DeviceId {
        self.signer.device_id()
    }

    /// Say hello: `Announce` carrying the firmware digest, then `NeedName`.
    ///
    /// Both, in one call, because announce alone never makes this device usable.
    /// The coordinator inserts into `registered_devices` only once it has a name
    /// for us (`usb_serial_manager.rs:462-478`), and `NeedName` is what makes the
    /// app ask for one. This device has nowhere durable to keep a name, so it
    /// asks every time rather than claiming one it cannot persist.
    ///
    /// Send this on the magic-bytes **edge**, not once per boot: a coordinator
    /// that restarts re-sends magic and expects a fresh announce.
    pub fn announce(&self, firmware_digest: Sha256Digest, out: &mut Outbox) -> Result<(), Fault> {
        out.push(DeviceSendBody::Announce { firmware_digest })?;
        out.push(DeviceSendBody::NeedName)?;
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

            // No durable name store exists, so a previewed name could only be
            // held until the next reset and then silently forgotten. `NeedName`
            // in `announce` is what actually gets this device registered.
            // `_Prompt` is a retired slot-reserver; nothing sends it.
            CoordinatorSendBody::Naming(NameCommand::Preview(_) | NameCommand::_Prompt(_)) => {
                Ok(Vec::new())
            }

            CoordinatorSendBody::AnnounceAck => {
                self.coordinator_acked = true;
                Ok(Vec::new())
            }

            // The coordinator abandoned whatever it had started. Dropping the
            // half-finished keygen/backup state matters: keeping it makes the
            // next legitimate message fail on a stale state.
            CoordinatorSendBody::Cancel => {
                self.signer.clear_tmp_data();
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
            CoordinatorToDeviceMessage::Restoration(CoordinatorRestoration::DisplayBackup {
                ..
            }) => return Err(Fault::Refused(Refusal::DisplayBackup)),
            CoordinatorToDeviceMessage::Restoration(
                CoordinatorRestoration::EnterPhysicalBackup { .. }
                | CoordinatorRestoration::SavePhysicalBackup { .. }
                | CoordinatorRestoration::SavePhysicalBackup2(_)
                | CoordinatorRestoration::Consolidate(_)
                | CoordinatorRestoration::CheckBackup { .. },
            ) => return Err(Fault::Refused(Refusal::PhysicalBackup)),
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
    pub fn confirm<R: rand_core::RngCore>(
        &mut self,
        prompt: DeviceToUserMessage,
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
        // `Ok(false)` — no screen for this prompt — is refused rather than
        // waved through, and that is load-bearing twice over: it is what an
        // informational prompt looks like, and it is also what a DELETED screen
        // arm looks like, so removing a screen from `prompt_screen` disables
        // consent instead of blinding it.
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
        match prompt_screen(
            &mut ui::Frame::new(),
            &prompt,
            ui::ConfirmDigit::draw(rng),
        ) {
            Ok(true) => {}
            Ok(false) => return Err(Fault::NotConfirmable),
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
            _ => Err(Fault::NotConfirmable),
        }
    }

    /// Run the signer's work queue to quiescence: coordinator-bound messages go
    /// to the outbox, nonce work is done here, prompts come back to the caller.
    fn run<I: IntoIterator<Item = DeviceSend>>(
        &mut self,
        sends: I,
        out: &mut Outbox,
    ) -> Result<Vec<DeviceToUserMessage>, Fault> {
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
/// - `Ok(true)` — `frame` holds a consent screen showing the request **in full**.
/// - `Ok(false)` — informational prompt with no screen; `frame` is untouched.
/// - `Err(refusal)` — this device cannot show the request, so it must not be
///   signed. `frame` holds [`ui::refusal`] on the way out, never a partial layout.
///
/// Every screen reached from here is reached *honestly*: `keygen_check` renders a
/// real `KeyGenPhase3`'s own session hash and t-of-n, `sign_test_message` a real
/// `SignTask::Test`, and `SignPages` a real `BitcoinTransaction` — the one sign
/// task `Session::recv` admits and this device could otherwise sign blind. The
/// four remaining §4.2 screens (backup display, backup entry, the quiz, address
/// verify) have no caller because every message that reaches them is refused in
/// [`Session::recv`]; adding one would be a lie about what the device does.
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
pub fn prompt_screen(
    frame: &mut ui::Frame,
    prompt: &DeviceToUserMessage,
    confirm: ui::ConfirmDigit,
) -> Result<bool, Refusal> {
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
            Ok(true)
        }
        DeviceToUserMessage::SignatureRequest { phase } => match &phase.sign_task().inner {
            // An unrenderable message is a REFUSAL and not a truncated layout:
            // showing 64 characters of 4,000 while signing all 4,000 is a blind
            // signer. Until this was wired into `confirm`, such a request was
            // drawn as a refusal and then signed anyway.
            SignTask::Test { message } => ui::sign_test_message_confirm(frame, message, confirm)
                .map(|()| true)
                .map_err(|_| Refusal::Undisplayable),
            // Page 0 of the validated set. `sign_consent` — the same call
            // `confirm` makes — either accepts the whole transaction or refuses
            // it, so there is no page here that omits a recipient.
            //
            // ONE page, because there is no button driver to advance the cursor
            // and `SignPage::Confirm` is last: a human cannot reach consent
            // without stepping through every page, and nothing can step. The
            // cursor belongs with the input driver (phase 5), not here.
            // `confirming` attaches the digit to the whole page set, so it is
            // `SignPage::Confirm` — the page that authorises — that prints it,
            // wherever a page cursor eventually lands. Page 0 is not that page,
            // so a bitcoin request shows no confirm key YET; there is still no
            // button driver to advance the cursor, and a legend on a page that
            // cannot consent would be the same lie `hold 1` was.
            _ => match sign_consent(phase.sign_task(), |pages| {
                pages.confirming(confirm).render(0, frame)
            }) {
                Ok(Some(true)) => Ok(true),
                // `render` says the page could not be drawn in full, or
                // `sign_consent` says this is not a task with a page set at all
                // (`Test` is handled above and `Nostr` already refuses, so this
                // is the arm a new `SignTask` variant lands in — fail closed).
                Ok(_) => Err(Refusal::Undisplayable),
                Err(refusal) => Err(refusal),
            },
        },
        // `FinalizeKeyGen` is informational, and `VerifyAddress`/`Restoration`
        // are reached only through a message `Session::recv` refuses.
        _ => Ok(false),
    };
    if shown.is_err() {
        ui::refusal(frame);
    }
    shown
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
        let value = slot.read_slot().expect("the slot must read back after the reset");
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
        out.push(DeviceSendBody::Core(DeviceToCoordinatorMessage::Restoration(
            one,
        )))
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
        assert_eq!(
            refuse(CoordinatorSendBody::DataErase),
            Refusal::DataErase
        );
    }

    /// `DisplayBackup` renders a secret share on the screen. This is the arm a
    /// blanket `_ => {}` over `Core` would have silently accepted.
    #[test]
    fn display_backup_is_refused() {
        let flash = fs_flash();
        let mut rng = entropy(13);
        let secret = identity::load_or_create(&mut *flash.borrow_mut(), &mut rng).unwrap();
        let session = Session::open(&flash, &secret).unwrap();
        let id = session.device_id();
        let shared_key = frostsnap_core::schnorr_fun::frost::SharedKey::from_poly(vec![session
            .signer
            .keypair()
            .public_key()
            .mark_zero()])
        .non_zero()
        .expect("a one-coefficient poly with a non-zero constant term");
        drop(session);
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
        assert_eq!(refuse(body), Refusal::DisplayBackup);
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
        let mut image =
            vec![0xffu8; (memmap::FLASH_ISR_LEN + memmap::FLASH_TEXT_LEN) as usize];
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
        let mut image =
            vec![0xffu8; (memmap::FLASH_ISR_LEN + memmap::FLASH_TEXT_LEN) as usize];
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
                coord_share_decryption_contrib:
                    CoordShareDecryptionContrib::for_master_share(
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

    /// `CheckBackup` -- one of the five messages the `PhysicalBackup` refusal
    /// covers, and an arm a blanket `_ => {}` over `Restoration` would swallow.
    #[test]
    fn physical_backup_is_refused() {
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
                sign_consent(&bitcoin_task(&[(300_000, addressable(1)), (1, bad)]), |_| ()).err(),
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
