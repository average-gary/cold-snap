//! The keygen share, on flash, so a completed keygen survives an unplug.
//!
//! Before this module nothing drained `FrostSigner::staged_mutations()`, so a
//! finished 9-of-9 keygen died at the next power cycle, `RequestHeldShares`
//! answered empty forever, and — with `DisplayBackup` and every physical-backup
//! path refused (`crate::Session::recv_core`) — the share was unrecoverable.
//!
//! # What is stored, and why it is one record
//!
//! `FrostSigner::save_complete_share` (`frostsnap_core/src/device.rs:526-542`)
//! stages exactly **three** mutations, always together and always in this order:
//! `NewKey`, `NewAccessStructure`, `SaveShare`. The count is O(1) in the group
//! size — a 2-of-2 and a 12-of-12 persist identical shapes; `n` only sizes the
//! *transient* keygen.
//!
//! Those three go in **one** record, and that is load-bearing rather than tidy.
//! `FrostSigner::apply_mutation` inserts for `NewKey` but uses
//! `keys.entry(..).and_modify(..)` with **no `or_insert`** for the other two
//! (`device.rs:176-235`), so a `SaveShare` replayed without its `NewKey` is
//! dropped **with no error**. Splitting the triple across two flash writes would
//! let the share bytes sit on flash while the device boots believing it holds
//! nothing. Upstream's own split — `NewKey`/`NewAccessStructure` into a
//! `NorFlashLog`, `SaveShare` into an `AbSlot` (`frostsnap/device/src/flash/log.rs:56-84`)
//! — has exactly that hazard across two independent failures. This does not.
//!
//! For the same reason `seal` cross-checks that all three name the same key
//! before anything reaches flash: a mismatched triple would persist happily and
//! reload as no-share.
//!
//! # Why `AbSlot` and not `NorFlashLog`, and not a new append log
//!
//! `frostsnap_embedded::NorFlashLog` cannot be constructed over this flash at
//! all: `nor_flash_log.rs:5` fixes `WORD_SIZE = 4` and `:16` asserts
//! `assert_eq!(WORD_SIZE, S::WRITE_SIZE)`, while `StmFlash::WRITE_SIZE` is 8
//! (`hal/src/flash.rs:323`). Under `panic = "abort"` that assert is a boot brick.
//! `hal/src/flash.rs:16-102` and `flash::assert_nor_flash_log_is_unusable` already
//! record the verdict.
//!
//! It is also **not needed**, which is the part that settles the design: upstream
//! does not put the share in the log either. `MutationLog::push` intercepts
//! `SaveShare`/`Save`/`Save2` and diverts them to an `AbSlot` — "we only store one
//! secret share at a time" — and `AbSlot` is *already proven over this exact
//! geometry* by `hal/tests/integration_frostsnap_over_hal.rs:171-201`, including
//! the tail-padding case. So this module is a **thin adapter over vendored code**:
//! no `NorFlashLog` patch, no append log of our own, no compaction, no wear
//! management. What is new here is only the record shape and its integrity check.
//!
//! # The record
//!
//! [`RECORD_LEN`] bytes, handed to `AbSlot` as a plain `[u8; RECORD_LEN]`:
//!
//! | offset | bytes | field |
//! |--------|-------|-------|
//! | `0x000` | 8 | [`MAGIC`] — format family + version |
//! | `0x008` | 2 | body length, LE (MEASURED 260) |
//! | `0x00a` | 127 | fixed fields at hand-laid offsets: `key_id`, `access_structure_id`, `threshold`, `name_len`, `name` |
//! | `0x089` | 133 | bincode `(KeyPurpose, AccessStructureKind, EncryptedSecretShare)` |
//! | … | 234 | zero padding, unused |
//! | `0x1f8` | 8 | `sha256(DOMAIN ‖ everything above)[..8]` — programmed **last** |
//!
//! ## What a torn write looks like on reload
//!
//! `AbSlot` writes the *older* copy first and picks the highest index, so an
//! interrupted save leaves the previous value live in the other copy — but
//! `SlotValue { index, value }` puts the index **first** (`ab_write.rs:246-250`)
//! and `AbSlot::read` takes the highest-index slot with **no integrity check and
//! no fallback** (`:113-117`). A tear therefore leaves the newest index pointing
//! at a partial body, and without a checksum a half-written share reads back as a
//! *valid* share. That is the failure this record's tail exists to prevent.
//!
//! `StmFlash::write` programs `bytes.chunks_exact(WRITE_SIZE)` in **ascending**
//! order (`hal/src/flash.rs:1256`) and `BincodeFlashWriter` streams a `[u8; N]` in
//! byte order, so putting the checksum in the final doubleword buys exactly
//! `hal/src/identity.rs`'s commit-word-last property for free: a tear anywhere in
//! the record leaves the tail at `0xff`, the checksum fails, and [`ShareStore::load`] answers
//! [`HeldShare::Damaged`] — never a share.
//! `the_checksum_occupies_the_last_doubleword` and
//! `a_tear_before_the_checksum_reads_as_damaged_not_as_a_share` hold that.
//!
//! [`HeldShare::Damaged`] is **not a hold**. It means "no share is readable this
//! boot", and it is safe to overwrite, because [`ShareStore::persist_staged`] runs
//! *before* the keygen ack reaches the outbox: a record that fails its own
//! checksum was never acknowledged, so no coordinator believes the share exists.
//! Bricking on it would be strictly worse — there is no PIN UI and no recovery
//! install path on this port (`mk4-bootloader/sdcard.c:248`).
//!
//! ponytail: the one case this ceiling does not cover is a torn *second* keygen —
//! `AbSlot` exposes no route to the intact older copy, so the previous share
//! becomes unreachable too. Acceptable on a device that holds one share and does
//! one keygen in its life; the upgrade path is `identity.rs`'s paired-record
//! design, read both copies and pick the newest that checksums.
//!
//! # Full
//!
//! There is no append and therefore no fill. The region is two fixed copies of
//! one record; a save erases and rewrites in place. The record cannot outgrow its
//! slot either: `key_name` is the only variable-length input and it is truncated
//! to [`KEY_NAME_MAX_CHARS`] before encoding, so the body is a MEASURED 260 B of
//! the 494 B available (const-asserted against the slot below, and pinned to the
//! byte by `the_sealed_record_has_room_to_spare`). The two remaining conditions are hard
//! refusals with a `Result`, never a panic and never a silent drop:
//! [`StoreFault::TooBig`] if an encode somehow overruns, and
//! [`StoreFault::Flash`] — which also covers `AbSlot`'s `u32` index exhaustion
//! after 2^32-1 saves.
//!
//! # Heap
//!
//! Saving allocates **nothing**: `seal` works in a stack `[u8; RECORD_LEN]` and
//! `AbSlot::try_write` uses an inline 256-byte writer buffer. Reloading allocates
//! only what `Mutation` itself owns — one `String` of at most
//! [`KEY_NAME_MAX_BYTES`] and one `Box<SaveShareMutation>` of ~125 B, so ~200 B
//! against the 5,024 B spare in `heap::HEAP_BYTES`. Deliberately avoided:
//! `FlashPartition::read_sector` and `is_empty`, which `Box::new([0u8; 4096])` per
//! call (`partition.rs:81-85`) — 4 KiB of that 5 KiB, per sector.
//!
//! # No `cfg` in this module
//!
//! Every branch here is host-compiled and host-tested. PLAN.md §9 item 22 records
//! that the 152 `cfg(target_arch)` blocks in this tree are invisible to every
//! test, clippy and rustdoc run, so a security property placed inside one is
//! unenforced by construction. The ordering property this store depends on
//! (persist strictly before the ack) belongs in `Session::run` for the same
//! reason, **not** at the outbox drain in `main.rs`'s `cfg`-gated `boot()`.

use core::cell::RefCell;

use alloc::{boxed::Box, collections::VecDeque};
use coldsnap_hal::memmap;
use embedded_storage::nor_flash::{NorFlash, NorFlashErrorKind};
use frostsnap_core::bincode;
use frostsnap_core::device::{
    keys::KeyMutation, EncryptedSecretShare, KeyPurpose, Mutation, SaveShareMutation,
};
use frostsnap_core::{AccessStructureId, AccessStructureKind, AccessStructureRef, KeyId};
use frostsnap_embedded::{AbSlot, AbWriteOutcome, FlashPartition, SECTOR_SIZE};
use sha2::{Digest, Sha256};

/// Total on-flash record length. A multiple of `flash::WRITE_SIZE` so the
/// checksum lands in its own final doubleword.
pub const RECORD_LEN: usize = 512;

/// The format tag, programmed first, checked before anything else is believed.
///
/// The high half is the family `coldsnap_hal::identity::MAGIC_DOMAIN` shares; the
/// low half is this record's kind and version, so a future format can be *refused*
/// by this firmware rather than erased. None of the three values that occur
/// naturally on this board appears as either half: `0x0000_0000` (zeroed SRAM),
/// `0xffff_ffff` (erased flash), `0xdead_beef` (the bootloader's SRAM fill,
/// `mk4-bootloader/main.c:42`).
pub const MAGIC: u64 = 0xC01D_5EED_5A1E_0001;

/// Domain separation for the checksum. Not a secret and not a key.
const DOMAIN: &[u8] = b"coldsnap-share-v1";

const MAGIC_LEN: usize = 8;
const LEN_LEN: usize = 2;
/// Magic + body length: everything before the bincode body.
const HEADER_LEN: usize = MAGIC_LEN + LEN_LEN;
/// The trailing checksum, and the commit: programmed last.
const CHECK_LEN: usize = 8;
/// Room the bincode body may use.
const BODY_MAX: usize = RECORD_LEN - HEADER_LEN - CHECK_LEN;

/// `frostsnap_comms::fixed_string::KEY_NAME_MAX_LENGTH`, in **chars**.
///
/// Restated rather than imported because the wire type is a plain `String`, not a
/// `FixedString` — nothing on the keygen path applies this bound
/// (`frostsnap_core/src/message.rs:53,82,166`), so the only thing that stops a
/// ~20 KiB coordinator-supplied name reaching a 4 KiB slot is `truncate_name`.
pub const KEY_NAME_MAX_CHARS: usize = 15;
/// The byte budget for a truncated name: 15 chars of up to 4 UTF-8 bytes.
pub const KEY_NAME_MAX_BYTES: usize = KEY_NAME_MAX_CHARS * 4;

const START_SECTOR: u32 = memmap::FS_SHARE_OFFSET / SECTOR_SIZE as u32;
const N_SECTORS: u32 = memmap::FS_SHARE_LEN / SECTOR_SIZE as u32;

const _: () = {
    assert!(memmap::FS_SHARE_OFFSET % SECTOR_SIZE as u32 == 0);
    assert!(memmap::FS_SHARE_LEN % SECTOR_SIZE as u32 == 0);
    // `AbSlot::new` asserts both of these at runtime (`ab_write.rs:26-32`), and an
    // assert during boot construction is a brick. Settle them at compile time.
    assert!(N_SECTORS >= 2 && N_SECTORS % 2 == 0);
    // Each A/B copy gets half the region. `SlotValue` prepends a 4-byte index, so
    // this is what makes `StoreFault::TooBig` unreachable for any legal record.
    assert!(RECORD_LEN + 4 <= (N_SECTORS as usize / 2) * SECTOR_SIZE);
    assert!(RECORD_LEN % coldsnap_hal::flash::WRITE_SIZE == 0);
    assert!(CHECK_LEN == coldsnap_hal::flash::WRITE_SIZE);
    assert!(KEY_NAME_MAX_BYTES <= BODY_MAX);
};

/// Fixint LE — matching `frostsnap_embedded`'s `ABWRITE_BINCODE_CONFIG` — plus a
/// **length limit**, which that config lacks.
///
/// The limit is not a nicety. With `NoLimit`, bincode's `claim_container_read` is
/// a no-op (`bincode-2.0.1/src/de/mod.rs:182-191`) and `Vec<u8>::decode` — which
/// is what `String::decode` calls, and `KeyPurpose::Bitcoin`'s `with_serde`
/// `bitcoin::Network` deserialises from a **string** — runs
/// `alloc::vec![0u8; len]` on the raw length claim *before* reading
/// (`impl_alloc.rs:263-272`). A damaged length field could therefore claim up to
/// `u32::MAX` on this 32-bit part, the allocation fails, and the alloc error
/// handler panics at *boot*, before any coordinator contact: a permanent reset
/// loop. With a limit the claim is refused and the record reads as
/// [`HeldShare::Damaged`].
///
/// Belt and braces: the checksum is verified before this config ever sees a byte,
/// so the length being decoded is always one we wrote.
fn body_config() -> impl bincode::config::Config {
    bincode::config::standard()
        .with_fixed_int_encoding()
        .with_limit::<RECORD_LEN>()
}

/// The keygen triple, flattened, with **no `String`, `Vec` or `Box`**.
///
/// `key_name` is bytes + length rather than a `String` so the reload path has no
/// length-prefixed allocation in it at all.
///
/// Deliberately **not** `#[derive(bincode::Encode)]`: that derive emits `::bincode`
/// paths, and `bincode` is in this crate's graph only as a re-export
/// (`frostsnap_core::bincode`), so deriving would mean a new manifest line for a
/// crate that is already linked. The fixed-size fields go at fixed offsets by hand
/// — see [`FIXED_LEN`] — and only the three vendored values that *have* to go
/// through bincode do, as one tuple (`Ciphertext`'s fields are private, so
/// `EncryptedSecretShare` cannot be laid out by hand; it is 32- and 33-byte
/// scalars and points throughout).
#[derive(Clone, Debug, PartialEq)]
struct ShareBody {
    key_id: [u8; 32],
    access_structure_id: [u8; 32],
    threshold: u16,
    name_len: u8,
    name: [u8; KEY_NAME_MAX_BYTES],
    purpose: KeyPurpose,
    kind: AccessStructureKind,
    share: EncryptedSecretShare,
}

/// Byte offsets of the hand-laid fixed fields inside the body.
const F_KEY_ID: usize = 0;
const F_ASID: usize = F_KEY_ID + 32;
const F_THRESHOLD: usize = F_ASID + 32;
const F_NAME_LEN: usize = F_THRESHOLD + 2;
const F_NAME: usize = F_NAME_LEN + 1;
/// Where the bincode tuple `(purpose, kind, share)` starts.
const FIXED_LEN: usize = F_NAME + KEY_NAME_MAX_BYTES;

/// The only part of the body bincode touches.
type Coded = (KeyPurpose, AccessStructureKind, EncryptedSecretShare);

/// Why a save did not happen. Every variant leaves the previous record intact and
/// the staged mutations undrained, so the caller can refuse the operation and
/// return before the ack reaches the outbox.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreFault {
    /// Flash refused an erase or a program, or `AbSlot` ran out of indexes.
    /// Nothing was committed.
    Flash(NorFlashErrorKind),
    /// The staged set is not one complete keygen triple naming one key. Refused
    /// rather than partially stored, because a partial triple reloads as
    /// no-share **silently**.
    NotOneKeygen,
    /// The sealed body overran the body budget. Unreachable for a truncated name
    /// (const-asserted margin above); present so the encode path has no `unwrap`.
    TooBig,
}

/// What the share region holds.
///
/// Three states, not an `Option`, because the caller's correct handling of a
/// damaged record differs from that of an empty one and folding them together is
/// how a device silently forgets a share. Same shape as `identity::Record`.
// `Share` carries the whole ~200-byte record by value on purpose: boxing it to
// even the variants out would put a heap allocation on the boot path for a value
// that is consumed immediately, and there is 5,024 B of arena to spare.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq)]
pub enum HeldShare {
    /// Nothing was ever committed here. A fresh keygen may proceed.
    Vacant,
    /// Something is here and it does not verify — a torn save, or rot. **Not a
    /// hold**: see the module docs. Treat as "no share this boot", and let a
    /// fresh keygen overwrite it.
    Damaged,
    /// A verified record. Feed [`Reload::mutations`] to
    /// `FrostSigner::apply_mutation` in the order given.
    Share(Reload),
}

/// A verified share record, ready to replay.
#[derive(Clone, Debug, PartialEq)]
pub struct Reload(ShareBody);

impl Reload {
    /// The three mutations in **staging order**: `NewKey`, then
    /// `NewAccessStructure`, then `SaveShare`.
    ///
    /// The order is not cosmetic. `apply_mutation` only `and_modify`s for the
    /// second and third (`device.rs:196-235`), so replaying them before `NewKey`
    /// drops them with no error and the device boots with no share.
    /// `reload_yields_the_triple_in_staging_order` holds this.
    #[must_use]
    pub fn mutations(self) -> [Mutation; 3] {
        let ShareBody {
            key_id,
            access_structure_id,
            threshold,
            purpose,
            kind,
            name_len,
            name,
            share,
        } = self.0;
        let access_structure_ref = AccessStructureRef {
            key_id: KeyId(key_id),
            access_structure_id: AccessStructureId(access_structure_id),
        };
        // `unseal` already proved this range is valid UTF-8 and in bounds; going
        // through `from_utf8` again keeps the `unwrap` out of the tree.
        let key_name = core::str::from_utf8(&name[..usize::from(name_len)])
            .unwrap_or_default()
            .into();
        [
            Mutation::Keygen(KeyMutation::NewKey {
                key_id: access_structure_ref.key_id,
                key_name,
                purpose,
            }),
            Mutation::Keygen(KeyMutation::NewAccessStructure {
                access_structure_ref,
                threshold,
                kind,
            }),
            Mutation::Keygen(KeyMutation::SaveShare(Box::new(SaveShareMutation {
                access_structure_ref,
                encrypted_secret_share: share,
            }))),
        ]
    }
}

/// The share region at [`memmap::FS_SHARE_OFFSET`], as two A/B copies of one
/// record.
#[derive(Clone, Debug)]
pub struct ShareStore<'a, F> {
    slot: AbSlot<'a, F>,
}

impl<'a, F: NorFlash> ShareStore<'a, F> {
    /// Open the region. Reads nothing and cannot fail — the sector geometry is
    /// const-asserted above, so `AbSlot::new`'s runtime asserts are unreachable.
    #[must_use]
    pub fn open(flash: &'a RefCell<F>) -> Self {
        Self {
            slot: AbSlot::new(FlashPartition::new(
                flash,
                START_SECTOR,
                N_SECTORS,
                "share",
            )),
        }
    }

    /// Persist the keygen mutations staged on the signer, then drain them.
    ///
    /// Call this at the **top of `Session::run`**, before the loop that pushes
    /// into the `Outbox`, and return the error without pushing. Ordering is a
    /// correctness property, not a style choice: the coordinator applies its own
    /// `NewShare` on the keygen ack and then shows the wallet as complete
    /// (`coordinator/keys.rs:74-78`), so a power cut between ack and persist
    /// leaves it believing `n` shares exist when `n-1` do. With no backup path on
    /// this port the threshold is then silently short and the funds are
    /// unspendable. Upstream persists first for the same reason
    /// (`esp32_run.rs:588-600` then `:618-624`).
    ///
    /// An empty `staged` is the common case and is `Ok(())`.
    ///
    /// `AbWriteOutcome::CommittedSingleCopy` counts as success: the value **is**
    /// readable (`ab_write.rs:83-92`), and refusing would discard a share the
    /// device actually holds.
    ///
    /// # Errors
    ///
    /// See [`StoreFault`]. `staged` is left untouched on every one of them, so
    /// nothing is ever dropped — but "a retry is possible" is only true of
    /// [`StoreFault::Flash`], where the same body can be written again.
    ///
    /// [`StoreFault::NotOneKeygen`] is permanent for the mutations that caused it:
    /// [`body_from`] accepts only a keygen triple, so a `Mutation::Restoration` —
    /// which is what `SavePhysicalBackup2` stages
    /// (`device/restoration.rs:90-97`) — is refused, stays staged, and is refused
    /// again by every later `Session::run` until a reset drops the signer's RAM
    /// `VecDeque`. Fail-CLOSED (nothing is written, nothing is acked, no share is
    /// lost), which is why it ships as is, and the reason lifting the
    /// `PhysicalBackup` refusal in the dispatch is not a one-line change: it needs
    /// a body `body_from` accepts first. Pinned by
    /// `a_non_keygen_mutation_is_refused_and_stays_staged`.
    pub fn persist_staged(&self, staged: &mut VecDeque<Mutation>) -> Result<(), StoreFault> {
        if staged.is_empty() {
            return Ok(());
        }
        let record = seal(&body_from(staged)?)?;
        match self.slot.try_write(&record) {
            AbWriteOutcome::Committed | AbWriteOutcome::CommittedSingleCopy(_) => {
                staged.clear();
                Ok(())
            }
            AbWriteOutcome::NotCommitted(e) => Err(StoreFault::Flash(e)),
        }
    }

    /// Read the region back. No `Result`: `AbSlot::read` maps every failure to
    /// `None` and offers nothing finer.
    ///
    /// ponytail: that means a read *fault* is indistinguishable from an empty
    /// region. On this part it is not a real condition — `StmFlash::read` is a
    /// bounds-checked volatile copy over a compile-time-fixed layout — so the
    /// ceiling is accepted rather than papered over. The upgrade path is a
    /// `FlashPartition::read` of the two copies directly.
    #[must_use]
    pub fn load(&self) -> HeldShare {
        match self.slot.read::<[u8; RECORD_LEN]>() {
            None => HeldShare::Vacant,
            Some(record) => unseal(&record),
        }
    }
}

/// `sha256(DOMAIN ‖ bytes)[..8]`. Integrity, not authentication: it detects a
/// tear or rot, and makes no claim against an attacker who can already program
/// flash.
fn tag_of(bytes: &[u8]) -> [u8; CHECK_LEN] {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(bytes);
    let digest = h.finalize();
    let mut tag = [0u8; CHECK_LEN];
    tag.copy_from_slice(&digest[..CHECK_LEN]);
    tag
}

/// Cut a coordinator-supplied name to [`KEY_NAME_MAX_CHARS`] on a char boundary.
///
/// `String::truncate` panics off a boundary and a panic here is a brick, so the
/// cut is by `char_indices`. 15 chars is at most 60 bytes, which is exactly
/// [`KEY_NAME_MAX_BYTES`], so the copy below can never overrun.
fn truncate_name(name: &str) -> ([u8; KEY_NAME_MAX_BYTES], u8) {
    let end = name
        .char_indices()
        .nth(KEY_NAME_MAX_CHARS)
        .map_or(name.len(), |(i, _)| i);
    let bytes = &name.as_bytes()[..end];
    let mut out = [0u8; KEY_NAME_MAX_BYTES];
    out[..bytes.len()].copy_from_slice(bytes);
    // `bytes.len() <= 60` by the char bound above, so this cast cannot wrap even
    // with `overflow-checks = false`.
    (out, bytes.len() as u8)
}

/// Flatten exactly one keygen triple, or refuse.
///
/// Refuses anything that is not three `Keygen` mutations, in staging order, all
/// naming the same key. Every one of those is fail-closed on purpose — a
/// mismatched or partial set would persist and then reload as no-share silently,
/// which is worse than not persisting.
fn body_from(staged: &VecDeque<Mutation>) -> Result<ShareBody, StoreFault> {
    if staged.len() != 3 {
        return Err(StoreFault::NotOneKeygen);
    }
    match (&staged[0], &staged[1], &staged[2]) {
        (
            Mutation::Keygen(KeyMutation::NewKey {
                key_id,
                key_name,
                purpose,
            }),
            Mutation::Keygen(KeyMutation::NewAccessStructure {
                access_structure_ref,
                threshold,
                kind,
            }),
            Mutation::Keygen(KeyMutation::SaveShare(share)),
        ) if access_structure_ref.key_id == *key_id
            && share.access_structure_ref == *access_structure_ref =>
        {
            let (name, name_len) = truncate_name(key_name);
            Ok(ShareBody {
                key_id: key_id.0,
                access_structure_id: access_structure_ref.access_structure_id.0,
                threshold: *threshold,
                purpose: *purpose,
                kind: *kind,
                name_len,
                name,
                share: share.encrypted_secret_share,
            })
        }
        _ => Err(StoreFault::NotOneKeygen),
    }
}

/// Encode and checksum. The checksum goes **last** in the buffer, which is what
/// makes it the last doubleword programmed — see the module docs.
fn seal(body: &ShareBody) -> Result<[u8; RECORD_LEN], StoreFault> {
    let mut record = [0u8; RECORD_LEN];
    record[..MAGIC_LEN].copy_from_slice(&MAGIC.to_le_bytes());
    {
        let out = &mut record[HEADER_LEN..HEADER_LEN + FIXED_LEN];
        out[F_KEY_ID..F_ASID].copy_from_slice(&body.key_id);
        out[F_ASID..F_THRESHOLD].copy_from_slice(&body.access_structure_id);
        out[F_THRESHOLD..F_NAME_LEN].copy_from_slice(&body.threshold.to_le_bytes());
        out[F_NAME_LEN] = body.name_len;
        out[F_NAME..].copy_from_slice(&body.name);
    }
    let coded: Coded = (body.purpose, body.kind, body.share);
    let written = FIXED_LEN
        + bincode::encode_into_slice(
            coded,
            &mut record[HEADER_LEN + FIXED_LEN..HEADER_LEN + BODY_MAX],
            body_config(),
        )
        .map_err(|_| StoreFault::TooBig)?;
    let len = u16::try_from(written).map_err(|_| StoreFault::TooBig)?;
    record[MAGIC_LEN..HEADER_LEN].copy_from_slice(&len.to_le_bytes());
    let tag = tag_of(&record[..RECORD_LEN - CHECK_LEN]);
    record[RECORD_LEN - CHECK_LEN..].copy_from_slice(&tag);
    Ok(record)
}

/// Verify, then decode. Never the other way round: the checksum is what stops a
/// torn length field reaching bincode's allocator.
fn unseal(record: &[u8; RECORD_LEN]) -> HeldShare {
    let mut magic = [0u8; MAGIC_LEN];
    magic.copy_from_slice(&record[..MAGIC_LEN]);
    if u64::from_le_bytes(magic) != MAGIC {
        // A whole erased record is "nothing was ever written". Anything else with
        // a bad tag was written and cannot be read.
        return if record.iter().all(|b| *b == 0xff) {
            HeldShare::Vacant
        } else {
            HeldShare::Damaged
        };
    }
    let (body, check) = record.split_at(RECORD_LEN - CHECK_LEN);
    if tag_of(body) != check {
        return HeldShare::Damaged;
    }
    let len = usize::from(u16::from_le_bytes([record[MAGIC_LEN], record[MAGIC_LEN + 1]]));
    if !(FIXED_LEN..=BODY_MAX).contains(&len) {
        return HeldShare::Damaged;
    }
    let body = &record[HEADER_LEN..HEADER_LEN + len];
    let Ok((coded, _)) = bincode::decode_from_slice::<Coded, _>(&body[FIXED_LEN..], body_config())
    else {
        return HeldShare::Damaged;
    };
    let name_len = body[F_NAME_LEN];
    // The name must be in bounds and valid UTF-8 before `Reload::mutations` can
    // rebuild a `String` from it without an `unwrap` that could lose it.
    if usize::from(name_len) > KEY_NAME_MAX_BYTES
        || core::str::from_utf8(&body[F_NAME..F_NAME + usize::from(name_len)]).is_err()
    {
        return HeldShare::Damaged;
    }
    let mut key_id = [0u8; 32];
    key_id.copy_from_slice(&body[F_KEY_ID..F_ASID]);
    let mut access_structure_id = [0u8; 32];
    access_structure_id.copy_from_slice(&body[F_ASID..F_THRESHOLD]);
    let mut name = [0u8; KEY_NAME_MAX_BYTES];
    name.copy_from_slice(&body[F_NAME..FIXED_LEN]);
    HeldShare::Share(Reload(ShareBody {
        key_id,
        access_structure_id,
        threshold: u16::from_le_bytes([body[F_THRESHOLD], body[F_THRESHOLD + 1]]),
        name_len,
        name,
        purpose: coded.0,
        kind: coded.1,
        share: coded.2,
    }))
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use coldsnap_hal::flash::fake::FakeFlash;
    use frostsnap_core::device::restoration::RestorationMutation;
    use frostsnap_core::schnorr_fun::frost::{ShareImage, ShareIndex};
    use frostsnap_core::schnorr_fun::fun::prelude::*;
    use alloc::string::String;
    use frostsnap_core::{Ciphertext, SymmetricKey};
    use std::vec::Vec as StdVec;

    /// A fake at the shipped geometry, sized to cover every claimed region so a
    /// write outside the share partition is out of bounds rather than silent.
    fn flash() -> RefCell<FakeFlash> {
        RefCell::new(FakeFlash::new(
            (memmap::FS_FREE_OFFSET / SECTOR_SIZE as u32) as usize,
        ))
    }

    fn encrypted_share(seed: u8) -> EncryptedSecretShare {
        EncryptedSecretShare {
            share_image: ShareImage {
                index: ShareIndex::one(),
                image: Point::zero(),
            },
            ciphertext: Ciphertext::encrypt(
                SymmetricKey([seed; 32]),
                &Scalar::<Secret, Zero>::zero(),
                &mut TestRng(seed),
            ),
        }
    }

    /// A deterministic `RngCore` for the ciphertext nonce. Not a security seam:
    /// nothing here is verified against a real coordinator.
    struct TestRng(u8);
    impl rand_core::RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            self.0 = self.0.wrapping_mul(7).wrapping_add(11);
            u32::from(self.0) * 0x0101_0101
        }
        fn next_u64(&mut self) -> u64 {
            u64::from(self.next_u32()) << 32 | u64::from(self.next_u32())
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for b in dest.iter_mut() {
                self.0 = self.0.wrapping_mul(7).wrapping_add(11);
                *b = self.0;
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    fn asr(seed: u8) -> AccessStructureRef {
        AccessStructureRef {
            key_id: KeyId([seed; 32]),
            access_structure_id: AccessStructureId([seed.wrapping_add(1); 32]),
        }
    }

    /// Exactly what `save_complete_share` stages, in its order.
    fn triple(seed: u8, name: &str) -> VecDeque<Mutation> {
        let access_structure_ref = asr(seed);
        VecDeque::from(std::vec![
            Mutation::Keygen(KeyMutation::NewKey {
                key_id: access_structure_ref.key_id,
                key_name: String::from(name),
                purpose: KeyPurpose::Test,
            }),
            Mutation::Keygen(KeyMutation::NewAccessStructure {
                access_structure_ref,
                threshold: 2,
                kind: AccessStructureKind::Master,
            }),
            Mutation::Keygen(KeyMutation::SaveShare(Box::new(SaveShareMutation {
                access_structure_ref,
                encrypted_secret_share: encrypted_share(seed),
            }))),
        ])
    }

    fn share_of(held: HeldShare) -> Reload {
        match held {
            HeldShare::Share(r) => r,
            other => panic!("expected a share, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // The happy path, and the drain contract.
    // -----------------------------------------------------------------------

    #[test]
    fn a_saved_triple_reloads_across_a_power_cycle() {
        let f = flash();
        let mut staged = triple(9, "vault");
        let want = staged.clone();
        ShareStore::open(&f).persist_staged(&mut staged).unwrap();
        assert!(staged.is_empty(), "a committed save must drain the staged set");

        // A fresh store over the same cells is exactly what the next boot does.
        let reloaded = share_of(ShareStore::open(&f).load()).mutations();
        assert_eq!(&reloaded[..], &StdVec::from(want)[..]);
    }

    /// MUTATION-VERIFY (reload ordering). Swap two arms of `Reload::mutations`
    /// and this fails: a `SaveShare` replayed before its `NewKey` is dropped by
    /// `apply_mutation` with no error at all.
    #[test]
    fn reload_yields_the_triple_in_staging_order() {
        let f = flash();
        let mut staged = triple(3, "abc");
        ShareStore::open(&f).persist_staged(&mut staged).unwrap();

        let got = share_of(ShareStore::open(&f).load()).mutations();
        assert!(
            matches!(got[0], Mutation::Keygen(KeyMutation::NewKey { .. })),
            "NewKey must be replayed first, got {:?}",
            got[0]
        );
        assert!(
            matches!(
                got[1],
                Mutation::Keygen(KeyMutation::NewAccessStructure { .. })
            ),
            "NewAccessStructure must be replayed second, got {:?}",
            got[1]
        );
        assert!(
            matches!(got[2], Mutation::Keygen(KeyMutation::SaveShare(_))),
            "SaveShare must be replayed last, got {:?}",
            got[2]
        );
    }

    #[test]
    fn nothing_staged_is_not_an_error_and_writes_nothing() {
        let f = flash();
        let mut staged = VecDeque::new();
        ShareStore::open(&f).persist_staged(&mut staged).unwrap();
        assert_eq!(f.borrow().programs, 0, "an empty save touched flash");
        assert_eq!(ShareStore::open(&f).load(), HeldShare::Vacant);
    }

    #[test]
    fn a_second_keygen_replaces_the_first() {
        let f = flash();
        let store = ShareStore::open(&f);
        store.persist_staged(&mut triple(1, "one")).unwrap();
        store.persist_staged(&mut triple(2, "two")).unwrap();
        let got = share_of(store.load()).mutations();
        assert_eq!(&got[..], &StdVec::from(triple(2, "two"))[..]);
    }

    // -----------------------------------------------------------------------
    // MUTATION-VERIFY 1: an all-0xff region must never read as a share.
    // -----------------------------------------------------------------------

    /// Delete the `MAGIC` check in `unseal`, or make the `Vacant` arm return a
    /// `Share`, and this fails. Erased flash is `0xff` everywhere and SRAM
    /// arrives as `0xdeadbeef`; neither may look like a record.
    #[test]
    fn an_erased_region_is_vacant_not_a_share() {
        let f = flash();
        assert_eq!(ShareStore::open(&f).load(), HeldShare::Vacant);

        // And the three naturally-occurring fill patterns are not records either:
        // 0xff is erased flash, 0x00 is zeroed SRAM, 0xef is a byte of the
        // bootloader's 0xdeadbeef fill.
        for fill in [0xffu8, 0x00, 0xef] {
            let f = flash();
            let base = memmap::FS_SHARE_OFFSET as usize;
            f.borrow_mut()
                .scribble(base, memmap::FS_SHARE_LEN as usize, fill);
            assert!(
                !matches!(ShareStore::open(&f).load(), HeldShare::Share(_)),
                "a region filled with {fill:#04x} read as a share"
            );
        }
    }

    // -----------------------------------------------------------------------
    // MUTATION-VERIFY 2 and 3: torn writes, and the commit-last property.
    // -----------------------------------------------------------------------

    /// MUTATION-VERIFY (accept a torn record). Drop the `tag_of(body) != check`
    /// arm from `unseal` and this fails at the `Damaged` assertion: the record
    /// would decode as a *valid* share whose ciphertext tail is `0xff`.
    ///
    /// The tear is fabricated by rewriting the tail of a committed record to
    /// `0xff`, which is byte-for-byte what a power cut mid-program leaves —
    /// `FakeFlash::refuse_programs_now` refuses *before* mutating a cell, so it
    /// models a clean refusal, not a tear.
    #[test]
    fn a_tear_before_the_checksum_reads_as_damaged_not_as_a_share() {
        for torn_bytes in [8usize, 64, RECORD_LEN - HEADER_LEN] {
            let f = flash();
            let store = ShareStore::open(&f);
            store.persist_staged(&mut triple(5, "torn")).unwrap();

            // Copy A starts at the region base; `SlotValue` prepends 4 bytes.
            let record_end = memmap::FS_SHARE_OFFSET as usize + 4 + RECORD_LEN;
            f.borrow_mut()
                .scribble(record_end - torn_bytes, torn_bytes, 0xff);

            assert_eq!(
                store.load(),
                HeldShare::Damaged,
                "a tear of {torn_bytes} bytes did not read as damaged"
            );
        }
    }

    /// MUTATION-VERIFY (skip the commit word). Move the checksum anywhere but the
    /// end of the record and this fails. Program order is ascending
    /// (`hal/src/flash.rs:1256`), so only a trailing checksum is guaranteed to be
    /// the last thing on flash — which is the whole reason a tear is detectable.
    #[test]
    fn the_checksum_occupies_the_last_doubleword() {
        let record = seal(&body_from(&triple(7, "commit")).unwrap()).unwrap();
        let (body, check) = record.split_at(RECORD_LEN - CHECK_LEN);
        assert_eq!(check, &tag_of(body)[..], "checksum is not the record tail");
        assert_eq!(CHECK_LEN, coldsnap_hal::flash::WRITE_SIZE);
        assert_eq!(RECORD_LEN % coldsnap_hal::flash::WRITE_SIZE, 0);
        // Losing only that final doubleword — the narrowest possible tear — is
        // still caught.
        let mut torn = record;
        torn[RECORD_LEN - CHECK_LEN..].fill(0xff);
        assert_eq!(unseal(&torn), HeldShare::Damaged);
    }

    /// MUTATION-VERIFY (silently drop a record / never report success falsely).
    /// Make the `NotCommitted` arm of `persist_staged` return `Ok(())`, or clear
    /// `staged` before the write, and this fails. A drained-but-unwritten set is
    /// a lost share that the coordinator is about to be told exists.
    #[test]
    fn a_refused_flash_commits_nothing_and_keeps_the_staged_set() {
        let f = flash();
        let store = ShareStore::open(&f);
        store.persist_staged(&mut triple(1, "first")).unwrap();

        f.borrow_mut().refuse_erases_now();
        let mut staged = triple(2, "second");
        assert_eq!(
            store.persist_staged(&mut staged),
            Err(StoreFault::Flash(NorFlashErrorKind::Other))
        );
        assert_eq!(staged.len(), 3, "a refused save drained the staged set");

        // The first record is untouched and still current.
        f.borrow_mut().heal();
        let got = share_of(store.load()).mutations();
        assert_eq!(&got[..], &StdVec::from(triple(1, "first"))[..]);
    }

    /// One surviving copy is enough, which is why `persist_staged` maps
    /// `AbWriteOutcome::CommittedSingleCopy` to `Ok`: refusing it would discard a
    /// share the device really holds. Copy B is erased here to stand for the
    /// second copy never having landed. (`AbSlot`'s own
    /// `fault_between_the_two_copies_reports_committed_and_the_new_value_is_live`
    /// pins the outcome value; this pins that a lone copy still *reads*.)
    #[test]
    fn one_surviving_copy_still_reads_as_the_share() {
        let f = flash();
        let store = ShareStore::open(&f);
        store.persist_staged(&mut triple(4, "single")).unwrap();

        // Copy B is the upper half of the region (`AbSlot::new` splits off the
        // end). Erased = never written.
        let half = memmap::FS_SHARE_LEN as usize / 2;
        f.borrow_mut()
            .scribble(memmap::FS_SHARE_OFFSET as usize + half, half, 0xff);

        let got = share_of(store.load()).mutations();
        assert_eq!(&got[..], &StdVec::from(triple(4, "single"))[..]);
    }

    // -----------------------------------------------------------------------
    // MUTATION-VERIFY 5: the triple must stay whole, and bounded.
    // -----------------------------------------------------------------------

    /// MUTATION-VERIFY (accept a partial triple). Relax `body_from`'s length or
    /// same-key check and this fails. A partial or mismatched set persists fine
    /// and then reloads as **no share**, because `apply_mutation` `and_modify`s
    /// without `or_insert`.
    #[test]
    fn a_partial_or_mismatched_triple_is_refused_and_nothing_is_written() {
        let f = flash();
        let store = ShareStore::open(&f);

        let full = triple(1, "k");
        for take in [1usize, 2] {
            let mut partial: VecDeque<Mutation> = full.iter().take(take).cloned().collect();
            assert_eq!(
                store.persist_staged(&mut partial),
                Err(StoreFault::NotOneKeygen)
            );
        }

        // Three mutations, but the SaveShare belongs to a different key.
        let mut crossed = full.clone();
        crossed[2] = Mutation::Keygen(KeyMutation::SaveShare(Box::new(SaveShareMutation {
            access_structure_ref: asr(2),
            encrypted_secret_share: encrypted_share(2),
        })));
        assert_eq!(
            store.persist_staged(&mut crossed),
            Err(StoreFault::NotOneKeygen)
        );

        // Six mutations (two keygens at once) is also not one record.
        let mut doubled = full.clone();
        doubled.extend(triple(2, "k2"));
        assert_eq!(
            store.persist_staged(&mut doubled),
            Err(StoreFault::NotOneKeygen)
        );

        assert_eq!(f.borrow().programs, 0, "a refused triple reached flash");
        assert_eq!(store.load(), HeldShare::Vacant);
    }

    /// MUTATION-VERIFY (a wedge that must stay visible, not a repair). `body_from`
    /// accepts only a keygen triple, so the single `Mutation::Restoration` that
    /// `SavePhysicalBackup2` stages (`device/restoration.rs:90-97`) is refused,
    /// stays staged, and is refused again by every later `Session::run` until a
    /// reset. Fail-closed, so it ships; pinned here so enabling that message can
    /// never be a one-line dispatch change. Make `persist_staged` clear `staged`
    /// off the error path and the "not dropped" assert fails; teach `body_from` to
    /// accept a `Restoration` and the first assert fails.
    #[test]
    fn a_non_keygen_mutation_is_refused_and_stays_staged() {
        let f = flash();
        let store = ShareStore::open(&f);
        let mut staged = VecDeque::from(std::vec![Mutation::Restoration(
            RestorationMutation::_UnSave(ShareImage {
                index: ShareIndex::one(),
                image: Point::zero(),
            })
        )]);
        assert_eq!(
            store.persist_staged(&mut staged),
            Err(StoreFault::NotOneKeygen)
        );
        assert_eq!(staged.len(), 1, "a refused mutation must not be dropped");
        assert_eq!(f.borrow().programs, 0, "a refused mutation reached flash");

        // And it stays wedged: a later legitimate keygen stages three more behind
        // the stuck one, which is four mutations and still not one record.
        staged.extend(triple(1, "after"));
        assert_eq!(
            store.persist_staged(&mut staged),
            Err(StoreFault::NotOneKeygen)
        );
        assert_eq!(store.load(), HeldShare::Vacant);
    }

    /// MUTATION-VERIFY (unbounded name). Remove `truncate_name`'s `nth` cut and
    /// this fails with `TooBig` — or, on real flash with a ~20 KiB
    /// coordinator-supplied name, with `OutOfBounds` *after* the human already
    /// consented. `key_name` is a plain `String` on the wire with nothing
    /// applying `KEY_NAME_MAX_LENGTH`.
    #[test]
    fn an_oversized_key_name_is_truncated_not_refused() {
        let f = flash();
        let store = ShareStore::open(&f);
        // 20 KiB, the `MAX_MESSAGE_ALLOC_SIZE` ceiling, and multi-byte so the cut
        // has a boundary to get wrong.
        let long = "é".repeat(10_000);
        let mut staged = triple(6, &long);
        store.persist_staged(&mut staged).unwrap();

        let got = share_of(store.load()).mutations();
        let Mutation::Keygen(KeyMutation::NewKey { key_name, .. }) = &got[0] else {
            panic!("first mutation is not NewKey");
        };
        assert_eq!(key_name.chars().count(), KEY_NAME_MAX_CHARS);
        assert_eq!(key_name.len(), KEY_NAME_MAX_CHARS * 2, "cut mid-char");
    }

    #[test]
    fn a_name_of_exactly_the_byte_budget_survives_whole() {
        let f = flash();
        let store = ShareStore::open(&f);
        // 15 four-byte chars = 60 bytes = the whole budget.
        let name = "\u{1d11e}".repeat(KEY_NAME_MAX_CHARS);
        assert_eq!(name.len(), KEY_NAME_MAX_BYTES);
        store.persist_staged(&mut triple(8, &name)).unwrap();
        let got = share_of(store.load()).mutations();
        let Mutation::Keygen(KeyMutation::NewKey { key_name, .. }) = &got[0] else {
            panic!("first mutation is not NewKey");
        };
        assert_eq!(*key_name, name);
    }

    /// The record is fixed-shape, so its encoded size is a constant. Pinned so a
    /// vendored type growing a field shows up here rather than as an
    /// `OutOfBounds` on a device that has just finished a keygen.
    #[test]
    fn the_sealed_record_has_room_to_spare() {
        let record = seal(&body_from(&triple(1, "abcdefghijklmno")).unwrap()).unwrap();
        let n = usize::from(u16::from_le_bytes([record[MAGIC_LEN], record[MAGIC_LEN + 1]]));
        std::eprintln!("share body encodes to {n} bytes of {BODY_MAX} (fixed part {FIXED_LEN})");
        // MEASURED, not computed: 127 B of hand-laid fixed fields plus a 133-byte
        // bincode tuple (4-byte KeyPurpose tag, 4-byte AccessStructureKind tag,
        // 65-byte ShareImage, 60-byte Ciphertext<32,_>).
        assert_eq!(
            n, 260,
            "the share body changed size ({n} B, was 260). Re-check the margin \
             below and the 16 KiB region before shipping."
        );
        assert!(
            n + 128 <= BODY_MAX,
            "share body is {n} B of {BODY_MAX} B — under 128 B of headroom"
        );
    }

    /// A body length below the fixed part must be refused *before* it is used to
    /// slice. The checksum makes this unreachable from a tear — a tear leaves
    /// `0xff` and fails the tag — so it is reachable only by forging a tag, which
    /// is what this does. Without the lower bound `unseal` indexes past the end of
    /// the body and panics, and a panic at boot under `panic = "abort"` is a brick.
    #[test]
    fn a_short_body_length_is_refused_before_it_is_used_to_slice() {
        for len in [0usize, FIXED_LEN - 1] {
            let mut record = seal(&body_from(&triple(1, "short")).unwrap()).unwrap();
            record[MAGIC_LEN..HEADER_LEN].copy_from_slice(&(len as u16).to_le_bytes());
            // Re-tag so the length is the only thing wrong.
            let tag = tag_of(&record[..RECORD_LEN - CHECK_LEN]);
            record[RECORD_LEN - CHECK_LEN..].copy_from_slice(&tag);
            assert_eq!(unseal(&record), HeldShare::Damaged, "len {len} was accepted");
        }
    }

    /// A record from a future format family must be refused, not read and not
    /// silently erased: `MAGIC`'s low half is the version for exactly this.
    #[test]
    fn a_future_version_reads_as_damaged() {
        let f = flash();
        let store = ShareStore::open(&f);
        store.persist_staged(&mut triple(1, "v2")).unwrap();
        let base = memmap::FS_SHARE_OFFSET as usize + 4;
        // Bump the version nibble in place.
        f.borrow_mut().scribble(base, 1, 0x09);
        assert_eq!(store.load(), HeldShare::Damaged);
    }
}
