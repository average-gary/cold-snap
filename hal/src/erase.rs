//! Resumable erasure of cold-snap's data region: the erase-in-progress marker,
//! the bounded eraser, and the boot-time interpretation of whatever an
//! interrupted erase left behind.
//!
//! # What is erased, and what is not
//!
//! The **data region** is `FLASH_FS[0 .. memmap::FS_ERASE_OFFSET)`: the identity
//! record, all four nonce streams (both A/B copies each), both A/B copies of the
//! share record, and both A/B copies of the name. That is every byte cold-snap
//! persists — the restore mutation is never persisted and nothing else is on
//! flash. Whole regions are erased, so stale A/B copies go with live ones.
//!
//! The eraser writes only the 8 K marker region at
//! [`memmap::FS_ERASE_OFFSET`] and erases only
//! the data region and that marker region. Nothing at or above
//! [`memmap::FS_FREE_OFFSET`] is addressed, and
//! nothing outside `FLASH_FS` CAN be: every offset here is FS-relative, and
//! [`StmFlash`](crate::flash::StmFlash) bounds each operation to `FLASH_FS`
//! (`flash::check_bounds`) and refuses any page below `FLASH_ERASE_FLOOR`
//! (`flash::erase_page_of`). No callgate call, no secure-element selector, no
//! option byte, and in particular not Coldcard's `fast_wipe()` — which clears
//! the MCU key and resets, and never touches `FLASH_FS`, so it would leave a
//! cold-snap share in place.
//!
//! This is not a Coldcard factory reset or PIN reset. On completion the data
//! region is blank, so the next [`identity::load_or_create`](crate::identity::load_or_create)
//! finds `Vacant` and generates a FRESH identity: a new `DeviceId`, no share,
//! no nonce streams, no name.
//!
//! # The marker
//!
//! 16 bytes at the start of the marker region, written in two programs:
//!
//! | offset | bytes | field |
//! |--------|-------|-------|
//! | `0x00` | 8 | `sha256(DOMAIN)[..8]`, the body |
//! | `0x08` | 8 | [`MAGIC`], programmed **last**: the commit |
//!
//! [`classify`] reads it as exactly one of:
//!
//! | bytes | [`Marker`] | boot does |
//! |---|---|---|
//! | erased, torn body, body without commit, somebody else's bytes | `Clear` | nothing: no erase was ever committed |
//! | body + commit, both exact | `Pending` | resume: [`destroy`], then [`finish`] |
//! | commit exact, body wrong | `Damaged` | hold |
//! | commit from our family (`0xC01D_5EED`), unknown version | `Damaged` | hold |
//!
//! A torn marker write before the commit is `Clear`, and [`destroy`] refuses
//! anything but `Pending`, so a torn write cannot start destruction. `Damaged`
//! is never read as "blank device": the region may be half-erased, so boot holds
//! rather than resuming on a record it cannot vouch for or regenerating over it.
//!
//! # Ordering, and why every restart state is defined
//!
//! 1. [`begin`]: erase the marker region, program body, program commit, read
//!    back. Until the commit lands nothing is destroyed.
//! 2. [`destroy`]: refuses unless the marker reads `Pending`. Erases the data
//!    region one 4 K sector per call, SHARE FIRST, then nonces, then name, and
//!    IDENTITY LAST; then reads every byte back as `0xff`.
//! 3. The caller acknowledges (`CommsMisc::EraseConfirmed`) — after `destroy`
//!    returned `Ok`, never before.
//! 4. [`finish`]: re-verifies the data region is blank, then erases the marker
//!    region and reads it back blank. The marker therefore outlives the data.
//! 5. The caller resets; boot finds `Clear` and a vacant identity.
//!
//! At boot, [`recover`] runs BEFORE identity generation, session opening, or
//! nonce use. `Pending` resumes steps 2 and 4 (idempotent — erasing blank
//! sectors again is harmless) and does NOT acknowledge: the original identity
//! may already be gone, so there is nothing true to sign the ack with. A
//! coordinator waiting on that ack keeps waiting; it is never told a falsehood.
//!
//! The share-first order is a second line behind the marker, not a substitute
//! for it: at every intermediate state, if any nonce or name or identity sector
//! has been erased then the whole share region already is, so even a device
//! that ignored the marker could not pair an old share with rewound nonce
//! state. `every_interrupted_state_is_blocked_and_every_restart_resolves` holds
//! both properties over every operation.
//!
//! # What this does NOT validate
//!
//! Every test here runs over `flash::fake::FakeFlash` (not linked: feature-gated), whose
//! erase and program are all-or-nothing per call. Host fault injection says
//! nothing about STM32 erase physics — a page erase torn by power loss, ECC
//! behaviour on half-erased cells, erase disturb — and nothing about secure
//! deletion from a physically compromised chip (remanence, decapping). Those
//! are bench questions (DECISIONS.md §5).

use crate::memmap;
use embedded_storage::nor_flash::{NorFlash, NorFlashError, NorFlashErrorKind, ReadNorFlash};
use sha2::{Digest, Sha256};

/// Commit word. High half is cold-snap's record family (the same
/// `0xC01D_5EED` [`crate::identity::MAGIC_DOMAIN`] and the share store use),
/// then `E7A5` for this record kind, then version `0001`. Programmed last.
pub const MAGIC: u64 = 0xC01D_5EED_E7A5_0001;

const FAMILY: u32 = (MAGIC >> 32) as u32;
const DOMAIN: &[u8] = b"coldsnap-erase-marker-v1";

/// Marker record length: body + commit.
pub const RECORD_LEN: usize = 16;

/// The data region the eraser destroys, in the order it destroys it.
///
/// Share first and identity last; see the module docs for why the order is
/// load-bearing.
const DATA: [(u32, u32); 4] = [
    (memmap::FS_SHARE_OFFSET, memmap::FS_SHARE_LEN),
    (memmap::FS_NONCE_OFFSET, memmap::FS_NONCE_LEN),
    (memmap::FS_NAME_OFFSET, memmap::FS_NAME_LEN),
    (memmap::FS_IDENTITY_OFFSET, memmap::FS_IDENTITY_LEN),
];

const SECTOR: u32 = crate::flash::ERASE_SIZE as u32;

// The four regions tile `[0, FS_ERASE_OFFSET)` exactly: nothing cold-snap
// stores is left out, and nothing past the marker is in.
const _: () = {
    assert!(memmap::FS_IDENTITY_OFFSET == 0);
    assert!(
        memmap::FS_IDENTITY_LEN + memmap::FS_NONCE_LEN + memmap::FS_SHARE_LEN + memmap::FS_NAME_LEN
            == memmap::FS_ERASE_OFFSET
    );
    assert!(memmap::FS_ERASE_OFFSET + memmap::FS_ERASE_LEN == memmap::FS_FREE_OFFSET);
    let mut i = 0;
    while i < DATA.len() {
        assert!(DATA[i].0 % SECTOR == 0 && DATA[i].1 % SECTOR == 0);
        i += 1;
    }
};

/// What the marker region says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Marker {
    /// No erase was ever committed. Proceed with a normal boot.
    Clear,
    /// A committed erase that has not been finished. Resume it before anything
    /// else reads the data region.
    Pending,
    /// A committed record that does not verify, or a newer format. Hold.
    Damaged,
}

/// Why an erase step (or boot recovery) stopped. Every variant leaves the
/// marker as it was on flash, so the next boot reinterprets from bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EraseFault {
    /// The marker is [`Marker::Damaged`]. Hold: do not resume, do not boot.
    Damaged,
    /// [`destroy`] or [`finish`] was called without a committed marker.
    /// Nothing was erased.
    NotBegun,
    /// Flash refused a read, program or erase.
    Flash(NorFlashErrorKind),
    /// An operation reported success and the read-back disagrees.
    VerifyFailed,
}

fn flash_err<E: NorFlashError>(e: E) -> EraseFault {
    EraseFault::Flash(e.kind())
}

fn body() -> [u8; 8] {
    let digest = Sha256::digest(DOMAIN);
    let mut b = [0u8; 8];
    b.copy_from_slice(&digest[..8]);
    b
}

/// The whole classification, over bytes. See the module docs' table.
#[must_use]
pub fn classify(record: &[u8; RECORD_LEN]) -> Marker {
    let mut commit = [0u8; 8];
    commit.copy_from_slice(&record[8..]);
    let commit = u64::from_le_bytes(commit);
    let body_ok = record[..8] == body();
    match (commit == MAGIC, body_ok) {
        (true, true) => Marker::Pending,
        (true, false) => Marker::Damaged,
        // Our family, a version this firmware does not know: a newer firmware's
        // workflow. Resuming it could be wrong and ignoring it could reopen a
        // half-erased device, so hold.
        (false, _) if (commit >> 32) as u32 == FAMILY => Marker::Damaged,
        // Erased, torn before commit, or LFS2 leftovers on a converted Mk4.
        (false, _) => Marker::Clear,
    }
}

/// Read and classify the marker.
///
/// # Errors
///
/// [`EraseFault::Flash`] if the read is refused.
pub fn read<S: ReadNorFlash>(flash: &mut S) -> Result<Marker, EraseFault> {
    let mut buf = [0u8; RECORD_LEN];
    flash
        .read(memmap::FS_ERASE_OFFSET, &mut buf)
        .map_err(flash_err)?;
    Ok(classify(&buf))
}

/// Commit an erase: write and verify the marker. Destroys nothing.
///
/// Call only after fresh on-device consent. Idempotent on an already-`Pending`
/// marker (which it leaves untouched).
///
/// # Errors
///
/// [`EraseFault::Damaged`] leaves the marker untouched. Any other fault may
/// leave it `Clear` (nothing committed) or `Pending` (committed, read-back
/// failed); the next boot's [`recover`] interprets whichever it is.
pub fn begin<S: NorFlash>(flash: &mut S) -> Result<(), EraseFault> {
    match read(flash)? {
        Marker::Pending => return Ok(()),
        Marker::Damaged => return Err(EraseFault::Damaged),
        Marker::Clear => {}
    }
    const AT: u32 = memmap::FS_ERASE_OFFSET;
    // Unconditionally: `Clear` includes a torn body and foreign bytes.
    flash
        .erase(AT, AT + memmap::FS_ERASE_LEN)
        .map_err(flash_err)?;
    flash.write(AT, &body()).map_err(flash_err)?;
    flash
        .write(AT + 8, &MAGIC.to_le_bytes())
        .map_err(flash_err)?;
    match read(flash)? {
        Marker::Pending => Ok(()),
        _ => Err(EraseFault::VerifyFailed),
    }
}

fn verify_blank<S: ReadNorFlash>(flash: &mut S, from: u32, len: u32) -> Result<(), EraseFault> {
    let mut buf = [0u8; 256];
    let mut at = from;
    while at < from + len {
        flash.read(at, &mut buf).map_err(flash_err)?;
        if buf.iter().any(|&b| b != 0xff) {
            return Err(EraseFault::VerifyFailed);
        }
        at += buf.len() as u32;
    }
    Ok(())
}

fn verify_data_blank<S: ReadNorFlash>(flash: &mut S) -> Result<(), EraseFault> {
    for (off, len) in DATA {
        verify_blank(flash, off, len)?;
    }
    Ok(())
}

/// Destroy the data region and verify it reads blank. Refuses — erasing
/// nothing — unless a committed marker is on flash.
///
/// # Errors
///
/// [`EraseFault::NotBegun`] or [`EraseFault::Damaged`] before any erase; a
/// flash or verify fault part way, with the marker still `Pending`.
pub fn destroy<S: NorFlash>(flash: &mut S) -> Result<(), EraseFault> {
    match read(flash)? {
        Marker::Pending => {}
        Marker::Clear => return Err(EraseFault::NotBegun),
        Marker::Damaged => return Err(EraseFault::Damaged),
    }
    for (off, len) in DATA {
        // One sector per call, so every sector is its own interruption point.
        let mut at = off;
        while at < off + len {
            flash.erase(at, at + SECTOR).map_err(flash_err)?;
            at += SECTOR;
        }
    }
    verify_data_blank(flash)
}

/// Clear the marker, which is the completion transition. Refuses unless the
/// marker is `Pending` and the data region already reads blank, so the marker
/// cannot be cleared ahead of the data.
///
/// # Errors
///
/// As [`destroy`] for the preconditions; then a flash or verify fault, after
/// which the marker may be `Pending` (resumed at boot) or `Clear`.
pub fn finish<S: NorFlash>(flash: &mut S) -> Result<(), EraseFault> {
    match read(flash)? {
        Marker::Pending => {}
        Marker::Clear => return Err(EraseFault::NotBegun),
        Marker::Damaged => return Err(EraseFault::Damaged),
    }
    verify_data_blank(flash)?;
    const AT: u32 = memmap::FS_ERASE_OFFSET;
    flash
        .erase(AT, AT + memmap::FS_ERASE_LEN)
        .map_err(flash_err)?;
    verify_blank(flash, AT, memmap::FS_ERASE_LEN)
}

/// Boot step: interpret the marker BEFORE identity, session or nonces.
///
/// `Ok(false)`: no erase in progress, boot normally. `Ok(true)`: an interrupted
/// erase was resumed and completed; the data region is blank and identity will
/// regenerate. No acknowledgement is owed or possible here (module docs).
///
/// # Errors
///
/// Every `Err` is a hold. [`EraseFault::Damaged`] touches nothing.
pub fn recover<S: NorFlash>(flash: &mut S) -> Result<bool, EraseFault> {
    match read(flash)? {
        Marker::Clear => Ok(false),
        Marker::Damaged => Err(EraseFault::Damaged),
        Marker::Pending => {
            destroy(flash)?;
            finish(flash)?;
            Ok(true)
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::flash::fake::FakeFlash;
    use crate::flash::FlashError;
    use embedded_storage::nor_flash::ErrorType;
    use std::vec::Vec;

    const FS_SECTORS: usize = (memmap::FLASH_FS_LEN / SECTOR) as usize;
    const DATA_END: usize = memmap::FS_ERASE_OFFSET as usize;
    const FREE: usize = memmap::FS_FREE_OFFSET as usize;
    const MARKER: usize = memmap::FS_ERASE_OFFSET as usize;

    #[test]
    fn classify_table() {
        let full = {
            let mut r = [0u8; RECORD_LEN];
            r[..8].copy_from_slice(&body());
            r[8..].copy_from_slice(&MAGIC.to_le_bytes());
            r
        };
        assert_eq!(classify(&[0xff; RECORD_LEN]), Marker::Clear, "erased");
        assert_eq!(classify(&[0x00; RECORD_LEN]), Marker::Clear, "zeroed");
        assert_eq!(classify(&[0x3c; RECORD_LEN]), Marker::Clear, "foreign");
        let mut torn = full;
        torn[8..].fill(0xff);
        assert_eq!(classify(&torn), Marker::Clear, "body without commit");
        let mut torn_body = torn;
        torn_body[4..8].fill(0xff);
        assert_eq!(classify(&torn_body), Marker::Clear, "torn body");
        assert_eq!(classify(&full), Marker::Pending);
        let mut rot = full;
        rot[0] ^= 1;
        assert_eq!(classify(&rot), Marker::Damaged, "committed, body rotted");
        let mut commit_only = [0xff; RECORD_LEN];
        commit_only[8..].copy_from_slice(&MAGIC.to_le_bytes());
        assert_eq!(
            classify(&commit_only),
            Marker::Damaged,
            "commit without body"
        );
        let mut newer = full;
        newer[8..].copy_from_slice(&(MAGIC + 1).to_le_bytes());
        assert_eq!(classify(&newer), Marker::Damaged, "unknown version");
        let mut other_kind = full;
        other_kind[8..].copy_from_slice(&0xC01D_5EED_5A1E_0001u64.to_le_bytes());
        assert_eq!(
            classify(&other_kind),
            Marker::Damaged,
            "our family, other kind"
        );
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Op {
        Read,
        Write,
        Erase,
    }

    /// FakeFlash with a per-call op log and one scheduled interruption: every
    /// call from index `fail_from` on is refused, or (with `after`) a mutation
    /// at exactly that index is PERFORMED and then reported as failed — power
    /// lost after the cells changed but before software saw success.
    struct Rig {
        inner: FakeFlash,
        log: Vec<(Op, u32, u32)>,
        fail_from: Option<usize>,
        after: bool,
    }

    impl Rig {
        fn over(inner: FakeFlash) -> Self {
            Rig {
                inner,
                log: Vec::new(),
                fail_from: None,
                after: false,
            }
        }
        fn gate(&mut self, op: Op, from: u32, to: u32) -> Result<bool, FlashError> {
            let i = self.log.len();
            self.log.push((op, from, to));
            match self.fail_from {
                Some(f) if i > f || (i == f && !(self.after && op != Op::Read)) => {
                    Err(FlashError::Hardware(1 << 4))
                }
                Some(f) if i == f => Ok(true),
                _ => Ok(false),
            }
        }
    }

    impl ErrorType for Rig {
        type Error = FlashError;
    }
    impl ReadNorFlash for Rig {
        const READ_SIZE: usize = 1;
        fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), FlashError> {
            self.gate(Op::Read, offset, offset + bytes.len() as u32)?;
            self.inner.read(offset, bytes)
        }
        fn capacity(&self) -> usize {
            self.inner.capacity()
        }
    }
    impl NorFlash for Rig {
        const WRITE_SIZE: usize = crate::flash::WRITE_SIZE;
        const ERASE_SIZE: usize = crate::flash::ERASE_SIZE;
        fn erase(&mut self, from: u32, to: u32) -> Result<(), FlashError> {
            let then_fail = self.gate(Op::Erase, from, to)?;
            self.inner.erase(from, to)?;
            if then_fail {
                return Err(FlashError::Hardware(1 << 4));
            }
            Ok(())
        }
        fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), FlashError> {
            let then_fail = self.gate(Op::Write, offset, offset + bytes.len() as u32)?;
            self.inner.write(offset, bytes)?;
            if then_fail {
                return Err(FlashError::Hardware(1 << 3));
            }
            Ok(())
        }
    }

    /// A whole `FLASH_FS`: data region patterned, marker region blank,
    /// everything from `FS_FREE_OFFSET` up filled with a sentinel.
    fn populated() -> FakeFlash {
        let mut f = FakeFlash::new(FS_SECTORS);
        for (i, (off, len)) in DATA.iter().enumerate() {
            f.scribble(*off as usize, *len as usize, 0xa0 + i as u8);
        }
        f.scribble(FREE, memmap::FLASH_FS_LEN as usize - FREE, 0x5a);
        f
    }

    fn bytes(f: &mut FakeFlash) -> Vec<u8> {
        let mut v = std::vec![0u8; f.capacity()];
        f.read(0, &mut v).unwrap();
        v
    }

    fn restore(image: &[u8]) -> FakeFlash {
        let mut f = FakeFlash::new(FS_SECTORS);
        f.write(0, image).unwrap();
        f
    }

    fn region(img: &[u8], (off, len): (u32, u32)) -> &[u8] {
        &img[off as usize..(off + len) as usize]
    }

    /// The full in-session sequence minus the ack, which is the caller's.
    fn session_erase(f: &mut Rig) -> Result<(), EraseFault> {
        begin(f)?;
        destroy(f)?;
        finish(f)
    }

    fn assert_in_bounds(log: &[(Op, u32, u32)]) {
        for &(op, from, to) in log {
            assert!(
                to as usize <= FREE,
                "{op:?} {from:#x}..{to:#x} reaches FS_FREE"
            );
            if op == Op::Erase && (from as usize) < MARKER {
                assert!(to as usize <= DATA_END, "an erase straddles the marker");
            }
            if op == Op::Write {
                assert!(
                    from as usize >= MARKER,
                    "the eraser programmed the data region"
                );
            }
        }
    }

    #[test]
    fn a_complete_erase_blanks_exactly_the_data_region_and_clears_the_marker() {
        let mut rig = Rig::over(populated());
        let before = bytes(&mut rig.inner);
        session_erase(&mut rig).unwrap();
        let after = bytes(&mut rig.inner);
        assert!(
            after[..FREE].iter().all(|&b| b == 0xff),
            "data or marker left"
        );
        assert_eq!(
            after[FREE..],
            before[FREE..],
            "a sentinel above FS_FREE moved"
        );
        assert_in_bounds(&rig.log);
        // Body before commit, both after the marker erase, and nothing else
        // written anywhere.
        let writes: Vec<_> = rig.log.iter().filter(|e| e.0 == Op::Write).collect();
        assert_eq!(writes.len(), 2);
        assert_eq!(
            (writes[0].1, writes[1].1),
            (MARKER as u32, MARKER as u32 + 8)
        );
        // Identity is the last data sector erased, share the first.
        let erases: Vec<_> = rig.log.iter().filter(|e| e.0 == Op::Erase).collect();
        assert_eq!(erases[1].1, memmap::FS_SHARE_OFFSET);
        assert_eq!(
            erases[erases.len() - 2].1,
            memmap::FS_IDENTITY_OFFSET + SECTOR
        );
        assert!(!recover(&mut rig).unwrap(), "a finished erase left work");
    }

    #[test]
    fn destroy_and_finish_refuse_without_a_committed_marker() {
        for torn in [false, true] {
            let mut rig = Rig::over(populated());
            if torn {
                rig.inner.write(MARKER as u32, &body()).unwrap();
            }
            let before = bytes(&mut rig.inner);
            assert_eq!(destroy(&mut rig), Err(EraseFault::NotBegun));
            assert_eq!(finish(&mut rig), Err(EraseFault::NotBegun));
            assert_eq!(recover(&mut rig), Ok(false));
            assert_eq!(bytes(&mut rig.inner), before, "torn={torn}: bytes changed");
            assert!(rig.log.iter().all(|e| e.0 == Op::Read));
        }
    }

    #[test]
    fn a_damaged_or_newer_marker_holds_and_touches_nothing() {
        for commit in [MAGIC, MAGIC + 1] {
            let mut rig = Rig::over(populated());
            let body = if commit == MAGIC { [0u8; 8] } else { body() };
            rig.inner.write(MARKER as u32, &body).unwrap();
            rig.inner
                .write(MARKER as u32 + 8, &commit.to_le_bytes())
                .unwrap();
            let before = bytes(&mut rig.inner);
            assert_eq!(recover(&mut rig), Err(EraseFault::Damaged));
            assert_eq!(begin(&mut rig), Err(EraseFault::Damaged));
            assert_eq!(destroy(&mut rig), Err(EraseFault::Damaged));
            assert_eq!(finish(&mut rig), Err(EraseFault::Damaged));
            assert_eq!(bytes(&mut rig.inner), before);
            assert!(rig.log.iter().all(|e| e.0 == Op::Read));
        }
    }

    #[test]
    fn a_refused_marker_read_is_a_bounded_fault() {
        let mut rig = Rig::over(populated());
        rig.fail_from = Some(0);
        assert!(matches!(recover(&mut rig), Err(EraseFault::Flash(_))));
        assert!(matches!(read(&mut rig), Err(EraseFault::Flash(_))));
    }

    /// Interrupt the in-session erase at EVERY flash call — each marker write,
    /// each sector erase, each verification read, the completion erase — both
    /// before the call takes effect and (for mutations) after it took effect but
    /// before success was seen. Then, from the resulting BYTES:
    ///
    /// * if any data byte changed, the marker reads `Pending` (boot resumes and
    ///   never opens a signer), and even ignoring the marker no nonce, name or
    ///   identity sector is gone while any share byte survives;
    /// * boot [`recover`] — itself interrupted at every mutation and at the
    ///   edges of every verification pass, then retried — ends either with the
    ///   data untouched and no marker (only if destruction never began) or with
    ///   the data region and marker blank;
    /// * sentinels from `FS_FREE_OFFSET` up never change, and no call leaves
    ///   `[0, FS_FREE_OFFSET)`.
    #[test]
    fn every_interrupted_state_is_blocked_and_every_restart_resolves() {
        let original = bytes(&mut populated());
        let mut full = Rig::over(populated());
        session_erase(&mut full).unwrap();
        let total = full.log.len();
        assert_in_bounds(&full.log);

        let mut states = 0;
        for fail in 0..total {
            for after in [false, true] {
                if after && full.log[fail].0 == Op::Read {
                    continue;
                }
                let mut rig = Rig::over(populated());
                rig.fail_from = Some(fail);
                rig.after = after;
                assert!(session_erase(&mut rig).is_err(), "fail={fail} not observed");
                assert_in_bounds(&rig.log);
                let img = bytes(&mut rig.inner);
                check_interrupted(&original, &img, fail, after);

                // Reboot, with the reboot itself interrupted.
                let mut plain = Rig::over(restore(&img));
                let marker_pending = classify(img[MARKER..MARKER + RECORD_LEN].try_into().unwrap())
                    == Marker::Pending;
                recover(&mut plain).unwrap();
                // A refused read mutates nothing, so the interior of a run of
                // verification reads yields the same bytes as its edges: nest
                // only from distinct states, at distinct points.
                let nest = edge(&full.log, fail);
                for m in 0..plain.log.len() {
                    let op = plain.log[m].0;
                    if !nest || !edge(&plain.log, m) {
                        continue;
                    }
                    for after2 in [false, true] {
                        if after2 && op == Op::Read {
                            continue;
                        }
                        let mut again = Rig::over(restore(&img));
                        again.fail_from = Some(m);
                        again.after = after2;
                        let r = recover(&mut again);
                        assert!(r.is_err(), "fail={fail} after={after} m={m} op={op:?} after2={after2} r={r:?} {:?}", &plain.log[m]);
                        assert_in_bounds(&again.log);
                        let mid = bytes(&mut again.inner);
                        check_interrupted(&original, &mid, m, after2);
                        let mut last = Rig::over(restore(&mid));
                        recover(&mut last).unwrap();
                        check_resolved(&original, &bytes(&mut last.inner), marker_pending);
                        states += 1;
                    }
                }
                check_resolved(&original, &bytes(&mut plain.inner), marker_pending);
                states += 1;
            }
        }
        // Not a constant to match: a floor that fails if the matrix collapses.
        std::eprintln!("erase matrix: {total} calls in one erase, {states} restart states checked");
        assert!(
            states > total,
            "only {states} restart states for {total} calls"
        );
    }

    /// A mutation, or the first or last read of a run of reads.
    fn edge(log: &[(Op, u32, u32)], m: usize) -> bool {
        let read = |i: usize| log.get(i).is_some_and(|e| e.0 == Op::Read);
        !read(m) || m == 0 || !read(m - 1) || !read(m + 1)
    }

    fn check_interrupted(original: &[u8], img: &[u8], fail: usize, after: bool) {
        assert_eq!(
            img[FREE..],
            original[FREE..],
            "sentinel moved (fail={fail})"
        );
        let touched = img[..DATA_END] != original[..DATA_END];
        let mut rec = [0u8; RECORD_LEN];
        rec.copy_from_slice(&img[MARKER..MARKER + RECORD_LEN]);
        // Touched data is covered by a committed marker, unless destruction is
        // already complete (the completion erase itself was interrupted after it
        // took effect): a blank data region with no marker IS the finished state.
        if touched && !img[..DATA_END].iter().all(|&b| b == 0xff) {
            assert_eq!(
                classify(&rec),
                Marker::Pending,
                "data touched with no committed marker (fail={fail}, after={after})"
            );
        }
        // Named regions, NOT `DATA`: the test must not inherit the order it checks.
        let share = (memmap::FS_SHARE_OFFSET, memmap::FS_SHARE_LEN);
        let share_gone = region(img, share).iter().all(|&b| b == 0xff);
        for later in &[
            (memmap::FS_NONCE_OFFSET, memmap::FS_NONCE_LEN),
            (memmap::FS_NAME_OFFSET, memmap::FS_NAME_LEN),
            (memmap::FS_IDENTITY_OFFSET, memmap::FS_IDENTITY_LEN),
        ] {
            if region(img, *later) != region(original, *later) {
                assert!(share_gone, "{later:?} erased while a share byte survives");
            }
        }
    }

    fn check_resolved(original: &[u8], img: &[u8], must_be_erased: bool) {
        assert_eq!(img[FREE..], original[FREE..], "sentinel moved");
        let blank = img[..FREE].iter().all(|&b| b == 0xff);
        let intact = img[..DATA_END] == original[..DATA_END]
            && classify(img[MARKER..MARKER + RECORD_LEN].try_into().unwrap()) == Marker::Clear;
        assert!(
            blank || (intact && !must_be_erased),
            "restart left a mixture"
        );
    }
}
