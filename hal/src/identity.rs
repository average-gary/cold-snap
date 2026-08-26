//! The device's durable identity secret: 32 bytes of scalar in `FLASH_FS`,
//! generated once and never regenerated.
//!
//! `DeviceId` is derived from this secret's public key, so a *new* secret is a
//! *new device*: every share the user already holds becomes unreferenceable.
//! That asymmetry decides every branch here.
//!
//! ```text
//!   absent / never committed  ->  generate, persist, verify   (safe: nothing
//!                                                              was ever announced)
//!   committed but damaged     ->  refuse                      (regenerating would
//!   ambiguous                 ->  refuse                       orphan shares)
//! ```
//!
//! # The record
//!
//! 48 bytes at [`crate::memmap::FS_IDENTITY_OFFSET`], written in **two**
//! `NorFlash::write` calls:
//!
//! | offset | bytes | field |
//! |--------|-------|-------|
//! | `0x00` | 32 | secret scalar, big-endian (the order `Scalar::from_bytes` wants) |
//! | `0x20` | 8  | `sha256(DOMAIN ‖ secret)[..8]` — integrity, not authentication |
//! | `0x28` | 8  | [`MAGIC`], programmed **last**: the commit |
//!
//! [`crate::flash::WRITE_SIZE`] is 8 and `StmFlash::write` programs ascending
//! doublewords, so a torn write leaves a programmed prefix and a `0xff` tail. The
//! checksum is what makes "the body is still the body" observable — which
//! `AbSlot` cannot do (see *Why not A/B* below) — and it is also what makes "the
//! write finished" observable, since a torn body cannot match its own tag.
//!
//! What the commit word being **last** buys is narrower than that, and worth
//! stating precisely because it is easy to overclaim: it decides which side of
//! `classify` the *wide* tear window falls on. A tear inside the 5-doubleword
//! body program leaves no commit word, which reads `Vacant` and is recoverable;
//! reverse the two writes and that same tear reads `Damaged`, which is not. The
//! one-doubleword gap *between* the two programs is unrecoverable either way.
//! `the_commit_word_is_programmed_last` is the test that holds the order.
//!
//! # Why not A/B
//!
//! `AbSlot` exists so a torn write cannot destroy the *previous* value. This
//! record has no previous value, ever: it is written once in the life of the
//! device. And `AbSlot::read` maps a decode failure to `None`
//! (`ab_write.rs:145,190`) while a fixed-size `[u8; 32]` under `Fixint` cannot
//! *fail* to decode — so a damaged key would read back as a valid key and
//! `AbSlot` would report nothing. It supplies freshness, which this record does
//! not need, and no integrity, which is the only thing it does need.
//!
//! # No `cfg` in this module
//!
//! Every branch here is a refusal, and a `cfg` on a refusal fails open. The
//! entropy gate is inherited rather than duplicated: [`load_or_create`] takes
//! `&mut Entropy` **concretely**, and with the `test-seam` feature off
//! [`Entropy::boot`](crate::rng::Entropy::boot) is the only way an `Entropy` can
//! exist. A generic `impl CryptoRng` bound would admit any RNG a future caller
//! writes and would force a second gate into this file.
//!
//! # What this module does not do
//!
//! It does not build a `KeyPair` — `coldsnap_hal` has no `schnorr_fun`
//! dependency and adding one to link a curve into the HAL is the *announce*
//! task's decision, not identity's. It hands back validated bytes that
//! `Scalar::<Secret, NonZero>::from_bytes` will accept, having applied that same
//! `0 < s < n` test itself (`scalar_is_in_range`) so the rejection is covered
//! by this module's tests rather than by a caller's `Option` handling.
//!
//! It also does not encrypt the secret. It is plaintext in `FLASH_FS`, readable
//! by anyone who defeats RDP=2; wrapping it with SE1/SE2 is separate work and
//! the version nibble in [`MAGIC`] is where that would announce itself.

use crate::rng::Entropy;
use embedded_storage::nor_flash::{NorFlash, NorFlashError, NorFlashErrorKind};
use rand_core::RngCore;
use sha2::{Digest, Sha256};

/// Length of the on-flash record.
pub const RECORD_LEN: usize = 48;

const SECRET_LEN: usize = 32;
const TAG_LEN: usize = 8;
/// Everything before the commit word: what the checksum covers and what the
/// first program writes. A multiple of [`crate::flash::WRITE_SIZE`].
const BODY_LEN: usize = SECRET_LEN + TAG_LEN;

/// The commit word, programmed after the body and nothing else.
///
/// None of the three values that occur naturally on this board — `0x0000_0000`
/// (zeroed SRAM), `0xffff_ffff` (erased flash) or `0xdead_beef` (the
/// bootloader's SRAM fill, `mk4-bootloader/main.c:42`) — appears as either half
/// of it.
///
/// The high half is [`MAGIC_DOMAIN`], constant for every version of this record;
/// the low half is the version. A future format (a wrapped secret, say) bumps the
/// version and keeps the domain, which is what lets *this* firmware refuse a
/// record it cannot read instead of erasing it — see `classify`'s
/// `(false, false) if ours` arm. That arm only helps if it is present in the
/// first shipped firmware, so it is not speculation: after ship, fielded units
/// that lack it destroy any newer record they are downgraded onto.
pub const MAGIC: u64 = 0xC01D_5EED_1D00_0001;

/// The format family. Every version of the identity record carries this in the
/// high half of its commit word; changing it is indistinguishable from garbage to
/// older firmware, so it must never change.
pub const MAGIC_DOMAIN: u32 = (MAGIC >> 32) as u32;

/// Domain separation for the checksum. Not a secret and not a key.
const DOMAIN: &[u8] = b"coldsnap-identity-v1";

/// The secp256k1 group order, big-endian. `Scalar::<Secret, NonZero>::from_bytes`
/// applies exactly this bound (`secp256kfun-0.12.1/src/scalar.rs:85-109`); it is
/// restated here so the refusal is testable without a curve dependency, and it
/// is a fixed constant of the curve, not a tunable.
const SECP256K1_ORDER: [u8; SECRET_LEN] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// A validated identity secret. Only [`load_or_create`] constructs one, so
/// holding this value *is* the proof that the secret is durable on flash and
/// in range for the curve.
#[derive(Clone, PartialEq, Eq)]
pub struct IdentitySecret([u8; SECRET_LEN]);

impl IdentitySecret {
    /// The raw scalar, big-endian. Feed to `Scalar::<Secret, NonZero>::from_bytes`
    /// (which returns `Option` — handle it; do **not** reach for
    /// `from_bytes_mod_order`, which would silently map damaged bytes onto a
    /// different valid key).
    pub fn expose_secret(&self) -> &[u8; SECRET_LEN] {
        &self.0
    }
}

/// Deliberately opaque: a secret must not reach a log or a wire by accident.
impl core::fmt::Debug for IdentitySecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("IdentitySecret(<redacted>)")
    }
}

/// Why identity is unavailable this boot.
///
/// Every variant is a **hold**, not a panic: `panic = "abort"` plus RDP=2 makes
/// a reset unrecoverable, so panicking on a stable, on-flash condition is a reset
/// loop that ends in a brick.
///
/// The refusal is **not** structural, and reading it that way is how it failed
/// open once already: this is an ordinary `Result`, and `let _ = load_or_create(…)`
/// compiles and continues to the event loop with no identity. What makes the
/// firmware's hold safe is that its call site binds the `Ok` payload, so the
/// `Err` arm must unify with `IdentitySecret` and therefore has to diverge —
/// enforced by the type checker, not by this doc comment. The hold is also
/// **dark**: it sits above USB bring-up, so a device that cannot prove which
/// device it is never enumerates. See `firmware/src/main.rs` step 8b.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityFault {
    /// A record was committed and no longer verifies, or its commit word is
    /// damaged while its body still checksums. Refuse: this device may already
    /// have announced, so regenerating would orphan the user's shares.
    Damaged,
    /// Flash refused a read, erase or program. Nothing was committed.
    Flash(NorFlashErrorKind),
    /// The write reported success and the read-back did not verify. The bytes on
    /// flash are not the bytes we generated, so they are not usable and are not
    /// trusted.
    VerifyFailed,
    /// Entropy produced no in-range scalar in [`GENERATE_ATTEMPTS`] tries.
    /// Unreachable in practice (`p < 2^-1000`); it exists so generation has no
    /// unbounded loop and no `unwrap`.
    NoScalar,
}

/// Bound on the rejection-sampling loop in [`load_or_create`].
pub const GENERATE_ATTEMPTS: u8 = 8;

/// What a 48-byte buffer read off flash means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Record {
    /// No committed record here. Either erased flash, or a torn first write, or
    /// whatever MicroPython's LFS2 left behind — a converted Mk4 does **not**
    /// present erased flash on its first boot, so "not 0xff" must not mean
    /// "damaged". Safe to erase and generate: nothing here was ever announced.
    Vacant,
    /// A committed record whose checksum and range both hold.
    Valid([u8; SECRET_LEN]),
    /// Committed and damaged, or ambiguous. Refuse.
    Damaged,
}

fn tag_of(secret: &[u8; SECRET_LEN]) -> [u8; TAG_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update(secret);
    let digest = hasher.finalize();
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&digest[..TAG_LEN]);
    tag
}

/// `0 < s < n`. Big-endian byte order makes lexicographic comparison numeric,
/// which is why the record stores the scalar big-endian.
fn scalar_is_in_range(secret: &[u8; SECRET_LEN]) -> bool {
    *secret != [0u8; SECRET_LEN] && *secret < SECP256K1_ORDER
}

/// The whole classification, as pure bytes. No flash, no RNG, no `cfg`.
fn classify(record: &[u8; RECORD_LEN]) -> Record {
    let mut secret = [0u8; SECRET_LEN];
    secret.copy_from_slice(&record[..SECRET_LEN]);
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&record[SECRET_LEN..BODY_LEN]);
    let mut commit = [0u8; TAG_LEN];
    commit.copy_from_slice(&record[BODY_LEN..RECORD_LEN]);

    let commit_word = u64::from_le_bytes(commit);
    let committed = commit_word == MAGIC;
    // Our format family, some version. `0xffff_ffff` (erased) and `0x0000_0000`
    // are not `MAGIC_DOMAIN`, so this is false for a blank or zeroed record.
    let ours = (commit_word >> 32) as u32 == MAGIC_DOMAIN;
    let body_intact = tag_of(&secret) == tag;

    match (committed, body_intact) {
        // Committed and whole. The range test is the last gate, and it is also
        // what rejects an all-zero body outright.
        (true, true) if scalar_is_in_range(&secret) => Record::Valid(secret),
        // Committed and not whole: the body rotted after commit, or the scalar is
        // out of range. This is the case regeneration must never touch.
        (true, false) | (true, true) => Record::Damaged,
        // Not committed, but the body checksums: either the tear landed in the
        // one doubleword between body and commit, or the commit word itself
        // rotted. Indistinguishable, and one of the two means the key is live —
        // so refuse. (A 40-byte LFS2 fragment matching its own sha256 prefix is
        // a 2^-64 accident, so this arm does not fire on a converted Mk4.)
        (false, true) => Record::Damaged,
        // A commit word from our own format family with a version this firmware
        // does not know: a NEWER firmware wrote this record, and its body is
        // wrapped or derived so our v1 checksum cannot vouch for it. Erasing it is
        // the same wallet loss as regenerating over a v1 record. Refuse.
        (false, false) if ours => Record::Damaged,
        // Erased, or a torn body, or somebody else's filesystem.
        (false, false) => Record::Vacant,
    }
}

fn encode(secret: &[u8; SECRET_LEN]) -> [u8; RECORD_LEN] {
    let mut record = [0u8; RECORD_LEN];
    record[..SECRET_LEN].copy_from_slice(secret);
    record[SECRET_LEN..BODY_LEN].copy_from_slice(&tag_of(secret));
    record[BODY_LEN..].copy_from_slice(&MAGIC.to_le_bytes());
    record
}

fn flash_err<E: NorFlashError>(e: E) -> IdentityFault {
    IdentityFault::Flash(e.kind())
}

/// Read the identity secret, generating and persisting one only if no record was
/// ever committed.
///
/// `flash` is offset-relative to `FLASH_FS` (that is what
/// [`StmFlash`](crate::flash::StmFlash)'s `NorFlash` impl means), so the record
/// lands at [`crate::memmap::FS_IDENTITY_OFFSET`] and the erase covers exactly
/// [`crate::memmap::FS_IDENTITY_LEN`] — sized and aligned so that even a
/// `DBANK == 0` 8 KiB page erase cannot reach the nonce region.
///
/// # Errors
///
/// See [`IdentityFault`]. All four are holds. This function never panics: it is
/// called once at boot, before the event loop, and reads no coordinator input.
pub fn load_or_create<S: NorFlash>(
    flash: &mut S,
    entropy: &mut Entropy,
) -> Result<IdentitySecret, IdentityFault> {
    const OFFSET: u32 = crate::memmap::FS_IDENTITY_OFFSET;

    let mut buf = [0u8; RECORD_LEN];
    flash.read(OFFSET, &mut buf).map_err(flash_err)?;

    match classify(&buf) {
        Record::Valid(secret) => return Ok(IdentitySecret(secret)),
        Record::Damaged => return Err(IdentityFault::Damaged),
        Record::Vacant => {}
    }

    // Rejection sampling, bounded. `fill_bytes` is infallible by construction
    // (`Entropy` wraps ChaCha20 and touches no hardware after boot), so the only
    // way out of this loop other than success is the astronomically unlikely one.
    let mut secret = [0u8; SECRET_LEN];
    let mut accepted = false;
    for _ in 0..GENERATE_ATTEMPTS {
        entropy.fill_bytes(&mut secret);
        if scalar_is_in_range(&secret) {
            accepted = true;
            break;
        }
    }
    if !accepted {
        return Err(IdentityFault::NoScalar);
    }

    // Unconditionally, because "vacant" includes "full of LFS2 garbage".
    flash
        .erase(OFFSET, OFFSET + crate::memmap::FS_IDENTITY_LEN)
        .map_err(flash_err)?;

    let record = encode(&secret);
    // Body first, commit word second. The ordering is NOT what makes a torn write
    // detectable — the checksum is, and it would still be if these were merged.
    // What the ordering buys is WHICH SIDE of `classify` a tear lands on: with the
    // commit word last, a tear anywhere in the 5-doubleword body leaves the commit
    // word unwritten and the record reads `Vacant`, which is safe to overwrite.
    // Reversed, the same tear leaves a committed record with a bad body, i.e.
    // `Damaged`, which refuses forever. Pinned by
    // `over_flash::the_commit_word_is_programmed_last`, which asserts the program
    // order `[(0, 40), (40, 8)]` — added only after swapping these two lines left
    // the whole suite green.
    flash.write(OFFSET, &record[..BODY_LEN]).map_err(flash_err)?;
    flash
        .write(OFFSET + BODY_LEN as u32, &record[BODY_LEN..])
        .map_err(flash_err)?;

    // Read back and re-classify. `StmFlash::write_verified` exists but is an
    // inherent method the generic `NorFlash` bound cannot reach, and a byte
    // compare would be weaker than this anyway: the returned secret comes from
    // the bytes that came *off* flash, so there is no path from a generated
    // scalar to an announceable identity that skips a successful read.
    let mut back = [0u8; RECORD_LEN];
    flash.read(OFFSET, &mut back).map_err(flash_err)?;
    match classify(&back) {
        Record::Valid(persisted) if persisted == secret => Ok(IdentitySecret(persisted)),
        _ => Err(IdentityFault::VerifyFailed),
    }
    // Deliberately no erase-on-failure. It would turn a program fault into a
    // clean slate for the *next* boot, but it is also a "destroy the record"
    // path, and adding one of those to the module whose job is never destroying
    // the record is how the record gets destroyed. A device that faults between
    // the two writes holds at `Damaged` on the next boot instead.
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The gated seam, used from a test as intended: the bypass stays in `rng`
    /// and goes through the real mixer, so this module gains no `cfg` of its own.
    fn seeded_entropy(salt: u8) -> Entropy {
        use crate::rng::{mix_sources, SE1_BYTES, SE2_BYTES, TRNG_BYTES};
        let vary = |salt: u8| -> [u8; 32] {
            let mut bytes = [0u8; 32];
            let mut v = salt;
            for slot in bytes.iter_mut() {
                v = v.wrapping_mul(7).wrapping_add(11);
                *slot = v;
            }
            bytes
        };
        let (t, s1, s2) = (vary(salt), vary(salt.wrapping_add(1)), vary(salt.wrapping_add(2)));
        let seed = mix_sources(&t[..TRNG_BYTES], &s1[..SE1_BYTES], &s2[..SE2_BYTES])
            .expect("three good draws must mix");
        Entropy::from_proven_seed(seed)
    }

    // -- pure classification, over plain arrays --------------------------------

    #[test]
    fn erased_flash_is_vacant_not_a_key() {
        assert_eq!(classify(&[0xff; RECORD_LEN]), Record::Vacant);
    }

    #[test]
    fn all_zero_record_is_vacant_not_a_key() {
        assert_eq!(classify(&[0x00; RECORD_LEN]), Record::Vacant);
    }

    #[test]
    fn deadbeef_fill_is_vacant_not_a_key() {
        // 0xdeadbeef repeated IS a valid secp256k1 scalar, so only the tag and
        // commit word stand between unzeroed SRAM and a plausible-looking key.
        let mut buf = [0u8; RECORD_LEN];
        for chunk in buf.chunks_exact_mut(4) {
            chunk.copy_from_slice(&0xdead_beefu32.to_le_bytes());
        }
        assert_eq!(classify(&buf), Record::Vacant);
    }

    #[test]
    fn zero_scalar_with_a_valid_tag_and_commit_is_damaged() {
        // The case a checksum alone cannot catch: perfectly self-consistent
        // record, unusable scalar.
        let record = encode(&[0u8; SECRET_LEN]);
        assert_eq!(classify(&record), Record::Damaged);
    }

    #[test]
    fn out_of_range_scalars_are_damaged_not_valid() {
        for secret in [SECP256K1_ORDER, [0xff; SECRET_LEN]] {
            assert_eq!(classify(&encode(&secret)), Record::Damaged);
        }
        // One below the order is in range; this is the boundary, so it must pass.
        let mut just_under = SECP256K1_ORDER;
        just_under[SECRET_LEN - 1] = 0x40;
        assert_eq!(classify(&encode(&just_under)), Record::Valid(just_under));
    }

    #[test]
    fn a_flipped_body_bit_after_commit_is_damaged() {
        let mut record = encode(&[7u8; SECRET_LEN]);
        record[3] ^= 0x01;
        assert_eq!(classify(&record), Record::Damaged);
    }

    #[test]
    fn a_damaged_commit_word_over_an_intact_body_is_damaged_not_vacant() {
        // Ambiguous: torn just before the commit, or the commit word rotted. One
        // of those means the key is live, so this must never regenerate.
        let mut record = encode(&[9u8; SECRET_LEN]);
        record[BODY_LEN] ^= 0x08;
        assert_eq!(classify(&record), Record::Damaged);
    }

    #[test]
    fn a_torn_body_is_vacant_so_a_fresh_device_can_recover() {
        // Body half-programmed, tag and commit still erased.
        let mut record = encode(&[3u8; SECRET_LEN]);
        record[16..].fill(0xff);
        assert_eq!(classify(&record), Record::Vacant);
    }

    /// Before this test existed, a record written by a future firmware — bumped
    /// version, wrapped body, so the v1 checksum cannot match — classified
    /// `Vacant`, and `load_or_create` erased a live key and generated a new one.
    /// The `MAGIC` docs claimed the version half prevented that; it did not.
    #[test]
    fn a_newer_record_format_is_refused_not_erased() {
        const MAGIC_V2: u64 = MAGIC + 1;
        assert_eq!(MAGIC_V2 >> 32, u64::from(MAGIC_DOMAIN), "v2 changed the domain");

        let mut record = [0u8; RECORD_LEN];
        record[..SECRET_LEN].copy_from_slice(&[0x11; SECRET_LEN]); // wrapped, not raw
        record[SECRET_LEN..BODY_LEN].copy_from_slice(&[0xab; TAG_LEN]); // v2's own MAC
        record[BODY_LEN..].copy_from_slice(&MAGIC_V2.to_le_bytes());
        assert_eq!(classify(&record), Record::Damaged);

        // The other direction still holds: a foreign commit word is not ours.
        record[BODY_LEN..].copy_from_slice(&0x5a5a_5a5a_5a5a_5a5au64.to_le_bytes());
        assert_eq!(classify(&record), Record::Vacant);
    }

    #[test]
    fn magic_avoids_every_value_that_occurs_naturally() {
        for half in [(MAGIC >> 32) as u32, MAGIC as u32] {
            assert_ne!(half, 0x0000_0000);
            assert_ne!(half, 0xffff_ffff);
            assert_ne!(half, 0xdead_beef);
        }
        assert_eq!(BODY_LEN % crate::flash::WRITE_SIZE, 0);
        assert_eq!(RECORD_LEN % crate::flash::WRITE_SIZE, 0);
    }

    // -- over the real geometry -------------------------------------------------

    #[cfg(feature = "fake-flash")]
    mod over_flash {
        use super::*;
        use crate::flash::fake::FakeFlash;

        fn blank() -> FakeFlash {
            // Enough sectors for the identity region and then some.
            FakeFlash::new(4)
        }

        #[test]
        fn blank_flash_generates_persists_and_verifies() {
            let mut flash = blank();
            let secret = load_or_create(&mut flash, &mut seeded_entropy(1))
                .expect("blank flash must yield an identity");
            assert!(scalar_is_in_range(secret.expose_secret()));
            assert!(flash.erases > 0 && flash.programs > 0, "nothing was written");

            // And it is really on flash, not cached in Rust.
            let mut back = [0u8; RECORD_LEN];
            embedded_storage::nor_flash::ReadNorFlash::read(&mut flash, 0, &mut back).unwrap();
            assert_eq!(classify(&back), Record::Valid(*secret.expose_secret()));
        }

        #[test]
        fn second_boot_returns_the_same_secret_and_writes_nothing() {
            let mut flash = blank();
            let first = load_or_create(&mut flash, &mut seeded_entropy(1)).unwrap();
            let (programs, erases) = (flash.programs, flash.erases);

            // A *different* entropy stream: if this boot regenerated, the secret
            // would differ, so equality is evidence about the flash path and not
            // about the RNG being deterministic.
            let second = load_or_create(&mut flash, &mut seeded_entropy(2)).unwrap();
            assert_eq!(first.expose_secret(), second.expose_secret());
            assert_eq!(
                (flash.programs, flash.erases),
                (programs, erases),
                "an existing identity must not touch flash"
            );
        }

        #[test]
        fn corrupt_record_is_refused_not_regenerated() {
            let mut flash = blank();
            let original = load_or_create(&mut flash, &mut seeded_entropy(1)).unwrap();
            let (programs, erases) = (flash.programs, flash.erases);

            // One bit of rot in the scalar, everything else intact.
            flash.scribble(5, 1, 0x00);

            assert_eq!(
                load_or_create(&mut flash, &mut seeded_entropy(2)),
                Err(IdentityFault::Damaged),
                "a damaged record must refuse, never regenerate"
            );
            assert_eq!(
                (flash.programs, flash.erases),
                (programs, erases),
                "the refusal path wrote to flash"
            );
            // The damaged bytes are still there for a future recovery tool.
            let mut back = [0u8; RECORD_LEN];
            embedded_storage::nor_flash::ReadNorFlash::read(&mut flash, 0, &mut back).unwrap();
            assert_ne!(classify(&back), Record::Valid(*original.expose_secret()));
        }

        #[test]
        fn lfs2_garbage_generates_because_it_was_never_committed() {
            let mut flash = blank();
            // A converted Mk4 arrives with MicroPython's filesystem here, not 0xff.
            flash.scribble(0, 4096, 0x5a);
            let secret = load_or_create(&mut flash, &mut seeded_entropy(3))
                .expect("a converted device must be able to create its identity");
            assert!(scalar_is_in_range(secret.expose_secret()));
        }

        #[test]
        fn a_refused_program_reports_flash_and_commits_nothing() {
            let mut flash = blank();
            flash.refuse_programs_now();
            let fault = load_or_create(&mut flash, &mut seeded_entropy(1)).unwrap_err();
            assert!(matches!(fault, IdentityFault::Flash(_)), "got {fault:?}");

            flash.heal();
            let mut back = [0u8; RECORD_LEN];
            embedded_storage::nor_flash::ReadNorFlash::read(&mut flash, 0, &mut back).unwrap();
            assert_eq!(classify(&back), Record::Vacant, "a refused write committed");
        }

        #[test]
        fn a_refused_erase_reports_flash() {
            let mut flash = blank();
            flash.refuse_erases_now();
            assert!(matches!(
                load_or_create(&mut flash, &mut seeded_entropy(1)),
                Err(IdentityFault::Flash(_))
            ));
        }

        /// A flash that programs faithfully and reads back one flipped bit. The
        /// only way to exercise the read-back check, and therefore the only thing
        /// that makes it non-decorative.
        struct LyingFlash {
            inner: FakeFlash,
            lie: bool,
            /// Offset and length of each program, in order. The only way to see
            /// that the commit word went *last*; see
            /// `the_commit_word_is_programmed_last`.
            programs: [(u32, usize); 2],
            n: usize,
        }

        impl embedded_storage::nor_flash::ErrorType for LyingFlash {
            type Error = crate::flash::FlashError;
        }

        impl embedded_storage::nor_flash::ReadNorFlash for LyingFlash {
            const READ_SIZE: usize = 1;
            fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
                embedded_storage::nor_flash::ReadNorFlash::read(&mut self.inner, offset, bytes)?;
                if self.lie {
                    if let Some(first) = bytes.first_mut() {
                        *first ^= 0x01;
                    }
                }
                Ok(())
            }
            fn capacity(&self) -> usize {
                embedded_storage::nor_flash::ReadNorFlash::capacity(&self.inner)
            }
        }

        impl NorFlash for LyingFlash {
            const WRITE_SIZE: usize = crate::flash::WRITE_SIZE;
            const ERASE_SIZE: usize = crate::flash::ERASE_SIZE;
            fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
                self.inner.erase(from, to)
            }
            fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
                if let Some(slot) = self.programs.get_mut(self.n) {
                    *slot = (offset, bytes.len());
                }
                self.n += 1;
                let written = self.inner.write(offset, bytes);
                // Start lying only once the record is on flash, so the initial
                // "is there a record?" read still says vacant.
                self.lie = true;
                written
            }
        }

        fn lying(lie: bool) -> LyingFlash {
            LyingFlash {
                inner: blank(),
                lie,
                programs: [(u32::MAX, 0); 2],
                n: 0,
            }
        }

        /// The module docs lean on "body first, commit word last" as the whole
        /// torn-write story, and nothing else in this file can see program order:
        /// with both writes accepted the resulting bytes are identical either way,
        /// so reversing them leaves every other test green. What the order buys is
        /// which side of the classifier the *wide* tear window falls on — a tear
        /// inside the 5-doubleword body program must read back `Vacant`
        /// (recoverable), and it only does if no commit word has been programmed
        /// yet.
        #[test]
        fn the_commit_word_is_programmed_last() {
            let mut flash = lying(false);
            let _ = load_or_create(&mut flash, &mut seeded_entropy(1));
            assert_eq!(
                flash.programs,
                [(0, BODY_LEN), (BODY_LEN as u32, TAG_LEN)],
                "the commit word must be a separate, final program"
            );
            assert_eq!(flash.n, 2, "the record took {} programs, not 2", flash.n);

            // And the consequence: a tear anywhere inside the first program leaves
            // a record that regenerates rather than one that refuses forever.
            let record = encode(&[5u8; SECRET_LEN]);
            for landed in (0..BODY_LEN).step_by(crate::flash::WRITE_SIZE) {
                let mut torn = [0xff; RECORD_LEN];
                torn[..landed].copy_from_slice(&record[..landed]);
                assert_eq!(classify(&torn), Record::Vacant, "tear after {landed} bytes");
            }
        }

        #[test]
        fn a_read_back_that_disagrees_with_the_write_is_refused() {
            let mut flash = lying(false);
            assert_eq!(
                load_or_create(&mut flash, &mut seeded_entropy(1)),
                Err(IdentityFault::VerifyFailed),
                "the write-verify did not run"
            );
        }
    }
}
