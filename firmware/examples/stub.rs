//! The `hostcheck` harness's device side: the SHIPPING dispatch
//! (`coldsnap_firmware::Session`) and the REAL `coldsnap_hal::comms` framing, on
//! real file descriptors, against a real `frostsnap_coordinator` in another
//! process.
//!
//! WHAT CHANGED, and it is the whole reason this file moved out of
//! `hal/examples/`: it used to build `FrostSigner::new_random(&mut rng, 4)` with
//! the default in-RAM `MemoryNonceSlot`, so a green run proved `frostsnap_core`
//! works and proved nothing about this firmware. It now goes through
//! `Session::open`, which derives the keypair from
//! `coldsnap_hal::identity::load_or_create` and puts the nonce slots on flash at
//! `memmap::FS_NONCE_OFFSET` — byte for byte the code path in the ARM image. The
//! flash is `FakeFlash`, at `StmFlash`'s exact geometry (WRITE_SIZE 8,
//! ERASE_SIZE 4096), so the double is no more permissive than the hardware.
//!
//! Knows nothing about ptys. **fd 0 is the wire in, fd 1 is the wire out.** The
//! harness creates the pty, keeps the SLAVE for the coordinator, and hands us the
//! MASTER as both of our standard streams (MEASURED: `FIONREAD` on a darwin pty
//! master always returns 0, so a coordinator holding the master would see an
//! eternally empty port and hang silently).
//!
//! NEVER `println!` IN THIS FILE. fd 1 *is* the wire: one stray byte
//! desynchronises the coordinator, whose magic-byte scan has no backtracking
//! (any mismatch resets progress to 0). Every diagnostic goes to **stderr**.
//!
//! `N_DEVICES` (currently **9**) sessions in this one process, each with its OWN
//! `FakeFlash`, all multiplexed over the one wire and told apart by
//! `Destination` — which is what the real daisy chain does too, so nothing is
//! faked by co-hosting them. We complete a THRESHOLD-of-N_DEVICES keygen, a nonce
//! replenishment and a signature with the coordinator, and then keep serving so
//! the coordinator can ask each device what it holds.
//!
//! OUR EXIT STATUS IS NOT THE PROOF, and under `hostcheck` it is not even
//! observed: `hostcheck`'s `reap()` SIGKILLs this process once its own
//! verification is done, so the EOF/PASS path below is reached only when this
//! binary is run BY HAND. What the harness passes on is what the COORDINATOR
//! verified for itself — the aggregated signature against its own derived key,
//! and 9/9 `HeldShares2` replies. Every `die` here is still a failure, because a
//! stub that dies mid-run makes `hostcheck`'s `try_wait` fail the pass by name.
//!
//! WHAT IT PROVES, precisely: this binary links cold-snap's VENDORED
//! `frostsnap_core` through `coldsnap_firmware`; `hostcheck` links UPSTREAM's via
//! `frostsnap_coordinator`. Two independent copies of the state machine agree on
//! every message, bincode-encoded through `frostsnap_comms` and framed by
//! `hal/src/comms.rs`. A mock could not fail; these can, and mutation-tested,
//! they do.
//!
//! THE RESTART, and what it is worth. Immediately after writing the announces
//! this process throws away **everything RAM-side** — every `Session`, every
//! `FrostSigner`, every nonce cache — and rebuilds from the same `FakeFlash`
//! bytes, then does the entire keygen/nonce/signing/HeldShares2 run with the
//! rebuilt sessions. The coordinator learned our `DeviceId`s from the PRE-restart
//! announce, so if `identity::load_or_create` had failed to read back what it
//! wrote, the ids would differ and the coordinator would never complete a keygen
//! with them. That is the end-to-end proof that flash-backed identity survives a
//! reset. HONEST LIMIT: it is an in-process restart. `FakeFlash` lives in RAM, so
//! a second OS process would need the flash image persisted to a file, which is
//! harness plumbing, not device code — see the open list.
//!
//! NOT evidence about the shipped device. An `examples/` target here compiles
//! `coldsnap_hal` with `fake-flash` AND `test-seam` on; both are BYPASSES. The
//! RNG is the real `rng::Entropy` but seeded through the `test-seam`
//! `mix_sources` constructor from FIXED bytes, so a failure replays exactly. The
//! digest is computed by the shipped `firmware_digest` over a SYNTHETIC image (a
//! host process has no flashed image to hash) — real function, fake input.
//!
//! WRITE-BLOCKING / DEADLOCK, read this before raising n. Every frame leaves here
//! in 64-byte chunks (`STUB_CHUNK` overrides), and this loop does not read while
//! it writes. MEASURED: an undrained pty blocks writes past ~1 KB. `CertifyPlease`
//! is 2,179 B at 9-of-9 and a single-segment `NonceResponse` is 2,040 B, so the
//! coordinator's own write bound is what carries this, not the frame sizes. It
//! works because the traffic is one-directional at those points. What deadlocks is
//! both sides writing >1 KB AT ONCE. Today no exchange does that. Fix when one
//! does: read between chunks here instead of after the whole write.
//!
//! Run it via the harness, not by hand:
//!   cargo build --target aarch64-apple-darwin -p coldsnap_firmware --example stub
//!   (then `hostcheck` spawns the built artifact)

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use coldsnap_firmware::{firmware_digest, DebugFlash, Fault, Outbox, Session};
use coldsnap_hal::comms::{decode_body, CoordinatorSendBody, Link, MAGIC_REPLY};
use coldsnap_hal::flash::fake::FakeFlash;
use coldsnap_hal::flash::ERASE_SIZE;
use coldsnap_hal::rng::{mix_sources, Entropy, ProvenSeed, SE1_BYTES, SE2_BYTES, TRNG_BYTES};
use coldsnap_hal::{identity, memmap};
use frostsnap_comms::{DeviceSendBody, ReceiveSerial, Upstream};
use frostsnap_core::device::keys::KeyMutation;
use frostsnap_core::device::{DeviceToUserMessage, Mutation};
use frostsnap_core::schnorr_fun::frost::Fingerprint;
use frostsnap_core::{AccessStructureRef, DeviceId};

/// Must match `hostcheck`'s N_DEVICES; the coordinator learns the ids from our
/// Announces, so only the count has to agree.
const N_DEVICES: usize = 9;

/// One flash per device, at the shipped geometry. `DebugFlash` is only the
/// `core::fmt::Debug` shim `FrostSigner::new` demands — see its doc in the lib.
type Flash = DebugFlash<FakeFlash>;

/// Named so a stall is a diagnosis rather than a mystery.
///
/// MONOTONIC, and that is load-bearing: every store is a `fetch_max`, because
/// dispatching any `Core` body sets `KeygenInProgress` and would otherwise walk
/// the signing states backwards and report the wrong stall.
///
/// There is no `NonceJobsRun` state any more: running the nonce batch moved into
/// the shipped dispatch (`Session::run`), so this process never sees it as a
/// prompt. `hostcheck` proves the replenishment happened — the signature it
/// verifies cannot exist without it.
const STATES: [&str; 7] = [
    "WaitingForCoordinatorMagic",
    "SentAnnounces",
    "RestartedFromFlash",
    "WaitingForKeygenBegin",
    "KeygenInProgress",
    "SharesSaved",
    "SignatureShareSent",
];
static STATE: AtomicUsize = AtomicUsize::new(0);
static BYTES_READ: AtomicUsize = AtomicUsize::new(0);
/// How many devices have handed back a `SignatureShare`. Global rather than
/// threaded through `drive` because `STATE` already is, and it is read only by
/// `die` and the exit log.
static SIG_ACKS: AtomicUsize = AtomicUsize::new(0);

/// LONGER than the harness's own budget on purpose, and that is load-bearing.
/// `hostcheck` owns the budget and kills us itself; this watchdog only exists so
/// a stub run BY HAND cannot hang forever. If it fires during a `hostcheck` run,
/// the news is that the harness's bound is broken.
///
/// 90 s: a 9-of-9 certpedpop keygen is real elliptic-curve work in a DEBUG build,
/// nine signers deep, and at `STUB_CHUNK=1` every byte of every frame costs a
/// syscall. The harness's own budget is 35 s, so this is ~2.5x its bound —
/// deliberately, so that when both fire it is the harness's message you read.
const DEADLINE: Duration = Duration::from_secs(90);

/// The tier-2 test fingerprint (`frostsnap_core/tests/common/mod.rs`), NOT the
/// shipped `Fingerprint::FROST_V0`, and `hostcheck` sets the identical value.
///
/// Why: the fingerprint is a coordinator-side grind — `FROST_V0` is 18 bits per
/// coefficient, i.e. ~2^18 trials per coefficient inside
/// `finish_with_fingerprint`, which in a debug build is minutes of CPU and
/// nothing to do with the wire. It selects WHICH coefficients get chosen, never
/// how they are encoded, so the cross-tree bincode agreement this harness exists
/// to prove is unaffected. It must match on both sides because the device
/// verifies it (`device/keygen.rs` `check_fingerprint`) — mismatch is a keygen
/// failure, which is why it is stated in both files rather than defaulted.
const TEST_FINGERPRINT: Fingerprint = Fingerprint {
    bits_per_coeff: 2,
    max_bits_total: 6,
    tag: "test",
};

/// USB packet reality: `frostsnap_comms` moves bytes over OTG_FS in 64-byte
/// packets, so a real device NEVER hands the coordinator a whole frame at once.
/// Override with `STUB_CHUNK=<n>`; `STUB_CHUNK=1` is the adversarial setting.
fn chunk_size() -> usize {
    std::env::var("STUB_CHUNK")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(64)
}

/// WHEN the device throws away its keygen scratch state, i.e. where firmware
/// would put `FrostSigner::clear_tmp_data()`. Sized in `hal/src/heap.rs`: it is
/// worth 12,456 B of an 18,036 B per-device live figure, so whether firmware may
/// call it decides `HEAP_BYTES`. Values:
///
///  - `finalize` (DEFAULT): in the `FinalizeKeyGen` arm, i.e. after
///    `keygen_finalize` -> `save_complete_share` has staged NewKey/
///    NewAccessStructure/SaveShare. This is the shipped call site. Default ON so
///    that every `hostcheck` run is evidence for it, not just the run that
///    measured it: keygen -> nonces -> a signature that VERIFIES -> HeldShares2
///    all have to keep working with the scratch state gone.
///  - `off`: the vendored default, for A/B comparison.
///  - `check`: DELIBERATELY WRONG and kept runnable so the failure stays
///    reproducible -- clears in the `CheckKeyGen` arm, i.e. AFTER `keygen_ack`
///    stashed `tmp_keygen_pending_finalize` but BEFORE the coordinator's
///    `Finalize` asks for it back. Expect the stub to die 2 with "device doesn't
///    have keygen for <keygen_id>" (`device/keygen.rs` `keygen_finalize`).
fn clear_tmp_mode() -> String {
    std::env::var("STUB_CLEAR_TMP").unwrap_or_else(|_| "finalize".into())
}

/// Write in `chunk`-sized pieces, flushing each, with a 1 ms gap on the first
/// `GAP_CHUNKS`.
///
/// The gap is what makes the chunking REAL rather than cosmetic: chunked
/// `write`+`flush` syscalls take ~2 us each, so with no gap the pty coalesces
/// them into the coordinator's next poll (it sleeps 2 ms a lap) and it still
/// decodes one complete frame from one buffer -- exactly the case that was
/// already covered. With the gap the coordinator provably sees a partial frame
/// and reassembles inside `decode_from_reader`: MEASURED, its magic->announce
/// delta goes from 2.5 ms at chunk 64 to 85 ms at chunk 1.
///
/// The gap stops after 64 chunks because these frames are hundreds to thousands
/// of bytes, not 67: 1 ms/byte across an 800-byte frame is 0.8 s of sleeping per
/// frame, and while we sleep we do not read — which is exactly the undrained-pty
/// hazard in the header note. Sixty-four one-byte writes are already enough to
/// guarantee the reader sees an incomplete frame; the rest proves nothing new.
fn write_chunked(w: &mut impl Write, bytes: &[u8], chunk: usize) -> std::io::Result<()> {
    const GAP_CHUNKS: usize = 64;
    for (i, piece) in bytes.chunks(chunk).enumerate() {
        w.write_all(piece)?;
        w.flush()?;
        if i < GAP_CHUNKS {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    Ok(())
}

/// Lowercase hex, for the two values this stub reports to the coordinator over
/// the wire. Same one-liner `hostcheck` has; a dependency for this would be silly.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn die(code: i32, why: &str) -> ! {
    eprintln!(
        "stub: FAIL in {} after {} bytes read, {} signature share(s) sent: {why}",
        STATES[STATE.load(Ordering::Relaxed)],
        BYTES_READ.load(Ordering::Relaxed),
        SIG_ACKS.load(Ordering::Relaxed),
    );
    std::process::exit(code)
}

/// A `ProvenSeed` through the real mixer from FIXED bytes — the `test-seam`
/// bypass, used on purpose so a failing keygen replays byte for byte. There is
/// deliberately no other way to get a `ProvenSeed`, so even this has to pass
/// three `check_source` calls. Copied from
/// `hal/tests/integration_frostsnap_over_hal.rs`; 12 lines beats a shared
/// test-support crate for two callers.
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

/// `N_DEVICES` blank flashes at the shipped geometry, sized so a write past the
/// nonce region is out of bounds rather than silently landing in `FS_FREE`.
///
/// Separate from `open_sessions` because these must OUTLIVE every session: a
/// `Session` borrows its `RefCell<Flash>`, and the restart works by dropping all
/// the sessions while the flashes stay exactly as they are — which is what a
/// power cycle does.
fn blank_flashes() -> Vec<RefCell<Flash>> {
    let sectors = memmap::FS_FREE_OFFSET as usize / ERASE_SIZE;
    (0..N_DEVICES)
        .map(|_| RefCell::new(DebugFlash(FakeFlash::new(sectors))))
        .collect()
}

/// Build one `Session` per flash, entirely out of what is ON that flash.
///
/// THE POINT OF THIS FILE: `identity::load_or_create` for the keypair (durable,
/// so the `DeviceId` is stable across resets) and `Session::open` for the nonce
/// slots (durable, because FROST nonce reuse after a reset is a key leak).
/// Neither `FrostSigner::new_random` nor `MemoryNonceSlot` appears anywhere.
///
/// Called TWICE: once at start-up, which creates each identity, and once for the
/// restart, which must READ BACK the same 32 bytes. The second call getting a
/// different secret shows up as a changed `DeviceId`.
fn open_sessions<'a>(
    flashes: &'a [RefCell<Flash>],
    rng: &mut Entropy,
) -> BTreeMap<DeviceId, Session<'a, Flash>> {
    let mut sessions = BTreeMap::new();
    for flash in flashes {
        // `load_or_create` wants `&mut Flash` and the session takes a shared
        // borrow of the same `RefCell` for its whole life, so the identity has to
        // be read first. Nothing else may hold a borrow here.
        let secret = match identity::load_or_create(&mut *flash.borrow_mut(), rng) {
            Ok(secret) => secret,
            Err(e) => die(2, &format!("identity::load_or_create: {e:?}")),
        };
        let mut session = match Session::open(flash, &secret) {
            Ok(session) => session,
            Err(e) => die(2, &format!("Session::open: {e:?}")),
        };
        session.signer.keygen_fingerprint = TEST_FINGERPRINT;
        if sessions.insert(session.device_id(), session).is_some() {
            die(2, "two devices derived the SAME DeviceId from different flashes");
        }
    }
    sessions
}

/// The digest the shipped `firmware_digest` computes, over a synthetic image.
///
/// The function is the one the ARM image calls; the INPUT cannot be real, because
/// a host process has no flashed, signed Mk4 image to hash. So: a
/// `FW_MIN_BODY_LEN` buffer with a valid `firmware_length` at header+24, hashed
/// over exactly the range `mk4-bootloader/verify.c:265-273` signs. No
/// coordinator refuses any digest today (`DO_GENUINE_CHECK = false`) and none
/// verifies one, so what this exercises is our own bounds-checking and framing,
/// not attestation.
fn synthetic_digest() -> frostsnap_comms::Sha256Digest {
    let length = memmap::FW_MIN_BODY_LEN;
    let mut image = vec![0xa5u8; length as usize];
    let off = memmap::FW_HEADER_OFFSET as usize + 24;
    image[off..off + 4].copy_from_slice(&length.to_le_bytes());
    firmware_digest(&image).expect("a well-formed synthetic image must hash")
}

/// Feed one decoded coordinator body to one session, answer the prompts a human
/// would answer, and record any share it staged.
///
/// AUTO-ACK, and it is why the two consent prompts are NOT answered by the
/// dispatch: `Session::recv` returns `CheckKeyGen` and `SignatureRequest` and
/// answers neither. `CheckKeyGen` is a human comparing the session hash against
/// the coordinator's display, which is the defence against a coordinator that
/// lies about who is in the access structure; `SignatureRequest` is a human
/// reading the transaction. **A REAL DEVICE MUST NOT ACK EITHER ITSELF.** This
/// stub has no display and acks both unconditionally, exactly as the vendored
/// tier-2 harness does. It is a harness affordance, not a policy — and the fact
/// that it lives HERE rather than in `firmware/src/lib.rs` is the load-bearing
/// part.
fn drive(
    session: &mut Session<'_, Flash>,
    body: CoordinatorSendBody,
    rng: &mut Entropy,
    wire: &mut Vec<u8>,
    saved: &mut BTreeMap<DeviceId, AccessStructureRef>,
) {
    let id = session.device_id();
    // The shipped outbox: it applies the three framing caps (one nonce segment
    // per frame, `Debug` truncation, refuse an over-long `HeldShares2` whole) at
    // the single point where a body becomes bytes. This file no longer encodes
    // anything itself.
    let mut out = Outbox::new(id);
    let mut prompts: VecDeque<DeviceToUserMessage> = match session.recv(body, rng, &mut out) {
        Ok(prompts) => prompts.into(),
        // A refusal is policy, not failure: the device cannot do the thing at
        // all. It answers nothing and the link stays up.
        Err(Fault::Refused(r)) => {
            eprintln!("stub: {id} REFUSED {r:?} (policy, not an error)");
            // ON THE WIRE, not just on stderr. A refusal the coordinator cannot
            // observe is a refusal no harness can assert, and "the device answered
            // nothing" is also what a dead device looks like. `Debug` is the only
            // free-form device body; `Outbox` caps it at 256 B on a UTF-8
            // boundary, and `hostcheck` intercepts it before the
            // `FrostCoordinator` state machine, so it cannot perturb the protocol.
            if let Err(e) = out.push(DeviceSendBody::Debug {
                message: format!("refused={r:?}"),
            }) {
                die(2, &format!("Debug(refused) refused by framing: {e:?}"));
            }
            VecDeque::new()
        }
        Err(e) => die(2, &format!("Session::recv({id}): {e:?}")),
    };

    while let Some(prompt) = prompts.pop_front() {
        match prompt {
            DeviceToUserMessage::CheckKeyGen { phase } => {
                // THE ANTI-MITM VALUE, PUT ON THE WIRE. The device computes this
                // itself, over the transcript it VERIFIED (`KeyGenPhase3`); the
                // coordinator computes its own from its own state. A real device
                // shows it to a human who compares it against the coordinator's
                // screen -- that human is unautomatable, but the EQUALITY is not,
                // and reporting it here is what turns it into a host gate
                // (`hostcheck` compares, by name, at PASS).
                let session_hash = phase.session_hash();
                if let Err(e) = out.push(DeviceSendBody::Debug {
                    message: format!("session_hash={}", hex(&session_hash.0)),
                }) {
                    die(2, &format!("Debug(session_hash) refused by framing: {e:?}"));
                }
                eprintln!("stub: {id} CheckKeyGen -> auto-ack (a real device asks a human)");
                let p = DeviceToUserMessage::CheckKeyGen { phase };
                match session.confirm(p, rng, &mut out) {
                    Ok(more) => prompts.extend(more),
                    Err(e) => die(2, &format!("confirm(CheckKeyGen, {id}): {e:?}")),
                }
                if clear_tmp_mode() == "check" {
                    eprintln!("stub: {id} clear_tmp_data() at CheckKeyGen -- WRONG ON PURPOSE");
                    session.signer.clear_tmp_data();
                }
            }
            p @ DeviceToUserMessage::SignatureRequest { .. } => {
                eprintln!("stub: {id} SignatureRequest -> auto-ack (a real device asks a human)");
                match session.confirm(p, rng, &mut out) {
                    Ok(more) => {
                        SIG_ACKS.fetch_add(1, Ordering::Relaxed);
                        STATE.fetch_max(6, Ordering::Relaxed);
                        prompts.extend(more);
                    }
                    Err(e) => die(2, &format!("confirm(SignatureRequest, {id}): {e:?}")),
                }
            }
            DeviceToUserMessage::FinalizeKeyGen { key_name } => {
                let clear = clear_tmp_mode() == "finalize";
                eprintln!("stub: {id} FinalizeKeyGen(key_name={key_name:?}) clear_tmp_data={clear}");
                // THE SHIPPED CALL SITE. Safe here because every tmp map has
                // already been `remove`d from by this point -- phase1 by
                // `CertifyPlease`, phase2 by `Check`, pending_finalize by the
                // `Finalize` that produced this very message -- and because it
                // does not touch `self.mutations`, which is the share drained
                // below. If either were false this run fails.
                //
                // FIRMWARE SHOULD PREFER `clear_unfinished_keygens()` (the keygen
                // leg alone, `device.rs:249`). It frees the SAME 12,456 B -- the
                // restoration leg only clears `tmp_loaded_backups`, whose
                // `BTreeMap` never allocates in a flow that enters no physical
                // backup -- while not being able to throw away a backup a human
                // has typed in but not yet saved. This calls the WIDER one on
                // purpose: passing the superset is the stronger evidence.
                if clear {
                    session.signer.clear_tmp_data();
                }
            }
            // Debug is not derived on every inner phase type, so no {other:?}.
            _other => eprintln!("stub: {id} ignoring an unrelated ToUser message"),
        }
    }

    // The device's persistence record. `keygen_finalize` -> `save_complete_share`
    // stages NewKey/NewAccessStructure/SaveShare; firmware's job is to write
    // these to flash, and NOTHING DOES YET -- there is no FLASH_FS region for
    // shares (`FS_FREE_OFFSET` is unclaimed), which is why the restart below
    // happens before keygen rather than after it. Draining them here is what "the
    // device saved its share" means for this harness, and the coordinator checks
    // it independently over the wire with `RequestHeldShares`.
    for mutation in session.signer.staged_mutations().drain(..) {
        if let Mutation::Keygen(KeyMutation::SaveShare(save)) = mutation {
            eprintln!(
                "stub: {id} SAVED share for {:?} (index {})",
                save.access_structure_ref, save.encrypted_secret_share.share_image.index
            );
            saved.insert(id, save.access_structure_ref);
        }
    }

    wire.extend_from_slice(&out.take());
}

fn main() {
    std::thread::spawn(|| {
        std::thread::sleep(DEADLINE);
        die(3, "watchdog fired: no progress within the deadline");
    });

    let mut rng = entropy(0x5a);
    let flashes = blank_flashes();
    let mut sessions = open_sessions(&flashes, &mut rng);
    let ids: Vec<DeviceId> = sessions.keys().copied().collect();
    eprintln!("stub: {N_DEVICES} flash-backed sessions: {ids:?}");

    let digest = synthetic_digest();
    let mut saved: BTreeMap<DeviceId, AccessStructureRef> = BTreeMap::new();
    let mut announced_save = false;

    let mut link = Link::new();
    let mut wire_in = std::io::stdin().lock();
    let mut wire_out = std::io::stdout().lock();
    let mut buf = [0u8; 512];
    let chunk = chunk_size();

    loop {
        // Read every iteration: an undrained pty blocks writes past ~1 KB, and
        // while unlinked `Link::poll` is silent, so reading is the only way
        // anything ever happens.
        let n = match wire_in.read(&mut buf) {
            // EOF is the ending for a HAND run: `hostcheck` kills us instead
            // (`reap()`), so in a harness run neither of these arms is reached and
            // our exit status is not what the pass hinges on. Kept, and kept
            // asymmetric, because it is the only contract a hand run has: EOF
            // after a successful save is success, EOF before one is a failure, and
            // it must stay that way or a stub killed early would look clean.
            Ok(0) if saved.len() == N_DEVICES => {
                eprintln!(
                    "stub: PASS -- coordinator closed the wire after verifying \
                     {N_DEVICES}/{N_DEVICES} held shares and {} signature share(s), all from \
                     sessions REBUILT FROM FLASH after the restart",
                    SIG_ACKS.load(Ordering::Relaxed)
                );
                return;
            }
            Ok(0) => die(
                2,
                &format!(
                    "wire EOF with only {}/{N_DEVICES} share(s) saved -- the coordinator gave \
                     up first",
                    saved.len()
                ),
            ),
            Ok(n) => n,
            Err(e) => die(2, &format!("read(fd 0): {e}")),
        };
        BYTES_READ.fetch_add(n, Ordering::Relaxed);

        // The "just linked" edge is observed HERE, from outside, on purpose:
        // `Link` exposes `is_linked()` but no edge, and this file is specified to
        // need zero `hal/src/` changes.
        let was_linked = link.is_linked();
        let mut wire: Vec<u8> = Vec::new();
        let poll = link.poll::<ReceiveSerial<Upstream>, _>(&buf[..n], |frame| match frame {
            ReceiveSerial::Message(msg) => {
                let mut dest = msg.target_destinations;
                let targets: Vec<DeviceId> =
                    ids.iter().copied().filter(|id| dest.is_destined_to(*id)).collect();
                // `decode_body`, NOT the vendored `message_body.decode()`: the
                // vendored one re-enters bincode with a 32 KiB budget, where a
                // 20-byte inner blob provokes a 32,640 B allocation (measured).
                // This bounds it at `ENCAPS_DECODE_LIMIT` and names the failure.
                match decode_body(msg.message_body) {
                    Ok(body) => {
                        if matches!(body, CoordinatorSendBody::Core(_)) {
                            STATE.fetch_max(4, Ordering::Relaxed);
                            eprintln!("stub: rx Core -> {} device(s)", targets.len());
                        } else {
                            eprintln!("stub: rx {body:?} -> {} device(s)", targets.len());
                        }
                        // EVERY body goes to the shipped dispatch, including
                        // `AnnounceAck` (which latches `coordinator_acked`) and
                        // anything it refuses. This file no longer has an opinion
                        // about which bodies matter.
                        for id in targets {
                            let session =
                                sessions.get_mut(&id).expect("id came from `sessions`");
                            drive(session, body.clone(), &mut rng, &mut wire, &mut saved);
                        }
                    }
                    // Over the inner limit, not valid bincode, or one of the two
                    // dead compat variants. NOT a desync: the framing is intact
                    // and the link stays up, so a single bad body cannot drop it.
                    Err(e) => eprintln!("stub: rx undecodable body ({e:?})"),
                }
            }
            // The coordinator keeps re-sending magic every 100 ms until it reads
            // our reply; those arrive as ordinary frames once linked.
            ReceiveSerial::MagicBytes(_) => eprintln!("stub: rx MagicBytes"),
            ReceiveSerial::Conch => eprintln!("stub: rx Conch"),
            ReceiveSerial::Reset => eprintln!("stub: rx Reset"),
            _ => eprintln!("stub: rx unused variant"),
        });
        if let Err(e) = poll {
            die(
                2,
                &format!("Link::poll: {e:?} (pending {} bytes)", link.pending()),
            );
        }

        if !was_linked && link.is_linked() {
            eprintln!(
                "stub: LINKED after {} bytes",
                BYTES_READ.load(Ordering::Relaxed)
            );
            // MAGIC_REPLY then `Session::announce` per device -- `Announce` AND
            // `NeedName`, because announce alone never registers a device with the
            // real coordinator: its gate is a NAME. All in this iteration
            // deliberately: the coordinator stops writing magic bytes the moment
            // it reads our reply, so deferring to the next loop iteration would
            // park us in `read()` waiting for a byte it will never send.
            let mut hello = Vec::from(MAGIC_REPLY);
            for session in sessions.values() {
                let mut out = Outbox::new(session.device_id());
                if let Err(e) = session.announce(digest, &mut out) {
                    die(2, &format!("announce({}): {e:?}", session.device_id()));
                }
                hello.extend_from_slice(&out.take());
            }
            if let Err(e) = write_chunked(&mut wire_out, &hello, chunk) {
                die(2, &format!("write(fd 1): {e}"));
            }
            STATE.fetch_max(1, Ordering::Relaxed);
            eprintln!(
                "stub: sent MAGIC_REPLY + {N_DEVICES} Announce+NeedName = {} bytes in {} chunk(s) \
                 of {chunk}",
                hello.len(),
                hello.len().div_ceil(chunk),
            );

            // ===================== THE RESTART =====================
            // Everything RAM-side goes away and is rebuilt from the same flash
            // bytes -- which is exactly what a power cycle does, since `FakeFlash`
            // IS the flash array and the sessions are all the state that is not
            // on it. This happens HERE, immediately after the announce write and
            // before any reply can be read, for two reasons:
            //
            //  - the coordinator learned our ids from the PRE-restart announce, so
            //    everything after this point -- keygen, nonce replenishment, the
            //    signature it verifies, HeldShares2 -- is done by sessions that
            //    read their keypair back out of flash. A non-durable identity
            //    yields different ids and the coordinator never completes a keygen
            //    with them. The coordinator is the judge, not us;
            //  - nothing persists a completed share yet (see `drive`), so a
            //    restart after keygen would lose it. Before keygen there is
            //    nothing on flash but the identity, which is the point.
            //
            // The assert below is belt: it fails fast and by name, whereas the
            // coordinator's failure would be a keygen timeout.
            sessions = open_sessions(&flashes, &mut rng);
            let after: Vec<DeviceId> = sessions.keys().copied().collect();
            if after != ids {
                die(
                    2,
                    &format!(
                        "IDENTITY DID NOT SURVIVE THE RESTART: announced {ids:?} but flash \
                         rebuilt as {after:?}"
                    ),
                );
            }
            STATE.fetch_max(2, Ordering::Relaxed);
            eprintln!(
                "stub: RESTARTED -- dropped all {N_DEVICES} signers and rebuilt them from flash; \
                 every DeviceId unchanged, so the coordinator is still talking to the same devices"
            );
        }

        let acked = sessions.values().filter(|s| s.coordinator_acked).count();
        if acked == N_DEVICES && STATE.load(Ordering::Relaxed) == 2 {
            STATE.fetch_max(3, Ordering::Relaxed);
            eprintln!(
                "stub: all {N_DEVICES} devices acked (post-restart sessions), waiting for keygen"
            );
        }

        if !wire.is_empty() {
            let bytes = wire.len();
            if let Err(e) = write_chunked(&mut wire_out, &wire, chunk) {
                die(2, &format!("write(fd 1): {e}"));
            }
            eprintln!("stub: sent {bytes} B");
        }

        if saved.len() == N_DEVICES && !announced_save {
            announced_save = true;
            STATE.fetch_max(5, Ordering::Relaxed);
            let refs: std::collections::BTreeSet<_> = saved.values().collect();
            // Every share belongs to ONE access structure, or the keygen did not
            // agree with itself.
            if refs.len() != 1 {
                die(
                    2,
                    &format!("{} distinct access structures saved: {refs:?}", refs.len()),
                );
            }
            eprintln!(
                "stub: {N_DEVICES}/{N_DEVICES} devices saved a share for {:?}",
                saved.values().next().expect("just checked len"),
            );
            // DO NOT exit here. Exiting on our own say-so made the device half of
            // the proof a single bit -- our exit status -- decided by the process
            // the claim is about; a stub that persisted nothing and returned 0
            // passed. Now we keep serving so the coordinator can send
            // `RequestHeldShares` and check for itself, and the run ends when IT
            // closes the pty (read -> EOF above).
        }
    }
}
