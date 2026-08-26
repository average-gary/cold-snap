//! M1/M2: a REAL `frostsnap_coordinator` handshakes with cold-snap's REAL device
//! framing over a real pty. M3: the same two processes complete a REAL 9-of-9
//! KEYGEN. Two processes, two workspaces, two independent copies of
//! `frostsnap_core`, real file descriptors.
//!
//! This process is the COORDINATOR. It creates the pty pair, keeps the **SLAVE**
//! and drives an unmodified `FramedSerialPort<Downstream>` over it; the device
//! side is `firmware/examples/stub.rs`, spawned with the **MASTER** as its fd 0/fd 1.
//! It drives `coldsnap_firmware::Session` -- the SAME dispatch the ARM image
//! contains -- over a `FakeFlash` at the shipped geometry, so this run is evidence
//! about our firmware and not just about `frostsnap_core`.
//!
//! TWO of those ports, over one pty: the main loop's is READ-ONLY, and a writer
//! thread owns a second one on a `dup` of the same fd so that a blocked write
//! cannot park the loop. Both are upstream's, unmodified, and every byte is still
//! encoded by its `raw_send`. See `WRITE_STALL_LIMIT` and `spawn_writer`.
//!
//! The slave/master split is not a coin toss: MEASURED on darwin, `FIONREAD` on a
//! pty MASTER always returns 0, and `FramedSerialPort::anything_to_read()` is
//! exactly that ioctl -- so a coordinator holding the master would see an
//! eternally empty port and hang forever, silently.
//!
//! M5 extends the SAME run: one nonce stream per device, then a real 9-of-9
//! signature over `WireSignTask::Test`. It passes only if
//! `CheckedSignTask::verify_final_signatures` returns TRUE against a group key
//! read out of the coordinator's own `CompleteKey` -- see the block at the end of
//! `one_pass`. `Signed` arriving is not a pass; a verified signature is.
//!
//! WHAT M3 PASSES ON, exactly (assert, not "no error"):
//!  1. `finalize_keygen` returned an `AccessStructureRef`, and that ref is
//!     findable afterwards in `coordinator.iter_access_structures()` with
//!     `threshold == 2` and 3 device shares. Both halves are checked: the
//!     returned value AND the coordinator's own persisted view of it.
//!  2. A `SessionHash` was delivered to the user layer (`CheckKeyGen`) -- the
//!     value a human would compare against the device screens.
//!  3. The stub exited 0, which it only does after all THREE `FrostSigner`s
//!     staged a `KeyMutation::SaveShare` for one and the same access structure.
//!     That is the device-side half of the proof and it lives in the other
//!     process, in the other copy of `frostsnap_core`.
//! All of it at BOTH chunk sizes, run back to back by one invocation.
//!
//! WHY IT IS NOT A MOCK: this binary links UPSTREAM `frostsnap_core` (through
//! `frostsnap_coordinator`); the stub links cold-snap's VENDORED copy. Every
//! keygen message is encoded by one tree and decoded by the other. A byte of
//! disagreement anywhere in `message.rs` or the bincode config fails the run --
//! and the mutation tests at the bottom of this comment show it does.
//!
//! MUTATIONS -- each of these was RUN, not reasoned about:
//!  M2 (framing/bound):
//!  - Announce truncated by 4 bytes, sent immediately: `DEADLINE ... in state
//!    WaitingForAnnounce -- read_timeouts=1` at **5.0009 s**. Before M2 this hung
//!    ~10 s and was released by the stub exiting, not by this deadline.
//!  - Same truncation held back to 4.81 s, i.e. the stall lands as the deadline
//!    expires: fails at **5.0639 s**, exactly stall + one `PORT_TIMEOUT`.
//!  - Device silent, then late magic: `WaitingForMagic` at **5.069 s**.
//!  - One magic byte flipped: `WaitingForMagic -- magic_writes=48` at
//!    **5.0004 s** (the scan has no backtracking, so it never links).
//!  - CHUNKING: at the DEFAULT `STUB_CHUNK=64` the stub's writes COALESCE and
//!    reassembly is never exercised -- its "sent" line prints BEFORE the
//!    coordinator's first read. Only `STUB_CHUNK=1` forces it. For one run
//!    `STUB_CHUNK` was an env var that NOTHING set, i.e. a test that could not
//!    fail; `main` now runs both sizes every time.
//!  M3 (keygen). All three RUN, at chunk 64, each restored after:
//!  - One byte flipped in the middle of the device's 318-byte `KeyGenResponse`
//!    frame (`out[len/2] ^= 1`): **`recv_device_message ... in
//!    KeygenAwaitingShares: Invalid message of kind KeyGen: proof-of-possession
//!    signature did not verify`**, exit 1, before the second device even
//!    answered. Note what that proves: the failure came from upstream's
//!    CRYPTO, on a message the vendored tree encoded -- the two trees are
//!    really agreeing, not both being sloppy.
//!  - Device never acks `CheckKeyGen` (the human-confirmation step): `DEADLINE
//!    (35s) in state KeygenAwaitingAcks -- shares=3, acks=0, session_hash=true`
//!    at **35.0000 s**. The counters localise it exactly: hash delivered, zero
//!    acks.
//!  - The coordinator's `Finalize` dropped by the device (4th inbound Core
//!    frame discarded): `DEADLINE (35s) in state KeygenAwaitingDeviceSave --
//!    shares=3, acks=3, session_hash=true` at **35.0007 s**. That is the state
//!    that exists to catch precisely "coordinator thinks it is done, device has
//!    nothing": the coordinator HAD its `AccessStructureRef` and still failed.
//!
//!  M4 (the WRITE path -- `WRITE_STALL_LIMIT`). Stub mutated to send 2,018 B of
//!  Announces and then NEVER read again, so the coordinator has >1 KB queued to a
//!  peer that is not draining -- i.e. the M5 condition, where every signing frame
//!  is over 1 KB. Both runs used the SAME mutated stub; the stub was restored and
//!  `diff`ed clean afterwards.
//!  - BEFORE (write on the loop's own thread, reproduced by making `send_frame`
//!    park its caller until the frame is written): the loop never reaches ANY
//!    deadline check. Killed by the watchdog at **37.021 s**, `exit(5)`, and the
//!    only diagnosis is `state WaitingForAnnounces` -- one announce in, no
//!    counters, no mention of a write, and a process kill rather than an error.
//!    That is 7.4x the budget the failure actually deserved.
//!  - AFTER (writer thread): **5.0035 s**, exit 1, `WRITE STALL (5.003534458s >
//!    5s) in state KeygenAwaitingShares -- frame 2/32 is stuck in
//!    raw_send/tcdrain ... announced=3, shares=0, acks=0`. Note it got FURTHER
//!    than the BEFORE run -- 3 announces and a started keygen instead of 1
//!    announce -- because the read path kept running THROUGH the blocked write.
//!    That is the writer thread's whole value, visible in the log.
//!  - The read path's own bound, re-checked against the same change (stub's
//!    Announce burst truncated by 4 B): `DEADLINE (5s) in state
//!    WaitingForAnnounces -- writes_queued=4, writes_done=4, read_timeouts=1` at
//!    **5.0029 s**, matching M2's 5.0009 s. The new write counters are what
//!    exonerate the writer here, which is the diagnosis M2 could not make.
//!
//!  M5 (nonces + a real signature). MEASURED whole pass, keygen included:
//!  **0.53 s at chunk 64, 1.66 s at chunk 1**. Frame sizes on the wire matched
//!  the predictions exactly: `NonceResponse` 1x30 = **2,040 B** and
//!  `SignatureShare` + full replenish = **2,105 B**, both device->coordinator,
//!  and both crossed at `STUB_CHUNK=1` -- i.e. as 2,040 and 2,105 SEPARATE
//!  one-byte writes -- with no deadlock. Those were the first frames over 1 KB
//!  ever to cross this pty. They work because the traffic is one-directional
//!  there: the coordinator has nothing queued while it reads, so it drains.
//!  All three mutations RUN at chunk 64, stub restored and `diff`ed clean after
//!  each:
//!  - One byte flipped in the middle of the 2,105 B `SignatureShare`
//!    (`out[1052]`, inside the replenish nonces): **`body.decode() ... in
//!    SigningAwaitingShares: OtherString("Invalid 66-byte encoding of a public
//!    binonce")`**, exit 1, at **1.39 s**.
//!  - Same mutation at `out[60]` instead -- inside the message header, so it
//!    lands on `session_id` -- does NOT produce a named failure: UPSTREAM
//!    PANICS. `frostsnap_core/src/coordinator.rs:877`
//!    `active_signing_sessions.get(&session_id).expect("inavariant")`. exit 101
//!    at **1.33 s**. A device-supplied field with no guard: any device can
//!    crash the real coordinator with one `SignatureShare`. NOT worked around
//!    here on purpose -- a harness that swallows a real crash is worse than one
//!    that shows it.
//!  - Device answers `NonceResponse` for a stream id the coordinator never
//!    opened (`segments[0].stream_id.0[0] ^= 1`): the coordinator ACCEPTS it
//!    (`coord_nonces.rs:36` `check_can_extend` returns `Ok(())` for an unknown
//!    stream id) and builds a signing session on it; the failure comes from the
//!    DEVICE refusing the resulting `RequestSign` ("device did not have that
//!    nonce stream id"), surfacing here as `stub exited 2 in
//!    SigningAwaitingShares having reported 3/3 held shares, 3/3 nonce
//!    replenishments and 0/2 signature shares`, exit 1 at **1.21 s**.
//!  - Signing reply dropped entirely (`sign_ack` called, its sends discarded):
//!    `DEADLINE (65s) in state SigningAwaitingShares -- ... held=3,
//!    replenished=3, sign_session=true, sig_shares=0/2` at **65.0001 s**, i.e.
//!    `HANDSHAKE + KEYGEN + SIGN` exactly. `writes_done=17` of
//!    `writes_queued=17` in the same line exonerates the write path.
//!  - AND ONE ON THIS FILE, because none of the three above ever reached
//!    `verify_final_signatures` and so none of them proved the pass GATE is the
//!    verification rather than the arrival of `Signed`. The verify site was
//!    pointed at a `WireSignTask::Test` carrying a different message: **`SIGNATURE
//!    DOES NOT VERIFY: 1 sig(s) over "cold-snap M5" against master_appkey 03c5..`**,
//!    exit 1 at **1.36 s**. Restored and `diff`ed clean.
//!
//! Usage: `hostcheck [path-to-stub-binary]`. Build the stub FIRST and pass the
//! artifact -- never `cargo run`: the child's stdout IS the wire, and one stray
//! byte of cargo progress output desynchronises the magic scan permanently.
//!
//!   cargo build --target aarch64-apple-darwin -p coldsnap_firmware --example stub
//!   cargo run -p hostcheck        # from hostcheck/, default path below

use std::collections::VecDeque;
use std::io::Write;
use std::os::fd::{AsFd, FromRawFd, IntoRawFd, OwnedFd};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use frostsnap_coordinator::frostsnap_comms::{
    CoordinatorSendBody, CoordinatorSendMessage, DeviceSendBody, Downstream, MagicBytes,
    ReceiveSerial, Upstream, BINCODE_CONFIG, MAGIC_BYTES_PERIOD,
};
use frostsnap_coordinator::frostsnap_core::coordinator::{
    BeginKeygen, CoordinatorSend, CoordinatorToUserKeyGenMessage, CoordinatorToUserMessage,
    CoordinatorToUserSigningMessage, FrostCoordinator,
};
use frostsnap_coordinator::frostsnap_core::device::KeyPurpose;
use frostsnap_coordinator::frostsnap_core::message::{
    DeviceRestoration, DeviceToCoordinatorMessage, EncodedSignature,
};
use frostsnap_coordinator::frostsnap_core::schnorr_fun::frost::Fingerprint;
use frostsnap_coordinator::frostsnap_core::schnorr_fun::{Schnorr, Signature};
use frostsnap_coordinator::frostsnap_core::{
    sha2, AccessStructureRef, DeviceId, KeygenId, SessionHash, SignSessionId, SymmetricKey,
    WireSignTask,
};
// Not a direct dependency either: `frostsnap_core` re-exports the one `bincode`
// the coordinator decodes with, so the error matched in `is_read_timeout` is the
// same type the coordinator produced.
use frostsnap_coordinator::frostsnap_core::bincode;
use frostsnap_coordinator::frostsnap_core::Gist;
use frostsnap_coordinator::serialport::{SerialPort, TTYPort};
use frostsnap_coordinator::FramedSerialPort;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// Where `cargo build --target aarch64-apple-darwin -p coldsnap_firmware --example
/// stub` puts it. UNCHANGED by the move out of `hal/`: cargo puts every workspace
/// member's examples in one flat `target/<triple>/debug/examples/` directory.
///
/// Freshness IS checked, by `refuse_if_stale` below. It used to be `is_file()` only,
/// which meant a stale artifact from an earlier build got run and reported on -- a
/// fail-open in the one program whose entire job is verification, and the most
/// expensive kind: a green run certifying code that is not in the binary.
const DEFAULT_STUB: &str = "../target/aarch64-apple-darwin/debug/examples/stub";

/// 3 devices, threshold 2. n=3 is not arbitrary: it is what fits the frame bound.
/// MEASURED sizes at n=3 are `CertifyPlease` 778 B, `Check` 646 B,
/// `KeyGenResponse` ~318 B, so nothing crosses the ~1 KB point at which an
/// undrained pty blocks a write. That is now a bound, not a hang
/// (`WRITE_STALL_LIMIT`), but staying under it is still why keygen is fast.
/// At 9-of-9 `CertifyPlease` is
/// 2,179 B and does not even fit the device's frame limit. Do not raise these
/// without re-deriving both bounds.
const N_DEVICES: usize = 9;
const THRESHOLD: u16 = 9;

/// ONE nonce stream per device, and this is the whole M5 frame-size decision.
///
/// A `NonceResponse` is one segment per stream, and one 30-nonce segment MEASURED
/// 2,040 B -- the first frame over 1 KB ever to cross this pty, which is the point
/// of M5. Two streams is 4,038 B against a 4,096 bound, i.e. 58 bytes of headroom,
/// and the real flutter app asks for FOUR (`N_NONCE_STREAMS`), ~8 KB, which does
/// not fit at all. The only reason that is not a live bug upstream is that
/// `NonceReplenishProtocol::new` calls `OpenNonceStreams::split()` and asks for one
/// stream at a time; the stub caps at one segment per frame as belt-and-braces
/// against a coordinator that stops splitting. Raising this proves nothing extra
/// about the wire and walks straight into the bound.
const NONCE_STREAMS: usize = 1;

/// The message we sign. `WireSignTask::Test` is the simplest task that yields a
/// verifiable signature: exactly one `SignItem`, no taproot sighash work, no
/// `bdk`, and `AppTweak::TestMessage` so the verification is one `Schnorr::verify`
/// against a key derived from `master_appkey`. A bitcoin task would add PSBT
/// plumbing and prove nothing more about the wire.
const SIGN_MESSAGE: &str = "cold-snap M5";

/// Built twice (once to sign, once to verify) rather than cloned around: it is two
/// words, and building it at the verify site is what makes the verification
/// independent of whatever the signing path did with it.
fn sign_task() -> WireSignTask {
    WireSignTask::Test {
        message: SIGN_MESSAGE.into(),
    }
}

/// Matches the stub's constant. See the long note there: the fingerprint is a
/// coordinator-side grind (`FROST_V0` is 18 bits/coefficient, minutes of CPU in
/// a debug build), it must be equal on both sides because the device verifies
/// it, and it changes which coefficients are chosen -- never how they encode.
/// So it costs this harness nothing it was here to prove.
const TEST_FINGERPRINT: Fingerprint = Fingerprint {
    bits_per_coeff: 2,
    max_bits_total: 6,
    tag: "test",
};

/// The share-encryption key the coordinator persists its own key data under.
/// Constant, like the vendored tier-2 harness: this harness never reloads
/// anything from storage.
const ENCRYPTION_KEY: SymmetricKey = SymmetricKey([42u8; 32]);

/// Fixed seed, so a failing keygen replays exactly. The stub's `Entropy` is
/// fixed-seeded too, so the whole two-process run is deterministic.
const RNG_SEED: [u8; 32] = [7u8; 32];

/// 250 ms -- deliberately NOT `DesktopSerial`'s 5 s (`serial_port.rs:257-260`).
///
/// This timeout is the ONLY thing that can end a blocking read inside
/// `bincode::decode_from_reader`, so it is the slack term on every deadline
/// below: worst-case wall clock is `budget + PORT_TIMEOUT`.
///
/// What is traded, honestly:
///  - Upstream keeps 5 s because a read timeout is a device DISCONNECT
///    (`usb_serial_manager.rs:299-311`) and it must not evict a device that is
///    merely slow. This harness has no device to evict.
///  - Upstream's other reason is WRITES: "10ms is too low and leads to errors
///    when writing", on real USB CDC. 250 ms is 25x that, and this port is a
///    local pty.
///  - What IS given up: this harness cannot distinguish "device thinking for
///    300 ms" from "device stalled". Both become a deadline failure. That is why
///    keygen gets its own, much larger budget -- a debug-build certpedpop keygen
///    across three signers legitimately holds the wire for whole seconds.
const PORT_TIMEOUT: Duration = Duration::from_millis(250);

/// The handshake budget, unchanged from M2 so its measurements still stand: 5 s
/// for magic + 3 Announces. Hard on the read path (`budget + PORT_TIMEOUT`).
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(5);

/// The keygen budget, on top of `HANDSHAKE_DEADLINE`, and generous on purpose:
/// this is real elliptic-curve work in TWO debug builds, and at `STUB_CHUNK=1`
/// every byte of every frame is a syscall on the device side. MEASURED, whole
/// keygen from magic bytes to the stub's exit, 3 runs after the writer thread
/// landed: **95-120 ms at chunk 64, 1.30-1.33 s at chunk 1** (the difference is
/// the 1 ms-per-chunk gap on the first 64 bytes of each of ~10 frames). Chunk 64
/// halved (265 ms before) because a frame no longer waits for `tcdrain` on the
/// loop's own thread; chunk 1 rose (847 ms before) because the handoff costs a
/// scheduling round-trip per frame and at chunk 1 that no longer hides under the
/// device's own 1 ms gaps. Both directions are noise against the budget, which is
/// the point of having one. 30 s is ~23x the slower case, the right shape for a
/// whose only job is to turn a hang into a named failure -- tightening it to the
/// measurement would make the harness flaky on a loaded machine and prove
/// nothing extra. The two failing mutations above both died on it at 35.000 s,
/// i.e. `HANDSHAKE_DEADLINE + KEYGEN_DEADLINE`, exactly.
const KEYGEN_DEADLINE: Duration = Duration::from_secs(30);

/// M5's budget, on top of the two above, covering nonce replenishment AND signing.
/// One number for both phases deliberately: the deadline message names the state,
/// so splitting the budget would buy a tighter clock and no extra diagnosis.
///
/// 30 s is generous against MEASURED cost -- replenish + sign is 0.10 s at chunk
/// 64 and 1.35 s at chunk 1 -- and the shape is the same as `KEYGEN_DEADLINE`: it
/// exists to turn a hang into a named failure, not to be a performance assertion.
/// The chunk-1 case is the one to watch: three 2,040 B `NonceResponse` frames at
/// one byte per write, plus 30 nonce derivations per stream per device in a debug
/// build.
const SIGN_DEADLINE: Duration = Duration::from_secs(30);

/// The LAST-RESORT bound: a wall-clock watchdog for a stall anywhere in the main
/// loop that is not a read and not a write (both of which are bounded above).
///
/// It owns no I/O, so nothing it watches can stop it; it wakes every 100 ms, and
/// if the current pass has outlived its deadline it prints the state NAME and
/// `exit(5)`s the process. COARSE on purpose: one deadline per pass, set to the
/// pass's MAXIMUM budget, so a stall during the handshake is caught at 37 s
/// rather than at 7 s. VERIFIED by injecting a 60 s sleep inside the loop:
/// `WATCHDOG at 37.028 s -- state WaitingForAnnounces`, exit 5.
///
/// It is no longer the write path's only bound; see `WRITE_STALL_LIMIT`.
const WATCHDOG_SLACK: Duration = Duration::from_secs(2);

/// THE WRITE PATH, bounded.
///
/// `FramedSerialPort::raw_send` -> `flush()` -> serialport-4 -> `tcdrain(fd)`
/// blocks until the peer drains and is NOT subject to `PORT_TIMEOUT`. MEASURED at
/// M2, before this: a device that linked and then stopped reading parked this
/// harness **8.176 s**, released by the STUB's watchdog closing the pty -- the
/// read deadline was bypassed entirely because the loop never got back to it.
/// Every M5 signing frame is over 1 KB (`NonceResponse` 1x30 = 2,040 B,
/// `SignatureShare` + replenish = 2,105 B) and the pty blocks writes past ~1 KB,
/// so under M5 that is the FIRST frame, not a corner case.
///
/// WHAT IS IMPLEMENTED (design (a), a writer thread): every byte this harness
/// sends is written by `spawn_writer`'s thread, which owns a `dup` of the pty
/// slave fd and its own `FramedSerialPort`. The main loop only `send`s on an
/// `mpsc` channel, which never blocks, so a parked `tcdrain` can no longer keep
/// the loop away from its deadline checks. The writer publishes the start time of
/// each `raw_send` in `WRITE_BUSY_SINCE_MS`; the loop reads it every lap and fails
/// by NAME once one write has been in flight longer than this.
///
/// So the bound is honest but INDIRECT: the blocked `tcdrain` itself is still
/// uninterruptible -- that thread stays parked until the pty is drained or the
/// process exits. What is bounded is the RUN. Nothing else needs bounding: the
/// writer thread holds no lock the loop wants, and it is detached, so a leaked
/// parked writer only ever outlives a run that is already failing.
///
/// 5 s: the whole chunk-1 keygen MEASURED 1.33 s, so no single legitimate write
/// comes near it, and it is 1/7 of the keygen deadline, i.e. a write stall is
/// diagnosed as a write stall rather than as a late generic DEADLINE. This is the
/// knob to turn if a real device legitimately stops reading for seconds mid-sign.
const WRITE_STALL_LIMIT: Duration = Duration::from_secs(5);

/// Coordinator-side states. `NAMES` is the single source of truth for the
/// spelling, because both the loop's own error and the watchdog thread (which
/// has only an integer) print from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
enum State {
    WaitingForMagic = 0,
    WaitingForAnnounces,
    KeygenAwaitingShares,
    KeygenAwaitingSessionHash,
    KeygenAwaitingAcks,
    KeygenAwaitingDeviceSave,
    /// Waiting for each device to REPORT what it stored, over the wire.
    KeygenAwaitingHeldShares,
    /// M5: `OpenNonceStreams` sent, waiting for every device's `NonceResponse`.
    /// This is where the >1 KB frames are.
    NonceReplenish,
    /// M5: `RequestSign` sent to the threshold subset, waiting for their
    /// `SignatureShare`s and the coordinator's aggregation.
    SigningAwaitingShares,
}

const NAMES: [&str; 9] = [
    "WaitingForMagic",
    "WaitingForAnnounces",
    "KeygenAwaitingShares",
    "KeygenAwaitingSessionHash",
    "KeygenAwaitingAcks",
    "KeygenAwaitingDeviceSave",
    "KeygenAwaitingHeldShares",
    "NonceReplenish",
    "SigningAwaitingShares",
];

impl State {
    fn name(self) -> &'static str {
        NAMES[self as usize]
    }

    /// Publish for the watchdog, which cannot see the local variable.
    fn publish(self) {
        STATE.store(self as usize, Ordering::Relaxed);
    }

    /// CUMULATIVE, because it is compared against `started.elapsed()`: each phase
    /// adds its own budget on top of the ones before it, so the handshake keeps
    /// M2's 5 s exactly and keygen's mutations keep dying at 35 s.
    fn budget(self) -> Duration {
        match self {
            State::WaitingForMagic | State::WaitingForAnnounces => HANDSHAKE_DEADLINE,
            State::NonceReplenish | State::SigningAwaitingShares => {
                HANDSHAKE_DEADLINE + KEYGEN_DEADLINE + SIGN_DEADLINE
            }
            _ => HANDSHAKE_DEADLINE + KEYGEN_DEADLINE,
        }
    }
}

static STATE: AtomicUsize = AtomicUsize::new(0);
/// Millis since process start at which the watchdog should give up. 0 = idle.
static WATCHDOG_AT_MS: AtomicU64 = AtomicU64::new(0);

/// Millis since process start at which the writer thread entered the `raw_send`
/// it is currently inside. 0 = idle, i.e. every queued frame is on the wire.
static WRITE_BUSY_SINCE_MS: AtomicU64 = AtomicU64::new(0);
/// Largest coordinator->device frame actually put on the wire, in bytes.
///
/// This exists because every downstream figure was ARITHMETIC: the harness logged
/// `msg.gist()` and never a size, so "nothing over 1 KB has crossed
/// coordinator->device" was an inference. It is now measured, and it was WRONG once
/// N_DEVICES reached 9: `CertifyPlease` = 2,179 B and `Check` = 1,624 B cross every
/// run, matching PLAN.md §7's formulas to the byte.
static MAX_DOWN_B: AtomicUsize = AtomicUsize::new(0);

/// Frames that completed `raw_send`. Per pass; reset by `one_pass`.
static WRITES_DONE: AtomicUsize = AtomicUsize::new(0);
/// The writer thread's dying words, since it cannot return a `Result` to the loop.
static WRITE_ERR: Mutex<Option<String>> = Mutex::new(None);

/// The write half of the harness: a thread, a `dup`, and upstream's real encoder.
///
/// The frame type is `ReceiveSerial<Upstream>` because that is what `raw_send`
/// takes, and it covers both things this harness sends -- so magic bytes and
/// message frames go out through ONE queue, in order, from ONE fd. That ordering
/// is not a nicety: two `FramedSerialPort`s writing the same fd would interleave
/// bytes mid-frame, which is why the caller's port must never write again.
///
/// `raw_send` rather than `queue_send`+`poll_send` is the same bytes: with conch
/// disabled (it is -- the device signals version 2) `poll_send` is exactly
/// `raw_send(Message(..))`, and `write_magic_bytes` is exactly
/// `raw_send(MagicBytes(..))`. Upstream still does all the encoding and all the
/// writing; what changed is which thread it blocks.
///
/// The channel is unbounded, which is not the sloppy choice here: a bounded queue
/// would have to block or drop when full, and blocking is the thing being fixed.
/// Depth stays in single digits (keygen queues at most n+1 frames) and it is
/// reported in the deadline message, so a growing queue is visible.
fn spawn_writer(port: TTYPort, t0: Instant) -> Sender<ReceiveSerial<Upstream>> {
    let (tx, rx) = std::sync::mpsc::channel::<ReceiveSerial<Upstream>>();
    std::thread::spawn(move || {
        let mut port: FramedSerialPort<Downstream> =
            FramedSerialPort::new(Box::new(port) as Box<dyn SerialPort>);
        // Ends when the sender drops -- unless parked in `raw_send`, in which case
        // this thread leaks. Deliberate: see WRITE_STALL_LIMIT.
        for frame in rx {
            // Encode a throwaway copy purely to size it, with the same
            // `BINCODE_CONFIG` upstream's `raw_send` uses -- so this is the byte
            // count that lands on the wire, not an estimate.
            if let Ok(bytes) = bincode::encode_to_vec(&frame, BINCODE_CONFIG) {
                MAX_DOWN_B.fetch_max(bytes.len(), Ordering::Relaxed);
                if bytes.len() > 1024 {
                    eprintln!("hostcheck: -> {} B downstream frame", bytes.len());
                }
            }
            WRITE_BUSY_SINCE_MS.store((t0.elapsed().as_millis() as u64).max(1), Ordering::Relaxed);
            let result = port.raw_send(frame);
            WRITE_BUSY_SINCE_MS.store(0, Ordering::Relaxed);
            match result {
                Ok(()) => WRITES_DONE.fetch_add(1, Ordering::Relaxed),
                Err(e) => {
                    *WRITE_ERR.lock().unwrap() = Some(e.to_string());
                    return;
                }
            };
        }
    });
    tx
}

/// Hand one frame to the writer thread. Cannot block; fails only if that thread
/// is gone, which only happens after it has recorded why.
fn send_frame(tx: &Sender<ReceiveSerial<Upstream>>, frame: ReceiveSerial<Upstream>) -> Result<()> {
    tx.send(frame).map_err(|_| {
        anyhow::anyhow!(
            "writer thread is gone: {}",
            WRITE_ERR
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| "no error recorded".into())
        )
    })
}

/// A read timeout is `bincode::error::DecodeError::Io` wrapping
/// `ErrorKind::TimedOut`. It means "nothing more arrived within PORT_TIMEOUT",
/// which for us is not an error but the deadline's tick: keep looping.
///
/// It does NOT mean the stream is recoverable. Whatever bincode already consumed
/// of a partial frame is gone, so the stream is desynced and the run is
/// doomed -- it just now dies on the deadline, promptly and with a state name,
/// instead of surfacing as a mystery decode error.
fn is_read_timeout(e: &bincode::error::DecodeError) -> bool {
    matches!(e, bincode::error::DecodeError::Io { inner, .. }
        if inner.kind() == std::io::ErrorKind::TimedOut)
}

/// Everything the keygen drive needs to remember between laps.
struct Keygen {
    id: KeygenId,
    got_shares: usize,
    acks: usize,
    /// The hash a human compares on the device screens.
    session_hash: Option<SessionHash>,
    /// The completion value, straight out of `finalize_keygen`.
    finished: Option<AccessStructureRef>,
}

/// M5 state. Separate from `Keygen` rather than merged into it because the two
/// phases share nothing: keygen is done and asserted on before any of this starts.
#[derive(Default)]
struct Sign {
    /// `OpenNonceStreams` has been queued (once, for all devices).
    requested_nonces: bool,
    /// Devices whose `NonceResponse` the coordinator ACCEPTED -- i.e. it emitted
    /// `ReplenishedNonces`, which it only does for a segment that extends a stream
    /// it actually opened.
    replenished: std::collections::BTreeSet<DeviceId>,
    /// `Some` once `start_sign` succeeded; that call is also the real check that
    /// the nonces landed (`StartSignError::NotEnoughNoncesForDevice`).
    session_id: Option<SignSessionId>,
    /// The threshold subset asked to sign -- 2 of the 3, so the run also proves
    /// the third device is not needed.
    signers: std::collections::BTreeSet<DeviceId>,
    got_shares: std::collections::BTreeSet<DeviceId>,
    /// The aggregated signatures, decoded. Set from the coordinator's `Signed`
    /// message; VERIFIED (not merely present) before the pass returns.
    signatures: Option<Vec<Signature>>,
}

/// Refuse to certify a stub binary older than the sources it is built from.
///
/// The harness reports on the binary it spawns, not on the working tree, so a stale
/// artifact makes every claim it prints a claim about code that is no longer there.
/// This is deliberately a REFUSAL and not a warning: a warning in a verification tool
/// is read as noise, and the failure it hides is the one that matters most.
///
/// Compares mtimes against the sources that can change the stub's behaviour -- the
/// firmware lib and bin, the stub itself, and the whole HAL. Anything unreadable is
/// SKIPPED rather than fatal: this must not become a reason a correct run fails.
fn refuse_if_stale(stub: &str) -> Result<()> {
    let built = std::fs::metadata(stub).and_then(|m| m.modified());
    let Ok(built) = built else {
        // No mtime available (an exotic filesystem). Nothing to compare, so say so
        // rather than silently passing -- an unchecked binary is what we just fixed.
        eprintln!("hostcheck: WARNING cannot read stub mtime; freshness UNCHECKED");
        return Ok(());
    };
    let mut newest: Option<(std::time::SystemTime, String)> = None;
    let mut consider = |path: std::path::PathBuf| {
        if path.extension().is_none_or(|x| x != "rs") {
            return;
        }
        if let Ok(m) = std::fs::metadata(&path).and_then(|m| m.modified()) {
            if newest.as_ref().is_none_or(|(t, _)| m > *t) {
                newest = Some((m, path.display().to_string()));
            }
        }
    };
    // Only what the stub is actually BUILT FROM. Scanning all of
    // `firmware/examples/` was wrong and made this refuse forever: a sibling example
    // like `simulator.rs` is not a dependency of the stub, so cargo correctly does not
    // relink the stub when it changes, its mtime stays put, and the check then blocks
    // the harness with nothing to rebuild. Narrow beats loud — an over-strict staleness
    // check that cannot be satisfied gets disabled by whoever hits it next, which costs
    // the real protection.
    for dir in ["../firmware/src", "../hal/src"] {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for e in entries.flatten() {
                consider(e.path());
            }
        }
    }
    consider(std::path::PathBuf::from("../firmware/examples/stub.rs"));
    if let Some((t, which)) = newest {
        if t > built {
            bail!(
                "STALE stub binary at {stub}\n  {which} is newer than the built stub, so \
                 this run would report on code that is not in it.\n  rebuild: cargo build \
                 --target aarch64-apple-darwin -p coldsnap_firmware --example stub"
            );
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let stub = std::env::args().nth(1).unwrap_or_else(|| DEFAULT_STUB.into());
    if !std::path::Path::new(&stub).is_file() {
        bail!(
            "no stub binary at {stub}\n  build it first: cargo build --target \
             aarch64-apple-darwin -p coldsnap_firmware --example stub"
        );
    }
    refuse_if_stale(&stub)?;

    // See WATCHDOG_SLACK. This thread does no I/O, which is the only reason it
    // can outlive a blocked write.
    let t0 = Instant::now();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_millis(100));
        let at = WATCHDOG_AT_MS.load(Ordering::Relaxed);
        if at != 0 && t0.elapsed().as_millis() as u64 > at {
            eprintln!(
                "hostcheck: WATCHDOG at {:?} -- state {}, the loop is stuck OUTSIDE its own \
                 deadline check (a blocked write is the known way that happens)",
                t0.elapsed(),
                NAMES[STATE.load(Ordering::Relaxed)],
            );
            std::process::exit(5);
        }
    });

    // BOTH chunk sizes, every run, and this is not belt-and-braces -- it is the
    // only thing that makes the reassembly claim mean anything.
    //
    // At 64 (the OTG_FS packet size, so the realistic case) the stub's writes
    // COALESCE and the coordinator decodes whole frames from one buffer. At 1 it
    // provably reassembles across reads. So the realistic setting proves the
    // least, and keygen must pass at 1 as well -- that is the reassembly case for
    // frames an order of magnitude bigger than M1's 59-byte Announce.
    for chunk in [64usize, 1] {
        eprintln!("--- pass: STUB_CHUNK={chunk} ---");
        one_pass(&stub, chunk, &t0).with_context(|| format!("pass STUB_CHUNK={chunk}"))?;
    }
    println!(
        "M1+M2+M3+M5 PASS: real {THRESHOLD}-of-{N_DEVICES} keygen, nonce replenishment and a signature that \
         VERIFIES against the group key, across the pty at both chunk sizes, including the \
         1-byte case that forces reassembly"
    );
    Ok(())
}

fn one_pass(stub: &str, chunk: usize, t0: &Instant) -> Result<()> {
    // (master, slave). The master has `port_name: None` and so cannot be
    // reopened by path -- handing it over as the child's stdio is the whole
    // reason this works cross-process.
    let (master, mut slave) = TTYPort::pair().context("TTYPort::pair")?;
    slave.set_timeout(PORT_TIMEOUT).context("set_timeout")?;

    // fd 0 and fd 1 must be separate fds; `Stdio` takes ownership of each.
    // `TTYPort` only offers `IntoRawFd`, so the ownership transfer is manual.
    let wire_in = unsafe { OwnedFd::from_raw_fd(master.into_raw_fd()) };
    let wire_out = wire_in.as_fd().try_clone_to_owned()?;

    let mut cmd = Command::new(stub);
    cmd.env("STUB_CHUNK", chunk.to_string())
        .stdin(Stdio::from(wire_in))
        .stdout(Stdio::from(wire_out))
        .stderr(Stdio::inherit());
    let mut child = cmd.spawn().with_context(|| format!("spawn {stub}"))?;
    // Drop the parent's copies of the master fds NOW, so the stub exiting gives
    // the slave a clean EOF instead of a port that stays open forever.
    drop(cmd);

    // THE WRITE PATH LIVES OVER THERE, on a `dup` of this fd (`F_DUPFD_CLOEXEC`,
    // so the same file description and the same tty output queue -- a blocked
    // write blocks identically, it just blocks a thread nobody is waiting on).
    // From here on `port` is READ-ONLY; see `spawn_writer` on why writing from
    // both would corrupt frames.
    let wtx = spawn_writer(
        slave.try_clone_native().context("dup pty slave for writer")?,
        *t0,
    );
    WRITES_DONE.store(0, Ordering::Relaxed);
    WRITE_BUSY_SINCE_MS.store(0, Ordering::Relaxed);
    *WRITE_ERR.lock().unwrap() = None;

    let mut port: FramedSerialPort<Downstream> =
        FramedSerialPort::new(Box::new(slave) as Box<dyn SerialPort>);

    // No database: `FrostCoordinator::new()` is the whole state machine, and
    // `Persisted`/rusqlite is opt-in (`frostsnap_core/src/coordinator.rs`).
    let mut coordinator = FrostCoordinator::new();
    coordinator.keygen_fingerprint = TEST_FINGERPRINT;
    let mut rng = ChaCha20Rng::from_seed(RNG_SEED);

    let started = Instant::now();
    let mut state = State::WaitingForMagic;
    state.publish();
    WATCHDOG_AT_MS.store(
        (t0.elapsed() + State::SigningAwaitingShares.budget() + WATCHDOG_SLACK).as_millis()
            as u64,
        Ordering::Relaxed,
    );
    let mut last_wrote: Option<Instant> = None;
    let mut magic_writes = 0usize;
    let mut writes_queued = 0usize;
    // Devices that have REPORTED holding the finished access structure, over
    // the wire. `held.len() == N_DEVICES` is the pass condition.
    let mut held: std::collections::BTreeSet<DeviceId> = Default::default();
    let mut requested_held = false;
    let mut read_timeouts = 0usize;
    let mut announced: Vec<DeviceId> = Vec::new();
    // What each device says the keygen session hash is, and which devices refused
    // the forged `DataErase` below. Both arrive as `DeviceSendBody::Debug`, which
    // this loop intercepts and never hands to the `FrostCoordinator` -- so neither
    // can move the protocol along; they can only be compared at PASS.
    let mut device_hashes: std::collections::BTreeMap<DeviceId, String> = Default::default();
    let mut refused_erase: std::collections::BTreeSet<DeviceId> = Default::default();
    let mut lied = false;
    let mut keygen: Option<Keygen> = None;
    let mut sign = Sign::default();
    let mut queue: VecDeque<CoordinatorSend> = VecDeque::new();

    let outcome = loop {
        state.publish();
        if started.elapsed() > state.budget() {
            // The single most important property of this harness: it says where
            // it died. `FramedSerialPort` exposes no byte counter, so the
            // coordinator-side proxies are the magic-write count and whether the
            // port has anything buffered; the stub prints its own counts.
            break Err(anyhow::anyhow!(
                "DEADLINE ({:?}) in state {} -- magic_writes={magic_writes}, \
                 writes_queued={writes_queued}, writes_done={}, \
                 read_timeouts={read_timeouts}, announced={}, shares={}, acks={}, \
                 session_hash={}, held={}, replenished={}, sign_session={}, \
                 sig_shares={}/{}, anything_to_read={}, elapsed={:?}",
                state.budget(),
                state.name(),
                WRITES_DONE.load(Ordering::Relaxed),
                announced.len(),
                keygen.as_ref().map_or(0, |k| k.got_shares),
                keygen.as_ref().map_or(0, |k| k.acks),
                keygen
                    .as_ref()
                    .map_or(false, |k| k.session_hash.is_some()),
                held.len(),
                sign.replenished.len(),
                sign.session_id.is_some(),
                sign.got_shares.len(),
                sign.signers.len(),
                port.anything_to_read(),
                started.elapsed()
            ));
        }

        // THE WRITE-PATH DEADLINE. The writer thread cannot report a stall itself
        // (it is inside the stall), so this reads its published start time. Same
        // shape as the read deadline: checked every lap, and the longest this loop
        // can be away from here is one `PORT_TIMEOUT`, so a blocked write is
        // diagnosed within `WRITE_STALL_LIMIT + PORT_TIMEOUT`.
        if let Some(e) = WRITE_ERR.lock().unwrap().take() {
            break Err(anyhow::anyhow!(
                "writer thread failed in state {}: {e}",
                state.name()
            ));
        }
        let busy = WRITE_BUSY_SINCE_MS.load(Ordering::Relaxed);
        if busy != 0 {
            let blocked = t0
                .elapsed()
                .saturating_sub(Duration::from_millis(busy));
            if blocked > WRITE_STALL_LIMIT {
                break Err(anyhow::anyhow!(
                    "WRITE STALL ({blocked:?} > {WRITE_STALL_LIMIT:?}) in state {} -- frame \
                     {}/{writes_queued} is stuck in raw_send/tcdrain, i.e. the DEVICE has \
                     stopped reading (a pty blocks writes past ~1 KB when the peer does not \
                     drain). magic_writes={magic_writes}, read_timeouts={read_timeouts}, \
                     announced={}, shares={}, acks={}, replenished={}, sig_shares={}, \
                     anything_to_read={}, elapsed={:?}",
                    state.name(),
                    WRITES_DONE.load(Ordering::Relaxed) + 1,
                    announced.len(),
                    keygen.as_ref().map_or(0, |k| k.got_shares),
                    keygen.as_ref().map_or(0, |k| k.acks),
                    sign.replenished.len(),
                    sign.got_shares.len(),
                    port.anything_to_read(),
                    started.elapsed()
                ));
            }
        }

        match state {
            State::WaitingForMagic => match port.read_for_magic_bytes() {
                Ok(Some(features)) => {
                    eprintln!(
                        "hostcheck: got device magic bytes (conch_enabled={}) after {:?}",
                        features.conch_enabled,
                        started.elapsed()
                    );
                    // Device signals version 2 => false. A no-op against the
                    // default; kept because it is what the real driver does.
                    port.set_conch_enabled(features.conch_enabled);
                    state = State::WaitingForAnnounces;
                }
                Ok(None) => {
                    if last_wrote.is_none_or(|t| t.elapsed().as_millis() as u64 > MAGIC_BYTES_PERIOD)
                    {
                        if let Err(e) =
                            send_frame(&wtx, ReceiveSerial::MagicBytes(MagicBytes::default()))
                        {
                            break Err(e.context("write_magic_bytes"));
                        }
                        magic_writes += 1;
                        writes_queued += 1;
                        last_wrote = Some(Instant::now());
                    }
                }
                // `fill_buf` can time out here too (a device that sends 1 byte
                // and stops). Same treatment: next lap, deadline re-checked.
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => read_timeouts += 1,
                Err(e) => {
                    break Err(anyhow::anyhow!(
                        "read_for_magic_bytes in {}: {e}",
                        state.name()
                    ))
                }
            },

            // Everything from here on is the same read: decode a device frame,
            // route it. The only difference between the states is what we are
            // still waiting for, which is what the deadline message needs.
            _ => match port.try_read_message() {
                Ok(Some(ReceiveSerial::Message(msg))) => {
                    let from = msg.from;
                    let body = match msg.body.decode() {
                        Ok(body) => body,
                        Err(e) => {
                            break Err(anyhow::anyhow!(
                                "body.decode() from {from} in {}: {e}",
                                state.name()
                            ))
                        }
                    };
                    match body {
                        DeviceSendBody::Announce { firmware_digest } => {
                            if !announced.contains(&from) {
                                announced.push(from);
                                eprintln!(
                                    "hostcheck: ANNOUNCE {}/{N_DEVICES} from {from} digest \
                                     {firmware_digest} after {:?}",
                                    announced.len(),
                                    started.elapsed()
                                );
                            }
                            let ack = CoordinatorSendMessage::to(
                                from,
                                CoordinatorSendBody::AnnounceAck,
                            );
                            if let Err(e) = send_frame(&wtx, ReceiveSerial::Message(ack.into())) {
                                break Err(e.context("AnnounceAck"));
                            }
                            writes_queued += 1;
                            if announced.len() == N_DEVICES && keygen.is_none() {
                                let begin = BeginKeygen::new(
                                    announced.clone(),
                                    THRESHOLD,
                                    "cold-snap M3".to_string(),
                                    KeyPurpose::Test,
                                    &mut rng,
                                );
                                let id = begin.keygen_id;
                                eprintln!(
                                    "hostcheck: begin_keygen {THRESHOLD}-of-{N_DEVICES} \
                                     (keygen_id {id}) after {:?}",
                                    started.elapsed()
                                );
                                match coordinator.begin_keygen(begin, &mut rng) {
                                    Ok(sends) => queue.extend(sends),
                                    Err(e) => break Err(anyhow::anyhow!("begin_keygen: {e}")),
                                }
                                keygen = Some(Keygen {
                                    id,
                                    got_shares: 0,
                                    acks: 0,
                                    session_hash: None,
                                    finished: None,
                                });
                            }
                        }
                        DeviceSendBody::Core(core) => {
                            // THE DEVICE HALF OF THE PROOF, and the reason this
                            // arm exists. Until 2026-08-18 the device's claim to
                            // have stored a share crossed the process boundary as
                            // one bit -- its exit status -- decided by the same
                            // process the claim is about. A stub that read
                            // `Finalize`, persisted nothing and exited 0 PASSED
                            // (mutation d4). Now the coordinator asks, over the
                            // wire, and compares.
                            if let DeviceToCoordinatorMessage::Restoration(
                                DeviceRestoration::HeldShares2(shares),
                            ) = &core
                            {
                                let want = keygen
                                    .as_ref()
                                    .and_then(|k| k.finished)
                                    .expect("HeldShares2 only requested after finalize");
                                match shares
                                    .iter()
                                    .find(|s| s.access_structure_ref == Some(want))
                                {
                                    Some(s) => {
                                        eprintln!(
                                            "hostcheck: {from} REPORTS holding {want:?} \
                                             (threshold={:?}, {} share(s) total)",
                                            s.threshold,
                                            shares.len()
                                        );
                                        held.insert(from);
                                    }
                                    None => {
                                        break Err(anyhow::anyhow!(
                                            "{from} reported {} held share(s), NONE for the \
                                             access structure keygen just finished ({want:?}) \
                                             -- the device did not store what it acked",
                                            shares.len()
                                        ))
                                    }
                                }
                            }
                            match coordinator.recv_device_message(from, core) {
                                Ok(sends) => queue.extend(sends),
                                Err(e) => {
                                    break Err(anyhow::anyhow!(
                                        "recv_device_message from {from} in {}: {e}",
                                        state.name()
                                    ))
                                }
                            }
                        }
                        // The device's own report of two things the protocol has no
                        // field for: the session hash it computed, and a refusal.
                        // Parsed here rather than forwarded, so the coordinator's
                        // state machine never sees it.
                        DeviceSendBody::Debug { message } => {
                            match message.split_once('=') {
                                Some(("session_hash", value)) => {
                                    eprintln!("hostcheck: {from} says session_hash={value}");
                                    device_hashes.insert(from, value.to_string());
                                }
                                Some(("refused", what)) => {
                                    eprintln!(
                                        "hostcheck: {from} REFUSED {what} (a frame our own \
                                         coordinator never asked for)"
                                    );
                                    if what == "DataErase" {
                                        refused_erase.insert(from);
                                    }
                                }
                                _ => eprintln!("hostcheck: device debug from {from}: {message}"),
                            }
                        }
                        other => eprintln!("hostcheck: ignoring {other:?}"),
                    }
                }
                // Extra device MAGIC_REPLYs decode as MagicBytes once linked;
                // Conch/Reset are not errors either.
                Ok(Some(_)) | Ok(None) => {}
                // A frame that never completes stalls inside bincode for the
                // whole PORT_TIMEOUT and surfaces here as an io DecodeError, not
                // as Ok(None). Swallowing it is what makes the deadline hard: the
                // longest this loop can be away from the deadline check is one
                // PORT_TIMEOUT. NOT a recovery -- the partial frame's bytes are
                // already consumed, so the run will fail; it fails on the
                // deadline, by name, within 250 ms of the stall.
                Err(e) if is_read_timeout(&e) => read_timeouts += 1,
                Err(e) => {
                    break Err(anyhow::anyhow!(
                        "try_read_message in {}: {e}",
                        state.name()
                    ))
                }
            },
        }

        // Drain whatever the coordinator wants to say, then re-derive the state
        // from what it has told the user. Derived in ONE place on purpose: the
        // ordering of `ReceivedShares`/`CheckKeyGen`/`KeyGenAck` is the
        // coordinator's business, not ours.
        if let Some(kg) = keygen.as_mut() {
            if let Err(e) = pump(
                &mut queue,
                &wtx,
                &mut writes_queued,
                &mut coordinator,
                &mut rng,
                kg,
                &mut sign,
            ) {
                break Err(e.context(format!("pump in {}", state.name())));
            }
            state = if kg.finished.is_some() {
                State::KeygenAwaitingDeviceSave
            } else if kg.session_hash.is_some() || kg.acks > 0 {
                State::KeygenAwaitingAcks
            } else if kg.got_shares == N_DEVICES {
                State::KeygenAwaitingSessionHash
            } else {
                State::KeygenAwaitingShares
            };

            // Keygen has finished coordinator-side. Do NOT take the stub's word
            // for the device half: ask each device what it holds and compare.
            // `request_held_shares` is a real protocol message
            // (`CoordinatorRestoration::RequestHeldShares`), so this is a
            // round-trip, not a harness back-channel -- and it exercises
            // `HeldShares2`, one of the four frames the old 2,060 bound refused.
            if let Some(want) = kg.finished {
                if !requested_held {
                    requested_held = true;
                    for id in &announced {
                        queue.extend(coordinator.request_held_shares(*id));
                    }
                    eprintln!(
                        "hostcheck: keygen FINISHED {want:?}; asking {} device(s) what they hold",
                        announced.len()
                    );
                }
                state = State::KeygenAwaitingHeldShares;
            }

            // ============================ M5 ============================
            // Every device has reported the coordinator's own access structure,
            // so keygen is proven at both ends. Now: nonces, then a signature.
            //
            // Nonces FIRST is the protocol's ordering, not a preference:
            // `start_sign` fails outright with `NotEnoughNoncesForDevice` if the
            // cache is empty, so this sequencing is enforced by the coordinator.
            // ==================== THE LYING COORDINATOR ====================
            // A frame the `FrostCoordinator` state machine NEVER produced, pushed
            // through the same seam the `AnnounceAck` above uses
            // (`CoordinatorSendMessage::to` + `send_frame`). No fork of
            // `frostsnap_coordinator` and no byte-patching: upstream's own encoder
            // writes it.
            //
            // `DataErase` is the lie because obeying it destroys the shares the
            // devices JUST reported holding -- so the assertion is two-sided and
            // both sides are load-bearing: every device must report the refusal,
            // AND the signature below must still verify, which it cannot if any
            // device took the frame seriously.
            //
            // Sent here, after `HeldShares2` and before the nonce round trip, so a
            // device that obeyed has already told us it had something to lose.
            if held.len() == N_DEVICES && !lied {
                lied = true;
                let sent = announced.iter().try_for_each(|id| {
                    send_frame(
                        &wtx,
                        ReceiveSerial::Message(
                            CoordinatorSendMessage::to(*id, CoordinatorSendBody::DataErase).into(),
                        ),
                    )
                });
                if let Err(e) = sent {
                    break Err(e.context("forged DataErase"));
                }
                writes_queued += announced.len();
                eprintln!(
                    "hostcheck: FORGED DataErase to {} device(s) -- every one must refuse it \
                     and still be able to sign",
                    announced.len()
                );
            }

            if held.len() == N_DEVICES && !sign.requested_nonces {
                sign.requested_nonces = true;
                let devices: std::collections::BTreeSet<DeviceId> =
                    announced.iter().copied().collect();
                queue.extend(coordinator.maybe_request_nonce_replenishment(
                    &devices,
                    NONCE_STREAMS,
                    &mut rng,
                ));
                eprintln!(
                    "hostcheck: requesting {NONCE_STREAMS} nonce stream(s) from {} device(s) -- \
                     each reply is a ~2,040 B frame, the first over 1 KB to cross this pty",
                    devices.len()
                );
            }

            // Every device replenished => start signing. `start_sign` is itself
            // the assertion that the nonces landed: it reads the nonce cache the
            // `NonceResponse`s filled, and cannot succeed on an empty one.
            if sign.requested_nonces
                && sign.replenished.len() == N_DEVICES
                && sign.session_id.is_none()
            {
                let want = kg
                    .finished
                    .expect("nonces are only requested after finalize");
                // THRESHOLD of N, not all N: signing with a strict subset is what
                // selects the signer subset; at THRESHOLD == N_DEVICES that is everyone.
                sign.signers = announced.iter().copied().take(THRESHOLD as usize).collect();
                match coordinator.start_sign(want, sign_task(), &sign.signers, &mut rng) {
                    Ok(id) => {
                        eprintln!(
                            "hostcheck: start_sign {id} over {SIGN_MESSAGE:?} with {} of \
                             {N_DEVICES} device(s): {:?}",
                            sign.signers.len(),
                            sign.signers
                        );
                        sign.session_id = Some(id);
                        for device in sign.signers.clone() {
                            queue.push_back(CoordinatorSend::from(
                                coordinator.request_device_sign(id, device, ENCRYPTION_KEY),
                            ));
                        }
                    }
                    Err(e) => break Err(anyhow::anyhow!("start_sign: {e}")),
                }
            }

            // The coordinator has aggregated. Verification happens below, OUTSIDE
            // the loop, and the pass hinges on it -- not on getting here.
            if sign.signatures.is_some() {
                break Ok(());
            }
            if sign.session_id.is_some() {
                state = State::SigningAwaitingShares;
            } else if sign.requested_nonces {
                state = State::NonceReplenish;
            }

            // A stub that dies before the run is done is still a failure, and must
            // not be waited on forever. It is only allowed to exit at the very
            // end, when WE close the pty -- which by then has already happened,
            // because the pass breaks out of this loop above.
            if let Ok(Some(status)) = child.try_wait() {
                break Err(anyhow::anyhow!(
                    "stub exited {status} in {} having reported {}/{N_DEVICES} held shares, \
                     {}/{N_DEVICES} nonce replenishments and {}/{} signature shares",
                    state.name(),
                    held.len(),
                    sign.replenished.len(),
                    sign.got_shares.len(),
                    sign.signers.len(),
                ));
            }
        }

        // Publish again before sleeping: `state` may have advanced during this
        // lap, and the watchdog reports ONLY what was last published. MEASURED
        // that this matters: with the publish at the top of the lap only, a
        // stall injected right after the magic->announce transition was reported
        // as `WaitingForMagic` -- one state stale, i.e. the wrong diagnosis.
        state.publish();

        // The read paths return immediately when the port is empty, so without
        // this the loop is a hot spin.
        std::thread::sleep(Duration::from_millis(2));
    };

    WATCHDOG_AT_MS.store(0, Ordering::Relaxed);

    match outcome {
        Ok(()) => {
            let kg = keygen.expect("PASS implies a keygen was started");
            let as_ref = kg.finished.expect("PASS implies finalize_keygen returned");
            let session_hash = kg
                .session_hash
                .expect("PASS implies the user got a session hash to check");

            // ASSERT ON THE COMPLETION VALUE, not on "no error": the ref
            // `finalize_keygen` returned must be in the coordinator's own view,
            // THRESHOLD-of-N_DEVICES, with every device holding a share.
            let found = coordinator
                .iter_access_structures()
                .find(|a| a.access_structure_ref() == as_ref)
                .with_context(|| {
                    format!("{as_ref:?} came out of finalize_keygen but is not in the coordinator")
                })?;
            let devices: Vec<DeviceId> = found.devices().collect();
            if found.threshold() != THRESHOLD || devices.len() != N_DEVICES {
                bail!(
                    "expected {THRESHOLD}-of-{N_DEVICES}, coordinator has {}-of-{}",
                    found.threshold(),
                    devices.len()
                );
            }
            // ============ THE SESSION HASH, COMPARED ACROSS THE PROCESSES ============
            // PLAN.md §9 item 12 says this comparison is manual. It is not any more:
            // the device computed `session_hash` from the transcript IT verified,
            // this process computed its own from coordinator state, and the two
            // copies of `frostsnap_core` are different builds in different
            // processes (upstream via `frostsnap_coordinator` here, vendored in the
            // stub). Upstream's `recv_device_message` already refuses a mismatched
            // `ack_session_hash` -- but that is upstream's check, inside the black
            // box, and a re-vendor that dropped it would fail nothing. This is
            // ours, by name.
            //
            // What it still cannot replace: the HUMAN comparing the 4-byte code
            // against the coordinator app's display. A coordinator that lies about
            // the access structure lies to both sides equally.
            let want = hex(&session_hash.0);
            if device_hashes.len() != N_DEVICES {
                bail!(
                    "only {}/{N_DEVICES} device(s) reported a session hash: {device_hashes:?}",
                    device_hashes.len()
                );
            }
            for (id, got) in &device_hashes {
                if *got != want {
                    bail!(
                        "SESSION HASH MISMATCH: {id} computed {got}, the coordinator computed \
                         {want} -- the device acked a keygen transcript that is not the one \
                         this coordinator built"
                    );
                }
            }

            // ================= THE FORGED DataErase WAS REFUSED =================
            if refused_erase.len() != N_DEVICES {
                bail!(
                    "only {}/{N_DEVICES} device(s) refused the forged DataErase (refused: \
                     {refused_erase:?}) -- a device that neither refused nor died either \
                     obeyed it or dropped it silently",
                    refused_erase.len()
                );
            }

            // ===================== M5: THE SIGNATURE MUST VERIFY =====================
            // The pass hinges on THIS, not on reaching it. Nothing above proves a
            // signature: `Signed` only means the coordinator's aggregator ran. The
            // task is rebuilt from `SIGN_MESSAGE` and the key is read out of the
            // coordinator's own persisted `CompleteKey`, so the only thing supplied
            // by the run is the 64 bytes the two processes produced together.
            let sigs = sign
                .signatures
                .as_ref()
                .expect("PASS implies the coordinator aggregated");
            let key = coordinator
                .get_frost_key(as_ref.key_id)
                .with_context(|| format!("no key {:?} in the coordinator", as_ref.key_id))?;
            let master_appkey = key.complete_key.master_appkey;
            let checked = sign_task()
                .check(master_appkey, key.purpose)
                .map_err(|e| anyhow::anyhow!("sign task does not check against the key: {e:?}"))?;
            // Verify-only: this side holds no secret and must not need one.
            let schnorr = Schnorr::<sha2::Sha256>::verify_only();
            if !checked.verify_final_signatures(&schnorr, sigs) {
                bail!(
                    "SIGNATURE DOES NOT VERIFY: {} sig(s) over {SIGN_MESSAGE:?} against \
                     master_appkey {}",
                    sigs.len(),
                    hex(&master_appkey.0)
                );
            }
            // The key `verify` actually used, recomputed here so the log names the
            // thing that was checked rather than its parent.
            let items = checked.sign_items();
            let derived = items[0]
                .app_tweak
                .derive_xonly_key(&master_appkey.to_xpub());
            if sign.got_shares != sign.signers {
                bail!(
                    "signature verified but shares came from {:?}, not the {:?} we asked",
                    sign.got_shares,
                    sign.signers
                );
            }

            std::io::stderr().flush().ok();
            eprintln!(
                "  pass ok: keygen {} FINISHED in {:?}\n    access_structure_ref = {as_ref:?}\
                 \n    session_hash = {session_hash}\n    threshold {}-of-{}, devices {devices:?}\
                 \n    nonces: {} device(s) replenished {NONCE_STREAMS} stream(s) each\
                 \n    SIGNATURE VERIFIES over {SIGN_MESSAGE:?}\
                 \n      sig    = {}\n      key    = {derived}\
                 \n      appkey = {}\n      signers = {:?} ({} of {N_DEVICES})\
                 \n    device half verified over the wire: {}/{N_DEVICES} HeldShares2 \
                 reports matched our own access structure\
                 \n    session_hash AGREED device<->coordinator on {}/{N_DEVICES} devices \
                 (two processes, two copies of frostsnap_core)\
                 \n    forged DataErase REFUSED by {}/{N_DEVICES} devices, and they still signed\
                 \n    largest coordinator->device frame actually written: {} B \
                 (old FRAME_LIMIT was 2060, so this keygen was previously REFUSED)",
                kg.id,
                started.elapsed(),
                found.threshold(),
                devices.len(),
                sign.replenished.len(),
                hex(&sigs[0].to_bytes()),
                hex(&master_appkey.0),
                sign.signers,
                sign.signers.len(),
                held.len(),
                device_hashes.len(),
                refused_erase.len(),
                MAX_DOWN_B.load(Ordering::Relaxed),
            );
            // Reap on SUCCESS too. This was missing, and the effect was measured:
            // `break Ok(())` above happens before the loop's `try_wait`, so a
            // PASSING run never waited on the child -- both stubs were left
            // orphaned (PPID 1) and still alive tens of seconds later, and none of
            // them ever printed their own PASS line. A harness that leaks a
            // process per run is a harness that will eventually be debugged as
            // "the pty is busy".
            reap(&mut child);
            Ok(())
        }
        Err(e) => {
            reap(&mut child);
            Err(e)
        }
    }
}

/// One drain of the coordinator's outbox.
///
/// `ToDevice` becomes a frame; `ToUser` is auto-accepted, which for keygen means
/// exactly one decision: when the last device has acked the session hash, call
/// `finalize_keygen`. A REAL coordinator shows the session hash to a human first
/// and only finalizes if they confirm it matches every device screen -- that
/// comparison is the defence against a lying coordinator, and it is the step this
/// harness deliberately skips. Drive order mirrors
/// `frostsnap_coordinator/src/keygen.rs` (`process_to_user_message`) and the
/// vendored tier-2 `Env::user_react_to_coordinator`.
fn pump(
    queue: &mut VecDeque<CoordinatorSend>,
    wtx: &Sender<ReceiveSerial<Upstream>>,
    writes_queued: &mut usize,
    coordinator: &mut FrostCoordinator,
    rng: &mut ChaCha20Rng,
    kg: &mut Keygen,
    sign: &mut Sign,
) -> Result<()> {
    while let Some(send) = queue.pop_front() {
        match send {
            CoordinatorSend::ToDevice { .. } => {
                let msg: CoordinatorSendMessage = send
                    .try_into()
                    .map_err(|e: &'static str| anyhow::anyhow!("CoordinatorSend -> wire: {e}"))?;
                let n_dest = match &msg.target_destinations {
                    frostsnap_coordinator::frostsnap_comms::Destination::All => N_DEVICES,
                    frostsnap_coordinator::frostsnap_comms::Destination::Particular(d) => d.len(),
                };
                // The gist names the frame. It bounds WHICH frames are in the
                // writer's queue when it stalls; the exact one is the index in the
                // WRITE STALL message, since acks are queued from the loop too.
                eprintln!("hostcheck: -> {} to {n_dest} device(s)", msg.gist());
                // Hand off, do not wait: the writer thread has it on the wire
                // within microseconds when the stub is reading, and when the stub
                // is NOT reading this is exactly the call that used to park the
                // whole harness inside `tcdrain`.
                send_frame(wtx, ReceiveSerial::Message(msg.into())).context("keygen frame")?;
                *writes_queued += 1;
            }
            CoordinatorSend::ToUser(CoordinatorToUserMessage::KeyGen { keygen_id, inner }) => {
                if keygen_id != kg.id {
                    bail!("keygen_id {keygen_id} is not the one we started ({})", kg.id);
                }
                match inner {
                    CoordinatorToUserKeyGenMessage::ReceivedShares { from } => {
                        kg.got_shares += 1;
                        eprintln!(
                            "hostcheck: shares {}/{N_DEVICES} (from {from})",
                            kg.got_shares
                        );
                    }
                    CoordinatorToUserKeyGenMessage::CheckKeyGen { session_hash } => {
                        eprintln!("hostcheck: session_hash {session_hash} (auto-accepted)");
                        kg.session_hash = Some(session_hash);
                    }
                    CoordinatorToUserKeyGenMessage::KeyGenAck {
                        from,
                        all_acks_received,
                    } => {
                        kg.acks += 1;
                        eprintln!(
                            "hostcheck: keygen ack {}/{N_DEVICES} (from {from}, all={all_acks_received})"
                            , kg.acks
                        );
                        if all_acks_received {
                            let finalized = coordinator
                                .finalize_keygen(kg.id, ENCRYPTION_KEY, rng)
                                .map_err(|e| anyhow::anyhow!("finalize_keygen: {e}"))?;
                            kg.finished = Some(finalized.access_structure_ref);
                            eprintln!(
                                "hostcheck: FINALIZED {:?}",
                                finalized.access_structure_ref
                            );
                            queue.extend(finalized);
                        }
                    }
                }
            }
            // M5. `ReplenishedNonces` is the coordinator's own acceptance of a
            // `NonceResponse`: it is emitted once per FRAME (not per segment),
            // after `check_can_extend` passed for every segment in it, so a device
            // that sent nonces for a stream nobody opened never reaches here --
            // `recv_device_message` errors instead and the run dies there.
            CoordinatorSend::ToUser(CoordinatorToUserMessage::ReplenishedNonces { device_id }) => {
                sign.replenished.insert(device_id);
                eprintln!(
                    "hostcheck: nonces replenished {}/{N_DEVICES} ({device_id}); available now {:?}",
                    sign.replenished.len(),
                    coordinator.nonces_available(device_id),
                );
            }
            CoordinatorSend::ToUser(CoordinatorToUserMessage::Signing(msg)) => match msg {
                CoordinatorToUserSigningMessage::GotShare { from, session_id } => {
                    if Some(session_id) != sign.session_id {
                        bail!("GotShare for session {session_id}, not the one we started");
                    }
                    sign.got_shares.insert(from);
                    eprintln!(
                        "hostcheck: signature share {}/{} (from {from})",
                        sign.got_shares.len(),
                        sign.signers.len()
                    );
                }
                CoordinatorToUserSigningMessage::Signed {
                    signatures,
                    session_id,
                } => {
                    if Some(session_id) != sign.session_id {
                        bail!("Signed for session {session_id}, not the one we started");
                    }
                    // A 64-byte blob that is not a valid signature encoding is a
                    // failure HERE rather than a `false` from `verify` later,
                    // because the two say different things.
                    let sigs: Vec<Signature> = signatures
                        .into_iter()
                        .map(EncodedSignature::into_decoded)
                        .collect::<Option<_>>()
                        .context("coordinator aggregated a 64-byte blob that is not a signature")?;
                    eprintln!(
                        "hostcheck: SIGNED session {session_id} -- {} signature(s), verifying",
                        sigs.len()
                    );
                    sign.signatures = Some(sigs);
                }
            },
            CoordinatorSend::ToUser(other) => eprintln!("hostcheck: ignoring ToUser {other:?}"),
        }
    }
    Ok(())
}

/// Byte arrays print as `[1, 2, ...]` under `Debug`, which is unreadable for a
/// signature. One line beats a dependency.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A failing harness must not leave the stub parked on a pty forever.
fn reap(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}
