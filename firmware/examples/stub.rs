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
//! `ALL_DEVICES` (currently **13**) sessions in this one process, each with its OWN
//! `FakeFlash`, all multiplexed over the one wire and told apart by
//! `Destination` — which is what the real daisy chain does too, so nothing is
//! faked by co-hosting them. `STUB_SESSIONS=1` (with a per-process `STUB_SALT`) is
//! the OTHER shape, the one `tools/app-rig.py` runs: one device per pty, which is
//! the shipping topology. See [`session_count`] and [`salt`]. `N_DEVICES` (currently **12**) of them complete a
//! THRESHOLD-of-N_DEVICES keygen, a nonce replenishment and a signature with the
//! coordinator, and then keep serving so the coordinator can ask each device what it
//! holds.
//!
//! M12 — THE TENTH SESSION IS LEFT BLANK, and the COORDINATOR decides which one: it
//! owns `BeginKeygen`, so it cuts a nine-device roster and the tenth holds nothing at
//! all. This process is not told which, and must not be — it discovers it
//! structurally, as the session with no [`Sheet`] (see [`sheet_read`]), which is the
//! same discipline `advertised_key` follows. That tenth device is then asked to type
//! ANOTHER device's 25 words in off its sheet and consolidate them onto a flash that
//! holds no share.
//!
//! OUR EXIT STATUS IS NOT THE PROOF, and under `hostcheck` it is not even
//! observed: `hostcheck`'s `reap()` SIGKILLs this process once its own
//! verification is done, so the EOF/PASS path below is reached only when this
//! binary is run BY HAND. What the harness passes on is what the COORDINATOR
//! verified for itself — the aggregated signature against its own derived key,
//! and 10/10 `HeldShares2` replies (nine from the keygen, the tenth from M12's blank
//! device after it consolidated). Every `die` here is still a failure, because a
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
//! reset. It is an in-process restart. A PROCESS restart needs the flash to outlive
//! the process: `STUB_FLASH_FILE` (one session per process, the app rig's shape) backs
//! the `FakeFlash` with an image file — see [`FileFlash`] — and `tools/app-rig.py
//! --stub-restart` starts new processes on the same files.
//!
//! NOT evidence about the shipped device. An `examples/` target here compiles
//! `coldsnap_hal` with `fake-flash` AND `test-seam` on; both are BYPASSES. The
//! RNG is the real `rng::Entropy` but seeded through the `test-seam`
//! `mix_sources` constructor from FIXED bytes, so a failure replays exactly. The
//! digest is computed by the shipped `firmware_digest` over a SYNTHETIC image (a
//! host process has no flashed image to hash) — real function, fake input.
//!
//! WRITE-BLOCKING / DEADLOCK, read this before raising n. Every frame leaves here
//! in 64-byte chunks (`STUB_CHUNK` overrides). MEASURED: an undrained pty blocks
//! writes past ~1 KB. `CertifyPlease` is 2,179 B at 9-of-9 and a single-segment
//! `NonceResponse` is 2,040 B, so the coordinator's own write bound is what carries
//! this, not the frame sizes. It works because the traffic is one-directional at
//! those points. What deadlocks is both sides writing >1 KB AT ONCE. Today no
//! exchange does that.
//!
//! Our half of that hazard is now structurally gone rather than merely unexercised:
//! `spawn_reader` drains fd 0 from its own thread, so the pty keeps emptying while
//! the main loop is inside `write_chunked` (which sleeps 1 ms per chunk for the
//! first 64) or inside a keygen. UNTESTED as a claim — no exchange writes >1 KB
//! both ways, so nothing here demonstrates it; what IS demonstrated is the
//! parked-progress property `spawn_reader` exists for. The coordinator's own write
//! path stays bounded by its `WRITE_STALL_LIMIT`, which is its business, not ours.
//!
//! M7 — THE SCRIPTED HUMAN, and it can only answer what the GLASS says. The four
//! restoration flows (`DisplayBackup`, `CheckBackup`, `EnterPhysicalBackup` +
//! `SavePhysicalBackup2`, `Consolidate`) are driven here by a walk that reads its own
//! framebuffer back with the shipped `ui::Frame::cell` and presses only keys the
//! footer advertises:
//!
//!  - the reveal pages with `ui::NEXT_KEY`, checking each page's footer offers it, and
//!    recovers all 25 words plus the share index from the pixels into [`Sheet`] — this
//!    process's stand-in for the sheet of paper a human writes them on;
//!  - the check quiz is answered from [`Sheet`] and NOTHING else. [`quiz_answer`] is
//!    handed no `quiz::Quiz`, no `quiz::Screen` and no option list; it reads the
//!    position off row 0 and the three candidates off rows 2/4/6;
//!  - the letter picker is driven by [`entry_press`], which reads the prefix, the
//!    candidate letters and the ruler of keys above them off the pixels. **The
//!    candidate letters are a function of the secret prefix**, so a script that did
//!    not read this screen could not type a word at all;
//!  - all four consent screens are answered by [`advertised_key`] on the randomised
//!    digit `consent_screen` printed, which `COLDSNAP_GLASS_KEYS=yy9` demonstrates is
//!    structural rather than decorative.
//!
//! [`Sheet`] holds a PLAINTEXT share in a harness variable. Deliberate — a human holds
//! one too — and it reaches no flash, no signer and no wire body but the `Debug`
//! back-channel `hostcheck` intercepts and compares against its own
//! `expected_share_image`.
//!
//! Run it via the harness, not by hand:
//!   cargo build --target aarch64-apple-darwin -p coldsnap_firmware --example stub
//!   (then `hostcheck` spawns the built artifact)

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::Duration;

use coldsnap_firmware::{
    erase_screen, firmware_digest, prompt_screen_at, quiz, wordentry, Checked, DebugFlash, Fault,
    Outbox, Session, Shown, Typed,
};
use coldsnap_hal::comms::{decode_body, CoordinatorSendBody, Link, MAGIC_REPLY};
use coldsnap_hal::flash::fake::FakeFlash;
use coldsnap_hal::flash::{FlashError, ERASE_SIZE};
use embedded_storage::nor_flash::{ErrorType, NorFlash, ReadNorFlash};
use coldsnap_hal::rng::{mix_sources, Entropy, ProvenSeed, SE1_BYTES, SE2_BYTES, TRNG_BYTES};
use coldsnap_hal::{erase, identity, memmap, ui};
use frostsnap_comms::{DeviceSendBody, ReceiveSerial, Upstream};
use frostsnap_core::device::{restoration::ToUserRestoration, DeviceToUserMessage};
use frostsnap_core::schnorr_fun::frost::Fingerprint;
use frostsnap_core::{AccessStructureRef, DeviceId};

/// The KEYGEN ROSTER, matching `hostcheck`'s N_DEVICES; the coordinator learns the
/// ids from our Announces, so only the count has to agree.
///
/// This process does NOT know which sessions are in the roster and must not: the
/// coordinator owns `BeginKeygen` and therefore owns that choice. What this file uses
/// the number for is the count of sessions that must have STAGED a share, which is a
/// fact it observes rather than one it arranges.
const N_DEVICES: usize = 12;

/// Sessions this process hosts, matching `hostcheck`'s ALL_DEVICES. The LAST one is left
/// out of the keygen BY THE COORDINATOR (M12), so it reaches the signature holding
/// nothing; we discover which one that is structurally — it is the session with no
/// [`Sheet`] and no staged `SaveShare` — exactly as `advertised_key` discovers the
/// access structure rather than being told it.
const ALL_DEVICES: usize = N_DEVICES + 1;

/// One flash per device, at the shipped geometry. `DebugFlash` is only the
/// `core::fmt::Debug` shim `FrostSigner::new` demands — see its doc in the lib.
type Flash = DebugFlash<FileFlash>;

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
/// How many prompts the consent closure DECLINED. Global for the same reason
/// `SIG_ACKS` is, and read by the main loop's fail-closed check.
static DECLINES: AtomicUsize = AtomicUsize::new(0);

/// FAULT INJECTION, OFF by default (`STUB_LOSE_FIRST_SHARE`): the FIRST signature reply
/// this process produces is signed by the real core -- consent taken, nonce consumed,
/// signing state written to flash -- and then dropped instead of written to the wire, as
/// a cable pulled between the device signing and the coordinator reading would. What it
/// exists to drive is the core's at-most-once rule (`device_nonces.rs`: a re-sent request
/// for the same session is answered from the flash cache with no new nonce; a lower
/// index is `IndexUsed`). The app rig then replugs the device and re-sends the request;
/// a device that signed again from a fresh nonce would produce a share the coordinator
/// cannot combine, or die on `IndexUsed`. Only the loss is simulated; the re-send, the
/// cache and the verification are all real.
fn lose_first_share() -> bool {
    std::env::var_os("STUB_LOSE_FIRST_SHARE").is_some()
}
static SHARE_LOST: AtomicBool = AtomicBool::new(false);

/// LONGER than the harness's own budget on purpose, and that is load-bearing.
/// `hostcheck` owns the budget and kills us itself; this watchdog only exists so
/// a stub run BY HAND cannot hang forever. If it fires during a `hostcheck` run,
/// the news is that the harness's bound is broken.
///
/// 240 s: a 9-of-9 certpedpop keygen is real elliptic-curve work in a DEBUG build,
/// nine signers deep — M12's tenth device is NOT in the keygen, so nothing about the
/// keygen's cost moved when it was added — and at `STUB_CHUNK=1` every byte of every frame costs a
/// syscall. The harness's own cumulative budget is now 95 s — handshake 5 s + keygen
/// 30 s + signing 30 s + the M7 restoration phase's 30 s — so this is ~2.5x its
/// bound, deliberately, so that when both fire it is the harness's message you read.
///
/// It was 90 s against a 65 s harness bound until the restoration phase landed. That
/// ratio is the whole contract of this constant, so adding a phase to `hostcheck`
/// without moving this number would have put the stub in charge of killing a slow run
/// and thrown away the diagnosis.
///
/// SCALED by [`timeout_scale`], and that is why it is not used raw: `hostcheck`
/// scales its budgets by the same variable, so leaving this fixed would invert the
/// ~2.5x relationship above the first time a human took ten seconds per screen —
/// the stub would kill the run and the harness's diagnosis would never print.
const DEADLINE: Duration = Duration::from_secs(240);

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

/// Whether to re-announce when the coordinator asks for magic bytes on an already-linked
/// wire (`STUB_REANNOUNCE`, OFF by default). See the call site for what it is for and why
/// `hostcheck` must not have it.
fn reannounce() -> bool {
    std::env::var_os("STUB_REANNOUNCE").is_some()
}

/// Which fingerprint this process's devices CHECK (`STUB_FINGERPRINT`, `test` by default
/// — `hostcheck`'s value and every existing measurement's — or `frost-v0`).
///
/// LOAD-BEARING FOR THE APP RIG, and it was a silent 1-in-16 lottery until 2026-09-22.
/// The check is not symmetric with the grind: the COORDINATOR grinds coefficients to
/// satisfy its own `keygen_fingerprint`, and the device then requires its own. `hostcheck`
/// sets [`TEST_FINGERPRINT`] on both sides, so they agree. The real Flutter app's
/// coordinator uses the shipped `Fingerprint::FROST_V0` — different tag, so a completely
/// different hash — and against `TEST_FINGERPRINT`'s 2 bits per coefficient (capped at 6)
/// a 2-of-3 keygen then passed the device's check only by accident, about one run in
/// sixteen. MEASURED: two app-rig keygens passed and the third died with
/// `InvalidMessage { kind: "KeyGen", reason: "key generation did not match the
/// fingerprint" }` with no source change between them.
///
/// The grind is the coordinator's cost, not the device's — `check_fingerprint` is one
/// hash per coefficient — so a device checking `FROST_V0` costs this process nothing.
fn keygen_fingerprint() -> Fingerprint {
    let want = std::env::var("STUB_FINGERPRINT").unwrap_or_else(|_| "test".into());
    match want.as_str() {
        "test" => TEST_FINGERPRINT,
        "frost-v0" => Fingerprint::FROST_V0,
        // NOT a silent default: the wrong answer here is a keygen that fails 15 times
        // out of 16 with a message about coefficients.
        other => die(
            2,
            &format!("STUB_FINGERPRINT={other:?} is not `test` or `frost-v0`"),
        ),
    }
}

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

/// Multiplies this process's watchdog AND every budget in `hostcheck`
/// (`COLDSNAP_TIMEOUT_SCALE`, default **1** — the automated gate is unchanged).
///
/// ONE factor, read by both processes, because they are one clock: `hostcheck`
/// spawns us, so we inherit whatever it was given, and [`DEADLINE`]'s whole
/// contract is being ~2.5x the harness's bound. It exists for the window, where a
/// human takes seconds per screen and there are 18 consent prompts back to back;
/// no fixed budget covers both that and two debug builds talking to each other
/// (LIVE-GLASS-PLAN §10).
///
/// `filter(|&n| n > 0)`: a 0 would make the watchdog fire instantly, i.e. a typo
/// would look like a device fault.
fn timeout_scale() -> u32 {
    std::env::var("COLDSNAP_TIMEOUT_SCALE")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(1)
}

/// The SCRIPTED KEY SOURCE: what to press at each consent screen
/// (`COLDSNAP_GLASS_KEYS`, default `yyy`, i.e. exactly today's behaviour).
///
/// Three characters, `<CheckKeyGen><SignatureRequest><Restoration>`:
///  - `y` — press whatever the GLASS advertises, read back out of the rendered
///    pixels by [`advertised_key`]. The ONLY way to answer ANY of the three
///    correctly, because every one of them now prints a randomised digit — the
///    keygen check joined them on 2026-09-11.
///  - anything else — press THAT byte, whatever the screen says. `x` declines; `9`
///    is a wrong digit (not in `ui::CONFIRM_CHARSET`, so it is *always* a
///    refusal), which is how a hardcoded-key script is demonstrated to fail.
///
/// A missing character is `y`, so `COLDSNAP_GLASS_KEYS=y` also means "approve
/// everything", and the old two-character form still means what it used to.
///
/// KEYED BY PROMPT KIND, not positional, and that is deliberate: `N_DEVICES`
/// devices produce 2xN interleaved prompts, so a positional list would encode the
/// device count in an env var and start answering the wrong screen the moment n
/// changed. There are three consent-screen KINDS, so three characters is the whole
/// vocabulary.
///
/// The THIRD slot covers all four M7 restoration screens together — reveal, check
/// quiz, ingest, consolidation — and not one each, for that same reason: they are one
/// class (`consent_screen`'s randomised legend, [`approved`]'s
/// `digit.accepts(key)` arm), and `COLDSNAP_GLASS_KEYS=yy9` is what shows the class is
/// structural. `9` is never in `ui::CONFIRM_CHARSET`, so a script that pressed a
/// hardcoded key at a reveal declines, and a decline the run did not declare is a
/// nonzero exit. That is the whole demonstration; a slot per screen would buy four
/// identical ones.
///
/// # The FIRST slot became a real demonstration on 2026-09-11
///
/// `ui::keygen_check` printed a fixed `1=match x=no` until then, and [`approved`]'s
/// keygen arm compared `key == b'1'`. So `COLDSNAP_GLASS_KEYS=1yy` **passed**: the
/// anti-MITM screen was the one consent screen in this tree a hardcoded script could
/// clear, which is precisely backwards, because it is the screen whose whole purpose
/// is that a human read four bytes off it and compared them aloud on every device.
/// That screen now prints a randomised digit like all the others, so `1yy` fails and
/// `=9yy` fails — `9` is never in the charset, and `1` is the drawn digit on at most
/// one device in five, so over `N_DEVICES` devices a literal cannot carry a run.
///
/// LIVE-GLASS-PLAN §6 wrote this as `COLDSNAP_GLASS_KEYS=11`. That is no longer
/// expressible and the reason is the point of the whole step: with a randomised
/// digit there IS no fixed byte that authorises anything on this device. `y` is what
/// "press the confirm key" has to mean now, and it can only be answered by reading
/// the screen.
fn glass_keys() -> String {
    std::env::var("COLDSNAP_GLASS_KEYS").unwrap_or_else(|_| "yyy".into())
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
///
/// Task 08: what each device answers its Nth ERASE question with, one byte per
/// question, PER DEVICE (so `xy` declines every device's first `DataErase` and
/// approves its second). `y` presses what the glass advertises. Fix 2a: `p`, `c`, `a`
/// and `f` press it too and then CUT POWER mid-erase, at one point each: `p` before
/// the marker commits (every program refused: the device keeps its id and share);
/// `c` after the commit and one share sector (no ack); `a` after deletion with
/// `EraseConfirmed` still in RAM, lost unwritten; `f` in `finish`, after the ack was
/// written. The device then stays off until a replug reboots it into
/// `erase::recover`. Anything else is that literal key, and a missing byte is `x`.
/// DEFAULT `x`: a run that does not ask for an erase never gets one, whatever a
/// coordinator sends.
fn erase_keys() -> String {
    std::env::var("STUB_ERASE_KEYS").unwrap_or_else(|_| "x".into())
}

/// What [`drive`] did about an erase question, for `main` to act on.
#[derive(PartialEq, Eq)]
enum EraseOutcome {
    NotAsked,
    Declined,
    /// `Session::erase` returned `Ok`: data verified blank, `EraseConfirmed` pushed
    /// under the old id. The session is poisoned; `main` must rebuild it from flash.
    Erased,
    /// `p`/`c`/`a`/`f`: approved, then a power cut (see [`erase_keys`]). `main`
    /// powers it OFF (drops the session; it answers nothing) until the next replug.
    /// `committed`: the marker is `Pending`, so that boot's `erase::recover` finishes
    /// the erase and the ack it owes goes out under the old id before the fresh
    /// announce; otherwise the same device boots back, share intact.
    Interrupted { committed: bool },
}

/// `(programs, erases)` on every flash, for the "a no writes nothing" check.
fn flash_counters(flashes: &[RefCell<Flash>]) -> Vec<(u32, u32)> {
    flashes
        .iter()
        .map(|f| (f.borrow().0.programs, f.borrow().0.erases))
        .collect()
}

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

/// One fd-0 read. `Ok(bytes)` non-empty is wire traffic, `Ok(bytes)` EMPTY is EOF
/// (`read` returning 0), `Err` is the read error the old inline `match` reported by
/// name. It is an `io::Result` rather than a bespoke enum because `read` already
/// models all three and `io::Error` is `Send`.
type WireEv = std::io::Result<Vec<u8>>;

/// fd 0 in its own thread, feeding ONE channel. The main loop then consumes it with
/// a `recv_timeout`, which is the whole point.
///
/// WHY, and it is a deadlock rather than a tidiness argument. The old loop blocked
/// in `read(fd 0)`, so the ONLY thing that could ever wake it was a byte from the
/// coordinator. Any work the loop still owes that the coordinator is *waiting for*
/// therefore never happens — the loop is parked on the wrong fd. The comment on the
/// deferred-`hello` hazard further down describes exactly that shape ("the
/// coordinator stops writing magic bytes the moment it reads our reply, so deferring
/// to the next loop iteration would park us in `read()` waiting for a byte it will
/// never send"), and MUTATION-VERIFIED: defer that write by one lap and a blocking
/// consumer hangs the pass while a `recv_timeout` consumer still passes.
///
/// Live glass needs that property for a second reason: a prompt parked on a human
/// keypress arrives on a channel that is not fd 0, and a loop blocked on fd 0 can
/// never observe it. This step lands the threading alone, with no consent change and
/// no key channel, so that a regression here is unambiguous.
///
/// Same shape as `hostcheck`'s own `spawn_writer` — one thread, one unbounded
/// `mpsc` — deliberately, so this process has one concurrency model and not two.
/// Unbounded is not sloppy here: the sender is the coordinator, whose traffic is
/// already bounded by its own budgets, and a bounded queue would have to block the
/// reader, which is the thing being removed.
fn spawn_reader() -> Receiver<WireEv> {
    let (tx, rx) = std::sync::mpsc::channel::<WireEv>();
    std::thread::spawn(move || {
        // 512 B and one allocation per read, exactly the old inline buffer's size.
        // `Link` reassembles across reads, so read granularity was never load-bearing.
        let mut wire_in = std::io::stdin().lock();
        let mut buf = [0u8; 512];
        loop {
            let ev: WireEv = wire_in.read(&mut buf).map(|n| buf[..n].to_vec());
            // Stop after EOF or an error: `read` on a closed fd returns `Ok(0)`
            // forever, and looping on that would spin a core and flood the channel.
            let last = !matches!(&ev, Ok(bytes) if !bytes.is_empty());
            if tx.send(ev).is_err() || last {
                return;
            }
        }
    });
    rx
}

/// How long the main loop waits for wire bytes before doing another lap.
///
/// It adds ZERO latency to the automated path: `recv_timeout` returns the instant a
/// message lands, so this bounds only how long an IDLE loop sleeps. The numbers it
/// has to stay clear of are all `hostcheck`'s, and it is three orders of magnitude
/// under the smallest: `PORT_TIMEOUT` 250 ms, `WRITE_STALL_LIMIT` 5 s,
/// `HANDSHAKE_DEADLINE` 5 s, then cumulative budgets of 35 s (handshake + keygen)
/// and 65 s (+ signing), with a once-per-pass watchdog at 67 s
/// (`65 s + WATCHDOG_SLACK`). 2 ms matches the coordinator's own poll lap, so
/// neither side idles finer than the other. Step 6 scales the harness's budgets for
/// human latency; nothing here needs scaling, because a longer park costs laps, not
/// deadline.
const WIRE_POLL: Duration = Duration::from_millis(2);

/// How many prompts this run EXPECTS the consent closure to decline
/// (`STUB_EXPECT_DECLINES`, default **0**).
///
/// FAIL CLOSED, and that default is the whole point. A refusal has NO protocol
/// message (see [`decline`]), so all a decline can ever look like from outside is
/// a `Debug{declined=...}` line plus silence where a signature share would have
/// been — which is also exactly what a device that declines EVERYTHING looks
/// like. Default 0 therefore makes any unexpected decline a nonzero exit, and a
/// run that WANTS declines has to say how many (LIVE-GLASS-PLAN §10).
fn expect_declines() -> usize {
    std::env::var("STUB_EXPECT_DECLINES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0)
}

/// How many flash-backed sessions this process hosts (`STUB_SESSIONS`, default
/// [`ALL_DEVICES`] — `hostcheck`'s shape, unchanged).
///
/// The APP RIG (`tools/app-rig.py`) needs the other shape: the shipping topology is
/// one port per device (the conch is off on this board, so every cold-snap device is
/// a leaf), so the rig runs N processes of `STUB_SESSIONS=1` on N ptys and the real
/// coordinator sees N port state machines. `hostcheck`'s one-pty/13-session shape is
/// a convenience, not the shipping topology (HARNESS-PLAN §2), and both have to be
/// runnable from one binary or the app rig would be testing a second stub.
///
/// Only the COUNT is read here. Which sessions end up in a keygen is still the
/// coordinator's choice, observed rather than arranged — see [`N_DEVICES`].
fn session_count() -> usize {
    std::env::var("STUB_SESSIONS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(ALL_DEVICES)
}

/// The entropy salt for THIS PROCESS (`STUB_SALT`, decimal or `0x`-prefixed,
/// default `0x5a` — the value every existing measurement was taken at).
///
/// LOAD-BEARING FOR THE APP RIG, not cosmetic. [`entropy`] is deterministic, so two
/// processes run at the same salt derive the same keypair from
/// `identity::load_or_create` and announce the SAME `DeviceId`. [`open_sessions`]
/// only catches that WITHIN one process; across processes the coordinator would see
/// one device where the rig launched several. `tools/app-rig.py` gives each child a
/// distinct salt and then checks the announced ids are distinct, because a collision
/// here looks like a topology bug three layers up.
fn salt() -> u8 {
    let Ok(raw) = std::env::var("STUB_SALT") else {
        return 0x5a;
    };
    let parsed = match raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        Some(hex) => u8::from_str_radix(hex, 16),
        None => raw.parse::<u8>(),
    };
    match parsed {
        Ok(salt) => salt,
        // NOT a silent default: a typo'd salt would mean duplicate identities, which
        // is the one failure this variable exists to prevent.
        Err(e) => die(2, &format!("STUB_SALT={raw:?} is not a u8: {e}")),
    }
}

/// Which boot of this device's flash this process is (`STUB_BOOT`, default 0). See
/// [`entropy`].
fn boot() -> u8 {
    match std::env::var("STUB_BOOT") {
        Err(_) => 0,
        Ok(raw) => raw
            .parse()
            .unwrap_or_else(|e| die(2, &format!("STUB_BOOT={raw:?} is not a u8: {e}"))),
    }
}

/// The consent seam, and the only one: ONE closure threaded through [`drive`],
/// answering with **the key byte** a human would press after looking at `frame`.
///
/// WHY A KEY BYTE, when LIVE-GLASS-PLAN §4 drew this as
/// `&mut dyn FnMut(&DeviceToUserMessage) -> bool`. Step 0 landed after that was
/// written and made the digit that authorises a signature RANDOM
/// (`ui::ConfirmDigit`, charset `12346`, copied from Coldcard's `hsm_ux.py:58`),
/// so "did the user approve" is no longer answerable without the digit — and a
/// closure that is TOLD the digit can approve without ever looking at the screen,
/// which is the one shortcut this whole gate exists to forbid. So the closure is
/// handed the rendered [`ui::Frame`] and nothing else: its only route to the digit
/// is the pixels. That is what makes the glass assertion structural instead of
/// additional.
///
/// The other half of the shape is that [`approved`] — not the closure — calls
/// [`ui::ConfirmDigit::accepts`]. The fail-closed rule then lives at ONE place for
/// all three closures that will exist (this stub's, the window's, the script's)
/// rather than being re-implemented, and got subtly wrong, in each; and the
/// window's closure needs no `ui` knowledge at all, just "write 1,024 bytes, read
/// one back".
type Consent<'a> = &'a mut dyn FnMut(&DeviceToUserMessage, &ui::Frame) -> u8;

/// `"Press ("` — the fixed part of the legend `ui::press_legend` composes, and the
/// anchor [`advertised_key`] finds the digit by.
const PRESS: &[u8] = b"Press (";

/// The key the LAST ROW of `frame` advertises as its yes: the digit inside
/// `Press (n)`. `None` when the screen advertises no yes key at all — which is a
/// screen nothing may consent to.
///
/// This reads the digit **off the pixels**, and it is the cheapest always-approve
/// closure that can exist rather than an early down-payment on step 4: with a
/// randomised digit there IS no fixed byte that authorises a signature, so any
/// approving closure has to read the screen. `ui::Frame::cell` is the reverse
/// glyph lookup that already ships (`hal/src/ui.rs`) and requires a byte-for-byte
/// font match, so nothing here re-implements the font — an independent second
/// copy of that mapping would be a second thing to keep in sync.
///
/// # There is now ONE consent legend, and the second recognizer below is unreached
///
/// Every consent screen in `hal::ui` composes its footer from the one private
/// `press_legend`, so the `Press (n) x=no` branch is the only branch that fires
/// today. It was two forms until 2026-09-11: `keygen_check` printed a fixed
/// `1=match x=no`, and the `<key>=<what>` branch below existed FOR it.
///
/// **The `<key>=<what>` branch is KEPT, deliberately, and it is not dead
/// scaffolding.** It is the recognizer four legends in `hal/src/ui.rs` are shaped to
/// avoid — `NEXT_LEGEND` (`(9)next`, not `9=next`), `BACKUP_NEXT_LEGEND`,
/// `BACKUP_BACK_LEGEND` and `PIN_FOOTER` — with the reason spelled out at each of
/// them and enforced by a named test,
/// `no_screen_that_authorises_nothing_advertises_a_consent_key_to_the_stub_scraper`
/// (RENAMED from `no_pin_screen_advertises_a_consent_key_to_the_stub_scraper` by 74d9bcb,
/// when address verification joined the screens it covers; this citation named the old
/// name until 2026-09-13). Those decisions are
/// live: retiring the recognizer would silently retire their reason, and the next
/// person to write `9=next` on a page that cannot consent would have nothing telling
/// them not to. It costs three lines and cannot fail open — a screen it matched by
/// mistake yields a key `ConfirmDigit::accepts` refuses, i.e. a decline, i.e. a
/// failed run.
///
/// It also cannot re-open the hole it used to serve. If `keygen_check` ever went
/// back to `1=match`, this would find `1` and [`approved`] would hand it to
/// `digit.accepts`, which is true for one drawn digit in five per device — so a
/// nine-device `hostcheck` run fails at 1 - 5^-9. The fixed legend is refused by the
/// acceptance rule now, not by the scraper.
fn advertised_key(frame: &ui::Frame) -> Option<u8> {
    let row: Vec<u8> = (0..ui::COLS)
        .map(|col| frame.cell(col, ui::ROWS - 1).map_or(b' ', |(ch, _)| ch))
        .collect();
    if let Some(i) = row.windows(PRESS.len()).position(|w| w == PRESS) {
        return row.get(i + PRESS.len()).copied();
    }
    // `<key>=<what it does>`, the plain-press legend. UNREACHED since `keygen_check`
    // started printing a `ConfirmDigit`; kept because it is the shape four `hal::ui`
    // legends are deliberately NOT written in. See the doc above.
    if row.get(1) == Some(&b'=') {
        return row.first().copied();
    }
    None
}

/// The most pages [`approved`] will advance through before calling the page set
/// broken. `hal::ui::SignPages` is `recipients * 2 + high_fee + 2`, so `MAX_RECIPIENTS`
/// (32) tops out at 67; this is past every set the declared envelope admits, so
/// reaching it means the set does not terminate rather than that a transaction was
/// large. Bounded because an unbounded page walk is a hang, and a hang is
/// indistinguishable from a device that stopped answering.
const PAGE_CAP: usize = 256;

/// Every row of `frame`, read back through the shipped reverse glyph lookup, on
/// stderr — WHAT WAS ACTUALLY ON THE GLASS when this process consented.
///
/// THE ASSERTION CHANNEL FOR "check the displayed recipients/address/amounts against
/// the transaction being signed". The app rig cannot see a screen; it can read this
/// process's stderr, which the rig captures per device (`device-N.log`), so the
/// comparison the app-side test makes is against the RENDERED PIXELS and not against
/// anything the coordinator told the device. `ui::Frame::cell` is the shipped inverse
/// of the font (byte-for-byte match), the same lookup [`glass_code`] and [`row_text`]
/// use — nothing here re-implements the font.
///
/// A cell whose pixels are not a glyph is `?` rather than dropped: `mark_sensitive`
/// noise and a half-drawn cell must both be visible as unreadable instead of closing
/// up into a shorter string that might still match.
///
/// OFF unless `STUB_GLASS_LOG` is set, because `hostcheck` runs 13 sessions x 4 passes
/// through here on an inherited stderr and its output is read by a human.
fn log_glass(frame: &ui::Frame, page: usize, last: bool) {
    if std::env::var_os("STUB_GLASS_LOG").is_none() {
        return;
    }
    for row in 0..ui::ROWS {
        let text: String = (0..ui::COLS)
            .map(|col| char::from(frame.cell(col, row).map_or(b'?', |(ch, _)| ch)))
            .collect();
        let text = text.trim_end();
        if !text.is_empty() {
            eprintln!(
                "stub: glass page {page}{} row {row}: {text}",
                if last { " (last)" } else { "" }
            );
        }
    }
}

/// The four bytes the KEYGEN CHECK screen actually **drew**, read back off the
/// glass as 8 lowercase hex characters. `None` if those pixels are not eight
/// doubled font glyphs.
///
/// THE OPEN HALF OF PLAN.md §9 item 12. The session hash is already compared
/// core-to-core across the two processes (`hostcheck` bails `SESSION HASH
/// MISMATCH`); nothing until now asserted that the code on the SCREEN is that
/// value. Those four bytes are the entire anti-MITM defence, because they are what
/// a human reads aloud — a device that verified the right transcript and then drew
/// the wrong code passed every existing check.
///
/// `ui::Frame::cell_2x` is the shipping inverse of `text_2x` (one glyph per call,
/// `col` stepped by 2, byte-for-byte font match), so nothing here re-derives the
/// doubling; `ui::keygen_check` draws the high half at `((COLS - 8) / 2, 2)` and
/// the low half two rows down. `?` rather than `filter_map`, because a short read
/// must be a FAILURE and not a shorter string that might still prefix-match.
fn glass_code(frame: &ui::Frame) -> Option<String> {
    let base = (ui::COLS - 8) / 2;
    let mut code = String::new();
    for row in [2usize, 4] {
        for i in 0..4 {
            code.push(frame.cell_2x(base + i * 2, row)? as char);
        }
    }
    Some(code)
}

// ===========================================================================
// M7 — the restoration flows, driven OFF THE PIXELS
// ===========================================================================

/// One device's reveal as this process read it **off the glass**: the share index
/// page 0 drew, and the 25 words the word pages drew, each recovered cell by cell
/// with the shipped `ui::Frame::cell`.
///
/// This is the sheet of paper a human writes a reveal down on, and it is the whole
/// point of the M7b -> M7c -> M7d chain: the check quiz is answered from here and the
/// letter picker is driven from here, so nothing downstream ever asks `Session` which
/// candidate is right or which letter comes next. A plaintext share in a harness
/// variable, deliberately — a human holds one too — and it reaches no flash, no
/// signer and no wire body except the `Debug` back-channel `hostcheck` intercepts
/// before the `FrostCoordinator` state machine and compares against its own
/// `expected_share_image`.
#[derive(Default)]
struct Sheet {
    /// What page 0 of the reveal printed as `#N`. Public: it is on the
    /// coordinator's own screen and `ui::BackupPages` does not even noise it.
    index: Option<u32>,
    /// 1-based position -> the word drawn at it.
    words: BTreeMap<usize, String>,
}

/// The sheet a device is READING, which is not always the sheet it wrote.
///
/// M12: the blank device has no reveal of its own — it holds no share, so upstream
/// refuses `DisplayBackup` for it coordinator-side — and yet it is asked to type 25
/// words back in. Those words come from ANOTHER device's reveal, which is the whole
/// point: a human carries a sheet of paper from one unit to another. This is that
/// handoff, and it is a lookup rather than an argument threaded through `drive`
/// because `drive` is per-message and the sheet outlives the message.
///
/// `die`s rather than defaulting, in BOTH directions, and neither arm is decoration:
///  - ZERO sheets means the reveal walk never ran or never filled one. A default
///    `Sheet` would reach `type_backup`, whose `sheet.index.unwrap_or_else` dies with
///    `no share index was ever read off a reveal page` — a message that names the
///    symptom and points a reader at the reveal instead of at this plumbing.
///  - TWO OR MORE is the one that matters. With two reveals in the room there is no
///    rule saying which sheet the blank device is retyping, and picking one silently
///    is how a harness starts asserting about the wrong share. If a second reveal
///    ever lands here, the rule has to be written down, not guessed.
fn sheet_read(paper: &BTreeMap<DeviceId, Sheet>, id: DeviceId) -> &Sheet {
    if let Some(own) = paper.get(&id) {
        return own;
    }
    match paper.len() {
        1 => paper.values().next().expect("just matched len 1"),
        0 => die(
            2,
            &format!(
                "{id} was asked to read a reveal back and there is NO sheet in the room: no \
                 device has walked its reveal pages, so there is nothing to type"
            ),
        ),
        // CANNOT FIRE IN THIS TREE and is a refusal rather than an assert for exactly
        // that reason: only one device ever reaches `Grant::Reveal`, so `paper` never
        // holds two. It is what stops a SECOND reveal being added without writing down
        // the rule. MEASURED by forcing the discriminant to `paper.len() + 1`: `stub:
        // FAIL ... it has none of its own, but there are 2 sheets in the room`, exit 2.
        _ => die(
            2,
            &format!(
                "{id} was asked to read a reveal back and it has none of its own, but these \
                 devices have sheets ({:?}) -- with more than one there is no rule for which it \
                 retypes, and picking one silently would assert about the wrong share",
                paper.keys().collect::<Vec<_>>()
            ),
        ),
    }
}

/// Where a [`Sheet`] is carried BETWEEN PROCESSES (`STUB_SHEET_DIR`), which is the
/// one thing the app rig needs and `hostcheck` does not.
///
/// `hostcheck` hosts every session in ONE process, so the sheet M7b's reveal fills is
/// in the same `paper` map M7d's letter picker reads. The app rig runs one session per
/// process (the shipping topology — N ports, N devices), so the revealing device and
/// the blank device are different OS processes and `paper` cannot possibly be shared.
/// A FILE IS THE HONEST MODEL OF THAT: it is a human carrying a sheet of paper from
/// one unit to the other, which is exactly what the flow asks of them. Unset — every
/// existing `hostcheck` run — and nothing is written or read, so that path is byte for
/// byte unchanged.
///
/// It is a plaintext share on disk under an ignored `target/` path. Deliberately, and
/// for the same reason [`Sheet`] is a plaintext share in a harness variable: a human
/// holds one too. It reaches no flash, no signer and no wire body.
fn sheet_dir() -> Option<std::path::PathBuf> {
    std::env::var_os("STUB_SHEET_DIR").map(std::path::PathBuf::from)
}

/// Put `sheet` where another process can pick it up. No-op without [`sheet_dir`].
///
/// REFUSES TO OVERWRITE, because two sheets in the room is the case [`sheet_read`]
/// dies on rather than guessing between: silently replacing the first reveal would
/// turn that refusal into a harness asserting about the wrong share.
fn sheet_write(id: DeviceId, sheet: &Sheet) {
    let Some(dir) = sheet_dir() else { return };
    if let Err(e) = std::fs::create_dir_all(&dir) {
        die(2, &format!("STUB_SHEET_DIR {}: {e}", dir.display()));
    }
    let path = dir.join(format!("sheet-{id}.tsv"));
    if path.exists() {
        die(
            2,
            &format!(
                "{} already holds a sheet for {id}: a second reveal by the same device would \
                 replace the one another process may already be typing",
                path.display()
            ),
        );
    }
    let mut text = String::new();
    if let Some(index) = sheet.index {
        text.push_str(&format!("index\t{index}\n"));
    }
    for (pos, word) in &sheet.words {
        text.push_str(&format!("{pos}\t{word}\n"));
    }
    if let Err(e) = std::fs::write(&path, text) {
        die(2, &format!("writing {}: {e}", path.display()));
    }
    eprintln!(
        "stub: {id} wrote its reveal to {} ({} words) -- the sheet a human carries",
        path.display(),
        sheet.words.len()
    );
}

/// Pick up every sheet another process left in [`sheet_dir`], for a device that has
/// none of its own.
///
/// ONLY WHEN `paper` IS EMPTY. A device that revealed reads its OWN sheet out of
/// memory, and importing on top of that would put two sheets in the room —
/// [`sheet_read`]'s "there is no rule for which it retypes" refusal, which is the
/// check, not an obstacle.
fn sheets_import(paper: &mut BTreeMap<DeviceId, Sheet>) {
    if !paper.is_empty() {
        return;
    }
    let Some(dir) = sheet_dir() else { return };
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(id_hex) = name
            .strip_prefix("sheet-")
            .and_then(|rest| rest.strip_suffix(".tsv"))
        else {
            continue;
        };
        let Ok(id) = id_hex.parse::<DeviceId>() else {
            die(2, &format!("{name}: {id_hex:?} is not a DeviceId"));
        };
        let text = match std::fs::read_to_string(entry.path()) {
            Ok(text) => text,
            Err(e) => die(2, &format!("reading {}: {e}", entry.path().display())),
        };
        let mut sheet = Sheet::default();
        for line in text.lines() {
            let Some((key, value)) = line.split_once('\t') else {
                die(2, &format!("{name}: {line:?} is not <key>TAB<value>"));
            };
            if key == "index" {
                sheet.index = Some(match value.parse() {
                    Ok(index) => index,
                    Err(e) => die(2, &format!("{name}: index {value:?}: {e}")),
                });
            } else {
                match key.parse::<usize>() {
                    Ok(pos) => sheet.words.insert(pos, value.to_owned()),
                    Err(e) => die(2, &format!("{name}: position {key:?}: {e}")),
                };
            }
        }
        eprintln!(
            "stub: picked up {id}'s sheet from {} ({} words, share #{:?})",
            entry.path().display(),
            sheet.words.len(),
            sheet.index
        );
        paper.insert(id, sheet);
    }
}

/// Cells of a **noised** row that hold text rather than
/// `ui::Frame::mark_sensitive`'s noise: the `NN: ` label plus one `ui::MAX_WORD_LEN`
/// word.
///
/// Derived from `hal`'s own public bound rather than written as `12`, because `hal`'s
/// `SENSITIVE_TEXT_CELLS` is private and the number is load-bearing here. The noise
/// runs end at `WIDTH - 1` and are up to 31 px long, so pixel 97 — which is inside
/// cell 12 — can be noise, and [`row_text`] on that cell is then `None`. Reading
/// exactly this many cells is what makes the read deterministic; reading one more
/// would fail on roughly one row in four.
const CLEAR_CELLS: usize = "NN: ".len() + ui::MAX_WORD_LEN;

/// The most keypresses the letter picker is allowed for one whole 25-word share.
///
/// Bounded because an unbounded typing loop is a hang, and a hang here is
/// indistinguishable from a device that stopped answering. The real worst case is
/// `BACKUP_WORDS * MAX_WORD_LEN * pages` = 25 x 8 x 3 page-or-letter presses plus one
/// `y` per word and a handful for the share index; this is comfortably past it, so
/// hitting it means the picker is not converging rather than that a word was long.
const ENTRY_PRESS_CAP: usize = 1024;

/// `cells` cells of row `row`, read back through the shipped reverse glyph lookup and
/// right-trimmed.
///
/// `None` if **any** cell in the range is not a glyph of the shipped font. A partial
/// read must be a failure and never a shorter string that might still parse — the
/// same rule [`glass_code`] follows, and the reason `mark_sensitive`'s noise cannot
/// be mistaken here for a legible screen.
fn row_text(frame: &ui::Frame, row: usize, cells: usize) -> Option<String> {
    let mut text = String::new();
    for col in 0..cells {
        text.push(char::from(frame.cell(col, row)?.0));
    }
    Some(text.trim_end().to_string())
}

/// The footer of whatever is on `frame`. Never noised (`FOOTER_ROW` carries legends,
/// not share material), so all `ui::COLS` of it are readable.
fn footer(frame: &ui::Frame) -> String {
    row_text(frame, ui::ROWS - 1, ui::COLS).unwrap_or_default()
}

/// `(k)` — the parenthesised form every legend in `hal::ui` spells a live key with.
///
/// Built from the key byte rather than typed out, so a screen that advertises a key
/// the firmware does not compare cannot pass. That is the `5=next 8=back` class of
/// defect, which has shipped in this tree once (see `hal/src/ui.rs`'s
/// `BACKUP_NEXT_LEGEND`), closed on the harness side too.
fn offers(frame: &ui::Frame, key: u8) -> bool {
    let mut want = String::from("(");
    want.push(char::from(key));
    want.push(')');
    footer(frame).contains(&want)
}

/// The share index page 0 of a reveal **drew**, off the pixels: `#N` on row 4.
fn glass_share_index(frame: &ui::Frame) -> Option<u32> {
    let row = row_text(frame, 4, ui::COLS)?;
    row.strip_prefix('#')?.parse().ok()
}

/// The `NN: WORD` rows of one word page of a reveal, off the pixels.
///
/// Rows `2..2 + ui::WORDS_PER_PAGE`, which is where `ui::BackupPages::render` puts
/// them. A blank row ENDS the page rather than failing it — the last page holds one
/// word, because 25 is not a multiple of 4.
fn glass_words(frame: &ui::Frame) -> Option<Vec<(usize, String)>> {
    let mut found = Vec::new();
    for i in 0..ui::WORDS_PER_PAGE {
        let row = row_text(frame, 2 + i, CLEAR_CELLS)?;
        if row.is_empty() {
            break;
        }
        let (number, word) = row.split_once(": ")?;
        found.push((number.parse().ok()?, word.to_string()));
    }
    (!found.is_empty()).then_some(found)
}

/// The key to press for the check-quiz question **on the glass**: the option row
/// whose word is the word the REVEAL drew at the position this screen is asking
/// about.
///
/// It is handed no [`quiz::Quiz`], no `quiz::Screen` and no option list. The position
/// comes off row 0 and the three candidates off rows 2/4/6, both through
/// `ui::Frame::cell`, so the answer comes from what a different flow put on the glass
/// and never from asking the device which candidate is right. That is the whole of
/// M7c: it makes the reveal and the quiz agree about one share across two OS
/// processes and two independent builds of `frostsnap_core`.
///
/// It also checks that the digit drawn beside each option is the [`ui::QUIZ_KEYS`]
/// entry this function would press for it, so a renderer that labelled option 2 with
/// a `3` fails by name here rather than answering a question other than the one on
/// the glass.
fn quiz_answer(frame: &ui::Frame, sheet: &Sheet) -> Result<u8, String> {
    let head = row_text(frame, 0, ui::COLS).ok_or("the quiz question row is not legible")?;
    // `ui::backup_quiz_word` draws `word NN was?`.
    let number: usize = head
        .strip_prefix("word ")
        .and_then(|rest| rest.strip_suffix(" was?"))
        .and_then(|n| n.parse().ok())
        .ok_or_else(|| format!("the quiz question row reads {head:?}, not `word NN was?`"))?;
    let want = sheet.words.get(&number).ok_or_else(|| {
        format!("the quiz asks about word {number}, which the reveal's glass never drew")
    })?;
    let mut offered = Vec::new();
    for (i, key) in ui::QUIZ_KEYS.iter().enumerate() {
        let row = 2 + i * 2;
        let text = row_text(frame, row, CLEAR_CELLS)
            .ok_or_else(|| format!("quiz option row {row} is not legible"))?;
        let (label, word) = text
            .split_once(") ")
            .ok_or_else(|| format!("quiz option row {row} reads {text:?}, not `N) WORD`"))?;
        if label.as_bytes() != [*key] {
            return Err(format!(
                "quiz option {} is labelled {label:?} but ui::QUIZ_KEYS says {:?}, so the key a \
                 human presses is not the option they read",
                i + 1,
                char::from(*key)
            ));
        }
        if word == want {
            return Ok(*key);
        }
        offered.push(word.to_string());
    }
    Err(format!(
        "the reveal's glass drew {want:?} at word {number} and the quiz offers {offered:?} -- two \
         flows over the same share disagree about it"
    ))
}

/// The next key to press to type `sheet`'s word into the entry screen **on the
/// glass**.
///
/// Everything it decides from is pixels: the word number (row 0), the prefix typed so
/// far (row 4), the candidate letters (row 6) and the ruler of keys printed above them
/// (row 5). **The candidate letters are a function of the secret prefix**, so a script
/// that did not read this screen could not type a word at all — the same structural
/// property that makes the randomised confirm digit meaningful.
///
/// The rule is deliberately the SLOW one: type every letter of the target and only
/// then press [`ui::ENTRY_OK_KEY`]. `wordentry::Entry::accept` also commits at
/// uniqueness (`ABA` commits `ABANDON`), which is where its measured 5.69 presses per
/// word come from — but a script that pressed `y` the moment the footer offered it
/// would commit `ACT` where the paper said `ACTION`, and 49 BIP39 words are proper
/// prefixes of longer ones. Typing it out costs about one extra press per word and
/// cannot commit the wrong word.
fn entry_press(frame: &ui::Frame, sheet: &Sheet) -> Result<u8, String> {
    let head = row_text(frame, 0, ui::COLS).ok_or("the entry header row is not legible")?;
    // `ui::WordEntry::render` draws `word N of 25`.
    let number: usize = head
        .strip_prefix("word ")
        .and_then(|rest| rest.split_once(' '))
        .and_then(|(n, _)| n.parse().ok())
        .ok_or_else(|| format!("the entry header row reads {head:?}, not `word N of 25`"))?;
    let want = sheet.words.get(&number).ok_or_else(|| {
        format!("the entry asks for word {number}, which the reveal's glass never drew")
    })?;
    // Row 4 is `NN: <prefix>_`. The trailing `_` cursor is what gives way on a full
    // 8-letter field (`SENSITIVE_TEXT_CELLS` is `NN: ` plus `MAX_WORD_LEN`), so it is
    // stripped only when it is there.
    let field = row_text(frame, 4, CLEAR_CELLS).ok_or("the entry prefix row is not legible")?;
    let typed = field
        .split_once(": ")
        .map(|(_, rest)| rest.strip_suffix('_').unwrap_or(rest))
        .ok_or_else(|| format!("the entry prefix row reads {field:?}, not `NN: PREFIX_`"))?;
    if !want.starts_with(typed) {
        return Err(format!(
            "the entry screen has {typed:?} typed for word {number}, which is not a prefix of the \
             {want:?} the reveal's glass drew"
        ));
    }
    let Some(next) = want.as_bytes().get(typed.len()).copied() else {
        // Every letter is in. `ui::ENTRY_OK_KEY` commits it -- and the footer has to
        // be offering that key, or the press is one the screen never advertised.
        if !offers(frame, ui::ENTRY_OK_KEY) {
            return Err(format!(
                "word {number} reads {want:?} in full and the footer is {:?} -- the screen does \
                 not offer the key that accepts it",
                footer(frame)
            ));
        }
        return Ok(ui::ENTRY_OK_KEY);
    };
    // The two rows the pad reads: the letters this page offers, and the key printed
    // above each of them. `ui::WordEntry::render` builds BOTH from `letter_for_key`
    // and stops at the first key with no letter under it, so they are the same length
    // by construction -- checked rather than assumed, because a digit printed over
    // the wrong letter is exactly the defect that array is built from the key list to
    // prevent.
    let ruler = row_text(frame, 5, CLEAR_CELLS).ok_or("the entry ruler row is not legible")?;
    let letters = row_text(frame, 6, CLEAR_CELLS).ok_or("the entry letter row is not legible")?;
    if ruler.len() != letters.len() {
        return Err(format!(
            "the entry ruler {ruler:?} and its letters {letters:?} are different lengths, so a key \
             is printed over the wrong letter"
        ));
    }
    if let Some(slot) = letters.find(char::from(next)) {
        return ruler.as_bytes().get(slot).copied().ok_or_else(|| {
            format!(
                "letter {:?} is on the glass with no key printed above it",
                char::from(next)
            )
        });
    }
    // Not on this page. `ui::ENTRY_PAGE_KEY` WRAPS, so paging terminates -- and the
    // footer has to be advertising it, which `render` only does when there is more
    // than one page.
    if !offers(frame, ui::ENTRY_PAGE_KEY) {
        return Err(format!(
            "word {number} needs letter {:?} after {typed:?}, the glass offers {letters:?} and the \
             footer is {:?} -- there is no page to turn to",
            char::from(next),
            footer(frame)
        ));
    }
    Ok(ui::ENTRY_PAGE_KEY)
}

/// The next key for the entry's **share-index** page: a digit, or
/// [`ui::ENTRY_OK_KEY`] once the accumulator equals the index the reveal drew.
///
/// The index is the one field here that is NOT read back off the glass, and that is a
/// decision rather than a shortcut: it is public — it is on the coordinator's own
/// screen, and `ui::BackupPages::render` is the one share screen that does not noise
/// it — so there is no claim to make about reading it. The WORDS are the claim, and
/// [`entry_press`] takes every one of them off the pixels.
///
/// `None` when the accumulator has diverged from the target, which is a machine that
/// did not take the digit it was handed.
fn index_press(typed: Option<u32>, want: u32) -> Option<u8> {
    let want = want.to_string();
    let typed = typed.map(|t| t.to_string()).unwrap_or_default();
    if typed == want {
        return Some(ui::ENTRY_OK_KEY);
    }
    want.as_bytes().get(typed.len()).copied()
}

/// Which restoration consent screen is on the glass, and therefore what a `yes` to it
/// buys.
///
/// `main.rs`'s `grants` is the device's own version of this decision; it is private to
/// the `#![no_main]` bin and has its own host tests, so this is the harness's. An enum
/// and not three predicates for `grants`' reason: three booleans over five variants
/// can all be true, and "draw 25 words in plain" plus "accept 25 typed in" at once is
/// not a state any screen asked for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Grant {
    /// M7b. `Session::show_backup` may draw the whole share.
    Reveal,
    /// M7c. `Session::quiz_key` may score a keypress.
    Check,
    /// M7d. `Session::entry_key` may accept a keystroke.
    Enter,
    /// M7e. `confirm_at` performs the flash write itself and nothing lands on the
    /// glass, so there is no walk for this one.
    Consolidate,
    /// Informational: `prompt_screen_at` draws no screen and `confirm_at` refuses it.
    Nothing,
}

fn grants(inner: &ToUserRestoration) -> Grant {
    match inner {
        ToUserRestoration::DisplayBackup { .. } => Grant::Reveal,
        ToUserRestoration::CheckBackup { .. } => Grant::Check,
        ToUserRestoration::EnterBackup { .. } => Grant::Enter,
        ToUserRestoration::ConsolidateBackup(_) => Grant::Consolidate,
        ToUserRestoration::BackupSaved { .. } => Grant::Nothing,
    }
}

/// M7b: walk every page of a granted reveal, recover the words from the FRAMEBUFFER,
/// and answer `ui::backup_recorded`'s digit.
///
/// The paging key is checked rather than assumed: every page's footer has to be
/// advertising [`ui::NEXT_KEY`] before the cursor advances, so a screen naming a key
/// the firmware does not compare fails here. The `+1` itself is `main.rs`'s
/// `reveal_step`, which is private to the `#![no_main]` bin and has its own host
/// tests; this is the same arithmetic over the same `Session::show_backup`.
///
/// Every page is reported on the wire as it is read, so a reveal that dies half way
/// still tells `hostcheck` how far it got. `Outbox` caps a `Debug` at 256 B and one
/// page is at most four `NN: WORD` pairs, so nothing here can be truncated.
fn reveal(
    session: &mut Session<'_, Flash>,
    rng: &mut Entropy,
    out: &mut Outbox,
    sheet: &mut Sheet,
) {
    let id = session.device_id();
    let mut frame = ui::Frame::new();
    let mut page = 0usize;
    // One page per word page plus the index page plus the ending, doubled: a reveal
    // that does not end is a hang, and this names it instead.
    let cap = 2 * (2 + ui::BACKUP_WORDS.div_ceil(ui::WORDS_PER_PAGE));
    loop {
        if page > cap {
            die(2, &format!("the reveal at {id} did not end within {cap} pages"));
        }
        match session.show_backup(page, &mut frame, rng) {
            Ok(true) => {
                if !offers(&frame, ui::NEXT_KEY) {
                    die(
                        2,
                        &format!(
                            "backup page {page} footer is {:?} -- it does not advertise \
                             ui::NEXT_KEY ({:?}), so the key this walk presses is not the key the \
                             screen showed",
                            footer(&frame),
                            char::from(ui::NEXT_KEY)
                        ),
                    );
                }
                let report = if page == 0 {
                    let index = glass_share_index(&frame).unwrap_or_else(|| {
                        die(
                            2,
                            &format!(
                                "backup page 0 row 4 reads {:?}, not the `#N` share index",
                                row_text(&frame, 4, ui::COLS)
                            ),
                        )
                    });
                    sheet.index = Some(index);
                    format!("glassindex={index}")
                } else {
                    let words = glass_words(&frame).unwrap_or_else(|| {
                        die(
                            2,
                            &format!("backup page {page} has no legible `NN: WORD` rows"),
                        )
                    });
                    let mut report = String::from("glasswords=");
                    for (number, word) in words {
                        if !report.ends_with('=') {
                            report.push(' ');
                        }
                        report.push_str(&format!("{number}:{word}"));
                        sheet.words.insert(number, word);
                    }
                    report
                };
                if let Err(e) = out.push(DeviceSendBody::Debug { message: report }) {
                    die(2, &format!("Debug(glass reveal) refused by framing: {e:?}"));
                }
                // `ui::NEXT_KEY`, as `main.rs`'s `reveal_step` turns it into.
                page += 1;
            }
            // The pages ran out. `Session::show_backup` has dropped the grant and,
            // on this leg only, armed the recorded question.
            Ok(false) => break,
            Err(e) => die(2, &format!("show_backup(page {page}, {id}): {e:?}")),
        }
    }

    // THE "DID YOU WRITE IT DOWN?" QUESTION. Same shape as `main.rs`'s
    // `show_backup_page` `Ok(false) if record_pending()` leg: the digit is drawn
    // here, rendered here, and read back out of these very pixels, so the key this
    // process presses is the key the screen showed and nothing else. A hardcoded
    // byte cannot answer it.
    if !session.record_pending() {
        die(
            2,
            &format!(
                "the reveal at {id} ran off the end of its pages and armed no recorded question, \
                 so not every page was composed"
            ),
        );
    }
    let confirm = ui::ConfirmDigit::draw(rng);
    ui::backup_recorded(&mut frame, confirm);
    match advertised_key(&frame) {
        Some(key) if confirm.accepts(key) => {
            if let Err(e) = session.backup_recorded(out) {
                die(2, &format!("backup_recorded({id}): {e:?}"));
            }
            eprintln!(
                "stub: {id} read all {} words off its own glass and answered the recorded question \
                 on the digit it printed",
                sheet.words.len()
            );
        }
        other => die(
            2,
            &format!(
                "the recorded question advertised {:?}, which the ConfirmDigit it was drawn with \
                 does not accept",
                other.map(char::from)
            ),
        ),
    }
}

/// M7c: sit the whole check quiz, answering every question from what the REVEAL
/// showed.
///
/// Returns how many questions were answered. A wrong answer re-asks the same
/// position, so the count is also the assertion: a pass in exactly
/// [`quiz::QUIZ_POSITIONS`] answers means every one of them was right first time,
/// and anything more means the reveal and the quiz disagree about the same share.
fn check_quiz(
    session: &mut Session<'_, Flash>,
    rng: &mut Entropy,
    out: &mut Outbox,
    sheet: &Sheet,
) -> usize {
    let id = session.device_id();
    let mut answers = 0usize;
    loop {
        let Some(screen) = session.quiz_screen() else {
            die(2, &format!("the quiz at {id} ended without a pass"));
        };
        let quiz::Screen::Word { question, options } = screen else {
            // Unreachable: `quiz_key` DROPS the quiz on a pass, so `quiz_screen` is
            // already `None` by the time the passed screen exists. Named rather than
            // `unreachable!()` so a vendored change that broke it says so.
            die(
                2,
                "quiz_screen offered the passed screen while the quiz was still live",
            );
        };
        let mut frame = ui::Frame::new();
        if let Err(e) = ui::backup_quiz_word(&mut frame, question, options, rng) {
            die(2, &format!("backup_quiz_word({id}): {e:?}"));
        }
        let key = quiz_answer(&frame, sheet).unwrap_or_else(|why| die(2, &why));
        answers += 1;
        if answers > quiz::QUIZ_POSITIONS {
            die(
                2,
                &format!(
                    "the quiz has asked {answers} questions for {} positions, so an answer read \
                     off the reveal's glass was scored WRONG",
                    quiz::QUIZ_POSITIONS
                ),
            );
        }
        match session.quiz_key(key, rng, out) {
            Ok(Checked::Redraw) => {}
            Ok(Checked::Ended { checked: Some(n) }) => {
                if n != quiz::QUIZ_POSITIONS || answers != quiz::QUIZ_POSITIONS {
                    die(
                        2,
                        &format!(
                            "the quiz passed claiming {n} checked words after {answers} answers, \
                             not {} of each",
                            quiz::QUIZ_POSITIONS
                        ),
                    );
                }
                return answers;
            }
            Ok(Checked::Ended { checked: None }) => {
                die(2, "the quiz ABORTED on a key read off its own glass")
            }
            // A `QUIZ_KEYS` byte on a live quiz cannot do nothing, so this is a
            // machine that stopped scoring. Named rather than looped on, because
            // looping on it is a hang.
            Ok(Checked::Unchanged) => die(
                2,
                &format!(
                    "quiz key {:?} -- read off the glass, and one of ui::QUIZ_KEYS -- did nothing",
                    char::from(key)
                ),
            ),
            Err(e) => die(2, &format!("quiz_key({id}): {e:?}")),
        }
    }
}

/// M7d: type all 25 words back in through the letter picker.
///
/// Returns how many keys were pressed, for the log — it is a property of the picker,
/// not an assertion. The assertion is the coordinator's: the `share_image` the device
/// derives from these 25 words has to equal its own `expected_share_image`.
fn type_backup(
    session: &mut Session<'_, Flash>,
    rng: &mut Entropy,
    out: &mut Outbox,
    sheet: &Sheet,
) -> (usize, Vec<DeviceToUserMessage>) {
    let id = session.device_id();
    let index = sheet
        .index
        .unwrap_or_else(|| die(2, "no share index was ever read off a reveal page"));
    let mut presses = 0usize;
    loop {
        let key = {
            let Some(screen) = session.entry_screen() else {
                die(2, &format!("the entry at {id} ended without a share"));
            };
            match screen {
                wordentry::Screen::ShareIndex { typed } => index_press(typed, index)
                    .unwrap_or_else(|| {
                        die(
                            2,
                            &format!("the entry has index {typed:?} typed, not a prefix of {index}"),
                        )
                    }),
                wordentry::Screen::Word(word) => {
                    let mut frame = ui::Frame::new();
                    if let Err(e) = word.render(&mut frame, rng) {
                        die(2, &format!("WordEntry::render({id}): {e:?}"));
                    }
                    entry_press(&frame, sheet).unwrap_or_else(|why| die(2, &why))
                }
                wordentry::Screen::Failed => die(
                    2,
                    &format!(
                        "the 25 words read off {id}'s own reveal DID NOT CHECKSUM when typed back \
                         in -- the reveal and `ShareBackup::from_words` disagree"
                    ),
                ),
            }
        };
        presses += 1;
        if presses > ENTRY_PRESS_CAP {
            die(
                2,
                &format!("the letter picker at {id} took over {ENTRY_PRESS_CAP} presses"),
            );
        }
        match session.entry_key(key, out) {
            Ok(Typed::Ended(prompts)) => return (presses, prompts),
            Ok(Typed::Redraw) => {}
            // Every key here came off the glass, so a no-op press is a picker that
            // stopped accepting what it advertises. Looping on it is a hang.
            Ok(Typed::Unchanged) => die(
                2,
                &format!(
                    "entry key {:?}, read off the glass, did nothing",
                    char::from(key)
                ),
            ),
            Err(e) => die(2, &format!("entry_key({id}): {e:?}")),
        }
    }
}

/// Walk `prompt`'s pages, ask `consent` for a keypress on the last one, and decide.
/// `Some(page)` means confirm it AT THAT PAGE — hand the same number to
/// [`Session::confirm_at`], which accepts no other.
///
/// THE ONE PLACE A KEY BECOMES CONSENT. `Session::confirm` renders the screen
/// again for its own renderability gate, with its own throwaway digit (documented
/// at that call in `firmware/src/lib.rs`); THIS frame is the one the closure
/// answers and this digit is the one printed on it, so the legend that is
/// displayed and the value that is accepted are one `ConfirmDigit` and cannot
/// drift.
///
/// It also REPORTS the keygen code off this same frame (`glass=`), which is why it
/// takes the outbox. From THIS frame and not a re-render, deliberately: the four
/// bytes `hostcheck` compares against its own session hash have to be the four
/// bytes on the screen the consent below answered, or the assertion is about a
/// picture nobody approved.
fn approved(
    prompt: &DeviceToUserMessage,
    rng: &mut Entropy,
    consent: Consent,
    out: &mut Outbox,
) -> Option<usize> {
    // THE PAGE WALK, which is `main.rs`'s `Answer::Next` arm with the keypad taken
    // out: advance one page at a time, and only the page that reports `last` prints a
    // digit and may be answered. It is not an extra: `prompt_screen` (page 0) is
    // `Ok(false)` for a multi-page bitcoin transaction, so a caller without a cursor
    // used to reach `return true` below — approving a request it had not rendered —
    // and then die in `Session::confirm` with `Fault::NotConfirmable`. Every recipient
    // and the fee are on pages after the first (`hal::ui::SignPages`), so this loop is
    // what makes "the human read the transaction" true of this harness at all.
    //
    // SINGLE ADVANCES, deliberately: `Session::confirm_at`'s contract is "the drawn
    // digit, checked against the key, on a page reached by single advances", and
    // jumping straight to `len() - 1` would be a caller inventing a screen nobody saw.
    let mut page = 0usize;
    let (digit, frame) = loop {
        let digit = ui::ConfirmDigit::draw(rng);
        let mut frame = ui::Frame::new();
        // `Shown::Nothing` (informational, no screen), `Shown::Info` (drawn but
        // authorises nothing — address verification) and `Err` (this device cannot
        // draw the request in full) are all prompts NO key may authorise. They are
        // deliberately not called declines: `Session::confirm_at` fails closed on
        // exactly these — `NotConfirmable` and `Refused` — and names the failure
        // itself, so it stays the authority and its diagnostics keep their wording.
        match prompt_screen_at(&mut frame, prompt, digit, page) {
            Ok(Shown::Page { last: true }) => break (digit, frame),
            Ok(Shown::Page { last: false }) => {
                // What a human sees before pressing `ui::NEXT_KEY`, read back off the
                // pixels: this is the only record of WHICH transaction was on the
                // glass, and the app rig's assertion that the displayed recipients,
                // amounts and fee are the ones being signed is made against it.
                log_glass(&frame, page, false);
                page += 1;
                if page > PAGE_CAP {
                    die(
                        2,
                        &format!(
                            "no page below {PAGE_CAP} reported itself last -- the page set does \
                             not terminate, so nothing can be consented to"
                        ),
                    );
                }
            }
            // Same value the one-page funnel returned here, and the same reason: it is
            // not a decline, it is a prompt with nothing to answer. Page 0, because
            // that is the only page a caller may then name.
            _ => return Some(0),
        }
    };
    log_glass(&frame, page, true);
    // ASSERTION 1, on the wire. `UNREADABLE` rather than skipping the report: a
    // screen whose code cannot be read back is a screen whose code is not the
    // coordinator's, and `hostcheck` must fail on it rather than on a missing map
    // entry it could mistake for a device that never got there.
    if matches!(prompt, DeviceToUserMessage::CheckKeyGen { .. }) {
        let code = glass_code(&frame).unwrap_or_else(|| "UNREADABLE".into());
        if let Err(e) = out.push(DeviceSendBody::Debug {
            message: format!("glass={code}"),
        }) {
            die(2, &format!("Debug(glass) refused by framing: {e:?}"));
        }
    }
    let key = consent(prompt, &frame);
    // `Some(page)` — the page the key was pressed on, which is the page
    // `Session::confirm_at` must be told about and the only one it accepts.
    let granted = match prompt {
        // THE ANTI-MITM SCREEN, and as of 2026-09-11 it is gated exactly like the
        // signing one. This arm read `key == b'1'` because `ui::keygen_check` printed a
        // fixed `1=match x=no`; that made this the ONE consent screen in the tree a
        // hardcoded script could clear, on the one screen whose entire purpose is that
        // a human read four bytes off it and said them out loud. `keygen_check` now
        // prints the same randomised `ui::ConfirmDigit` drawn above, so only the digit
        // that is ON THE SCREEN acks — and `COLDSNAP_GLASS_KEYS=1yy`, which used to
        // PASS, now fails with no source mutation at all.
        DeviceToUserMessage::CheckKeyGen { .. } => digit.accepts(key),
        // FAIL CLOSED — `hsm_ux.py:66`'s `refused = (ch != confirm_char)`,
        // inverted. Only the digit that is ON THE SCREEN signs; `x`, another
        // charset digit and a key that is not on the pad are all refusals.
        DeviceToUserMessage::SignatureRequest { .. } => digit.accepts(key),
        // THE FOUR RESTORATION CONSENT SCREENS. Every one of them prints the same
        // randomised legend the signing screen does — `consent_screen`'s
        // `"Press (N) x=no"`, composed from the very `ConfirmDigit` drawn above — so
        // the same rule applies and for the same reason: only the digit that is ON
        // THE SCREEN grants, and `x`, another charset digit and a key that is not on
        // the pad are all refusals. This is `main.rs`'s `answer` arm for
        // `Consent::Prompt`, which since 2026-09-11 is ONE rule for every prompt:
        // `confirm.accepts(key)` with no inner match on the prompt kind at all. This
        // comment described that arm's deleted `_ =>` shape as if it were still live
        // until a review caught it; `the_keygen_prompt_is_answered_by_the_same_rule_as
        // _every_other_prompt` is what asserts the arm does not bind the prompt.
        //
        // `BackupSaved` never reaches here: `prompt_screen_at` draws no screen for
        // it, so the `Ok(true)` gate above has already returned.
        DeviceToUserMessage::Restoration(_) => digit.accepts(key),
        // Not a consent prompt. Unreachable from the call sites in `drive`, and a
        // decline — which fails the run — if that ever stops being true.
        _ => false,
    };
    granted.then_some(page)
}

/// The consent closure said no: `Session::confirm` is never called, and the only
/// thing that can carry a "no" to the coordinator is the `Debug` back-channel a
/// `Fault::Refused` already uses two dozen lines below.
///
/// The vendored protocol HAS no decline variant — that is a finding, not a detail
/// — so the alternative to `Debug` is silence, and silence is indistinguishable
/// from a dead device. `Outbox` caps `Debug` at 256 B on a UTF-8 boundary and
/// `hostcheck` intercepts it before the `FrostCoordinator` state machine, so it
/// cannot perturb the protocol.
fn decline(id: DeviceId, what: &str, out: &mut Outbox) {
    DECLINES.fetch_add(1, Ordering::Relaxed);
    eprintln!("stub: {id} DECLINED {what} -- the protocol has no message for a no");
    if let Err(e) = out.push(DeviceSendBody::Debug {
        message: format!("declined={what}"),
    }) {
        die(2, &format!("Debug(declined) refused by framing: {e:?}"));
    }
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
    let mut t = varying(TRNG_BYTES, salt);
    // A new boot draws new TRNG bytes (`STUB_BOOT`, 0 by default = every existing
    // measurement): the app rig's stub restart sets it, so the new process does not replay
    // the old one's RNG stream, and a restart onto BLANK flash derives a different id.
    t[0] = t[0].wrapping_add(boot());
    let s1 = varying(SE1_BYTES, salt.wrapping_add(1));
    let s2 = varying(SE2_BYTES, salt.wrapping_add(2));
    let seed: ProvenSeed = mix_sources(&t[..TRNG_BYTES], &s1[..SE1_BYTES], &s2[..SE2_BYTES])
        .expect("three good draws must mix");
    Entropy::from_proven_seed(seed)
}

/// [`session_count`] blank flashes at the shipped geometry, sized so a write past the
/// nonce region is out of bounds rather than silently landing in `FS_FREE`.
///
/// Separate from `open_sessions` because these must OUTLIVE every session: a
/// `Session` borrows its `RefCell<Flash>`, and the restart works by dropping all
/// the sessions while the flashes stay exactly as they are — which is what a
/// power cycle does.
///
/// FIX 12: with `STUB_FLASH_FILE` the one flash is loaded from that file instead (see
/// [`FileFlash`]), so a NEW PROCESS on the same file is a power cycle too.
fn blank_flashes() -> Vec<RefCell<Flash>> {
    let sectors = memmap::FS_FREE_OFFSET as usize / ERASE_SIZE;
    let path = std::env::var("STUB_FLASH_FILE").ok();
    if path.is_some() && session_count() != 1 {
        die(2, "STUB_FLASH_FILE backs ONE flash; it needs STUB_SESSIONS=1");
    }
    (0..session_count())
        .map(|_| {
            let mut cells = FakeFlash::new(sectors);
            let file = path.as_deref().map(|p| load_flash_file(&mut cells, p));
            RefCell::new(DebugFlash(FileFlash { cells, file }))
        })
        .collect()
}

/// FIX 12 — `FakeFlash` with every ACCEPTED program/erase written through to an image
/// file, so the flash outlives the process (`STUB_FLASH_FILE`, the app rig's stub
/// restart). Unset, `file` is `None` and this is exactly the RAM-only `FakeFlash`.
///
/// NO MORE PERMISSIVE THAN `FakeFlash`, by construction: every call goes to the inner
/// `FakeFlash` first, only an `Ok` is mirrored, and what the file receives is read back
/// OUT OF the fake's cells, never the caller's bytes. So a refused, misaligned,
/// out-of-bounds or bit-setting (unerased) program reaches neither, and the file only
/// ever holds bytes `FakeFlash` accepted. `Deref`
/// is there so the fault-injection knobs (`refuse_*`, `heal`, the counters) stay the
/// inner fake's. A host-test facility only; nothing like it is in the ARM image.
struct FileFlash {
    cells: FakeFlash,
    file: Option<std::fs::File>,
}

impl std::ops::Deref for FileFlash {
    type Target = FakeFlash;
    fn deref(&self) -> &FakeFlash {
        &self.cells
    }
}

impl std::ops::DerefMut for FileFlash {
    fn deref_mut(&mut self) -> &mut FakeFlash {
        &mut self.cells
    }
}

impl FileFlash {
    /// Copy `len` cells at `offset`, as the fake now holds them, to the same offset in
    /// the file, then check the WHOLE file equals the whole fake. The check is what makes
    /// an operation that was never mirrored (an erase, say, leaving stale bytes a later
    /// boot would read as an older A/B generation) die here, by name, at the next op.
    ///
    /// ponytail: re-reads the whole 80 KB image per op; fine at the rig's op count, drop
    /// to a dirty-range check if a run ever gets slow.
    fn mirror(&mut self, offset: u32, len: usize) {
        use std::os::unix::fs::FileExt;
        let Some(file) = &self.file else { return };
        let mut now = vec![0u8; self.cells.len()];
        if let Err(e) = self.cells.read(0, &mut now) {
            die(2, &format!("STUB_FLASH_FILE mirror read: {e:?}"));
        }
        let range = offset as usize..offset as usize + len;
        if let Err(e) = file.write_all_at(&now[range], u64::from(offset)) {
            die(2, &format!("STUB_FLASH_FILE write-through at {offset:#x}: {e}"));
        }
        let mut disk = vec![0u8; now.len()];
        if let Err(e) = file.read_exact_at(&mut disk, 0) {
            die(2, &format!("STUB_FLASH_FILE read-back: {e}"));
        }
        if disk != now {
            let at = disk.iter().zip(&now).position(|(d, n)| d != n).unwrap_or(0);
            die(2, &format!("STUB_FLASH_FILE DIVERGED from the flash at {at:#x}"));
        }
    }
}

impl ErrorType for FileFlash {
    type Error = FlashError;
}

impl ReadNorFlash for FileFlash {
    const READ_SIZE: usize = FakeFlash::READ_SIZE;
    fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), FlashError> {
        self.cells.read(offset, bytes)
    }
    fn capacity(&self) -> usize {
        self.cells.capacity()
    }
}

impl NorFlash for FileFlash {
    const WRITE_SIZE: usize = FakeFlash::WRITE_SIZE;
    const ERASE_SIZE: usize = FakeFlash::ERASE_SIZE;
    fn erase(&mut self, from: u32, to: u32) -> Result<(), FlashError> {
        self.cells.erase(from, to)?;
        self.mirror(from, (to - from) as usize);
        Ok(())
    }
    fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), FlashError> {
        self.cells.write(offset, bytes)?;
        self.mirror(offset, bytes.len());
        Ok(())
    }
}

/// Open (or create, all-`0xff`) the image at `path` and program it into the blank
/// `cells` through `FakeFlash`'s own `write`, so a load obeys the same rules a program
/// does. A file of the wrong size dies: it is not this device's flash.
///
/// PARSED BY `tools/app-rig.py`: the `sha256` is of the cells AFTER the load, read back
/// out of the fake, which is what the rig compares with the file the previous process
/// left. Keep the `STUB_FLASH_FILE <path>: ..., sha256 <hex>` shape.
fn load_flash_file(cells: &mut FakeFlash, path: &str) -> std::fs::File {
    use sha2::{Digest, Sha256};
    let open = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path);
    let mut file = open.unwrap_or_else(|e| die(2, &format!("STUB_FLASH_FILE={path:?}: {e}")));
    let mut image = Vec::new();
    if let Err(e) = file.read_to_end(&mut image) {
        die(2, &format!("STUB_FLASH_FILE={path:?} unreadable: {e}"));
    }
    let state = if image.is_empty() {
        image = vec![0xff; cells.len()];
        if let Err(e) = file.write_all(&image) {
            die(2, &format!("STUB_FLASH_FILE={path:?} not created: {e}"));
        }
        "created blank"
    } else if image.len() != cells.len() {
        die(
            2,
            &format!("STUB_FLASH_FILE={path:?} is {} B, the flash is {} B", image.len(), cells.len()),
        )
    } else {
        if let Err(e) = cells.write(0, &image) {
            die(2, &format!("STUB_FLASH_FILE={path:?} does not program: {e:?}"));
        }
        "loaded"
    };
    let mut held = vec![0u8; cells.len()];
    if let Err(e) = cells.read(0, &mut held) {
        die(2, &format!("read back STUB_FLASH_FILE={path:?}: {e:?}"));
    }
    eprintln!(
        "stub: STUB_FLASH_FILE {path}: {state}, {} B, sha256 {}",
        held.len(),
        hex(&Sha256::digest(&held))
    );
    file
}

/// Sessions by id, each id's flash index, and `(fresh, original)` per recovered erase.
type Booted<'a> = (
    BTreeMap<DeviceId, Session<'a, Flash>>,
    BTreeMap<DeviceId, usize>,
    Vec<(DeviceId, DeviceId)>,
);

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
///
/// The third element is every device whose boot FINISHED an interrupted erase: its
/// fresh id and the ORIGINAL id whose `EraseConfirmed` the caller owes the wire.
fn open_sessions<'a>(
    flashes: &'a [RefCell<Flash>],
    rng: &mut Entropy,
) -> Booted<'a> {
    let mut sessions = BTreeMap::new();
    let mut index = BTreeMap::new();
    let mut recovered_erases = Vec::new();
    for (i, flash) in flashes.iter().enumerate() {
        let (session, recovered) = open_one(flash, rng);
        if let Some(orig) = recovered {
            recovered_erases.push((session.device_id(), DeviceId(orig)));
        }
        index.insert(session.device_id(), i);
        if sessions.insert(session.device_id(), session).is_some() {
            die(2, "two devices derived the SAME DeviceId from different flashes");
        }
    }
    (sessions, index, recovered_erases)
}

/// One device's boot, out of what is on its flash. See [`open_sessions`]. The second
/// element is `erase::recover`'s: the ORIGINAL id of an interrupted erase it just
/// finished, whose `EraseConfirmed` the caller owes the wire.
fn open_one<'a>(
    flash: &'a RefCell<Flash>,
    rng: &mut Entropy,
) -> (Session<'a, Flash>, Option<[u8; erase::ID_LEN]>) {
    {
        // `load_or_create` wants `&mut Flash` and the session takes a shared
        // borrow of the same `RefCell` for its whole life, so the identity has to
        // be read first. Nothing else may hold a borrow here.
        //
        // And before THAT, `main.rs`'s step 8a: an interrupted erase is resumed
        // before identity or nonces are read, and a damaged marker is fatal. The
        // stub has no `main.rs` boot path, so it repeats the step here.
        let recovered = match erase::recover(&mut *flash.borrow_mut()) {
            Ok(recovered) => recovered,
            Err(e) => die(2, &format!("erase::recover: {e:?}")),
        };
        let secret = match identity::load_or_create(&mut *flash.borrow_mut(), rng) {
            Ok(secret) => secret,
            Err(e) => die(2, &format!("identity::load_or_create: {e:?}")),
        };
        let mut session = match Session::open(flash, &secret) {
            Ok(session) => session,
            Err(e) => die(2, &format!("Session::open: {e:?}")),
        };
        session.signer.keygen_fingerprint = keygen_fingerprint();
        (session, recovered)
    }
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

/// The digest this process ANNOUNCES, and which image it came from.
///
/// `STUB_IMAGE=<path>` hashes a REAL image file with the same shipped
/// `firmware_digest`; unset falls back to [`synthetic_digest`]. Both are the same
/// function over different bytes, and the difference matters to exactly one
/// consumer: the app identifies a device by announced digest against
/// `frostsnap_coordinator/src/coldsnap-mk4-registry.txt`, so the synthetic image's
/// digest is `DeviceProfile::Unrecognized` — `is_compatible() == false`, every
/// capability false, and the app's keygen gate refuses the device
/// (`device_list::check_keygen_group`). Pointing this at the packaged, key-0-signed
/// artifact makes the announced digest the CHECKED ARTIFACT'S, which is what task
/// 04's work item 4 asks for.
///
/// IT IS STILL NOT ATTESTATION and pointing at a file does not make it any more so.
/// The device reports this about itself over the same wire as everything else; a
/// registry hit says WHICH FIRMWARE and nothing about who sent it. This process is
/// not running the image it names — it is a host stub — so the honest statement is
/// "announced digest = the packaged artifact's", and the second element returned
/// here is what puts that provenance on stderr instead of leaving a reader to
/// guess. A missing or unhashable file DIES rather than falling back: silently
/// announcing the synthetic digest instead would look like a compatibility bug in
/// the app.
fn announced_digest() -> (frostsnap_comms::Sha256Digest, String) {
    let Ok(path) = std::env::var("STUB_IMAGE") else {
        return (synthetic_digest(), "synthetic (STUB_IMAGE unset)".into());
    };
    let image = match std::fs::read(&path) {
        Ok(image) => image,
        Err(e) => die(2, &format!("STUB_IMAGE={path:?} unreadable: {e}")),
    };
    match firmware_digest(&image) {
        Some(digest) => (digest, format!("{path} ({} B)", image.len())),
        None => die(
            2,
            &format!("STUB_IMAGE={path:?} is not a hashable image (header/length check failed)"),
        ),
    }
}

/// Feed one decoded coordinator body to one session, answer the prompts a human
/// would answer, and record any share it staged.
///
/// CONSENT, and it is why the two consent prompts are NOT answered by the
/// dispatch: `Session::recv` returns `CheckKeyGen` and `SignatureRequest` and
/// answers neither. `CheckKeyGen` is a human comparing the session hash against
/// the coordinator's display, which is the defence against a coordinator that
/// lies about who is in the access structure; `SignatureRequest` is a human
/// reading the transaction. **A REAL DEVICE MUST NOT ACK EITHER ITSELF.** That
/// the answer lives HERE rather than in `firmware/src/lib.rs` is the load-bearing
/// part, and it is now a `Consent` closure rather than an unconditional ack, so
/// the same two `session.confirm` call sites serve this harness, a human at the
/// simulator window and a scripted gate. By default the closure is the
/// always-approve one — press whatever the glass advertises — so it remains a
/// harness affordance and every existing measurement is unchanged;
/// `COLDSNAP_GLASS_KEYS` scripts it (see [`glass_keys`]), which is how
/// `hostcheck`'s DECLINE pass proves that `x` refuses.
fn drive(
    session: &mut Session<'_, Flash>,
    flash: &RefCell<Flash>,
    body: CoordinatorSendBody,
    rng: &mut Entropy,
    consent: Consent,
    wire: &mut Vec<u8>,
    saved: &mut BTreeMap<DeviceId, AccessStructureRef>,
    paper: &mut BTreeMap<DeviceId, Sheet>,
    erase_asks: &mut BTreeMap<DeviceId, usize>,
) -> EraseOutcome {
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

    // TASK 08: the ERASE QUESTION. `recv` only raised it; this is main.rs's
    // `show_erase` + `Flow::Erase` answer, done the same way every other consent here
    // is: the shipped screen, a randomised digit, and a key read off the glass.
    if session.erase_requested() {
        let n = erase_asks.entry(id).or_insert(0);
        *n += 1;
        let scripted = erase_keys().as_bytes().get(*n - 1).copied().unwrap_or(b'x');
        let digit = ui::ConfirmDigit::draw(rng);
        let mut frame = ui::Frame::new();
        if !erase_screen(&mut frame, digit) {
            die(2, "the erase question does not fit the glass");
        }
        log_glass(&frame, 0, true);
        let key = match scripted {
            b'y' | b'p' | b'c' | b'a' | b'f' => advertised_key(&frame).unwrap_or(b'x'),
            key => key,
        };
        let outcome = if digit.accepts(key) && b"pcaf".contains(&scripted) {
            {
                let mut f = flash.borrow_mut();
                if scripted == b'p' {
                    // The marker body is the first program: nothing commits.
                    let at = f.0.programs;
                    f.0.refuse_programs_after(at);
                } else if scripted == b'c' {
                    // Marker region = 2 pages, then the first share sector; every
                    // erase after that is refused, as a power cut would stop them.
                    let at = f.0.erases + 3;
                    f.0.refuse_erases_after(at);
                }
            }
            let r = session.erase(&mut out);
            let frames = out.frames();
            let mut fin = None;
            if scripted == b'a' {
                // Power gone with the ack still in the outbox: it never leaves RAM.
                drop(out.take());
            } else if scripted == b'f' {
                // main.rs's order: the ack is written, then `finish`, which the cut stops.
                wire.extend_from_slice(&out.take());
                let mut f = flash.borrow_mut();
                let at = f.0.erases;
                f.0.refuse_erases_after(at);
                drop(f);
                fin = Some(session.finish_erase());
            }
            flash.borrow_mut().0.heal();
            let marker = erase::read(&mut *flash.borrow_mut());
            let deleted = matches!(scripted, b'a' | b'f');
            let want = if scripted == b'p' { erase::Marker::Clear } else { erase::Marker::Pending };
            if r.is_ok() != deleted
                || frames != usize::from(deleted)
                || marker != Ok(want)
                || fin.as_ref().is_some_and(Result::is_ok)
            {
                die(
                    2,
                    &format!(
                        "{id}: cut {} erase gave {r:?}, {frames} frame(s), finish {fin:?}, \
                         marker {marker:?}",
                        scripted as char
                    ),
                );
            }
            let what = match scripted {
                b'p' => "before the commit: nothing committed, no EraseConfirmed sent",
                b'c' => "marker committed, no EraseConfirmed sent",
                b'a' => "after deletion: EraseConfirmed lost in RAM unwritten, marker kept",
                _ => "in finish: EraseConfirmed written, marker kept",
            };
            eprintln!(
                "stub: {id} POWER CUT mid-erase [{}] (erase question #{n}): {what}; off \
                 until the next boot runs erase::recover",
                scripted as char
            );
            EraseOutcome::Interrupted { committed: scripted != b'p' }
        } else if digit.accepts(key) {
            match session.erase(&mut out) {
                Ok(()) => {
                    eprintln!(
                        "stub: {id} ERASED on the randomised digit read off the glass (erase \
                         question #{n}); EraseConfirmed sent under this id after deletion"
                    );
                    EraseOutcome::Erased
                }
                Err(e) => die(2, &format!("Session::erase({id}): {e:?}")),
            }
        } else {
            session.decline_erase();
            eprintln!("stub: {id} DECLINED DataErase (erase question #{n}) -- nothing written");
            if let Err(e) = out.push(DeviceSendBody::Debug {
                message: "declined=DataErase".into(),
            }) {
                die(2, &format!("Debug(declined) refused by framing: {e:?}"));
            }
            EraseOutcome::Declined
        };
        wire.extend_from_slice(&out.take());
        return outcome;
    }

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
                let p = DeviceToUserMessage::CheckKeyGen { phase };
                if let Some(page) = approved(&p, rng, &mut *consent, &mut out) {
                    // NOT an auto-ack, and as of 2026-09-11 not weaker than the signing
                    // arm either: `approved` above required `digit.accepts(key)` against
                    // a RANDOMISED `ui::ConfirmDigit`, read back out of the rendered
                    // pixels. This note said the legend was "the fixed `1=match` ...
                    // which is the one respect in which this arm is weaker than the
                    // signing one -- a hardcoded `1` would also answer it". It no longer
                    // is, and `COLDSNAP_GLASS_KEYS=1yy` is the demonstration. Saying
                    // "auto-ack" here is what put "the stub auto-acks" into PLAN.md and
                    // README for weeks; do not put that back either.
                    eprintln!(
                        "stub: {id} CheckKeyGen -> approved on the randomised digit read off the glass"
                    );
                    match session.confirm_at(p, page, rng, &mut out) {
                        Ok(more) => prompts.extend(more),
                        Err(e) => die(2, &format!("confirm(CheckKeyGen, {id}): {e:?}")),
                    }
                    if clear_tmp_mode() == "check" {
                        eprintln!("stub: {id} clear_tmp_data() at CheckKeyGen -- WRONG ON PURPOSE");
                        session.signer.clear_tmp_data();
                    }
                } else {
                    decline(id, "CheckKeyGen", &mut out);
                }
            }
            p @ DeviceToUserMessage::SignatureRequest { .. } => {
                if let Some(page) = approved(&p, rng, &mut *consent, &mut out) {
                    // NOT an auto-ack either, and this one is structural: `approved`
                    // required `digit.accepts(key)` against a RANDOMISED
                    // `ui::ConfirmDigit` drawn on the frame the consent answered, so
                    // no hardcoded key can reach here (`COLDSNAP_GLASS_KEYS=y9`
                    // and `=y2` are refusals by construction). What a host cannot
                    // supply is a human who actually read the screen.
                    eprintln!(
                        "stub: {id} SignatureRequest -> approved on the randomised digit read off \
                         the glass, on page {page} (the last page of the set)"
                    );
                    match session.confirm_at(p, page, rng, &mut out) {
                        Ok(more) => {
                            if lose_first_share() && !SHARE_LOST.swap(true, Ordering::Relaxed) {
                                let lost = out.take();
                                eprintln!(
                                    "stub: {id} SIGNATURE REPLY LOST ON THE WIRE \
                                     (STUB_LOSE_FIRST_SHARE): {} B signed and dropped",
                                    lost.len()
                                );
                                prompts.extend(more);
                                continue;
                            }
                            SIG_ACKS.fetch_add(1, Ordering::Relaxed);
                            STATE.fetch_max(6, Ordering::Relaxed);
                            prompts.extend(more);
                        }
                        Err(e) => die(2, &format!("confirm(SignatureRequest, {id}): {e:?}")),
                    }
                } else {
                    decline(id, "SignatureRequest", &mut out);
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
            // =============================== M7 ===============================
            // THE RESTORATION FLOWS. Every one of them is a consent screen with the
            // randomised digit on it — `approved` answers all four with
            // `digit.accepts(key)`, read off the pixels — and what the digit BUYS
            // differs per flow, which is `Session::confirm_at`'s business and not this
            // file's. What is this file's is the scripted human afterwards: a walk
            // that pages, answers or types using only what the glass drew.
            DeviceToUserMessage::Restoration(restoration) => {
                let inner = *restoration;
                let grant = grants(&inner);
                if grant == Grant::Nothing {
                    // `BackupSaved`, the device's own note that `SavePhysicalBackup2`
                    // landed. `prompt_screen_at` draws no screen for it and
                    // `confirm_at` refuses it, so there is nothing to consent to; the
                    // coordinator learns the same fact from
                    // `DeviceRestoration::PhysicalSaved`, which `Session::run` has
                    // already put in the outbox.
                    eprintln!("stub: {id} Restoration({inner:?}) is informational");
                    continue;
                }
                let p = DeviceToUserMessage::Restoration(Box::new(inner));
                let Some(page) = approved(&p, rng, &mut *consent, &mut out) else {
                    decline(id, &format!("{grant:?}"), &mut out);
                    continue;
                };
                eprintln!(
                    "stub: {id} {grant:?} -> approved on the randomised digit read off the glass"
                );
                match session.confirm_at(p, page, rng, &mut out) {
                    Ok(more) => prompts.extend(more),
                    Err(e) => die(2, &format!("confirm({grant:?}, {id}): {e:?}")),
                }
                match grant {
                    // M7b. Nothing is on the wire until the last page has been drawn
                    // and the recorded question answered — that is what
                    // `Session::backup_recorded`'s `record_pending` gate means.
                    //
                    // THE ONLY WRITER, and the `entry()` lives HERE rather than above
                    // the match for that reason (M12). Taking `&mut Sheet` for every
                    // granted flow gave `paper` an EMPTY entry for any device that
                    // never revealed, and [`sheet_read`] would then hand that empty
                    // sheet straight to `type_backup` — which is exactly the blank
                    // device's situation.
                    Grant::Reveal => {
                        let sheet = paper.entry(id).or_default();
                        reveal(session, rng, &mut out, sheet);
                        // The handoff, and only when the rig asked for one: with one
                        // session per process the device that types this share back is
                        // a different process, so the sheet has to leave this one.
                        sheet_write(id, sheet);
                    }
                    // M7c. Answered ONLY from what M7b's reveal showed.
                    Grant::Check => {
                        sheets_import(paper);
                        let answers = check_quiz(session, rng, &mut out, sheet_read(paper, id));
                        if let Err(e) = out.push(DeviceSendBody::Debug {
                            message: format!("quiz={answers}"),
                        }) {
                            die(2, &format!("Debug(quiz) refused by framing: {e:?}"));
                        }
                    }
                    // M7d. `entry_key` sends `PhysicalEntered` itself, and only when
                    // 25 words pass their checksum.
                    Grant::Enter => {
                        // A BLANK DEVICE HAS NO SHEET OF ITS OWN -- it holds no share,
                        // so the coordinator refuses `DisplayBackup` for it -- and in
                        // the rig it is its own process, so the sheet it retypes has to
                        // come off the disk another process wrote it to.
                        sheets_import(paper);
                        let (presses, more) =
                            type_backup(session, rng, &mut out, sheet_read(paper, id));
                        eprintln!(
                            "stub: {id} typed all {} words back in through the letter picker in \
                             {presses} presses",
                            ui::BACKUP_WORDS
                        );
                        if let Err(e) = out.push(DeviceSendBody::Debug {
                            message: format!("typed={presses}"),
                        }) {
                            die(2, &format!("Debug(typed) refused by framing: {e:?}"));
                        }
                        prompts.extend(more);
                    }
                    // M7e. `confirm_at` -> `finish_consolidation` -> `run` has already
                    // persisted the keygen triple and put `FinishedConsolidation` in
                    // the outbox. Nothing lands on the glass, so there is no walk.
                    Grant::Consolidate => eprintln!(
                        "stub: {id} CONSOLIDATED -- the typed share REPLACED the stored record"
                    ),
                    Grant::Nothing => {}
                }
            }
            // ADDRESS VERIFICATION. `Shown::Info`: a screen that is DRAWN and
            // authorises nothing, so there is no consent and no `confirm_at` call —
            // `confirm_at` refuses `Info` fail-closed, and `approved` is never asked.
            // The only thing a human does with this screen is READ it, so the only
            // thing this process does is read it back off the pixels.
            //
            // THAT READ IS THE CHECK. The app's "Sender has correct address" button
            // sets a Dart bool and discards `verify_address`'s stream, so tapping it
            // proves nothing about what the device drew; this line is what the app rig
            // compares against the address the app's own wallet handed out. Until now
            // this prompt fell through to `_other` and the address was never rendered
            // at all, which is why nothing could compare it.
            p @ DeviceToUserMessage::VerifyAddress { .. } => {
                let mut frame = ui::Frame::new();
                match prompt_screen_at(&mut frame, &p, ui::ConfirmDigit::draw(rng), 0) {
                    Ok(Shown::Info) => {
                        eprintln!("stub: {id} VerifyAddress drawn (authorises nothing)");
                        log_glass(&frame, 0, false);
                    }
                    // A `Page` here would mean the address screen had started printing
                    // a confirm digit, i.e. had become answerable — `firmware/src/lib.rs`
                    // has a named test pinning that it must not. Refused rather than
                    // logged, because a harness that shrugs at it is how it would ship.
                    other => die(
                        2,
                        &format!(
                            "VerifyAddress drew {other:?}, not Shown::Info -- an address \
                             screen that authorises something is a hole, not a feature"
                        ),
                    ),
                }
            }
            // Debug is not derived on every inner phase type, so no {other:?}.
            _other => eprintln!("stub: {id} ignoring an unrelated ToUser message"),
        }
    }

    // The device's persistence record, READ OFF THE SIGNER. **This loop used to drain
    // `session.signer.staged_mutations()` looking for `KeyMutation::SaveShare`, and it
    // NEVER MATCHED ONCE**, so `saved` stayed empty for the whole run and both conditions
    // that read it were dead. MEASURED with a probe printing
    // `staged_mutations().len()` here: 308 calls in one `cargo run`, every single one
    // `staged=0`.
    //
    // The mechanism, and it is firmware doing its job rather than a bug: `keygen_ack`
    // stages the NewKey/NewAccessStructure/SaveShare triple and then calls
    // `Session::run`, whose FIRST statement is
    // `self.shares.persist_staged(self.signer.staged_mutations())` — and a committed
    // write ends in `staged.clear()`. So the queue is empty again before `recv` returns.
    // The comment here claimed the opposite ("NOTHING DOES YET -- there is no FLASH_FS
    // region for shares"), which stopped being true when `store::ShareStore` landed.
    //
    // Two conditions were vacuous as a result, and this is the one place that fixes both:
    // the `saved.len() == N_DEVICES && !announced_save` latch below never fired, so
    // `STATE` never reached `SharesSaved` and the `refs.len() != 1` check ("every share
    // belongs to ONE access structure") never ran; and the wire-EOF PASS arm's condition
    // was never true, so a HAND run always died `0/9 share(s) saved` after a completely
    // successful pass.
    //
    // `held_shares()` is the signer's own view of what it holds and is the SAME source
    // the `HeldShares2` reply is built from, so this is a local read of the fact the
    // coordinator independently checks over the wire. Filtering on
    // `access_structure_ref.is_some()` is what separates a real access-structure share
    // from a `needs_consolidation` saved backup, which carries `None`.
    for held in session.signer.held_shares() {
        if let Some(as_ref) = held.access_structure_ref {
            if saved.insert(id, as_ref).is_none() {
                eprintln!(
                    "stub: {id} HOLDS a share for {as_ref:?} (index {}) -- {} device(s) do now",
                    held.share_image.index,
                    saved.len()
                );
            }
        }
    }

    wire.extend_from_slice(&out.take());
    EraseOutcome::NotAsked
}

/// The upgrade listener's transport, over the same fd 0 / fd 1 the framed loop uses.
///
/// A BLOCKING read is correct here and nowhere else in this file: in `STUB_UPGRADE`
/// mode the stub does nothing but stage, and the host driver is in strict lockstep
/// (write a chunk, read one ack), so there is no second thing to service and no pty
/// deadlock to arrange around. That is why there is no `spawn_reader`, no channel and
/// no `Link` outside `upgrade::run` in this mode.
struct StdioWire {
    inp: std::io::StdinLock<'static>,
    out: std::io::StdoutLock<'static>,
}

impl coldsnap_firmware::upgrade::Wire for StdioWire {
    fn read(&mut self, buf: &mut [u8; coldsnap_hal::usb::MAX_PACKET_SIZE]) -> Option<usize> {
        // `Ok(0)` is EOF on a pipe, which IS the wire closing — the one case
        // `Wire::read`'s docs say `None` is for. An `Err` is treated the same way
        // rather than as `Some(0)`: on a pty a read error is not something this
        // process can survive, unlike `Cdc::poll`'s oversize-packet error.
        match self.inp.read(buf) {
            Ok(0) | Err(_) => None,
            Ok(n) => Some(n),
        }
    }

    fn write(&mut self, bytes: &[u8]) {
        // Unchunked and flushed. `write_chunked`'s 1 ms-per-chunk pacing exists for
        // multi-kilobyte frames; every write from the listener is 1 or 8 bytes.
        let _ = self.out.write_all(bytes);
        let _ = self.out.flush();
    }
}

fn main() {
    // THE UPGRADE LEG, and it returns rather than falling through: this mode drives
    // `coldsnap_firmware::upgrade::run` and nothing else, so the nine sessions, the
    // twelve milestones and every existing assertion are untouched by construction.
    // hostcheck's M13 spawns its own child with this set.
    if std::env::var_os("STUB_UPGRADE").is_some() {
        std::thread::spawn(|| {
            std::thread::sleep(Duration::from_secs(60) * timeout_scale());
            die(3, "upgrade watchdog fired: the chunk stream made no progress");
        });
        let mut wire = StdioWire {
            inp: std::io::stdin().lock(),
            out: std::io::stdout().lock(),
        };
        // Sized to the DEVICE's own admission ceiling, so a capacity refusal from
        // the double can never pre-empt a real refusal from `Stager` — a fake sized
        // to the image under test would make `Refuse::TooLarge` unreachable and turn
        // every over-size leg into an `OutOfBounds` from the double instead.
        let psram =
            coldsnap_hal::psram::fake::FakePsram::new(coldsnap_hal::psram::BURN_LEN_MAX as usize);
        let outcome = coldsnap_firmware::upgrade::run(&mut wire, psram);
        eprintln!("stub: upgrade listener finished: {outcome:?}");
        return;
    }

    std::thread::spawn(|| {
        std::thread::sleep(DEADLINE * timeout_scale());
        die(3, "watchdog fired: no progress within the deadline");
    });

    let mut rng = entropy(salt());
    let flashes = blank_flashes();
    let (mut sessions, mut flash_of, recovered) = open_sessions(&flashes, &mut rng);
    if !recovered.is_empty() {
        die(2, "a fresh stub's flash held a committed erase marker");
    }
    // Fix 2a: devices whose erase a power cut interrupted, OFF until the next replug.
    // `(id, committed)`: whether its marker committed before the cut.
    let mut powered_off: Vec<(DeviceId, bool)> = Vec::new();
    let mut ids: Vec<DeviceId> = sessions.keys().copied().collect();
    let mut erase_asks: BTreeMap<DeviceId, usize> = BTreeMap::new();
    // PARSED BY `tools/app-rig.py` — it reads the ids back off this line and refuses a
    // run in which two child processes announce the same one. Keep the
    // `flash-backed sessions: [..]` shape if you edit it.
    let hosted = sessions.len();
    eprintln!(
        "stub: {hosted} flash-backed sessions (salt {:#04x}): {ids:?}",
        salt()
    );
    // FIX 12, PARSED BY `tools/app-rig.py` after a stub restart: what this boot read off
    // the file, compared there with what the previous process's app recorded.
    if std::env::var_os("STUB_FLASH_FILE").is_some() {
        for s in sessions.values() {
            let shares: Vec<String> = s
                .signer
                .held_shares()
                .filter(|h| h.access_structure_ref.is_some())
                .map(|h| h.share_image.index.to_string())
                .collect();
            eprintln!(
                "stub: {} booted from STUB_FLASH_FILE: name {:?}, shares [{}]",
                s.device_id(),
                s.stored_name(),
                shares.join(",")
            );
        }
    }

    let (digest, digest_from) = announced_digest();
    eprintln!(
        "stub: announcing firmware digest {} from {digest_from}",
        hex(&digest.0)
    );
    let mut saved: BTreeMap<DeviceId, AccessStructureRef> = BTreeMap::new();
    let mut announced_save = false;
    // THE PAPER. Outside the restart on purpose: it is filled by M7b's reveal, which
    // happens long after it, and it must survive between the four restoration flows
    // because the quiz and the letter picker are answered from it. See [`Sheet`].
    let mut paper: BTreeMap<DeviceId, Sheet> = BTreeMap::new();

    // THE SCRIPTED GATE'S CONSENT, and the default is the automated gate's: press
    // whatever the SCREEN advertises.
    //
    // Not `|_| true`, because with a randomised digit there is no fixed byte that
    // authorises a signature — `advertised_key` reads it back out of the rendered
    // pixels, which is the only channel a closure has. `y` is still an
    // unconditional yes and still a harness affordance: it never says no, it just
    // cannot say yes without having read the screen correctly. A device that
    // rendered the wrong legend would make this press the wrong key and get a
    // refusal, which fails the run — so the glass assertion is a PRECONDITION of
    // passing, not an extra check bolted on.
    //
    // The digit is never derived from the RNG, the seed, or the `ConfirmDigit` the
    // caller holds. `COLDSNAP_GLASS_KEYS` can only ask for a LITERAL key, which is
    // exactly the hardcoded-script case, and a literal cannot match a randomised
    // digit reliably (`9` never can).
    let keys = glass_keys();
    eprintln!(
        "stub: consent keys = {keys:?} <CheckKeyGen><SignatureRequest><Restoration> (y = press \
         what the glass advertises; anything else is that literal key, whatever the screen says)"
    );
    let mut consent = |prompt: &DeviceToUserMessage, frame: &ui::Frame| -> u8 {
        let scripted = match prompt {
            DeviceToUserMessage::CheckKeyGen { .. } => keys.as_bytes().first(),
            // The four M7 restoration screens share the third slot. See `glass_keys`:
            // `COLDSNAP_GLASS_KEYS=yy9` is what demonstrates that no hardcoded key can
            // authorise a reveal, an ingest or a consolidation.
            DeviceToUserMessage::Restoration(_) => keys.as_bytes().get(2),
            _ => keys.as_bytes().get(1),
        };
        match scripted.copied().unwrap_or(b'y') {
            b'y' => match advertised_key(frame) {
                Some(key) => key,
                // FAIL CLOSED: a screen advertising no yes key gets `x`, which is a
                // decline, which fails the run unless it was declared.
                None => {
                    eprintln!("stub: the glass advertises NO confirm key -- declining");
                    b'x'
                }
            },
            key => key,
        }
    };

    let mut link = Link::new();
    let wire_rx = spawn_reader();
    let mut wire_out = std::io::stdout().lock();
    let chunk = chunk_size();

    loop {
        // fd 0 is drained by `spawn_reader`, never by this loop: an undrained pty
        // blocks writes past ~1 KB, while unlinked `Link::poll` is silent so wire
        // bytes are still the only thing that advances the protocol, and a loop
        // that BLOCKS for them cannot service anything else (see `spawn_reader`).
        let bytes = match wire_rx.recv_timeout(WIRE_POLL) {
            // EOF is the ending for a HAND run: `hostcheck` kills us instead
            // (`reap()`), so in a harness run neither of these arms is reached and
            // our exit status is not what the pass hinges on. Kept, and kept
            // asymmetric, because it is the only contract a hand run has: EOF
            // after a successful save is success, EOF before one is a failure, and
            // it must stay that way or a stub killed early would look clean.
            Ok(Ok(bytes)) if bytes.is_empty() => {
                // THE LATCH, not a re-derived count, and that is the M12 fix. `saved`
                // reaches TEN once the blank device consolidates — `finish_consolidation`
                // stages the same keygen triple and the drain in `drive` records it — so
                // `saved.len() == N_DEVICES` INVERTS here and turned a hand run's PASS
                // into `die(2, "wire EOF with only 10/9 share(s) saved")`. `announced_save`
                // latches below on the exact `== N_DEVICES`, so the strictness is
                // unchanged and the two different meanings of `saved.len()` stop sharing
                // one constant. It only ever bit a hand run, which is precisely where
                // nobody is watching for it.
                if announced_save {
                    eprintln!(
                        "stub: PASS -- coordinator closed the wire after verifying \
                         {N_DEVICES}/{N_DEVICES} keygen shares (of {} device(s) that have staged \
                         one) and {} signature share(s), all from sessions REBUILT FROM FLASH \
                         after the restart",
                        saved.len(),
                        SIG_ACKS.load(Ordering::Relaxed)
                    );
                    return;
                }
                die(
                    2,
                    &format!(
                        "wire EOF with only {}/{N_DEVICES} share(s) saved -- the coordinator gave \
                         up first",
                        saved.len()
                    ),
                )
            }
            Ok(Ok(bytes)) => bytes,
            Ok(Err(e)) => die(2, &format!("read(fd 0): {e}")),
            // No wire bytes this lap. Nothing else can have changed either --
            // `saved`, `coordinator_acked` and `wire` are all downstream of a
            // decoded body -- so skipping the rest is EXACTLY what the old blocking
            // read did, minus the block. Once a prompt can park (step 2) this arm is
            // where it gets serviced.
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => {
                die(2, "the fd-0 reader thread vanished without an EOF or an error")
            }
        };
        BYTES_READ.fetch_add(bytes.len(), Ordering::Relaxed);

        // The "just linked" edge is observed HERE, from outside, on purpose:
        // `Link` exposes `is_linked()` but no edge, and this file is specified to
        // need zero `hal/src/` changes.
        let was_linked = link.is_linked();
        // THE COORDINATOR HAS LOST US. It writes its magic pattern every
        // `MAGIC_BYTES_PERIOD` **only until it reads our reply**
        // (`usb_serial_manager::poll_ports`'s `awaiting_magic` loop), so magic bytes
        // arriving on an already-linked wire mean it is back in the handshake state for
        // this port -- it closed and re-opened it, or it restarted. That is the app rig's
        // REPLUG: the manifest line went away and came back, the app dropped the port and
        // opened it again, and its device registry no longer holds us.
        //
        // TWO THINGS DIVERGE FROM `firmware/src/main.rs` HERE AND BOTH ARE RECORDED
        // RATHER THAN QUIETLY PAPERED OVER:
        //  - `main.rs` replies `MAGIC_REPLY` to every `MagicBytes` frame
        //    (`send_magic_reply = true` in its callback, with no `was_linked` guard) and
        //    this file did not reply at all once linked. That was a straight fidelity
        //    bug in this stub: the app sat in `awaiting_magic` writing magic bytes
        //    forever -- 1,758 of them in one measured run -- and no device came back.
        //  - `main.rs` announces ONLY on the link edge (`!was_linked && link.is_linked()`),
        //    so on the ARM image a coordinator that re-opens a port without the device
        //    power-cycling gets a `MAGIC_REPLY` and no `Announce`, and never re-registers
        //    the device. Its own comment expects a desync to unlink and produce a fresh
        //    edge, but repeat magic bytes decode as an ordinary frame
        //    (`comms::test::magic_bytes_after_the_handshake_are_an_ordinary_frame`), so
        //    there is no desync and no edge. On real hardware an unplug cuts power and
        //    the device reboots, which is how the gap stays hidden. THIS FILE
        //    RE-ANNOUNCES; the ARM image does not, and that difference is a finding to
        //    fix in `main.rs`, not something this run may claim as covered.
        //
        // OPT-IN (`STUB_REANNOUNCE=1`, which only `tools/app-rig.py` sets) because
        // `hostcheck` writes coordinator magic bytes CONTINUOUSLY on a linked wire, not
        // only while it is waiting for a reply. Re-announcing there re-registers every
        // device in the middle of a keygen and throws its keygen state away — MEASURED:
        // `Session::recv(...): InvalidMessage { kind: "KeyGen", reason: "no keygen state
        // for provided keygen_id" }`, exit 2, on the first hostcheck run after this was
        // unconditional. So the two coordinators genuinely need different answers here,
        // and that is itself the evidence that "magic bytes on a linked wire" does not
        // mean one thing on this protocol.
        let mut rehello = false;
        let mut wire: Vec<u8> = Vec::new();
        // `(id, cut)`: `Some(committed)` = a power cut interrupted the erase.
        let mut erased: Vec<(DeviceId, Option<bool>)> = Vec::new();
        let poll = link.poll::<ReceiveSerial<Upstream>, _>(&bytes, |frame| match frame {
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
                            let before = flash_counters(&flashes);
                            let flash = &flashes[flash_of[&id]];
                            match drive(
                                session,
                                flash,
                                body.clone(),
                                &mut rng,
                                &mut consent,
                                &mut wire,
                                &mut saved,
                                &mut paper,
                                &mut erase_asks,
                            ) {
                                // A no to an erase wrote NOTHING, on any flash.
                                EraseOutcome::Declined if flash_counters(&flashes) != before => {
                                    die(2, &format!("{id} declined an erase and flash changed"))
                                }
                                EraseOutcome::Erased => erased.push((id, None)),
                                EraseOutcome::Interrupted { committed } => {
                                    erased.push((id, Some(committed)))
                                }
                                _ => {}
                            }
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
            ReceiveSerial::MagicBytes(_) => {
                eprintln!("stub: rx MagicBytes");
                rehello = true;
            }
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

        // TASK 08: a device that erased RESETS. Its poisoned session is dropped and
        // rebuilt from its flash exactly as a boot would (`erase::recover`, then
        // `load_or_create`, then `Session::open`), and it must come back a DIFFERENT
        // device holding nothing: a fresh id, no share, no name. Its Announce +
        // NeedName follow the `EraseConfirmed` already in `wire`, which is the order a
        // real unit's reset puts them in. (A real reset also drops USB and re-runs the
        // magic handshake; one pty cannot model that for one of N sessions.)
        for (old, cut) in erased {
            let Some(mut session) = sessions.remove(&old) else {
                die(2, &format!("{old} erased with no session"));
            };
            let i = flash_of.remove(&old).expect("every session has a flash");
            ids = sessions.keys().copied().collect();
            if let Some(committed) = cut {
                // FIX 2a: power is off. Nothing answers for `old` until the replug
                // below reboots this flash through `erase::recover`.
                powered_off.push((old, committed));
                eprintln!("stub: {old} OFF after the power cut; its flash waits for boot");
                continue;
            }
            // main.rs's order: the EraseConfirmed is WRITTEN, then the marker cleared.
            if let Err(e) = write_chunked(&mut wire_out, &wire, chunk) {
                die(2, &format!("write(fd 1): {e}"));
            }
            wire.clear();
            if let Err(e) = session.finish_erase() {
                die(2, &format!("{old}: finish_erase after the ack was written: {e:?}"));
            }
            drop(session);
            let (fresh, recovered) = open_one(&flashes[i], &mut rng);
            // An uncut erase acked in session and `finish` cleared its marker, so
            // boot owes nothing; a second ack here would be a duplicate.
            if let Some(orig) = recovered {
                die(2, &format!("{old}: acked erase left a marker for {orig:02x?}"));
            }
            let new = fresh.device_id();
            if new == old || sessions.contains_key(&new) {
                die(2, &format!("{old} erased but came back as {new}"));
            }
            let shares = fresh.signer.held_shares().count();
            let name = fresh.stored_name();
            if shares != 0 || name.is_some() {
                die(
                    2,
                    &format!("{old} erased but {new} holds {shares} share(s), name {name:?}"),
                );
            }
            let mut out = Outbox::new(new);
            if let Err(e) = fresh.announce(digest, &mut out) {
                die(2, &format!("announce({new}) after erase: {e:?}"));
            }
            wire.extend_from_slice(&out.take());
            eprintln!(
                "stub: {old} RESET after erase and rebuilt from flash as {new}: 0 shares, no \
                 name; Announce+NeedName queued behind the EraseConfirmed"
            );
            flash_of.insert(new, i);
            sessions.insert(new, fresh);
            ids = sessions.keys().copied().collect();
        }

        // The re-hello, which is a POWER CYCLE first. A cold-snap unit is USB-powered, so
        // an unplug/replug drops every byte of RAM: the sessions are rebuilt from the same
        // `FakeFlash` bytes BEFORE the re-announce, exactly as a boot would, and the
        // DeviceIds are asserted unchanged. Unlike the link-edge restart below, this one
        // happens AFTER keygen, so the rebuilt session has to read its share and its nonce
        // streams back off flash -- the app rig signs with this device after the replug
        // to prove it did. Only with `STUB_REANNOUNCE` (the app rig); hostcheck never
        // replugs. It must NOT fall through to the link-edge restart. See the `rehello`
        // comment above for the `main.rs` divergence.
        if rehello && link.is_linked() && was_linked && reannounce() {
            let recovered;
            (sessions, flash_of, recovered) = open_sessions(&flashes, &mut rng);
            // FIX 2a: a device whose erase a power cut interrupted boots HERE. Its
            // boot finished the erase; it must be one we powered off, come back as a
            // new id with nothing on it, and its ack (old id) leads the hello.
            let mut acks = Vec::new();
            let mut expect = ids.clone();
            for (new, orig) in &recovered {
                let Some(at) = powered_off.iter().position(|&(o, c)| o == *orig && c) else {
                    die(2, &format!("boot recovered an erase for {orig}, which was never cut"));
                };
                powered_off.remove(at);
                let fresh = &sessions[new];
                if new == orig
                    || fresh.signer.held_shares().count() != 0
                    || fresh.stored_name().is_some()
                {
                    die(2, &format!("{orig} recovered as {new} but is not blank"));
                }
                match coldsnap_firmware::recovered_erase_ack(orig.0) {
                    Ok(ack) => acks.extend_from_slice(ack.bytes()),
                    Err(e) => die(2, &format!("recovered_erase_ack({orig}): {e:?}")),
                }
                eprintln!(
                    "stub: {orig} erase::recover FINISHED the cut erase at boot; \
                     EraseConfirmed queued under the old id after recovery verified the \
                     flash blank; rebuilt from flash as {new}: 0 shares, no name"
                );
                expect.push(*new);
            }
            // A cut before the commit: boot finds no marker and the SAME device,
            // share intact, and owes no ack.
            for (off, committed) in powered_off.drain(..) {
                let kept = sessions.get(&off).map(|s| s.signer.held_shares().count());
                if committed || kept.is_none_or(|n| n == 0) {
                    die(
                        2,
                        &format!("{off} was cut (committed={committed}) but booted as {kept:?}"),
                    );
                }
                eprintln!(
                    "stub: {off} rebooted after a pre-commit power cut: same id, {} share(s) \
                     kept, no EraseConfirmed",
                    kept.unwrap_or(0)
                );
                expect.push(off);
            }
            expect.sort();
            ids = expect;
            let after: Vec<DeviceId> = sessions.keys().copied().collect();
            if after != ids {
                die(
                    2,
                    &format!(
                        "IDENTITY DID NOT SURVIVE THE REPLUG RESTART: announced {ids:?} but \
                         flash rebuilt as {after:?}"
                    ),
                );
            }
            eprintln!(
                "stub: REPLUG RESTART -- dropped all {hosted} signers and rebuilt them from \
                 flash after keygen; every DeviceId unchanged except {} recovered erase(s)",
                recovered.len()
            );
            let mut hello = Vec::from(MAGIC_REPLY);
            hello.extend_from_slice(&acks);
            for session in sessions.values() {
                let mut out = Outbox::new(session.device_id());
                if let Err(e) = session.announce(digest, &mut out) {
                    die(2, &format!("re-announce({}): {e:?}", session.device_id()));
                }
                hello.extend_from_slice(&out.take());
            }
            if let Err(e) = write_chunked(&mut wire_out, &hello, chunk) {
                die(2, &format!("write(fd 1): {e}"));
            }
            eprintln!(
                "stub: the coordinator asked for magic on a LINKED wire -- it re-opened this \
                 port, so MAGIC_REPLY + {hosted} Announce again ({} bytes), after the \
                 replug restart above.",
                hello.len()
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
                "stub: sent MAGIC_REPLY + {hosted} Announce+NeedName = {} bytes in {} chunk(s) \
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
            //  - and NOT because a share would be lost. This read "nothing persists a
            //    completed share yet (see `drive`), so a restart after keygen would lose
            //    it" until review caught it on 2026-09-12: `store::ShareStore::persist_staged`
            //    writes the keygen triple to `FS_SHARE`, and it runs as `Session::run`'s
            //    FIRST statement, so a post-keygen restart would find the share on flash.
            //    The reason above is the whole reason. A restart AFTER keygen is therefore
            //    possible now and is deliberately not done here — it would be a second
            //    durability claim, and this file makes one.
            //
            // The assert below is belt: it fails fast and by name, whereas the
            // coordinator's failure would be a keygen timeout.
            let recovered;
            (sessions, flash_of, recovered) = open_sessions(&flashes, &mut rng);
            if !recovered.is_empty() {
                die(2, "an erase marker survived to the link-edge restart");
            }
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
                "stub: RESTARTED -- dropped all {hosted} signers and rebuilt them from flash; \
                 every DeviceId unchanged, so the coordinator is still talking to the same devices"
            );
        }

        // `hosted` (= [`session_count`], `ALL_DEVICES` by default) and not `N_DEVICES`,
        // because every session on the wire gets an
        // `AnnounceAck` including the blank one, and this is an EQUALITY recomputed each
        // lap rather than a latch: at 9 it would claim "all acked" while one device has
        // not. Left at 9 and reached, `STATE` never advances to 3 and the progress word
        // in every subsequent `die` message is one stage stale — a silently wrong
        // diagnosis rather than a cosmetic count.
        //
        // CORRECT BY CONSTRUCTION AND **NOT** LOAD-BEARING AT THIS MACHINE'S TIMING, and
        // that distinction is recorded because the first version of this comment claimed
        // the opposite. It said all ten acks "can arrive inside a single
        // `wire_rx.recv_timeout` payload, so `acked` jumps 0 -> 10 and 9 is never
        // observed", and asserted that reverting to `N_DEVICES` removes the line from the
        // log. MEASURED, and neither holds: `hostcheck` queues each ack on its own lap, so
        // `acked` walks 1..10, the equality catches it at 9, and reverting to `N_DEVICES`
        // leaves the harness GREEN at exit 0 with the line still printing. Caught by
        // review, 2026-09-12. The failure this guards is real and would be INVISIBLE — if
        // the acks ever do coalesce (heavier load, larger reads, a chunk-size change), 9
        // is skipped and nothing says so.
        let acked = sessions.values().filter(|s| s.coordinator_acked).count();
        if acked == hosted && STATE.load(Ordering::Relaxed) == 2 {
            STATE.fetch_max(3, Ordering::Relaxed);
            eprintln!(
                "stub: all {hosted} devices acked (post-restart sessions), waiting for keygen"
            );
        }

        if !wire.is_empty() {
            let bytes = wire.len();
            if let Err(e) = write_chunked(&mut wire_out, &wire, chunk) {
                die(2, &format!("write(fd 1): {e}"));
            }
            eprintln!("stub: sent {bytes} B");
        }

        // FAIL CLOSED on a decline, and checked AFTER the write so the
        // `declined=` line is on the wire before we go. A decline is a pass only
        // if the run asked for one: otherwise a bug that declined every prompt
        // would look like a quiet, clean — and completely signature-free — run,
        // which is the failure mode LIVE-GLASS-PLAN §10 names.
        let declined = DECLINES.load(Ordering::Relaxed);
        if declined > expect_declines() {
            die(
                2,
                &format!(
                    "{declined} prompt(s) DECLINED but STUB_EXPECT_DECLINES={} -- a declined \
                     prompt is a FAILURE unless the run declares it",
                    expect_declines()
                ),
            );
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
