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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::Duration;

use coldsnap_firmware::{
    firmware_digest, prompt_screen, quiz, wordentry, Checked, DebugFlash, Fault, Outbox, Session,
    Typed,
};
use coldsnap_hal::comms::{decode_body, CoordinatorSendBody, Link, MAGIC_REPLY};
use coldsnap_hal::flash::fake::FakeFlash;
use coldsnap_hal::flash::ERASE_SIZE;
use coldsnap_hal::rng::{mix_sources, Entropy, ProvenSeed, SE1_BYTES, SE2_BYTES, TRNG_BYTES};
use coldsnap_hal::{identity, memmap, ui};
use frostsnap_comms::{DeviceSendBody, ReceiveSerial, Upstream};
use frostsnap_core::device::keys::KeyMutation;
use frostsnap_core::device::{restoration::ToUserRestoration, DeviceToUserMessage, Mutation};
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
/// How many prompts the consent closure DECLINED. Global for the same reason
/// `SIG_ACKS` is, and read by the main loop's fail-closed check.
static DECLINES: AtomicUsize = AtomicUsize::new(0);

/// LONGER than the harness's own budget on purpose, and that is load-bearing.
/// `hostcheck` owns the budget and kills us itself; this watchdog only exists so
/// a stub run BY HAND cannot hang forever. If it fires during a `hostcheck` run,
/// the news is that the harness's bound is broken.
///
/// 240 s: a 9-of-9 certpedpop keygen is real elliptic-curve work in a DEBUG build,
/// nine signers deep, and at `STUB_CHUNK=1` every byte of every frame costs a
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
/// `no_pin_screen_advertises_a_consent_key_to_the_stub_scraper`. Those decisions are
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

/// Render `prompt`, ask `consent` for a keypress, and decide. `true` means
/// confirm it.
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
) -> bool {
    let digit = ui::ConfirmDigit::draw(rng);
    let mut frame = ui::Frame::new();
    // `Ok(false)` (informational, no screen) and `Err` (this device cannot draw
    // the request in full) are both prompts NO key may authorise. They are
    // deliberately not called declines: `Session::confirm` fails closed on exactly
    // these two — `NotConfirmable` and `Refused` — and names the failure itself,
    // so it stays the authority and its diagnostics keep their existing wording.
    if !matches!(prompt_screen(&mut frame, prompt, digit), Ok(true)) {
        return true;
    }
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
    match prompt {
        // THE ANTI-MITM SCREEN, and as of 2026-09-11 it is gated exactly like the
        // signing one. This arm read `key == b'1'` because `ui::keygen_check` printed a
        // fixed `1=match x=no`; that made this the ONE consent screen in the tree a
        // hardcoded script could clear, on the one screen whose entire purpose is that
        // a human read four bytes off it and said them out loud. `keygen_check` now
        // prints the same randomised `ui::ConfirmDigit` drawn above, so only the digit
        // that is ON THE SCREEN acks — and `COLDSNAP_GLASS_KEYS=1yy`, which used to
        // PASS, now fails with no source mutation at all.
        DeviceToUserMessage::CheckKeyGen { .. } => digit.accepts(key),
        // FAIL CLOSED — `hsm_ux.py:58`'s `refused = (ch != confirm_char)`,
        // inverted. Only the digit that is ON THE SCREEN signs; `x`, another
        // charset digit and a key that is not on the pad are all refusals.
        DeviceToUserMessage::SignatureRequest { .. } => digit.accepts(key),
        // THE FOUR RESTORATION CONSENT SCREENS. Every one of them prints the same
        // randomised legend the signing screen does — `consent_screen`'s
        // `"Press (N) x=no"`, composed from the very `ConfirmDigit` drawn above — so
        // the same rule applies and for the same reason: only the digit that is ON
        // THE SCREEN grants, and `x`, another charset digit and a key that is not on
        // the pad are all refusals. This is `main.rs`'s `answer` arm for
        // `Consent::Prompt`, whose `_ => confirm.accepts(key)` covers exactly these.
        //
        // `BackupSaved` never reaches here: `prompt_screen_at` draws no screen for
        // it, so the `Ok(true)` gate above has already returned.
        DeviceToUserMessage::Restoration(_) => digit.accepts(key),
        // Not a consent prompt. Unreachable from the call sites in `drive`, and a
        // decline — which fails the run — if that ever stops being true.
        _ => false,
    }
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
    body: CoordinatorSendBody,
    rng: &mut Entropy,
    consent: Consent,
    wire: &mut Vec<u8>,
    saved: &mut BTreeMap<DeviceId, AccessStructureRef>,
    paper: &mut BTreeMap<DeviceId, Sheet>,
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
                let p = DeviceToUserMessage::CheckKeyGen { phase };
                if !approved(&p, rng, &mut *consent, &mut out) {
                    decline(id, "CheckKeyGen", &mut out);
                } else {
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
                    match session.confirm(p, rng, &mut out) {
                        Ok(more) => prompts.extend(more),
                        Err(e) => die(2, &format!("confirm(CheckKeyGen, {id}): {e:?}")),
                    }
                    if clear_tmp_mode() == "check" {
                        eprintln!("stub: {id} clear_tmp_data() at CheckKeyGen -- WRONG ON PURPOSE");
                        session.signer.clear_tmp_data();
                    }
                }
            }
            p @ DeviceToUserMessage::SignatureRequest { .. } => {
                if !approved(&p, rng, &mut *consent, &mut out) {
                    decline(id, "SignatureRequest", &mut out);
                } else {
                    // NOT an auto-ack either, and this one is structural: `approved`
                    // required `digit.accepts(key)` against a RANDOMISED
                    // `ui::ConfirmDigit` drawn on the frame the consent answered, so
                    // no hardcoded key can reach here (`COLDSNAP_GLASS_KEYS=y9`
                    // and `=y2` are refusals by construction). What a host cannot
                    // supply is a human who actually read the screen.
                    eprintln!(
                        "stub: {id} SignatureRequest -> approved on the randomised digit read off the glass"
                    );
                    match session.confirm(p, rng, &mut out) {
                        Ok(more) => {
                            SIG_ACKS.fetch_add(1, Ordering::Relaxed);
                            STATE.fetch_max(6, Ordering::Relaxed);
                            prompts.extend(more);
                        }
                        Err(e) => die(2, &format!("confirm(SignatureRequest, {id}): {e:?}")),
                    }
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
                if !approved(&p, rng, &mut *consent, &mut out) {
                    decline(id, &format!("{grant:?}"), &mut out);
                    continue;
                }
                eprintln!(
                    "stub: {id} {grant:?} -> approved on the randomised digit read off the glass"
                );
                match session.confirm(p, rng, &mut out) {
                    Ok(more) => prompts.extend(more),
                    Err(e) => die(2, &format!("confirm({grant:?}, {id}): {e:?}")),
                }
                let sheet = paper.entry(id).or_default();
                match grant {
                    // M7b. Nothing is on the wire until the last page has been drawn
                    // and the recorded question answered — that is what
                    // `Session::backup_recorded`'s `record_pending` gate means.
                    Grant::Reveal => reveal(session, rng, &mut out, sheet),
                    // M7c. Answered ONLY from what M7b's reveal showed.
                    Grant::Check => {
                        let answers = check_quiz(session, rng, &mut out, sheet);
                        if let Err(e) = out.push(DeviceSendBody::Debug {
                            message: format!("quiz={answers}"),
                        }) {
                            die(2, &format!("Debug(quiz) refused by framing: {e:?}"));
                        }
                    }
                    // M7d. `entry_key` sends `PhysicalEntered` itself, and only when
                    // 25 words pass their checksum.
                    Grant::Enter => {
                        let (presses, more) = type_backup(session, rng, &mut out, sheet);
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
        std::thread::sleep(DEADLINE * timeout_scale());
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
                if saved.len() == N_DEVICES {
                    eprintln!(
                        "stub: PASS -- coordinator closed the wire after verifying \
                         {N_DEVICES}/{N_DEVICES} held shares and {} signature share(s), all from \
                         sessions REBUILT FROM FLASH after the restart",
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
        let mut wire: Vec<u8> = Vec::new();
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
                            drive(
                                session,
                                body.clone(),
                                &mut rng,
                                &mut consent,
                                &mut wire,
                                &mut saved,
                                &mut paper,
                            );
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
